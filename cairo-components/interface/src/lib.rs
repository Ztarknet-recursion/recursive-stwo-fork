use cairo_air::CairoProof;
use cairo_plonk_dsl_answer::AnswerResults;
use cairo_plonk_dsl_composition::CairoCompositionCheck;
use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_folding::FoldingResults;
use cairo_plonk_dsl_hints::{
    folding::CairoFoldingHints, AnswerHints, CairoDecommitmentHints, CairoFiatShamirHints,
};
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{ChannelVar, Poseidon2HalfVar};
use num_traits::One;
use stwo::core::{
    channel::{Channel, Poseidon31Channel},
    fields::qm31::QM31,
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
};

pub fn compute_output_hash(proof: &CairoProof<Poseidon31MerkleHasher>) -> Poseidon31Hash {
    let output = &proof.claim.public_data.public_memory.output;
    assert_eq!(output.len(), 5);

    let mut channel = Poseidon31Channel::default();
    for (_, value) in output.iter() {
        channel.mix_u32s(value);
    }
    Poseidon31Hash(channel.digest())
}

pub fn verifier_input(output_hash: &Poseidon31Hash) -> Vec<(usize, QM31)> {
    let h = output_hash.0;
    vec![
        (1, QM31::one()),
        (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
        (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        (4, QM31::from_m31(h[0], h[1], h[2], h[3])),
        (5, QM31::from_m31(h[4], h[5], h[6], h[7])),
    ]
}

pub fn verify_output_hash(expected_hash: Poseidon2HalfVar, proof_var: &CairoProofVar) {
    assert_eq!(
        proof_var
            .claim
            .public_data
            .public_memory
            .output
            .values
            .len(),
        5
    );

    let mut channel = ChannelVar::default(&proof_var.cs());
    for value in proof_var
        .claim
        .public_data
        .public_memory
        .output
        .values
        .iter()
    {
        for v in value.iter() {
            v.mix_into(&mut channel);
        }
    }
    channel.digest.equalverify(&expected_hash);
}

pub fn verify_proof(proof: &CairoProof<Poseidon31MerkleHasher>, proof_var: &CairoProofVar) {
    let cs = proof_var.cs();

    let fiat_shamir_hints = CairoFiatShamirHints::new(proof);
    let proof_var = CairoProofVar::new_witness(&cs, proof);
    let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);

    CairoCompositionCheck::compute(&fiat_shamir_results, &fiat_shamir_hints, &proof_var);

    let answer_hints = AnswerHints::new(&fiat_shamir_hints, proof);
    let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, proof);

    let folding_hints = CairoFoldingHints::new(&fiat_shamir_hints, &answer_hints, proof);
    let decommitment_results = CairoDecommitmentResultsVar::compute(
        &fiat_shamir_hints,
        &decommitment_hints,
        &fiat_shamir_results,
        &proof_var,
    );
    let answer_results = AnswerResults::compute(
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &decommitment_results,
        &proof_var,
    );
    FoldingResults::compute(
        &fiat_shamir_hints,
        &folding_hints,
        &fiat_shamir_results,
        &answer_results,
        &proof_var,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use std::path::PathBuf;

    #[test]
    fn test_compute_output_hash() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let output_hash = compute_output_hash(&proof);

        let cs = ConstraintSystemRef::new();

        let output_hash_var = Poseidon2HalfVar::new_public_input(&cs, &output_hash);
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        verify_output_hash(output_hash_var, &proof_var);
        verify_proof(&proof, &proof_var);

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
