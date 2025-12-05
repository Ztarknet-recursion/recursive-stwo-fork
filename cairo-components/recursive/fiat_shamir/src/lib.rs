use cairo_plonk_dsl_data_structures::{CairoClaimVar, CairoProofVar, lookup::CairoInteractionElementsVar};
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_channel::ChannelVar;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_poseidon31::Poseidon2HalfVar;
use circle_plonk_dsl_bits::BitsVar;
use cairo_air::verifier::INTERACTION_POW_BITS;
use circle_plonk_dsl_fields::M31Var;

pub struct CairoFiatShamirResults {}

impl CairoFiatShamirResults {
    pub fn compute(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProofVar,
    ) -> Self {
        let cs = proof.cs();
        
        let mut channel = ChannelVar::default(&cs);
        channel.digest = Poseidon2HalfVar::new_constant(&cs, &fiat_shamir_hints.initial_channel);

        Self::check_claim(&proof.claim);
        proof.claim.mix_into(&mut channel);

        channel.mix_root(&proof.stark_proof.trace_commitment);

        let _ = BitsVar::from_m31(&proof.interaction_pow.0[0], 22);
        let _ = BitsVar::from_m31(&proof.interaction_pow.0[1], 21);
        let _ = BitsVar::from_m31(&proof.interaction_pow.0[2], 21);

        proof.interaction_pow.mix_into(&mut channel);

        let lower_bits = BitsVar::from_m31(&channel.digest.to_qm31()[0].decompose_m31()[0], 31)
            .compose_range(0..INTERACTION_POW_BITS as usize);
        lower_bits.equalverify(&M31Var::zero(&cs));

        let _interaction_elements = CairoInteractionElementsVar::draw(&mut channel);
        println!("channel n2: {:?}", channel.digest.value());        

        println!("size of constraint system: {:?} {:?}", cs.num_plonk_rows(), cs.num_poseidon_invocations());

        Self {}
    }

    pub fn check_claim(claim: &CairoClaimVar) {
        let public_data = &claim.public_data;

        public_data.public_memory.public_segments.range_check_128.enforce_is_not_empty();

        public_data.public_memory.public_segments.pedersen.enforce_is_empty();
        public_data.public_memory.public_segments.ecdsa.enforce_is_empty();
        public_data.public_memory.public_segments.bitwise.enforce_is_empty();
        public_data.public_memory.public_segments.ec_op.enforce_is_empty();
        public_data.public_memory.public_segments.keccak.enforce_is_empty();
        public_data.public_memory.public_segments.poseidon.enforce_is_empty();
        public_data.public_memory.public_segments.range_check_96.enforce_is_empty();
        public_data.public_memory.public_segments.add_mod.enforce_is_empty();
        public_data.public_memory.public_segments.mul_mod.enforce_is_empty();
    }

    /*pub fn lookup_sum(
        claim: &CairoClaimVar,
        elements: &CairoInteractionElementsVar,
        interaction_claim: &CairoInteractionClaimVar,
    ) -> QM31Var {
        let cs = claim.cs();
        let mut sum = QM31Var::zero(&cs);

        
    }*/
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::AllocVar};
    use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
    use super::*;

    #[test]
    fn test_fiat_shamir() {
        let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent().unwrap()
            .parent().unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");
            
        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();

        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let _fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}