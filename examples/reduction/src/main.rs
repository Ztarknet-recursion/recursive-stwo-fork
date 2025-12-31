use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_interface::{
    compute_output_hash, verifier_input, verify_output_hash, verify_proof,
};
use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
use circle_plonk_dsl_primitives::Poseidon2HalfVar;
use std::io::Write;
use std::path::PathBuf;
use stwo::core::{
    fields::m31::M31, fri::FriConfig, pcs::PcsConfig,
    vcs::poseidon31_merkle::Poseidon31MerkleChannel,
};
use stwo_examples::plonk_with_poseidon::air::{
    prove_plonk_with_poseidon, verify_plonk_with_poseidon,
};

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("cairo-components")
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

    let output_hash_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join("output_hash.txt");

    if std::fs::exists(&output_hash_path).unwrap() {
        println!("Output hash is cached. Proof is not generated.");
        return;
    }

    let encoded = serde_json::to_string_pretty(&output_hash).unwrap();
    let mut fs = std::fs::File::create(output_hash_path).unwrap();
    fs.write_all(encoded.as_bytes()).unwrap();

    let initial_proof_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join("initial_proof.bin");

    if std::fs::exists(&initial_proof_path).unwrap() {
        println!("Proof is cached.");
        return;
    }

    let config = PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig::new(0, 1, 70),
    };

    let (plonk, mut poseidon) = cs.generate_plonk_with_poseidon_circuit();
    let proof = prove_plonk_with_poseidon::<Poseidon31MerkleChannel>(config, &plonk, &mut poseidon);
    assert_eq!(
        proof.stark_proof.commitments[0].0,
        [
            M31::from(1700934344),
            M31::from(1243211772),
            M31::from(165254824),
            M31::from(941355991),
            M31::from(5055852),
            M31::from(364491116),
            M31::from(77117614),
            M31::from(1214499037)
        ]
    );

    let encoded = bincode::serialize(&proof).unwrap();
    let mut fs = std::fs::File::create(initial_proof_path).unwrap();
    fs.write_all(&encoded).unwrap();

    verify_plonk_with_poseidon::<Poseidon31MerkleChannel>(
        proof,
        config,
        &verifier_input(&output_hash),
    )
    .unwrap();
}
