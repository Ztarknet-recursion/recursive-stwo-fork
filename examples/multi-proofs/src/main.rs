use circle_plonk_dsl_answer::AnswerResults;
use circle_plonk_dsl_composition::CompositionCheck;
use circle_plonk_dsl_constraint_system::var::AllocVar;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_data_structures::PlonkWithPoseidonProofVar;
use circle_plonk_dsl_fiat_shamir::FiatShamirResults;
use circle_plonk_dsl_folding::FoldingResults;
use circle_plonk_dsl_hints::{
    AnswerHints, DecommitHints, FiatShamirHints, FirstLayerHints, InnerLayersHints,
};
use circle_plonk_dsl_primitives::QM31Var;
use circle_plonk_dsl_primitives::{CirclePointQM31Var, Poseidon2HalfVar};
use num_traits::One;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::poseidon31_hash::Poseidon31Hash;
use stwo::core::vcs::poseidon31_merkle::{Poseidon31MerkleChannel, Poseidon31MerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo_examples::plonk_with_poseidon::air::{
    prove_plonk_with_poseidon_unchecked, verify_plonk_with_poseidon, PlonkWithPoseidonProof,
};

pub fn demo_recurse<C: MerkleChannel>(
    src: &Path,
    src_config: PcsConfig,
    dest: &Path,
    dest_config: PcsConfig,
    output_hash: Poseidon31Hash,
) where
    SimdBackend: BackendForChannel<C>,
    C::H: Serialize,
{
    println!(
        "Generating a proof at {} that verifies {}",
        dest.display(),
        src.display()
    );

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join(src);

    let mut fs = std::fs::File::open(src_path).unwrap();

    let inputs = vec![
        (1, QM31::one()),
        (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
        (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        (
            4,
            QM31::from_m31(
                output_hash.0[0],
                output_hash.0[1],
                output_hash.0[2],
                output_hash.0[3],
            ),
        ),
        (
            5,
            QM31::from_m31(
                output_hash.0[4],
                output_hash.0[5],
                output_hash.0[6],
                output_hash.0[7],
            ),
        ),
    ];

    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize_from(&mut fs).unwrap();

    let fiat_shamir_hints = FiatShamirHints::new(&proof, src_config, &inputs);
    let answer_hints = AnswerHints::compute(&fiat_shamir_hints, &proof);
    let decommitment_hints = DecommitHints::compute(&fiat_shamir_hints, &proof);
    let first_layer_hints = FirstLayerHints::compute(&fiat_shamir_hints, &answer_hints, &proof);
    let inner_layer_hints = InnerLayersHints::compute(
        &first_layer_hints.folded_evals_by_column,
        &fiat_shamir_hints,
        &proof,
    );

    let cs = ConstraintSystemRef::new();

    let output_hash_var = Poseidon2HalfVar::new_public_input(&cs, &output_hash);
    let output_hash_var_qm31 = output_hash_var.to_qm31();

    let mut proof_var = PlonkWithPoseidonProofVar::new_witness(&cs, &proof);

    println!(
        "-> after allocating the proof: {}, {}",
        cs.num_plonk_rows(),
        cs.num_poseidon_invocations()
    );

    let fiat_shamir_results = FiatShamirResults::compute(
        &fiat_shamir_hints,
        &mut proof_var,
        src_config,
        &[
            (1, QM31Var::one(&cs)),
            (2, QM31Var::i(&cs)),
            (3, QM31Var::j(&cs)),
            (4, output_hash_var_qm31[0].clone()),
            (5, output_hash_var_qm31[1].clone()),
        ],
    );

    println!(
        "-> after fiat-shamir: {} {}",
        cs.num_plonk_rows(),
        cs.num_poseidon_invocations()
    );

    CompositionCheck::compute(
        &fiat_shamir_hints,
        &fiat_shamir_results.lookup_elements,
        fiat_shamir_results.random_coeff.clone(),
        fiat_shamir_results.oods_point.clone(),
        &proof_var,
    );

    println!(
        "-> after composition: {} {}",
        cs.num_plonk_rows(),
        cs.num_poseidon_invocations()
    );

    let answer_results = AnswerResults::compute(
        &CirclePointQM31Var::new_witness(&cs, &fiat_shamir_hints.oods_point),
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_hints,
        &decommitment_hints,
        &proof_var,
        src_config,
    );

    println!(
        "-> after answer: {} {}",
        cs.num_plonk_rows(),
        cs.num_poseidon_invocations()
    );

    FoldingResults::compute(
        &proof_var,
        &fiat_shamir_hints,
        &fiat_shamir_results,
        &answer_results,
        &first_layer_hints,
        &inner_layer_hints,
    );

    println!(
        "-> after folding: {} {}",
        cs.num_plonk_rows(),
        cs.num_poseidon_invocations()
    );

    cs.pad();
    cs.check_arithmetics();
    cs.populate_logup_arguments();
    cs.check_poseidon_invocations();

    let (plonk, mut poseidon) = cs.generate_plonk_with_poseidon_circuit();

    let dest_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join(dest);

    if std::fs::exists(&dest_path).unwrap() {
        println!("Skip proof generation because it has been cached.");
        return;
    }

    let timer = std::time::Instant::now();
    let proof = prove_plonk_with_poseidon_unchecked::<C>(dest_config, &plonk, &mut poseidon);
    println!("proof generation time: {}s", timer.elapsed().as_secs_f64());

    let encoded = bincode::serialize(&proof).unwrap();
    let mut fs = std::fs::File::create(dest_path).unwrap();
    fs.write_all(&encoded).unwrap();

    verify_plonk_with_poseidon::<C>(proof, dest_config, &inputs).unwrap();
}

fn main() {
    let initial_config = PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig::new(0, 1, 70),
    };
    let fast_prover_config = PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(8, 1, 80),
    };
    let fast_prover2_config = PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(8, 3, 27),
    };
    let fast_verifier_config = PcsConfig {
        pow_bits: 23,
        fri_config: FriConfig::new(8, 7, 11),
    };
    let fast_verifier2_config = PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(8, 8, 10),
    };
    let fast_verifier3_config = PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    };

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output_hash_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join("output_hash.txt");
    let output_hash =
        serde_json::from_str::<Poseidon31Hash>(&std::fs::read_to_string(output_hash_path).unwrap())
            .unwrap();

    demo_recurse::<Poseidon31MerkleChannel>(
        Path::new("initial_proof.bin"),
        initial_config,
        Path::new("level1_20_8_1.bin"),
        fast_prover_config,
        output_hash,
    );
    demo_recurse::<Poseidon31MerkleChannel>(
        Path::new("level1_20_8_1.bin"),
        fast_prover_config,
        Path::new("level2_20_8_3.bin"),
        fast_prover2_config,
        output_hash,
    );
    demo_recurse::<Poseidon31MerkleChannel>(
        Path::new("level2_20_8_3.bin"),
        fast_prover2_config,
        Path::new("level3_23_8_7.bin"),
        fast_verifier_config,
        output_hash,
    );
    demo_recurse::<Poseidon31MerkleChannel>(
        Path::new("level3_23_8_7.bin"),
        fast_verifier_config,
        Path::new("level4_20_8_8.bin"),
        fast_verifier2_config,
        output_hash,
    );
    demo_recurse::<Poseidon31MerkleChannel>(
        Path::new("level4_20_8_8.bin"),
        fast_verifier2_config,
        Path::new("level5_28_7_9.bin"),
        fast_verifier3_config,
        output_hash,
    );
}
