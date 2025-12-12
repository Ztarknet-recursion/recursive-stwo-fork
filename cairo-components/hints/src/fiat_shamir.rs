use cairo_air::{
    air::{lookup_sum, CairoClaim, CairoComponents, CairoInteractionElements},
    verifier::INTERACTION_POW_BITS,
    CairoProof, PreProcessedTraceVariant,
};
use itertools::Itertools;
use num_traits::{One, Zero};
use std::collections::HashMap;
use stwo::core::{
    air::Components,
    channel::{Channel, Poseidon31Channel},
    circle::CirclePoint,
    fields::{
        m31::{BaseField, M31},
        qm31::{SecureField, SECURE_EXTENSION_DEGREE},
    },
    pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
    vcs::{
        poseidon31_hash::Poseidon31Hash,
        poseidon31_merkle::{Poseidon31MerkleChannel, Poseidon31MerkleHasher},
    },
    ColumnVec,
};
use stwo_cairo_common::{
    builtins::RANGE_CHECK_MEMORY_CELLS, memory::LARGE_MEMORY_VALUE_ID_BASE,
    prover_types::cpu::PRIME,
};
use stwo_constraint_framework::PREPROCESSED_TRACE_IDX;

pub struct CairoFiatShamirHints {
    pub initial_channel: [M31; 8],

    pub pcs_config: PcsConfig,
    pub preprocessed_log_sizes: Vec<u32>,
    pub preprocessed_commitment: Poseidon31Hash,
    pub trace_commitment: Poseidon31Hash,
    pub interaction_commitment: Poseidon31Hash,
    pub composition_commitment: Poseidon31Hash,

    pub oods_point: CirclePoint<SecureField>,
    pub sample_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    pub random_coeff: SecureField,

    pub component_generator: CairoComponents,
    pub composition_log_size: u32,
    pub n_preprocessed_columns: usize,
}

impl CairoFiatShamirHints {
    fn verify_claim(claim: &CairoClaim) {
        let segment_ranges = &claim.public_data.public_memory.public_segments;

        // the only builtin we implemented is range_check_128
        assert!(segment_ranges.range_check_128.is_some());
        assert!(!segment_ranges.range_check_128.as_ref().unwrap().is_empty());

        assert!(segment_ranges.pedersen.is_some());
        assert!(segment_ranges.ecdsa.is_some());
        assert!(segment_ranges.bitwise.is_some());
        assert!(segment_ranges.ec_op.is_some());
        assert!(segment_ranges.keccak.is_some());
        assert!(segment_ranges.poseidon.is_some());
        assert!(segment_ranges.range_check_96.is_some());
        assert!(segment_ranges.add_mod.is_some());
        assert!(segment_ranges.mul_mod.is_some());

        assert!(segment_ranges.pedersen.as_ref().unwrap().is_empty());
        assert!(segment_ranges.ecdsa.as_ref().unwrap().is_empty());
        assert!(segment_ranges.bitwise.as_ref().unwrap().is_empty());
        assert!(segment_ranges.ec_op.as_ref().unwrap().is_empty());
        assert!(segment_ranges.keccak.as_ref().unwrap().is_empty());
        assert!(segment_ranges.poseidon.as_ref().unwrap().is_empty());
        assert!(segment_ranges.range_check_96.as_ref().unwrap().is_empty());
        assert!(segment_ranges.add_mod.as_ref().unwrap().is_empty());
        assert!(segment_ranges.mul_mod.as_ref().unwrap().is_empty());

        // check output builtin
        assert!(segment_ranges.output.stop_ptr.value < 1 << 31);
        assert!(segment_ranges.output.start_ptr.value <= segment_ranges.output.stop_ptr.value);

        // find the claim for range_check_128
        // check the well-formedness of the range_check_128 builtin
        assert!(claim.builtins.range_check_128_builtin.is_some());
        {
            let range_check_128_claim = claim.builtins.range_check_128_builtin.as_ref().unwrap();
            let segment_range = segment_ranges.range_check_128.as_ref().unwrap();

            let segment_start = range_check_128_claim.range_check_builtin_segment_start;
            let log_size = range_check_128_claim.log_size;

            let segment_end = segment_start + (1 << log_size) * RANGE_CHECK_MEMORY_CELLS as u32;
            let start_ptr = segment_range.start_ptr.value;
            let stop_ptr = segment_range.stop_ptr.value;

            assert_eq!(start_ptr, segment_start);
            assert!(start_ptr <= stop_ptr);
            assert!(stop_ptr <= segment_end);
            assert!(segment_end < 1 << 31);
        }

        assert!(claim.builtins.pedersen_builtin.is_none());
        assert!(claim.builtins.bitwise_builtin.is_none());
        assert!(claim.builtins.poseidon_builtin.is_none());
        assert!(claim.builtins.range_check_96_builtin.is_none());
        assert!(claim.builtins.add_mod_builtin.is_none());
        assert!(claim.builtins.mul_mod_builtin.is_none());

        let program = &claim.public_data.public_memory.program;
        let n_builtins = claim
            .public_data
            .public_memory
            .public_segments
            .present_segments()
            .len() as u32;

        // First instruction: add_app_immediate (n_builtins).
        assert_eq!(program[0].1, [0x7fff7fff, 0x4078001, 0, 0, 0, 0, 0, 0]); // add_ap_imm.
        assert_eq!(program[1].1, [n_builtins, 0, 0, 0, 0, 0, 0, 0]); // Imm.

        // Safe call.
        assert_eq!(program[2].1, [0x80018000, 0x11048001, 0, 0, 0, 0, 0, 0]); // Instruction: call rel ?
        assert_eq!(program[4].1, [0x7fff7fff, 0x1078001, 0, 0, 0, 0, 0, 0]); // Instruction: jmp rel 0.
        assert_eq!(program[5].1, [0, 0, 0, 0, 0, 0, 0, 0]); // Imm of last instruction (jmp rel 0).

        let initial_pc = &claim.public_data.initial_state.pc;
        let initial_ap = &claim.public_data.initial_state.ap;
        let initial_fp = &claim.public_data.initial_state.fp;
        let final_fp = &claim.public_data.final_state.fp;
        let final_pc = &claim.public_data.final_state.pc;
        let final_ap = &claim.public_data.final_state.ap;

        assert_eq!(*initial_pc, BaseField::one());
        assert!(
            *initial_pc + BaseField::from(2) < *initial_ap,
            "Initial pc + 2 must be less than initial ap, but got initial_pc: {initial_pc}, initial_ap: {initial_ap}"
        );
        assert_eq!(initial_fp, final_fp);
        assert_eq!(initial_fp, initial_ap);
        assert_eq!(*final_pc, BaseField::from(5));
        assert!(initial_ap <= final_ap);

        let mut relation_uses = HashMap::<&'static str, u64>::new();
        claim.accumulate_relation_uses(&mut relation_uses);
        relation_uses.iter().for_each(|(_, count)| {
            assert!(*count < PRIME as u64);
        });

        // Large value IDs reside in [LARGE_MEMORY_VALUE_ID_BASE..P).
        // Check that IDs in (ID -> Value) do not overflow P.
        let largest_id = claim
            .memory_id_to_value
            .big_log_sizes
            .iter()
            .map(|log_size| 1 << log_size)
            .sum::<u32>()
            - 1
            + LARGE_MEMORY_VALUE_ID_BASE;
        assert!(largest_id < PRIME);
    }

    pub fn new(proof: &CairoProof<Poseidon31MerkleHasher>) -> Self {
        let claim = &proof.claim;
        let stark_proof = &proof.stark_proof;
        let channel_salt = proof.channel_salt;

        Self::verify_claim(claim);

        let channel = &mut Poseidon31Channel::default();
        assert!(channel_salt.is_none());

        let pcs_config = stark_proof.config;
        pcs_config.mix_into(channel);

        let commitment_scheme_verifier =
            &mut CommitmentSchemeVerifier::<Poseidon31MerkleChannel>::new(pcs_config);

        let preprocessed_trace =
            PreProcessedTraceVariant::CanonicalWithoutPedersen.to_preprocessed_trace();

        let mut log_sizes = claim.log_sizes();
        log_sizes[PREPROCESSED_TRACE_IDX] = preprocessed_trace.log_sizes();

        let initial_channel: [M31; 8];

        // Preproccessed trace.
        commitment_scheme_verifier.commit(stark_proof.commitments[0], &log_sizes[0], channel);

        let mut channel_backup = channel.clone();
        {
            {
                let program = &claim.public_data.public_memory.program;
                let public_segments = &claim.public_data.public_memory.public_segments;
                let output = &claim.public_data.public_memory.output;
                let safe_call_ids = &claim.public_data.public_memory.safe_call_ids;

                // Mix program memory section. All the ids are mixed first, then all the values, each of
                // them in the order it appears in the section.
                channel.mix_u32s(&program.iter().map(|(id, _)| *id).collect_vec());
                channel.mix_u32s(&program.iter().flat_map(|(_, value)| *value).collect_vec());

                initial_channel = channel.digest().clone();

                // Mix public segments.
                public_segments.mix_into(channel);

                // Mix output memory section. All the ids are mixed first, then all the values, each of them
                // in the order it appears in the section.
                channel.mix_u32s(&output.iter().map(|(id, _)| *id).collect_vec());
                channel.mix_u32s(&output.iter().flat_map(|(_, value)| *value).collect_vec());

                // Mix safe_ids memory section.
                for id in safe_call_ids {
                    channel.mix_u64(*id as u64);
                }
            }

            claim.public_data.initial_state.mix_into(channel);
            claim.public_data.final_state.mix_into(channel);

            // Force a specific shape of the opcodes
            assert_eq!(claim.opcodes.add.len(), 1);
            assert_eq!(claim.opcodes.add_small.len(), 1);
            assert_eq!(claim.opcodes.add_ap.len(), 1);
            assert_eq!(claim.opcodes.assert_eq.len(), 1);
            assert_eq!(claim.opcodes.assert_eq_imm.len(), 1);
            assert_eq!(claim.opcodes.assert_eq_double_deref.len(), 1);
            assert_eq!(claim.opcodes.blake.len(), 1);
            assert_eq!(claim.opcodes.call.len(), 1);
            assert_eq!(claim.opcodes.call_rel_imm.len(), 1);
            assert_eq!(claim.opcodes.generic.len(), 0);
            assert_eq!(claim.opcodes.jnz.len(), 1);
            assert_eq!(claim.opcodes.jnz_taken.len(), 1);
            assert_eq!(claim.opcodes.jump.len(), 0);
            assert_eq!(claim.opcodes.jump_double_deref.len(), 0);
            assert_eq!(claim.opcodes.jump_rel.len(), 1);
            assert_eq!(claim.opcodes.jump_rel_imm.len(), 1);
            assert_eq!(claim.opcodes.mul.len(), 1);
            assert_eq!(claim.opcodes.mul_small.len(), 1);
            assert_eq!(claim.opcodes.qm31.len(), 1);
            assert_eq!(claim.opcodes.ret.len(), 1);

            claim.opcodes.mix_into(channel);
            claim.verify_instruction.mix_into(channel);
            claim.blake_context.mix_into(channel);
            claim.builtins.mix_into(channel);
            assert!(claim.pedersen_context.claim.is_none());
            assert!(claim.poseidon_context.claim.is_none());
            claim.memory_address_to_id.mix_into(channel);
            assert_eq!(claim.memory_id_to_value.big_log_sizes.len(), 1);
            claim.memory_id_to_value.mix_into(channel);
            claim.verify_bitwise_xor_4.mix_into(channel);
            claim.verify_bitwise_xor_7.mix_into(channel);
            claim.verify_bitwise_xor_8.mix_into(channel);
            claim.verify_bitwise_xor_8_b.mix_into(channel);
            claim.verify_bitwise_xor_9.mix_into(channel);
        }

        {
            claim.mix_into(&mut channel_backup);
            assert_eq!(channel_backup.digest(), channel.digest());
        }

        commitment_scheme_verifier.commit(stark_proof.commitments[1], &log_sizes[1], channel);

        // Proof of work.
        if !channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow) {
            panic!("Proof of work failed");
        }
        channel.mix_u64(proof.interaction_pow);
        let interaction_elements = CairoInteractionElements::draw(channel);

        assert!(proof.interaction_claim.opcodes.generic.is_empty());
        assert!(proof.interaction_claim.opcodes.jump.is_empty());
        assert!(proof.interaction_claim.opcodes.jump_double_deref.is_empty());
        assert!(proof.interaction_claim.blake_context.claim.is_some());
        assert!(proof.interaction_claim.builtins.add_mod_builtin.is_none());
        assert!(proof.interaction_claim.builtins.bitwise_builtin.is_none());
        assert!(proof.interaction_claim.builtins.mul_mod_builtin.is_none());
        assert!(proof.interaction_claim.builtins.pedersen_builtin.is_none());
        assert!(proof.interaction_claim.builtins.poseidon_builtin.is_none());
        assert!(proof
            .interaction_claim
            .builtins
            .range_check_96_builtin
            .is_none());
        assert!(proof
            .interaction_claim
            .builtins
            .range_check_128_builtin
            .is_some());
        assert!(proof.interaction_claim.pedersen_context.claim.is_none());
        assert!(proof.interaction_claim.poseidon_context.claim.is_none());
        assert_eq!(
            proof
                .interaction_claim
                .memory_id_to_value
                .big_claimed_sums
                .len(),
            1
        );

        // Verify lookup argument.
        if lookup_sum(&claim, &interaction_elements, &proof.interaction_claim)
            != SecureField::zero()
        {
            panic!("Invalid logup sum");
        }
        proof.interaction_claim.mix_into(channel);
        commitment_scheme_verifier.commit(stark_proof.commitments[2], &log_sizes[2], channel);

        let component_generator = CairoComponents::new(
            &claim,
            &interaction_elements,
            &proof.interaction_claim,
            &preprocessed_trace.ids(),
        );

        let components = component_generator.components();

        let n_preprocessed_columns = commitment_scheme_verifier.trees[PREPROCESSED_TRACE_IDX]
            .column_log_sizes
            .len();

        let components = Components {
            components: components.to_vec(),
            n_preprocessed_columns,
        };
        let composition_log_size = components.composition_log_degree_bound();
        let random_coeff = channel.draw_secure_felt();

        // Read composition polynomial commitment.
        commitment_scheme_verifier.commit(
            *proof.stark_proof.commitments.last().unwrap(),
            &[composition_log_size - 1; 2 * SECURE_EXTENSION_DEGREE],
            channel,
        );

        // Draw OODS point.
        let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

        // Get mask sample points relative to oods point.
        let mut sample_points = components.mask_points(oods_point);
        // Add the composition polynomial mask points.
        sample_points.push(vec![vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);

        let _sample_points_by_column = sample_points.as_cols_ref().flatten();

        channel.mix_felts(&proof.stark_proof.sampled_values.clone().flatten_cols());
        let _after_sampled_values_random_coeff = channel.draw_secure_felt();

        println!(
            "channel after drawing another random coeff: {:?}",
            channel.digest()
        );

        Self {
            initial_channel,
            pcs_config,
            preprocessed_log_sizes: log_sizes[0].clone(),
            preprocessed_commitment: stark_proof.commitments[0].clone(),
            trace_commitment: stark_proof.commitments[1].clone(),
            interaction_commitment: stark_proof.commitments[2].clone(),
            composition_commitment: stark_proof.commitments[3].clone(),

            oods_point,
            sample_points,
            random_coeff,
            component_generator,
            composition_log_size,
            n_preprocessed_columns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use std::path::PathBuf;

    #[test]
    fn test_fiat_shamir_hints() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let _ = CairoFiatShamirHints::new(&proof);
    }
}
