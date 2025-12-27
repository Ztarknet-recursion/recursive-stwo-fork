use std::collections::HashMap;
use std::ops::Neg;

use cairo_air::verifier::INTERACTION_POW_BITS;
use cairo_plonk_dsl_data_structures::{
    interaction_claim::CairoInteractionClaimVar, lookup::CairoInteractionElementsVar,
    CairoClaimVar, CairoProofVar,
};
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{
    channel::ConditionalChannelMixer, BitIntVar, BitVar, BitsVar, ChannelVar, CirclePointQM31Var,
    M31Var, Poseidon2HalfVar, QM31Var,
};
use indexmap::IndexMap;
use stwo::core::{fields::m31::M31, vcs::poseidon31_hash::Poseidon31Hash};
use stwo_cairo_common::{
    memory::LARGE_MEMORY_VALUE_ID_BASE,
    preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
};

pub struct CairoFiatShamirResults {
    pub oods_point: CirclePointQM31Var,
    pub random_coeff: QM31Var,
    pub after_sampled_values_random_coeff: QM31Var,
    pub interaction_elements: CairoInteractionElementsVar,
    pub max_log_size: M31Var,
    pub queries: Vec<BitsVar>,
    pub query_log_size: M31Var,
    pub composition_log_size: M31Var,

    pub first_layer_alpha: QM31Var,
    pub inner_layers_alphas: IndexMap<u32, QM31Var>,
}

impl CairoFiatShamirResults {
    pub fn compute(fiat_shamir_hints: &CairoFiatShamirHints, proof: &CairoProofVar) -> Self {
        let cs = proof.cs();

        let mut channel = ChannelVar::default(&cs);
        channel.digest =
            Poseidon2HalfVar::new_constant(&cs, &Poseidon31Hash(fiat_shamir_hints.initial_channel));

        Self::check_claim(&proof.claim);
        proof.claim.mix_into(&mut channel);

        channel.mix_root(&proof.stark_proof.trace_commitment);

        proof.interaction_pow.mix_into(&mut channel);

        let lower_bits = BitsVar::from_m31(&channel.digest.to_qm31()[0].decompose_m31()[0], 31)
            .compose_range(0..INTERACTION_POW_BITS as usize);
        lower_bits.equalverify(&M31Var::zero(&cs));

        let interaction_elements = CairoInteractionElementsVar::draw(&mut channel);
        proof.interaction_claim.mix_into(&mut channel);

        channel.mix_root(&proof.stark_proof.interaction_commitment);
        let random_coeff = channel.draw_felts()[0].clone();
        channel.mix_root(&proof.stark_proof.composition_commitment);

        // Draw OODS point.
        let oods_point = CirclePointQM31Var::from_channel(&mut channel);

        let channel_mixer = ConditionalChannelMixer::new(channel);
        channel = channel_mixer.mix(
            &proof.stark_proof.sampled_values.clone().flatten_cols(),
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let after_sampled_values_random_coeff = channel.draw_felts()[0].clone();

        println!(
            "size of constraint system so far: {:?} {:?}",
            cs.num_plonk_rows(),
            cs.num_poseidon_invocations()
        );

        let lookup_sum = Self::lookup_sum(
            &proof.claim,
            &interaction_elements,
            &proof.interaction_claim,
        );
        lookup_sum.equalverify(&QM31Var::zero(&cs));

        let max_preprocessed_trace_log_size = proof.stark_proof.max_preprocessed_trace_log_size();
        let max_trace_and_interaction_log_size = proof.claim.max_trace_and_interaction_log_size();
        println!(
            "max_preprocessed_trace_log_size: {:?}",
            max_preprocessed_trace_log_size.value
        );
        println!(
            "max_trace_and_interaction_log_size: {:?}",
            max_trace_and_interaction_log_size.value
        );

        let max_log_size =
            max_preprocessed_trace_log_size.max(&max_trace_and_interaction_log_size, 5);
        let composition_log_size = &max_log_size + &M31Var::one(&cs);

        println!("max_log_size: {:?}", max_log_size.value);

        channel.mix_root(&proof.stark_proof.fri_proof.first_layer.commitment);
        let first_layer_alpha = channel.draw_felts()[0].clone();

        let mut num_layers_to_skip =
            &M31Var::new_constant(&cs, &M31::from(MAX_SEQUENCE_LOG_SIZE)) - &max_log_size;

        let mut inner_layers_alphas = IndexMap::new();
        for layer_log_size in (1..MAX_SEQUENCE_LOG_SIZE).rev() {
            let skip = num_layers_to_skip.is_zero().neg();
            num_layers_to_skip = &num_layers_to_skip - &skip.0;

            let existing_channel = channel.digest.to_qm31();
            channel.mix_root(
                &proof
                    .stark_proof
                    .fri_proof
                    .inner_layers
                    .get(&layer_log_size)
                    .unwrap()
                    .commitment,
            );
            let alpha = channel.draw_felts()[0].clone();
            inner_layers_alphas.insert(layer_log_size, alpha);

            let candidate_channel = channel.digest.to_qm31();

            let new_digest = [
                QM31Var::select(&candidate_channel[0], &existing_channel[0], &skip),
                QM31Var::select(&candidate_channel[1], &existing_channel[1], &skip),
            ];

            channel.digest = Poseidon2HalfVar::from_qm31(&new_digest[0], &new_digest[1]);
        }

        channel.mix_one_felt(&proof.stark_proof.fri_proof.last_layer_constant);

        println!("max_log_size: {:?}", max_log_size.value);
        println!("composition_log_size: {:?}", composition_log_size.value);

        proof.stark_proof.proof_of_work.mix_into(&mut channel);

        let lower_bits = BitsVar::from_m31(&channel.digest.to_qm31()[0].decompose_m31()[0], 31)
            .compose_range(0..26); // hardcoded pow_bits of 26
        lower_bits.equalverify(&M31Var::zero(&cs));

        let query_log_size = composition_log_size.clone(); // when the log_blowup_factor is 1

        let pcs_config = &fiat_shamir_hints.pcs_config;
        let mut raw_queries = Vec::with_capacity(pcs_config.fri_config.n_queries);
        let mut draw_queries_felts =
            Vec::with_capacity(pcs_config.fri_config.n_queries.div_ceil(4));
        for _ in 0..pcs_config.fri_config.n_queries.div_ceil(4) {
            let [a, b] = channel.draw_felts();
            draw_queries_felts.push(a);
            draw_queries_felts.push(b);
        }
        for felt in draw_queries_felts.iter() {
            raw_queries.extend_from_slice(&felt.decompose_m31());
        }
        raw_queries.truncate(pcs_config.fri_config.n_queries);

        let max_len = (MAX_SEQUENCE_LOG_SIZE
            + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            as usize;

        let mut mask: Vec<BitVar> = vec![];
        let mut cur = query_log_size.clone();
        for _ in 0..max_len {
            let is_cur_nonzero = cur.is_zero().neg();
            cur = &cur - &is_cur_nonzero.0;
            mask.push(is_cur_nonzero);
        }

        let mut queries = vec![];
        for raw_query in raw_queries.iter() {
            let mut bits = BitsVar::from_m31(raw_query, 31);
            bits.0.truncate(max_len);
            for (bit, mask_bit) in bits.0.iter_mut().zip(mask.iter()) {
                *bit = &*bit & mask_bit;
            }
            queries.push(bits);
        }

        println!(
            "channel after sampling queries: {:?}",
            channel.digest.value()
        );

        Self {
            oods_point,
            random_coeff,
            after_sampled_values_random_coeff,
            interaction_elements,
            max_log_size,
            queries,
            query_log_size,
            composition_log_size,

            first_layer_alpha,
            inner_layers_alphas,
        }
    }

    pub fn check_claim(claim: &CairoClaimVar) {
        let public_data = &claim.public_data;
        let segment_ranges = &public_data.public_memory.public_segments;

        segment_ranges.range_check_128.enforce_is_not_empty();
        segment_ranges.pedersen.enforce_is_empty();
        segment_ranges.ecdsa.enforce_is_empty();
        segment_ranges.bitwise.enforce_is_empty();
        segment_ranges.ec_op.enforce_is_empty();
        segment_ranges.keccak.enforce_is_empty();
        segment_ranges.poseidon.enforce_is_empty();
        segment_ranges.range_check_96.enforce_is_empty();
        segment_ranges.add_mod.enforce_is_empty();
        segment_ranges.mul_mod.enforce_is_empty();

        // check output builtin
        {
            let start_ptr_bits = &segment_ranges.output.start_ptr.value.bits;
            let stop_ptr_bits = &segment_ranges.output.stop_ptr.value.bits;
            start_ptr_bits
                .is_greater_than(stop_ptr_bits)
                .equalverify(&BitVar::new_false(&start_ptr_bits.cs()));
        }

        // find the claim for range_check_128
        {
            let segment_start = &claim.builtins.range_check_builtin_segment_start;
            let start_ptr = &segment_ranges.range_check_128.start_ptr.value;
            let stop_ptr = &segment_ranges.range_check_128.stop_ptr.value;
            start_ptr.enforce_equal(segment_start);

            let start_ptr_bits = &start_ptr.bits;
            let stop_ptr_bits = &stop_ptr.bits;
            start_ptr_bits
                .is_greater_than(stop_ptr_bits)
                .equalverify(&BitVar::new_false(&start_ptr_bits.cs()));

            let segment_end =
                &segment_start.to_m31() + &claim.builtins.range_check_128_builtin_log_size.pow2;
            let segment_end_bits = BitsVar::from_m31(&segment_end, 31);

            stop_ptr_bits
                .is_greater_than(&segment_end_bits)
                .equalverify(&BitVar::new_false(&stop_ptr_bits.cs()));
        }

        // program is a constant, so we do not check it
        let initial_pc = &claim.public_data.initial_state.pc;
        let initial_ap = &claim.public_data.initial_state.ap;
        let initial_fp = &claim.public_data.initial_state.fp;
        let final_fp = &claim.public_data.final_state.fp;
        let final_pc = &claim.public_data.final_state.pc;
        let final_ap = &claim.public_data.final_state.ap;

        initial_pc.enforce_equal(&BitIntVar::<31>::new_constant(&initial_pc.cs(), &1u64));

        let initial_ap_bits = &initial_ap.bits;
        // Initial pc + 2 must be less than initial ap, but got initial_pc
        initial_ap_bits
            .is_greater_than(&BitsVar::from_m31(
                &M31Var::new_constant(&initial_pc.cs(), &M31::from(3)),
                31,
            ))
            .equalverify(&BitVar::new_true(&initial_pc.cs()));
        initial_fp.enforce_equal(final_fp);
        initial_fp.enforce_equal(initial_ap);

        final_pc.enforce_equal(&BitIntVar::<31>::new_constant(&final_pc.cs(), &5u64));

        let final_ap_bits = &final_ap.bits;
        initial_ap_bits
            .is_greater_than(final_ap_bits)
            .equalverify(&BitVar::new_false(&initial_ap_bits.cs()));

        // check that the relation uses do not overflow PRIME
        let mut relation_uses: HashMap<&str, M31Var> = HashMap::<&'static str, M31Var>::new();
        claim.accumulate_relation_uses(&mut relation_uses);

        // check that the largest id does not overflow PRIME
        let _ = (&claim.memory_id_to_value.big_log_size.to_m31().exp2()
            - &M31Var::one(&claim.cs()))
            .add_assert_no_overflow(&M31Var::new_constant(
                &claim.cs(),
                &M31::from(LARGE_MEMORY_VALUE_ID_BASE),
            ));
    }

    pub fn lookup_sum(
        claim: &CairoClaimVar,
        elements: &CairoInteractionElementsVar,
        interaction_claim: &CairoInteractionClaimVar,
    ) -> QM31Var {
        let mut sum = claim.public_data.logup_sum(elements);
        sum = &sum + &interaction_claim.opcodes.sum();
        sum = &sum + &interaction_claim.verify_instruction;
        sum = &sum + &interaction_claim.blake_context.sum();
        sum = &sum + &interaction_claim.builtins;
        sum = &sum + &interaction_claim.memory_address_to_id;
        sum = &sum + &interaction_claim.memory_id_to_value.sum();
        sum = &sum + &interaction_claim.range_checks.sum();
        sum = &sum + &interaction_claim.verify_bitwise_xor_4;
        sum = &sum + &interaction_claim.verify_bitwise_xor_7;
        sum = &sum + &interaction_claim.verify_bitwise_xor_8;
        sum = &sum + &interaction_claim.verify_bitwise_xor_8_b;
        sum = &sum + &interaction_claim.verify_bitwise_xor_9;
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use std::path::PathBuf;

    #[test]
    fn test_fiat_shamir() {
        let cs = ConstraintSystemRef::new();

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
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
