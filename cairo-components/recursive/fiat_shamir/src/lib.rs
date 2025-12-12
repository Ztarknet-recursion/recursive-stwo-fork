use std::collections::HashMap;

use cairo_air::verifier::INTERACTION_POW_BITS;
use cairo_plonk_dsl_data_structures::{
    interaction_claim::CairoInteractionClaimVar, lookup::CairoInteractionElementsVar, BitIntVar,
    CairoClaimVar, CairoProofVar,
};
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{
    BitVar, BitsVar, ChannelVar, CirclePointQM31Var, M31Var, Poseidon2HalfVar, QM31Var,
};
use stwo::core::fields::m31::M31;
use stwo_cairo_common::memory::LARGE_MEMORY_VALUE_ID_BASE;

pub struct CairoFiatShamirResults {
    pub oods_point: CirclePointQM31Var,
    pub random_coeff: QM31Var,
    pub after_sampled_values_random_coeff: QM31Var,
}

impl CairoFiatShamirResults {
    pub fn compute(fiat_shamir_hints: &CairoFiatShamirHints, proof: &CairoProofVar) -> Self {
        let cs = proof.cs();

        let mut channel = ChannelVar::default(&cs);
        channel.digest = Poseidon2HalfVar::new_constant(&cs, &fiat_shamir_hints.initial_channel);

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

        let sampled_values_flattened = proof.stark_proof.sampled_values.clone().flatten_cols();
        for chunk in sampled_values_flattened.chunks(2) {
            if chunk.len() == 1 {
                channel.mix_one_felt(&chunk[0]);
            } else {
                channel.mix_two_felts(&chunk[0], &chunk[1]);
            }
        }
        let after_sampled_values_random_coeff = channel.draw_felts()[0].clone();

        println!(
            "channel after drawing another random coeff: {:?}",
            channel.digest.value()
        );

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

        Self {
            oods_point,
            random_coeff,
            after_sampled_values_random_coeff,
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
                .is_greater_than(&stop_ptr_bits)
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
                .is_greater_than(&stop_ptr_bits)
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
            .is_greater_than(&final_ap_bits)
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
        let cs = ConstraintSystemRef::new_plonk_with_poseidon_ref();

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
