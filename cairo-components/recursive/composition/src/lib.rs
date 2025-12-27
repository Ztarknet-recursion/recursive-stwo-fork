#![allow(clippy::needless_borrow)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::let_and_return)]
#![allow(clippy::needless_return)]

use cairo_air::air::CairoComponents;
use cairo_plonk_dsl_data_structures::{
    evaluator::PointEvaluationAccumulatorVar, lookup::CairoInteractionElementsVar, CairoProofVar,
};
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{
    fields::WrappedQM31Var,
    oblivious_map::{ObliviousMapVar, SelectVar},
    BitVar, CirclePointM31Var, CirclePointQM31Var, LogSizeVar, M31Var, QM31Var,
};
use indexmap::IndexMap;
use itertools::Itertools;
use std::sync::OnceLock;
use stwo::core::{
    fields::{m31::M31, qm31::SECURE_EXTENSION_DEGREE},
    poly::circle::CanonicCoset,
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;
use stwo_cairo_common::prover_types::simd::LOG_N_LANES;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, PREPROCESSED_TRACE_IDX};

use crate::{
    components::ComponentVar,
    data_structures::{PointEvaluatorVar, WrappedSamplesValues},
};

pub mod components;
pub mod data_structures;

pub static COSET_SHIFT_MAP: OnceLock<ObliviousMapVar<(M31, M31)>> = OnceLock::new();

fn initialize_coset_shift_map() -> ObliviousMapVar<(M31, M31)> {
    let mut map = IndexMap::new();
    // IMPORTANT: keys must match `LogSizeVar::bitmap` domain, i.e.
    // `LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE`. Otherwise `ObliviousMapVar::select` will panic.
    for i in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
        let coset = CanonicCoset::new(i).coset;
        let point = -coset.initial + coset.step_size.half().to_point();
        map.insert(i, (point.x, point.y));
    }
    ObliviousMapVar::new(map)
}

pub fn coset_vanishing_var(p: &CirclePointQM31Var, coset_log_size: &LogSizeVar) -> QM31Var {
    let cs = p.cs();
    let coset_shift_map = COSET_SHIFT_MAP.get_or_init(initialize_coset_shift_map);
    let shift_point_result = coset_shift_map.select(&coset_log_size);

    let shift_point = CirclePointM31Var {
        x: shift_point_result.0,
        y: shift_point_result.1,
    };

    let mut x = (p + &shift_point).x;

    let mut map = IndexMap::new();
    // Build x-doublings up to MAX, but only store keys that are selectable via `LogSizeVar`.
    for i in 1..MAX_SEQUENCE_LOG_SIZE {
        let sq = &x * &x;
        x = &(&sq + &sq) - &M31Var::one(&cs);
        let log_size = i + 1;
        if log_size >= LOG_N_LANES {
            map.insert(log_size, x.clone());
        }
    }

    let omap = ObliviousMapVar::new(map);
    let result = omap.select(&coset_log_size);
    result
}

pub struct CairoFiatCompositionCheck {}

impl CairoFiatCompositionCheck {
    pub fn compute(
        fiat_shamir_results: &CairoFiatShamirResults,
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProofVar,
    ) {
        let samples: WrappedSamplesValues =
            WrappedSamplesValues::new(&proof.stark_proof.sampled_values);

        let mut point_evaluation_accumulator =
            PointEvaluationAccumulatorVar::new(&fiat_shamir_results.random_coeff);

        Self::opcodes_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::verify_instruction_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::blake_context_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::range_check_builtin_bits_128_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::memory_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::range_checks_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        Self::verify_bitwise_evaluation(
            &mut point_evaluation_accumulator,
            &fiat_shamir_hints.component_generator,
            &fiat_shamir_results.interaction_elements,
            &fiat_shamir_results.oods_point,
            &proof,
            &samples,
        );

        let composition_oods_expected = {
            let left_and_right_composition_mask =
                proof.stark_proof.sampled_values.0.last().unwrap();
            let left_and_right_coordinate_evals: [QM31Var; 2 * SECURE_EXTENSION_DEGREE] =
                left_and_right_composition_mask
                    .iter()
                    .map(|columns| {
                        if columns.len() == 1 {
                            return Some(columns[0].clone());
                        } else {
                            return None;
                        };
                    })
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
                    .try_into()
                    .unwrap();

            let (left_coordinate_evals, right_coordinate_evals) =
                left_and_right_coordinate_evals.split_at(SECURE_EXTENSION_DEGREE);

            let left_eval = QM31Var::from_partial_evals(left_coordinate_evals.try_into().unwrap());
            let right_eval =
                QM31Var::from_partial_evals(right_coordinate_evals.try_into().unwrap());

            let double_times = &fiat_shamir_results.max_log_size - &M31Var::one(&proof.cs());

            let mut x = fiat_shamir_results.oods_point.x.clone();

            let mut session = QM31Var::select_start(&proof.cs());
            for _ in 0..LOG_N_LANES {
                let x_square = &x * &x;
                x = &(&x_square + &x_square) - &M31Var::one(&x.cs());
            }
            for i in LOG_N_LANES..=25 {
                let bit = double_times.is_eq(&M31Var::new_constant(&proof.cs(), &M31::from(i)));
                QM31Var::select_add(&mut session, &x, &bit);
                let x_square = &x * &x;
                x = &(&x_square + &x_square) - &M31Var::one(&x.cs());
            }
            let result = QM31Var::select_end(session);

            &left_eval + &(&result * &right_eval)
        };
        composition_oods_expected.equalverify(&point_evaluation_accumulator.accumulation);
    }

    pub fn opcodes_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let add_var = crate::components::opcodes::add_opcode::Component {
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.add[0],
            &add_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.add,
            &proof.interaction_claim.opcodes.add,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let add_small_var = crate::components::opcodes::add_opcode_small::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.add_small[0],
            &add_small_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.add_small,
            &proof.interaction_claim.opcodes.add_small,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let add_ap_opcode_var = crate::components::opcodes::add_ap_opcode::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            range_check_18_lookup_elements: interaction_elements.range_checks.rc_18.clone(),
            range_check_11_lookup_elements: interaction_elements.range_checks.rc_11.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.add_ap[0],
            &add_ap_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.add_ap,
            &proof.interaction_claim.opcodes.add_ap,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let assert_eq_opcode_var = crate::components::opcodes::assert_eq_opcode::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.assert_eq[0],
            &assert_eq_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.assert_eq,
            &proof.interaction_claim.opcodes.assert_eq,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let assert_eq_opcode_imm_var =
            crate::components::opcodes::assert_eq_opcode_imm::Component {
                verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.assert_eq_imm[0],
            &assert_eq_opcode_imm_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.assert_eq_imm,
            &proof.interaction_claim.opcodes.assert_eq_imm,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let assert_eq_opcode_double_deref_var =
            crate::components::opcodes::assert_eq_opcode_double_deref::Component {
                verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
                opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.assert_eq_double_deref[0],
            &assert_eq_opcode_double_deref_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.assert_eq_double_deref,
            &proof.interaction_claim.opcodes.assert_eq_double_deref,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let blake_compress_opcode_var =
            crate::components::opcodes::blake_compress_opcode::Component {
                log_size: component_generator.opcodes.blake[0].log_size(),
                verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
                range_check_7_2_5_lookup_elements: interaction_elements
                    .range_checks
                    .rc_7_2_5
                    .clone(),
                verify_bitwise_xor_8_lookup_elements: interaction_elements
                    .verify_bitwise_xor_8
                    .clone(),
                blake_round_lookup_elements: interaction_elements.blake_round.clone(),
                triple_xor_32_lookup_elements: interaction_elements.triple_xor_32.clone(),
                opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.blake[0],
            &blake_compress_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.blake,
            &proof.interaction_claim.opcodes.blake,
            true,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let call_opcode_abs_var = crate::components::opcodes::call_opcode_abs::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.call[0],
            &call_opcode_abs_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.call,
            &proof.interaction_claim.opcodes.call,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let call_opcode_rel_imm_var = crate::components::opcodes::call_opcode_rel_imm::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.call_rel_imm[0],
            &call_opcode_rel_imm_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.call_rel_imm,
            &proof.interaction_claim.opcodes.call_rel_imm,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let jnz_opcode_non_taken_var =
            crate::components::opcodes::jnz_opcode_non_taken::Component {
                verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
                opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.jnz[0],
            &jnz_opcode_non_taken_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.jnz,
            &proof.interaction_claim.opcodes.jnz,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let jnz_opcode_taken_var = crate::components::opcodes::jnz_opcode_taken::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.jnz_taken[0],
            &jnz_opcode_taken_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.jnz_taken,
            &proof.interaction_claim.opcodes.jnz_taken,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let jump_opcode_rel_var = crate::components::opcodes::jump_opcode_rel::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.jump_rel[0],
            &jump_opcode_rel_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.jump_rel,
            &proof.interaction_claim.opcodes.jump_rel,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let jump_opcode_rel_imm_var = crate::components::opcodes::jump_opcode_rel_imm::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.jump_rel_imm[0],
            &jump_opcode_rel_imm_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.jump_rel_imm,
            &proof.interaction_claim.opcodes.jump_rel_imm,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let mul_opcode_var = crate::components::opcodes::mul_opcode::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            range_check_20_lookup_elements: interaction_elements.range_checks.rc_20.clone(),
            range_check_20_b_lookup_elements: interaction_elements.range_checks.rc_20_b.clone(),
            range_check_20_c_lookup_elements: interaction_elements.range_checks.rc_20_c.clone(),
            range_check_20_d_lookup_elements: interaction_elements.range_checks.rc_20_d.clone(),
            range_check_20_e_lookup_elements: interaction_elements.range_checks.rc_20_e.clone(),
            range_check_20_f_lookup_elements: interaction_elements.range_checks.rc_20_f.clone(),
            range_check_20_g_lookup_elements: interaction_elements.range_checks.rc_20_g.clone(),
            range_check_20_h_lookup_elements: interaction_elements.range_checks.rc_20_h.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.mul[0],
            &mul_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.mul,
            &proof.interaction_claim.opcodes.mul,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let mul_opcode_small_var = crate::components::opcodes::mul_opcode_small::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
            range_check_11_lookup_elements: interaction_elements.range_checks.rc_11.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.mul_small[0],
            &mul_opcode_small_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.mul_small,
            &proof.interaction_claim.opcodes.mul_small,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let qm_31_add_mul_opcode_var =
            crate::components::opcodes::qm_31_add_mul_opcode::Component {
                verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
                opcodes_lookup_elements: interaction_elements.opcodes.clone(),
                range_check_4_4_4_4_lookup_elements: interaction_elements
                    .range_checks
                    .rc_4_4_4_4
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.qm31[0],
            &qm_31_add_mul_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.qm31,
            &proof.interaction_claim.opcodes.qm31,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let ret_opcode_var = crate::components::opcodes::ret_opcode::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            opcodes_lookup_elements: interaction_elements.opcodes.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.opcodes.ret[0],
            &ret_opcode_var,
            &oods_point,
            &samples,
            &proof.claim.opcode_claim.ret,
            &proof.interaction_claim.opcodes.ret,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn verify_instruction_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let verify_instruction_var = crate::components::verify_instruction::Component {
            verify_instruction_lookup_elements: interaction_elements.verify_instruction.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            range_check_7_2_5_lookup_elements: interaction_elements.range_checks.rc_7_2_5.clone(),
            range_check_4_3_lookup_elements: interaction_elements.range_checks.rc_4_3.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_instruction,
            &verify_instruction_var,
            &oods_point,
            &samples,
            &proof.claim.verify_instruction,
            &proof.interaction_claim.verify_instruction,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn blake_context_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let cs = proof.cs();
        let blake_context_components = &component_generator
            .blake_context
            .components
            .as_ref()
            .unwrap();

        let blake_round_var = crate::components::blake::blake_round::Component {
            blake_round_sigma_lookup_elements: interaction_elements.blake_sigma.clone(),
            range_check_7_2_5_lookup_elements: interaction_elements.range_checks.rc_7_2_5.clone(),
            memory_address_to_id_lookup_elements: interaction_elements.memory_address_to_id.clone(),
            memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            blake_g_lookup_elements: interaction_elements.blake_g.clone(),
            blake_round_lookup_elements: interaction_elements.blake_round.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &blake_context_components.blake_round,
            &blake_round_var,
            &oods_point,
            &samples,
            &proof.claim.blake_context.blake_round,
            &proof.interaction_claim.blake_context.blake_round,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let blake_g_var = crate::components::blake::blake_g::Component {
            verify_bitwise_xor_8_lookup_elements: interaction_elements.verify_bitwise_xor_8.clone(),
            verify_bitwise_xor_8_b_lookup_elements: interaction_elements
                .verify_bitwise_xor_8_b
                .clone(),
            verify_bitwise_xor_12_lookup_elements: interaction_elements
                .verify_bitwise_xor_12
                .clone(),
            verify_bitwise_xor_4_lookup_elements: interaction_elements.verify_bitwise_xor_4.clone(),
            verify_bitwise_xor_7_lookup_elements: interaction_elements.verify_bitwise_xor_7.clone(),
            verify_bitwise_xor_9_lookup_elements: interaction_elements.verify_bitwise_xor_9.clone(),
            blake_g_lookup_elements: interaction_elements.blake_g.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &blake_context_components.blake_g,
            &blake_g_var,
            &oods_point,
            &samples,
            &proof.claim.blake_context.blake_g,
            &proof.interaction_claim.blake_context.blake_g,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let blake_sigma_var = crate::components::blake::blake_round_sigma::Component {
            blake_round_sigma_lookup_elements: interaction_elements.blake_sigma.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &blake_context_components.blake_sigma,
            &blake_sigma_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::blake_round_sigma::LOG_SIZE),
            &proof.interaction_claim.blake_context.blake_sigma,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let triple_xor_32_var = crate::components::blake::triple_xor_32::Component {
            triple_xor_32_lookup_elements: interaction_elements.triple_xor_32.clone(),
            verify_bitwise_xor_8_lookup_elements: interaction_elements.verify_bitwise_xor_8.clone(),
            verify_bitwise_xor_8_b_lookup_elements: interaction_elements
                .verify_bitwise_xor_8_b
                .clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &blake_context_components.triple_xor_32,
            &triple_xor_32_var,
            &oods_point,
            &samples,
            &proof.claim.blake_context.triple_xor_32,
            &proof.interaction_claim.blake_context.triple_xor_32,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let verify_bitwise_xor_12_var =
            crate::components::blake::verify_bitwise_xor_12::Component {
                verify_bitwise_xor_12_lookup_elements: interaction_elements
                    .verify_bitwise_xor_12
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &blake_context_components.verify_bitwise_xor_12,
            &verify_bitwise_xor_12_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::verify_bitwise_xor_12::LOG_SIZE),
            &proof.interaction_claim.blake_context.verify_bitwise_xor_12,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn range_check_builtin_bits_128_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let range_check_128_builtin = component_generator
            .builtins
            .range_check_128_builtin
            .as_ref()
            .unwrap();

        let range_check_builtin_bits_128_var =
            crate::components::range_check_builtin_bits_128::Component {
                log_size: range_check_128_builtin.log_size(),
                range_check_builtin_segment_start: proof
                    .claim
                    .builtins
                    .range_check_builtin_segment_start
                    .to_m31(),
                memory_address_to_id_lookup_elements: interaction_elements
                    .memory_address_to_id
                    .clone(),
                memory_id_to_big_lookup_elements: interaction_elements.memory_id_to_value.clone(),
            };

        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &range_check_128_builtin,
            &range_check_builtin_bits_128_var,
            &oods_point,
            &samples,
            &proof.claim.builtins.range_check_128_builtin_log_size,
            &proof.interaction_claim.builtins,
            true,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn memory_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let memory_address_to_id_var = crate::components::memory_address_to_id::Component {
            log_size: component_generator.memory_address_to_id.log_size(),
            pow2: WrappedQM31Var::wrap(QM31Var::from(&proof.claim.memory_address_to_id.pow2)),
            lookup_elements: interaction_elements.memory_address_to_id.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.memory_address_to_id,
            &memory_address_to_id_var,
            &oods_point,
            &samples,
            &proof.claim.memory_address_to_id,
            &proof.interaction_claim.memory_address_to_id,
            true,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let memory_id_to_big_components = &component_generator.memory_id_to_value.0[0];
        assert_eq!(memory_id_to_big_components.offset, 0);
        let memory_id_to_big_var = crate::components::memory_id_to_big::BigComponent {
            log_size: memory_id_to_big_components.log_size(),
            offset: memory_id_to_big_components.offset,
            lookup_elements: interaction_elements.memory_id_to_value.clone(),
            range_check_9_9_lookup_elements: interaction_elements.range_checks.rc_9_9.clone(),
            range_check_9_9_b_lookup_elements: interaction_elements.range_checks.rc_9_9_b.clone(),
            range_check_9_9_c_lookup_elements: interaction_elements.range_checks.rc_9_9_c.clone(),
            range_check_9_9_d_lookup_elements: interaction_elements.range_checks.rc_9_9_d.clone(),
            range_check_9_9_e_lookup_elements: interaction_elements.range_checks.rc_9_9_e.clone(),
            range_check_9_9_f_lookup_elements: interaction_elements.range_checks.rc_9_9_f.clone(),
            range_check_9_9_g_lookup_elements: interaction_elements.range_checks.rc_9_9_g.clone(),
            range_check_9_9_h_lookup_elements: interaction_elements.range_checks.rc_9_9_h.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &memory_id_to_big_components,
            &memory_id_to_big_var,
            &oods_point,
            &samples,
            &proof.claim.memory_id_to_value.big_log_size,
            &proof.interaction_claim.memory_id_to_value.big_claimed_sum,
            true,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let memory_id_to_small_components = &component_generator.memory_id_to_value.1;
        let memory_id_to_small_var = crate::components::memory_id_to_big::SmallComponent {
            log_size: memory_id_to_small_components.log_size(),
            lookup_elements: interaction_elements.memory_id_to_value.clone(),
            range_check_9_9_relation: interaction_elements.range_checks.rc_9_9.clone(),
            range_check_9_9_b_relation: interaction_elements.range_checks.rc_9_9_b.clone(),
            range_check_9_9_c_relation: interaction_elements.range_checks.rc_9_9_c.clone(),
            range_check_9_9_d_relation: interaction_elements.range_checks.rc_9_9_d.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &memory_id_to_small_components,
            &memory_id_to_small_var,
            &oods_point,
            &samples,
            &proof.claim.memory_id_to_value.small_log_size,
            &proof.interaction_claim.memory_id_to_value.small_claimed_sum,
            true,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn range_checks_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let cs = proof.cs();
        let range_check_6_var = crate::components::range_checks::range_check_6::Component {
            range_check_6_lookup_elements: interaction_elements.range_checks.rc_6.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_6,
            &range_check_6_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_6::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_6,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_8_var = crate::components::range_checks::range_check_8::Component {
            range_check_8_lookup_elements: interaction_elements.range_checks.rc_8.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_8,
            &range_check_8_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_8::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_8,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_11_var = crate::components::range_checks::range_check_11::Component {
            range_check_11_lookup_elements: interaction_elements.range_checks.rc_11.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_11,
            &range_check_11_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_11::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_11,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_12_var = crate::components::range_checks::range_check_12::Component {
            range_check_12_lookup_elements: interaction_elements.range_checks.rc_12.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_12,
            &range_check_12_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_12::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_12,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_18_var = crate::components::range_checks::range_check_18::Component {
            range_check_18_lookup_elements: interaction_elements.range_checks.rc_18.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_18,
            &range_check_18_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_18::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_18,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_18_b_var = crate::components::range_checks::range_check_18_b::Component {
            range_check_18_b_lookup_elements: interaction_elements.range_checks.rc_18_b.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_18_b,
            &range_check_18_b_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_18_b::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_18_b,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let range_check_20_var = crate::components::range_checks::range_check_20::Component {
            range_check_20_lookup_elements: interaction_elements.range_checks.rc_20.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20,
            &range_check_20_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_b_var = crate::components::range_checks::range_check_20_b::Component {
            range_check_20_b_lookup_elements: interaction_elements.range_checks.rc_20_b.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_b,
            &range_check_20_b_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_b::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_b,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_c_var = crate::components::range_checks::range_check_20_c::Component {
            range_check_20_c_lookup_elements: interaction_elements.range_checks.rc_20_c.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_c,
            &range_check_20_c_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_c::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_c,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_d_var = crate::components::range_checks::range_check_20_d::Component {
            range_check_20_d_lookup_elements: interaction_elements.range_checks.rc_20_d.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_d,
            &range_check_20_d_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_d::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_d,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_e_var = crate::components::range_checks::range_check_20_e::Component {
            range_check_20_e_lookup_elements: interaction_elements.range_checks.rc_20_e.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_e,
            &range_check_20_e_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_e::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_e,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_f_var = crate::components::range_checks::range_check_20_f::Component {
            range_check_20_f_lookup_elements: interaction_elements.range_checks.rc_20_f.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_f,
            &range_check_20_f_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_f::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_f,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_g_var = crate::components::range_checks::range_check_20_g::Component {
            range_check_20_g_lookup_elements: interaction_elements.range_checks.rc_20_g.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_g,
            &range_check_20_g_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_g::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_g,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_20_h_var = crate::components::range_checks::range_check_20_h::Component {
            range_check_20_h_lookup_elements: interaction_elements.range_checks.rc_20_h.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_20_h,
            &range_check_20_h_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_20_h::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_20_h,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_4_3_var = crate::components::range_checks::range_check_4_3::Component {
            range_check_4_3_lookup_elements: interaction_elements.range_checks.rc_4_3.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_4_3,
            &range_check_4_3_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_4_3::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_4_3,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_4_4_var = crate::components::range_checks::range_check_4_4::Component {
            range_check_4_4_lookup_elements: interaction_elements.range_checks.rc_4_4.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_4_4,
            &range_check_4_4_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_4_4::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_4_4,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_5_4_var = crate::components::range_checks::range_check_5_4::Component {
            range_check_5_4_lookup_elements: interaction_elements.range_checks.rc_5_4.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_5_4,
            &range_check_5_4_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_5_4::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_5_4,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_var = crate::components::range_checks::range_check_9_9::Component {
            range_check_9_9_lookup_elements: interaction_elements.range_checks.rc_9_9.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9,
            &range_check_9_9_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_b_var = crate::components::range_checks::range_check_9_9_b::Component {
            range_check_9_9_b_lookup_elements: interaction_elements.range_checks.rc_9_9_b.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_b,
            &range_check_9_9_b_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_b::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_b,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_c_var = crate::components::range_checks::range_check_9_9_c::Component {
            range_check_9_9_c_lookup_elements: interaction_elements.range_checks.rc_9_9_c.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_c,
            &range_check_9_9_c_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_c::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_c,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_d_var = crate::components::range_checks::range_check_9_9_d::Component {
            range_check_9_9_d_lookup_elements: interaction_elements.range_checks.rc_9_9_d.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_d,
            &range_check_9_9_d_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_d::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_d,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_e_var = crate::components::range_checks::range_check_9_9_e::Component {
            range_check_9_9_e_lookup_elements: interaction_elements.range_checks.rc_9_9_e.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_e,
            &range_check_9_9_e_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_e::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_e,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_f_var = crate::components::range_checks::range_check_9_9_f::Component {
            range_check_9_9_f_lookup_elements: interaction_elements.range_checks.rc_9_9_f.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_f,
            &range_check_9_9_f_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_f::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_f,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_g_var = crate::components::range_checks::range_check_9_9_g::Component {
            range_check_9_9_g_lookup_elements: interaction_elements.range_checks.rc_9_9_g.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_g,
            &range_check_9_9_g_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_g::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_g,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_9_9_h_var = crate::components::range_checks::range_check_9_9_h::Component {
            range_check_9_9_h_lookup_elements: interaction_elements.range_checks.rc_9_9_h.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_9_9_h,
            &range_check_9_9_h_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_9_9_h::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_9_9_h,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );

        let range_check_7_2_5_var = crate::components::range_checks::range_check_7_2_5::Component {
            range_check_7_2_5_lookup_elements: interaction_elements.range_checks.rc_7_2_5.clone(),
        };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_7_2_5,
            &range_check_7_2_5_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_7_2_5::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_7_2_5,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_3_6_6_3_var =
            crate::components::range_checks::range_check_3_6_6_3::Component {
                range_check_3_6_6_3_lookup_elements: interaction_elements
                    .range_checks
                    .rc_3_6_6_3
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_3_6_6_3,
            &range_check_3_6_6_3_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_3_6_6_3::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_3_6_6_3,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_4_4_4_4_var =
            crate::components::range_checks::range_check_4_4_4_4::Component {
                range_check_4_4_4_4_lookup_elements: interaction_elements
                    .range_checks
                    .rc_4_4_4_4
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_4_4_4_4,
            &range_check_4_4_4_4_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_4_4_4_4::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_4_4_4_4,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let range_check_3_3_3_3_3_var =
            crate::components::range_checks::range_check_3_3_3_3_3::Component {
                range_check_3_3_3_3_3_lookup_elements: interaction_elements
                    .range_checks
                    .rc_3_3_3_3_3
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.range_checks.rc_3_3_3_3_3,
            &range_check_3_3_3_3_3_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE),
            &proof.interaction_claim.range_checks.rc_3_3_3_3_3,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }

    pub fn verify_bitwise_evaluation(
        evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
        component_generator: &CairoComponents,
        interaction_elements: &CairoInteractionElementsVar,
        oods_point: &CirclePointQM31Var,
        proof: &CairoProofVar,
        samples: &WrappedSamplesValues,
    ) {
        let cs = proof.cs();
        let verify_bitwise_4_var =
            crate::components::verify_bitwise::verify_bitwise_xor_4::Component {
                verify_bitwise_xor_4_lookup_elements: interaction_elements
                    .verify_bitwise_xor_4
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_bitwise_xor_4,
            &verify_bitwise_4_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::verify_bitwise_xor_4::LOG_SIZE),
            &proof.interaction_claim.verify_bitwise_xor_4,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let verify_bitwise_7_var =
            crate::components::verify_bitwise::verify_bitwise_xor_7::Component {
                verify_bitwise_xor_7_lookup_elements: interaction_elements
                    .verify_bitwise_xor_7
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_bitwise_xor_7,
            &verify_bitwise_7_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::verify_bitwise_xor_7::LOG_SIZE),
            &proof.interaction_claim.verify_bitwise_xor_7,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let verify_bitwise_8_var =
            crate::components::verify_bitwise::verify_bitwise_xor_8::Component {
                verify_bitwise_xor_8_lookup_elements: interaction_elements
                    .verify_bitwise_xor_8
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_bitwise_xor_8,
            &verify_bitwise_8_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::verify_bitwise_xor_8::LOG_SIZE),
            &proof.interaction_claim.verify_bitwise_xor_8,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let verify_bitwise_8_b_var =
            crate::components::verify_bitwise::verify_bitwise_xor_8_b::Component {
                verify_bitwise_xor_8_b_lookup_elements: interaction_elements
                    .verify_bitwise_xor_8_b
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_bitwise_xor_8_b,
            &verify_bitwise_8_b_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(
                &cs,
                &cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
            ),
            &proof.interaction_claim.verify_bitwise_xor_8_b,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
        let verify_bitwise_9_var =
            crate::components::verify_bitwise::verify_bitwise_xor_9::Component {
                verify_bitwise_xor_9_lookup_elements: interaction_elements
                    .verify_bitwise_xor_9
                    .clone(),
            };
        update_evaluation_accumulator_var(
            evaluation_accumulator,
            &component_generator.verify_bitwise_xor_9,
            &verify_bitwise_9_var,
            &oods_point,
            &samples,
            &LogSizeVar::new_constant(&cs, &cairo_air::components::verify_bitwise_xor_9::LOG_SIZE),
            &proof.interaction_claim.verify_bitwise_xor_9,
            false,
            &proof.stark_proof.is_preprocessed_trace_present,
        );
    }
}

pub fn update_evaluation_accumulator_var<C: FrameworkEval, R: ComponentVar>(
    evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
    component: &FrameworkComponent<C>,
    component_var: &R,
    point: &CirclePointQM31Var,
    mask: &WrappedSamplesValues,
    log_size: &LogSizeVar,
    claimed_sum: &QM31Var,
    seq_franking: bool,
    is_preprocessed_trace_present: &[BitVar],
) {
    let preprocessed_mask = (*component)
        .preprocessed_column_indices()
        .iter()
        .map(|idx| &mask.0[PREPROCESSED_TRACE_IDX][*idx])
        .collect_vec();

    let mut mask_points = mask.0.sub_tree(&(*component).trace_locations());
    mask_points[PREPROCESSED_TRACE_IDX] = preprocessed_mask;

    let denom_inverse = coset_vanishing_var(point, log_size).inv();

    component_var.evaluate(PointEvaluatorVar::new(
        mask_points,
        evaluation_accumulator,
        &denom_inverse,
        log_size,
        claimed_sum,
        seq_franking,
        &mask.0[PREPROCESSED_TRACE_IDX],
        is_preprocessed_trace_present,
    ));
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use cairo_plonk_dsl_hints::CairoCompositionHints;
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use rand::{Rng, SeedableRng};
    use stwo::core::{
        circle::{CirclePoint, SECURE_FIELD_CIRCLE_ORDER},
        constraints::coset_vanishing,
        fields::qm31::SecureField,
    };

    use super::*;

    #[test]
    fn test_coset_vanishing() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

        let p_index = rng.gen_range(0..SECURE_FIELD_CIRCLE_ORDER);
        let p = CirclePoint::<SecureField>::get_point(p_index);

        let cs = ConstraintSystemRef::new();
        let p_var = CirclePointQM31Var::new_constant(&cs, &p);
        let coset_log_size = LogSizeVar::new_constant(&cs, &12);
        let result = coset_vanishing_var(&p_var, &coset_log_size);

        let coset = CanonicCoset::new(12).coset;
        let expected = coset_vanishing(coset, p);
        assert_eq!(result.value(), expected);
    }

    #[test]
    fn test_composition_check() {
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
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);
        let _ = CairoCompositionHints::new(&fiat_shamir_hints, &proof);
        CairoFiatCompositionCheck::compute(&fiat_shamir_results, &fiat_shamir_hints, &proof_var);

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
