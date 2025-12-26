#![allow(clippy::needless_borrow)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::let_and_return)]
#![allow(clippy::needless_return)]

pub mod data_structures;
use std::ops::Add;

use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_primitives::oblivious_map::ObliviousMapVar;
use circle_plonk_dsl_primitives::{CM31Var, CirclePointM31Var, QM31Var};
pub use data_structures::*;

use circle_plonk_dsl_constraint_system::var::Var;
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

pub struct AnswerResults {
    pub answers: Vec<IndexMap<usize, QM31Var>>,
}

impl AnswerResults {
    pub fn compute(
        fiat_shamir_hints: &CairoFiatShamirHints,
        fiat_shamir_results: &CairoFiatShamirResults,
        decommitment_results: &CairoDecommitmentResultsVar,
        proof_var: &CairoProofVar,
    ) -> AnswerResults {
        let cs = proof_var.cs();

        let preprocessed_trace_sample_result = PreprocessedTraceSampleResultVar::new(
            &cs,
            &proof_var.stark_proof.sampled_values[0],
            &proof_var.stark_proof.is_preprocessed_trace_present,
        );
        let trace_sample_result =
            TraceSampleResultVar::new(&cs, &proof_var.stark_proof.sampled_values[1]);
        let interaction_sample_result =
            InteractionSampleResultVar::new(&cs, &proof_var.stark_proof.sampled_values[2]);
        let composition_sample_result =
            CompositionSampleResultVar::new(&proof_var.stark_proof.sampled_values[3]);

        let shifted_points = {
            let mut map = IndexMap::new();
            let oods_point = &fiat_shamir_results.oods_point;
            for i in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
                map.insert(
                    i,
                    oods_point.add(&CanonicCoset::new(i).step().mul_signed(-1)),
                );
            }
            ObliviousMapVar::new(map)
        };

        let preprocessed_trace_quotient_constants = PreprocessedTraceQuotientConstantsVar::new(
            &fiat_shamir_results.oods_point,
            &preprocessed_trace_sample_result,
        );
        let trace_quotient_constants =
            TraceQuotientConstantsVar::new(&fiat_shamir_results.oods_point, &trace_sample_result);
        let interaction_quotient_constants = InteractionQuotientConstantsVar::new(
            &proof_var.claim,
            &fiat_shamir_results.oods_point,
            &interaction_sample_result,
            &shifted_points,
        );
        let composition_quotient_constants = CompositionQuotientConstantsVar::new(
            &fiat_shamir_results.oods_point,
            &composition_sample_result,
        );

        let n_queries = fiat_shamir_hints.pcs_config.fri_config.n_queries as usize;
        let mut answer_accumulator = Vec::with_capacity(n_queries);
        for _ in 0..n_queries {
            answer_accumulator.push(AnswerAccumulator::new(
                &cs,
                &fiat_shamir_results.after_sampled_values_random_coeff,
            ));
        }

        let query_positions_var = CairoQueryPositionsPerLogSizeVar::new(
            &fiat_shamir_results.queries,
            fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor,
            &fiat_shamir_results.query_log_size,
        );
        let domain_points: IndexMap<u32, Vec<CirclePointM31Var>> = query_positions_var
            .points
            .iter()
            .map(|(k, v)| {
                let v = v.iter().map(|v| v.get_next_point()).collect_vec();
                (*k, v)
            })
            .collect();

        let [prx, pix] = fiat_shamir_results.oods_point.x.decompose_cm31();
        let [pry, piy] = fiat_shamir_results.oods_point.y.decompose_cm31();

        let denominator_inverses_with_oods_point: IndexMap<u32, Vec<CM31Var>> = {
            domain_points
                .iter()
                .map(|(k, v)| {
                    let v = v
                        .iter()
                        .map(|v| (&(&(&prx - &v.x) * &piy) - &(&(&pry - &v.y) * &pix)).inv())
                        .collect_vec();
                    (*k, v)
                })
                .collect()
        };

        compute_preprocessed_trace_answers(
            n_queries,
            &mut answer_accumulator,
            &piy,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &decommitment_results,
            &preprocessed_trace_quotient_constants,
        );
        compute_trace_answers(
            n_queries,
            &mut answer_accumulator,
            &piy,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &decommitment_results,
            &trace_quotient_constants,
            &proof_var.claim,
        );
        compute_interaction_answers_without_shift(
            n_queries,
            &mut answer_accumulator,
            &piy,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &decommitment_results,
            &interaction_quotient_constants,
            &proof_var.claim,
        );
        compute_composition_answers(
            n_queries,
            &mut answer_accumulator,
            &piy,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &decommitment_results,
            &composition_quotient_constants,
            &fiat_shamir_results.composition_log_size,
        );
        compute_interaction_answers_shift_only(
            n_queries,
            &mut answer_accumulator,
            &domain_points,
            &decommitment_results,
            &interaction_quotient_constants,
            &proof_var.claim,
        );
        Self {
            answers: answer_accumulator
                .into_iter()
                .map(|accumulator| accumulator.finalize())
                .collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use cairo_plonk_dsl_hints::{CairoDecommitmentHints, CairoFiatShamirHints};
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use std::path::PathBuf;

    #[test]
    fn test_answer_results() {
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
        let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, &proof);
        let decommitment_results = CairoDecommitmentResultsVar::compute(
            &fiat_shamir_hints,
            &decommitment_hints,
            &fiat_shamir_results,
            &proof_var,
        );
        let _ = AnswerResults::compute(
            &fiat_shamir_hints,
            &fiat_shamir_results,
            &decommitment_results,
            &proof_var,
        );

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
