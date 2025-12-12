use cairo_plonk_dsl_data_structures::{
    data_structures::LogSizeVar, evaluator::PointEvaluationAccumulatorVar, CairoProofVar,
};
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use circle_plonk_dsl_constraint_system::var::Var;
use circle_plonk_dsl_primitives::{CirclePointQM31Var, M31Var, QM31Var};
use itertools::Itertools;
use stwo::core::poly::circle::CanonicCoset;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, PREPROCESSED_TRACE_IDX};

use crate::data_structures::WrappedSamplesValues;

pub mod data_structures;

pub fn coset_vanishing_var(p: &CirclePointQM31Var, coset_log_size: &LogSizeVar) -> QM31Var {
    /*let cs = p.cs();
    let coset = CanonicCoset::new(coset_log_size).coset;
    let mut x = (p + &(-coset.initial + coset.step_size.half().to_point())).x;

    // The formula for the x coordinate of the double of a point.
    for _ in 1..coset.log_size {
        let sq = &x * &x;
        x = &(&sq + &sq) - &M31Var::one(&cs);
    }
    x*/
    todo!()
}

pub struct CairoFiatCompositionCheck {}

impl CairoFiatCompositionCheck {
    pub fn compute(fiat_shamir_results: &CairoFiatShamirResults, proof: &CairoProofVar) {
        let samples = WrappedSamplesValues::new(&proof.stark_proof.sampled_values);

        let point_evaluation_accumulator =
            PointEvaluationAccumulatorVar::new(&fiat_shamir_results.random_coeff);

        todo!()
    }
}

pub fn update_evaluation_accumulator_var<C: FrameworkEval>(
    evaluation_accumulator: &mut PointEvaluationAccumulatorVar,
    component: &FrameworkComponent<C>,
    point: CirclePointQM31Var,
    mask: &WrappedSamplesValues,
    log_size: &LogSizeVar,
) {
    let preprocessed_mask = (*component)
        .preprocessed_column_indices()
        .iter()
        .map(|idx| &mask.0[PREPROCESSED_TRACE_IDX][*idx])
        .collect_vec();

    let mut mask_points = mask.0.sub_tree(&(*component).trace_locations());
    mask_points[PREPROCESSED_TRACE_IDX] = preprocessed_mask;

    /*component.evaluate(PointEvaluatorVar::new(
        mask_points,
        evaluation_accumulator,
        coset_vanishing(CanonicCoset::new((*component).log_size()).coset, point).inverse(),
        (*component).log_size(),
        (*component).claimed_sum(),
    ));*/

    todo!()
}
