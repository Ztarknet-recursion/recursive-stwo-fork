use std::collections::{HashMap, HashSet};
use std::ops::Mul;
use std::ops::Neg;
use std::sync::OnceLock;

use cairo_air::PreProcessedTraceVariant;
use cairo_plonk_dsl_data_structures::data_structures::LogSizeVar;
use cairo_plonk_dsl_data_structures::evaluator::PointEvaluationAccumulatorVar;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_primitives::fields::WrappedQM31Var;
use circle_plonk_dsl_primitives::oblivious_map::SelectVar;
use circle_plonk_dsl_primitives::{BitVar, M31Var, QM31Var};
use num_traits::Zero;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::{QM31, SECURE_EXTENSION_DEGREE};
use stwo::core::pcs::TreeVec;
use stwo::core::{ColumnVec, Fraction};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    PreProcessedColumn, Seq, MAX_SEQUENCE_LOG_SIZE,
};
use stwo_cairo_common::prover_types::simd::LOG_N_LANES;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, Relation, RelationEntry, INTERACTION_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

pub static SEQ_PREPROCESSED_TRACE_MAP: OnceLock<HashMap<PreProcessedColumnId, usize>> =
    OnceLock::new();

fn initialize_seq_preprocessed_trace_map() -> HashMap<PreProcessedColumnId, usize> {
    let ids = PreProcessedTraceVariant::CanonicalWithoutPedersen
        .to_preprocessed_trace()
        .ids();
    let map = ids
        .iter()
        .enumerate()
        .filter(|(_, id)| id.id.to_string().starts_with("seq_"))
        .map(|(i, id)| (id.clone(), i))
        .collect();
    map
}

pub struct LogupAtRowVar {
    pub interaction: usize,
    pub cumsum_shift: WrappedQM31Var,
    pub fracs: Vec<Fraction<WrappedQM31Var, WrappedQM31Var>>,
    pub is_finalized: bool,
    pub log_size: LogSizeVar,
}

impl LogupAtRowVar {
    pub fn new(interaction: usize, total_sum: &QM31Var, log_size: &LogSizeVar) -> Self {
        LogupAtRowVar {
            interaction,
            cumsum_shift: WrappedQM31Var::wrap(total_sum * &log_size.pow2.inv()),
            fracs: vec![],
            is_finalized: true,
            log_size: log_size.clone(),
        }
    }
}

impl Drop for LogupAtRowVar {
    fn drop(&mut self) {
        assert!(self.is_finalized);
    }
}

pub struct PointEvaluatorVar<'a> {
    pub mask: TreeVec<ColumnVec<&'a Vec<WrappedQM31Var>>>,
    pub evaluation_accumulator: &'a mut PointEvaluationAccumulatorVar,
    pub denom_inverse: QM31Var,
    pub logup: LogupAtRowVar,
    pub col_index: Vec<usize>,
    pub seq_franking: bool,
    pub preprocessed_mask: &'a ColumnVec<Vec<WrappedQM31Var>>,
    pub is_preprocessed_trace_present: &'a [BitVar],
}

impl<'a> PointEvaluatorVar<'a> {
    pub fn new(
        mask: TreeVec<ColumnVec<&'a Vec<WrappedQM31Var>>>,
        evaluation_accumulator: &'a mut PointEvaluationAccumulatorVar,
        denom_inverse: &QM31Var,
        log_size: &LogSizeVar,
        total_sum: &QM31Var,
        seq_franking: bool,
        preprocessed_mask: &'a ColumnVec<Vec<WrappedQM31Var>>,
        is_preprocessed_trace_present: &'a [BitVar],
    ) -> Self {
        let col_index = vec![0; mask.len()];
        let logup = LogupAtRowVar::new(INTERACTION_TRACE_IDX, total_sum, log_size);
        Self {
            mask,
            evaluation_accumulator,
            denom_inverse: denom_inverse.clone(),
            logup,
            col_index,
            seq_franking,
            preprocessed_mask,
            is_preprocessed_trace_present,
        }
    }
}

impl EvalAtRow for PointEvaluatorVar<'_> {
    type F = WrappedQM31Var;
    type EF = WrappedQM31Var;

    fn get_preprocessed_column(&mut self, column: PreProcessedColumnId) -> Self::F {
        if self.seq_franking {
            if column.id.to_string().starts_with("seq_") && self.seq_franking {
                let [mask_item_for_check] = self.next_interaction_mask(PREPROCESSED_TRACE_IDX, [0]);
                let mask_item_for_check = match mask_item_for_check {
                    WrappedQM31Var::Constant(value) => value,
                    WrappedQM31Var::Allocated(variable) => variable.value(),
                };
                // cannot use mask_item_for_check in the constraint system because its location is dynamic

                let seq_preprocessed_trace_map =
                    SEQ_PREPROCESSED_TRACE_MAP.get_or_init(initialize_seq_preprocessed_trace_map);

                let log_size = &self.logup.log_size.m31;
                let mut session = QM31Var::select_start(&self.cs());
                for i in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
                    let loc = seq_preprocessed_trace_map.get(&Seq::new(i).id()).unwrap();
                    let bit = log_size.is_eq(&M31Var::new_constant(&self.cs(), &M31::from(i)));

                    // if bit is true, we require that its preprocessed trace is present
                    // => bit * is_preprocessed_trace_present + !bit = one
                    let is_preprocessed_trace_present = &self.is_preprocessed_trace_present[*loc];
                    let constraint = &(&bit & is_preprocessed_trace_present) | &bit.neg();
                    constraint.equalverify(&BitVar::new_true(&self.cs()));

                    QM31Var::select_add(
                        &mut session,
                        &self.preprocessed_mask[*loc][0].unwrap(&self.cs()),
                        &bit,
                    );
                }
                let res = QM31Var::select_end(session);
                assert_eq!(res.value(), mask_item_for_check);
                WrappedQM31Var::wrap(res)
            } else {
                let [mask_item] = self.next_interaction_mask(PREPROCESSED_TRACE_IDX, [0]);
                mask_item
            }
        } else {
            let [mask_item] = self.next_interaction_mask(PREPROCESSED_TRACE_IDX, [0]);
            mask_item
        }
    }

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        _offsets: [isize; N],
    ) -> [WrappedQM31Var; N] {
        let col_index = self.col_index[interaction];
        self.col_index[interaction] += 1;
        self.mask[interaction][col_index]
            .clone()
            .try_into()
            .unwrap()
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        let value: Self::EF = constraint.into();
        self.evaluation_accumulator
            .accumulate(&value.unwrap(&self.cs()) * &self.denom_inverse);
    }

    fn combine_ef(values: [WrappedQM31Var; SECURE_EXTENSION_DEGREE]) -> WrappedQM31Var {
        let mut cs = None;
        for value in values.iter() {
            if let WrappedQM31Var::Allocated(variable) = value {
                cs = Some(variable.cs());
                break;
            }
        }
        if let Some(cs) = cs {
            let values = values.map(|v| v.unwrap(&cs));
            WrappedQM31Var::wrap(
                &(&(&values[0] + &values[1].shift_by_i()) + &values[2].shift_by_j())
                    + &values[3].shift_by_ij(),
            )
        } else {
            let values = values.map(|v| v.unwrap_constant());
            WrappedQM31Var::Constant(
                values[0]
                    + values[1] * QM31::from_u32_unchecked(0, 1, 0, 0)
                    + values[2] * QM31::from_u32_unchecked(0, 0, 1, 0)
                    + values[3] * QM31::from_u32_unchecked(0, 0, 0, 1),
            )
        }
    }

    fn add_to_relation<R: Relation<WrappedQM31Var, WrappedQM31Var>>(
        &mut self,
        entry: RelationEntry<WrappedQM31Var, WrappedQM31Var, R>,
    ) {
        let denom = entry.relation.combine(entry.values);
        self.write_logup_frac(Fraction::new(entry.multiplicity, denom));
    }

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        if self.logup.fracs.is_empty() {
            self.logup.is_finalized = false;
        }
        self.logup.fracs.push(fraction);
    }

    fn add_to_relation_ef<R: Relation<WrappedQM31Var, WrappedQM31Var>>(
        &mut self,
        entry: RelationEntry<WrappedQM31Var, WrappedQM31Var, R>,
    ) {
        self.add_to_relation(entry);
    }

    fn finalize_logup(&mut self) {
        let batches = (0..self.logup.fracs.len()).collect();
        self.finalize_logup_batched(&batches)
    }

    fn finalize_logup_in_pairs(&mut self) {
        let batches = (0..self.logup.fracs.len()).map(|n| n / 2).collect();
        self.finalize_logup_batched(&batches)
    }

    fn finalize_logup_batched(&mut self, batching: &Vec<usize>) {
        assert!(!self.logup.is_finalized, "LogupAtRow was already finalized");
        assert_eq!(
            batching.len(),
            self.logup.fracs.len(),
            "Batching must be of the same length as the number of entries"
        );

        let last_batch = *batching.iter().max().unwrap();

        let mut fracs_by_batch = HashMap::<usize, Vec<Fraction<Self::EF, Self::EF>>>::new();

        for (batch, frac) in batching.iter().zip(self.logup.fracs.iter()) {
            fracs_by_batch
                .entry(*batch)
                .or_insert_with(Vec::new)
                .push(frac.clone());
        }

        let keys_set: HashSet<_> = fracs_by_batch.keys().cloned().collect();
        let all_batches_set: HashSet<_> = (0..last_batch + 1).collect();

        assert_eq!(
            keys_set, all_batches_set,
            "Batching must contain all consecutive batches"
        );

        let mut prev_col_cumsum = WrappedQM31Var::zero();

        // All batches except the last are cumulatively summed in new interaction columns.
        for batch_id in 0..last_batch {
            let cur_frac: Fraction<_, _> = fracs_by_batch[&batch_id].iter().cloned().sum();
            let [cur_cumsum] = self.next_extension_interaction_mask(self.logup.interaction, [0]);
            let diff = cur_cumsum.clone() - prev_col_cumsum.clone();
            prev_col_cumsum = cur_cumsum;
            self.add_constraint(diff * cur_frac.denominator - cur_frac.numerator);
        }

        let frac: Fraction<_, _> = fracs_by_batch[&last_batch].clone().into_iter().sum();
        let [prev_row_cumsum, cur_cumsum] =
            self.next_extension_interaction_mask(self.logup.interaction, [-1, 0]);

        let diff = cur_cumsum - prev_row_cumsum - prev_col_cumsum;
        // Instead of checking diff = num / denom, check diff = num / denom - cumsum_shift.
        // This makes (num / denom - cumsum_shift) have sum zero, which makes the constraint
        // uniform - apply on all rows.
        let shifted_diff = diff + self.logup.cumsum_shift.clone();

        self.add_constraint(shifted_diff * frac.denominator - frac.numerator);

        self.logup.is_finalized = true;
    }
}

impl PointEvaluatorVar<'_> {
    pub fn cs(&self) -> ConstraintSystemRef {
        self.denom_inverse.cs()
    }
}

pub struct WrappedSamplesValues(pub TreeVec<ColumnVec<Vec<WrappedQM31Var>>>);

impl WrappedSamplesValues {
    pub fn new(sampled_values: &TreeVec<ColumnVec<Vec<QM31Var>>>) -> Self {
        let mut res = TreeVec::new(vec![]);
        for column in sampled_values.iter() {
            let mut column_res = ColumnVec::new();
            for value in column.iter() {
                column_res.push(
                    value
                        .iter()
                        .map(|eval| WrappedQM31Var::wrap(eval.clone()))
                        .collect(),
                );
            }
            res.push(column_res);
        }
        Self(res)
    }
}
