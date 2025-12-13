// This file was created by the AIR team.

use crate::components::prelude::*;

pub const N_TRACE_COLUMNS: usize = 1;
pub const LOG_SIZE: u32 = 18;

pub struct Component {
    pub range_check_9_9_d_lookup_elements: RangeCheck99DVar,
}

impl ComponentVar for Component {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let range_check_9_9_column_0 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "range_check_9_9_column_0".to_owned(),
        });
        let range_check_9_9_column_1 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "range_check_9_9_column_1".to_owned(),
        });
        let multiplicity = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(
            &self.range_check_9_9_d_lookup_elements,
            -E::EF::from(multiplicity),
            &[
                range_check_9_9_column_0.clone(),
                range_check_9_9_column_1.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
