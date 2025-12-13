// This file was created by the AIR team.

use crate::components::prelude::*;

pub const N_TRACE_COLUMNS: usize = 1;
pub const LOG_SIZE: u32 = 20;

pub struct Component {
    pub range_check_20_d_lookup_elements: RangeCheck20DVar,
}

impl ComponentVar for Component {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let seq_20 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "seq_20".to_owned(),
        });
        let multiplicity = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(
            &self.range_check_20_d_lookup_elements,
            -E::EF::from(multiplicity),
            std::slice::from_ref(&seq_20),
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
