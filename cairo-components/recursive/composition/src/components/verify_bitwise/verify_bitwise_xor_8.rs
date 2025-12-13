// This file was created by the AIR team.

use crate::components::prelude::*;

pub const N_TRACE_COLUMNS: usize = 1;
pub const LOG_SIZE: u32 = 16;

pub struct Component {
    pub verify_bitwise_xor_8_lookup_elements: VerifyBitwiseXor8Var,
}

impl ComponentVar for Component {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let bitwise_xor_8_0 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "bitwise_xor_8_0".to_owned(),
        });
        let bitwise_xor_8_1 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "bitwise_xor_8_1".to_owned(),
        });
        let bitwise_xor_8_2 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "bitwise_xor_8_2".to_owned(),
        });
        let multiplicity = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(
            &self.verify_bitwise_xor_8_lookup_elements,
            -E::EF::from(multiplicity),
            &[
                bitwise_xor_8_0.clone(),
                bitwise_xor_8_1.clone(),
                bitwise_xor_8_2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
