// This file was created by the AIR team.

use circle_plonk_dsl_primitives::{M31Var, QM31Var};

use crate::components::prelude::*;
use crate::components::subroutines::read_positive_num_bits_128::ReadPositiveNumBits128;

pub struct Component {
    pub log_size: u32,
    pub range_check_builtin_segment_start: M31Var,
    pub memory_address_to_id_lookup_elements: MemoryAddressToIdVar,
    pub memory_id_to_big_lookup_elements: MemoryIdToBigVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let seq = eval.get_preprocessed_column(Seq::new(self.log_size).id());
        let value_id_col0 = eval.next_trace_mask();
        let value_limb_0_col1 = eval.next_trace_mask();
        let value_limb_1_col2 = eval.next_trace_mask();
        let value_limb_2_col3 = eval.next_trace_mask();
        let value_limb_3_col4 = eval.next_trace_mask();
        let value_limb_4_col5 = eval.next_trace_mask();
        let value_limb_5_col6 = eval.next_trace_mask();
        let value_limb_6_col7 = eval.next_trace_mask();
        let value_limb_7_col8 = eval.next_trace_mask();
        let value_limb_8_col9 = eval.next_trace_mask();
        let value_limb_9_col10 = eval.next_trace_mask();
        let value_limb_10_col11 = eval.next_trace_mask();
        let value_limb_11_col12 = eval.next_trace_mask();
        let value_limb_12_col13 = eval.next_trace_mask();
        let value_limb_13_col14 = eval.next_trace_mask();
        let value_limb_14_col15 = eval.next_trace_mask();
        let partial_limb_msb_col16 = eval.next_trace_mask();

        let range_check_builtin_segment_start =
            WrappedQM31Var::wrap(QM31Var::from(&self.range_check_builtin_segment_start));

        ReadPositiveNumBits128::evaluate(
            [(range_check_builtin_segment_start + seq.clone())],
            value_id_col0.clone(),
            value_limb_0_col1.clone(),
            value_limb_1_col2.clone(),
            value_limb_2_col3.clone(),
            value_limb_3_col4.clone(),
            value_limb_4_col5.clone(),
            value_limb_5_col6.clone(),
            value_limb_6_col7.clone(),
            value_limb_7_col8.clone(),
            value_limb_8_col9.clone(),
            value_limb_9_col10.clone(),
            value_limb_10_col11.clone(),
            value_limb_11_col12.clone(),
            value_limb_12_col13.clone(),
            value_limb_13_col14.clone(),
            value_limb_14_col15.clone(),
            partial_limb_msb_col16.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        eval.finalize_logup_in_pairs();
        eval
    }
}
