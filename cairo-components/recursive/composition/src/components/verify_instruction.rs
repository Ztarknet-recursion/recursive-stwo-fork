// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::encode_offsets::EncodeOffsets;
use crate::components::subroutines::mem_verify::MemVerify;

pub struct Component {
    pub range_check_7_2_5_lookup_elements: RangeCheck725Var,
    pub range_check_4_3_lookup_elements: RangeCheck43Var,
    pub memory_address_to_id_lookup_elements: MemoryAddressToIdVar,
    pub memory_id_to_big_lookup_elements: MemoryIdToBigVar,
    pub verify_instruction_lookup_elements: VerifyInstructionVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let M31_0 = E::F::from(M31::from(0));
        let input_pc_col0 = eval.next_trace_mask();
        let input_offset0_col1 = eval.next_trace_mask();
        let input_offset1_col2 = eval.next_trace_mask();
        let input_offset2_col3 = eval.next_trace_mask();
        let input_inst_felt5_high_col4 = eval.next_trace_mask();
        let input_inst_felt6_col5 = eval.next_trace_mask();
        let input_opcode_extension_col6 = eval.next_trace_mask();
        let offset0_low_col7 = eval.next_trace_mask();
        let offset0_mid_col8 = eval.next_trace_mask();
        let offset1_low_col9 = eval.next_trace_mask();
        let offset1_mid_col10 = eval.next_trace_mask();
        let offset1_high_col11 = eval.next_trace_mask();
        let offset2_low_col12 = eval.next_trace_mask();
        let offset2_mid_col13 = eval.next_trace_mask();
        let offset2_high_col14 = eval.next_trace_mask();
        let instruction_id_col15 = eval.next_trace_mask();
        let multiplicity = eval.next_trace_mask();

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [encode_offsets_output_tmp_16a4f_8_limb_1, encode_offsets_output_tmp_16a4f_8_limb_3] =
            EncodeOffsets::evaluate(
                [
                    input_offset0_col1.clone(),
                    input_offset1_col2.clone(),
                    input_offset2_col3.clone(),
                ],
                offset0_low_col7.clone(),
                offset0_mid_col8.clone(),
                offset1_low_col9.clone(),
                offset1_mid_col10.clone(),
                offset1_high_col11.clone(),
                offset2_low_col12.clone(),
                offset2_mid_col13.clone(),
                offset2_high_col14.clone(),
                &self.range_check_7_2_5_lookup_elements,
                &self.range_check_4_3_lookup_elements,
                &mut eval,
            );
        MemVerify::evaluate(
            [
                input_pc_col0.clone(),
                offset0_low_col7.clone(),
                encode_offsets_output_tmp_16a4f_8_limb_1.clone(),
                offset1_mid_col10.clone(),
                encode_offsets_output_tmp_16a4f_8_limb_3.clone(),
                offset2_mid_col13.clone(),
                (offset2_high_col14.clone() + input_inst_felt5_high_col4.clone()),
                input_inst_felt6_col5.clone(),
                input_opcode_extension_col6.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
                M31_0.clone(),
            ],
            instruction_id_col15.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        eval.add_to_relation(RelationEntry::new(
            &self.verify_instruction_lookup_elements,
            -E::EF::from(multiplicity),
            &[
                input_pc_col0.clone(),
                input_offset0_col1.clone(),
                input_offset1_col2.clone(),
                input_offset2_col3.clone(),
                input_inst_felt5_high_col4.clone(),
                input_inst_felt6_col5.clone(),
                input_opcode_extension_col6.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
