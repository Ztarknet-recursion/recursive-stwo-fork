// This file was created by the AIR team.

use crate::components::{
    prelude::*,
    subroutines::{
        decode_instruction_d2a10::DecodeInstructionD2A10, range_check_ap::RangeCheckAp,
        read_small::ReadSmall,
    },
};

pub struct Component {
    pub verify_instruction_lookup_elements: VerifyInstructionVar,
    pub memory_address_to_id_lookup_elements: MemoryAddressToIdVar,
    pub memory_id_to_big_lookup_elements: MemoryIdToBigVar,
    pub range_check_18_lookup_elements: RangeCheck18Var,
    pub range_check_11_lookup_elements: RangeCheck11Var,
    pub opcodes_lookup_elements: OpcodesVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let M31_1 = E::F::from(M31::from(1));
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let offset2_col3 = eval.next_trace_mask();
        let op1_imm_col4 = eval.next_trace_mask();
        let op1_base_fp_col5 = eval.next_trace_mask();
        let mem1_base_col6 = eval.next_trace_mask();
        let op1_id_col7 = eval.next_trace_mask();
        let msb_col8 = eval.next_trace_mask();
        let mid_limbs_set_col9 = eval.next_trace_mask();
        let op1_limb_0_col10 = eval.next_trace_mask();
        let op1_limb_1_col11 = eval.next_trace_mask();
        let op1_limb_2_col12 = eval.next_trace_mask();
        let remainder_bits_col13 = eval.next_trace_mask();
        let partial_limb_msb_col14 = eval.next_trace_mask();
        let range_check_ap_bot11bits_col15 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [decode_instruction_d2a10_output_tmp_c921e_6_offset2, decode_instruction_d2a10_output_tmp_c921e_6_op1_base_ap] =
            DecodeInstructionD2A10::evaluate(
                [input_pc_col0.clone()],
                offset2_col3.clone(),
                op1_imm_col4.clone(),
                op1_base_fp_col5.clone(),
                &self.verify_instruction_lookup_elements,
                &mut eval,
            );
        // if imm then offset2 is 1.
        eval.add_constraint(
            (op1_imm_col4.clone()
                * (M31_1.clone() - decode_instruction_d2a10_output_tmp_c921e_6_offset2.clone())),
        );
        // mem1_base.
        eval.add_constraint(
            (mem1_base_col6.clone()
                - (((op1_imm_col4.clone() * input_pc_col0.clone())
                    + (op1_base_fp_col5.clone() * input_fp_col2.clone()))
                    + (decode_instruction_d2a10_output_tmp_c921e_6_op1_base_ap.clone()
                        * input_ap_col1.clone()))),
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [read_small_output_tmp_c921e_16_limb_0] = ReadSmall::evaluate(
            [(mem1_base_col6.clone()
                + decode_instruction_d2a10_output_tmp_c921e_6_offset2.clone())],
            op1_id_col7.clone(),
            msb_col8.clone(),
            mid_limbs_set_col9.clone(),
            op1_limb_0_col10.clone(),
            op1_limb_1_col11.clone(),
            op1_limb_2_col12.clone(),
            remainder_bits_col13.clone(),
            partial_limb_msb_col14.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        let next_ap_tmp_c921e_17 = eval.add_intermediate(
            (input_ap_col1.clone() + read_small_output_tmp_c921e_16_limb_0.clone()),
        );
        RangeCheckAp::evaluate(
            [next_ap_tmp_c921e_17.clone()],
            range_check_ap_bot11bits_col15.clone(),
            &self.range_check_18_lookup_elements,
            &self.range_check_11_lookup_elements,
            &mut eval,
        );
        eval.add_to_relation(RelationEntry::new(
            &self.opcodes_lookup_elements,
            E::EF::from(enabler.clone()),
            &[
                input_pc_col0.clone(),
                input_ap_col1.clone(),
                input_fp_col2.clone(),
            ],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.opcodes_lookup_elements,
            -E::EF::from(enabler.clone()),
            &[
                (input_pc_col0.clone() + (M31_1.clone() + op1_imm_col4.clone())),
                next_ap_tmp_c921e_17.clone(),
                input_fp_col2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
