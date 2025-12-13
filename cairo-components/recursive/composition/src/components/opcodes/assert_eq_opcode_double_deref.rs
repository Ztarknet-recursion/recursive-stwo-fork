use crate::components::{
    prelude::*,
    subroutines::{
        decode_instruction_cb32b::DecodeInstructionCb32B, mem_verify_equal::MemVerifyEqual,
        read_positive_num_bits_29::ReadPositiveNumBits29,
    },
};

pub struct Component {
    pub verify_instruction_lookup_elements: VerifyInstructionVar,
    pub memory_address_to_id_lookup_elements: MemoryAddressToIdVar,
    pub memory_id_to_big_lookup_elements: MemoryIdToBigVar,
    pub opcodes_lookup_elements: OpcodesVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let M31_1 = E::F::from(M31::from(1));
        let M31_134217728 = E::F::from(M31::from(134217728));
        let M31_262144 = E::F::from(M31::from(262144));
        let M31_512 = E::F::from(M31::from(512));
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let offset0_col3 = eval.next_trace_mask();
        let offset1_col4 = eval.next_trace_mask();
        let offset2_col5 = eval.next_trace_mask();
        let dst_base_fp_col6 = eval.next_trace_mask();
        let op0_base_fp_col7 = eval.next_trace_mask();
        let ap_update_add_1_col8 = eval.next_trace_mask();
        let mem_dst_base_col9 = eval.next_trace_mask();
        let mem0_base_col10 = eval.next_trace_mask();
        let mem1_base_id_col11 = eval.next_trace_mask();
        let mem1_base_limb_0_col12 = eval.next_trace_mask();
        let mem1_base_limb_1_col13 = eval.next_trace_mask();
        let mem1_base_limb_2_col14 = eval.next_trace_mask();
        let mem1_base_limb_3_col15 = eval.next_trace_mask();
        let partial_limb_msb_col16 = eval.next_trace_mask();
        let dst_id_col17 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [decode_instruction_cb32b_output_tmp_b1151_8_offset0, decode_instruction_cb32b_output_tmp_b1151_8_offset1, decode_instruction_cb32b_output_tmp_b1151_8_offset2] =
            DecodeInstructionCb32B::evaluate(
                [input_pc_col0.clone()],
                offset0_col3.clone(),
                offset1_col4.clone(),
                offset2_col5.clone(),
                dst_base_fp_col6.clone(),
                op0_base_fp_col7.clone(),
                ap_update_add_1_col8.clone(),
                &self.verify_instruction_lookup_elements,
                &mut eval,
            );
        // mem_dst_base.
        eval.add_constraint(
            (mem_dst_base_col9.clone()
                - ((dst_base_fp_col6.clone() * input_fp_col2.clone())
                    + ((M31_1.clone() - dst_base_fp_col6.clone()) * input_ap_col1.clone()))),
        );
        // mem0_base.
        eval.add_constraint(
            (mem0_base_col10.clone()
                - ((op0_base_fp_col7.clone() * input_fp_col2.clone())
                    + ((M31_1.clone() - op0_base_fp_col7.clone()) * input_ap_col1.clone()))),
        );
        ReadPositiveNumBits29::evaluate(
            [(mem0_base_col10.clone()
                + decode_instruction_cb32b_output_tmp_b1151_8_offset1.clone())],
            mem1_base_id_col11.clone(),
            mem1_base_limb_0_col12.clone(),
            mem1_base_limb_1_col13.clone(),
            mem1_base_limb_2_col14.clone(),
            mem1_base_limb_3_col15.clone(),
            partial_limb_msb_col16.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        MemVerifyEqual::evaluate(
            [
                (mem_dst_base_col9.clone()
                    + decode_instruction_cb32b_output_tmp_b1151_8_offset0.clone()),
                ((((mem1_base_limb_0_col12.clone()
                    + (mem1_base_limb_1_col13.clone() * M31_512.clone()))
                    + (mem1_base_limb_2_col14.clone() * M31_262144.clone()))
                    + (mem1_base_limb_3_col15.clone() * M31_134217728.clone()))
                    + decode_instruction_cb32b_output_tmp_b1151_8_offset2.clone()),
            ],
            dst_id_col17.clone(),
            &self.memory_address_to_id_lookup_elements,
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
                (input_pc_col0.clone() + M31_1.clone()),
                (input_ap_col1.clone() + ap_update_add_1_col8.clone()),
                input_fp_col2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
