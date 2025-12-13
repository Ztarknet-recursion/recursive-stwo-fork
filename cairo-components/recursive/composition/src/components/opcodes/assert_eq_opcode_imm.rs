use crate::components::{
    prelude::*,
    subroutines::{
        decode_instruction_161c9::DecodeInstruction161C9, mem_verify_equal::MemVerifyEqual,
    },
};

pub struct Component {
    pub verify_instruction_lookup_elements: VerifyInstructionVar,
    pub memory_address_to_id_lookup_elements: MemoryAddressToIdVar,
    pub opcodes_lookup_elements: OpcodesVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let M31_1 = E::F::from(M31::from(1));
        let M31_2 = E::F::from(M31::from(2));
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let offset0_col3 = eval.next_trace_mask();
        let dst_base_fp_col4 = eval.next_trace_mask();
        let ap_update_add_1_col5 = eval.next_trace_mask();
        let mem_dst_base_col6 = eval.next_trace_mask();
        let dst_id_col7 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [decode_instruction_161c9_output_tmp_bb09e_5_offset0] =
            DecodeInstruction161C9::evaluate(
                [input_pc_col0.clone()],
                offset0_col3.clone(),
                dst_base_fp_col4.clone(),
                ap_update_add_1_col5.clone(),
                &self.verify_instruction_lookup_elements,
                &mut eval,
            );
        // mem_dst_base.
        eval.add_constraint(
            (mem_dst_base_col6.clone()
                - ((dst_base_fp_col4.clone() * input_fp_col2.clone())
                    + ((M31_1.clone() - dst_base_fp_col4.clone()) * input_ap_col1.clone()))),
        );
        MemVerifyEqual::evaluate(
            [
                (mem_dst_base_col6.clone()
                    + decode_instruction_161c9_output_tmp_bb09e_5_offset0.clone()),
                (input_pc_col0.clone() + M31_1.clone()),
            ],
            dst_id_col7.clone(),
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
                (input_pc_col0.clone() + M31_2.clone()),
                (input_ap_col1.clone() + ap_update_add_1_col5.clone()),
                input_fp_col2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
