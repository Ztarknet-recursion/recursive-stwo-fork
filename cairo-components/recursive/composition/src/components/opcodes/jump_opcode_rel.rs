// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::decode_instruction_ba944::DecodeInstructionBa944;
use crate::components::subroutines::read_small::ReadSmall;

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
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let offset2_col3 = eval.next_trace_mask();
        let op1_base_fp_col4 = eval.next_trace_mask();
        let ap_update_add_1_col5 = eval.next_trace_mask();
        let mem1_base_col6 = eval.next_trace_mask();
        let next_pc_id_col7 = eval.next_trace_mask();
        let msb_col8 = eval.next_trace_mask();
        let mid_limbs_set_col9 = eval.next_trace_mask();
        let next_pc_limb_0_col10 = eval.next_trace_mask();
        let next_pc_limb_1_col11 = eval.next_trace_mask();
        let next_pc_limb_2_col12 = eval.next_trace_mask();
        let remainder_bits_col13 = eval.next_trace_mask();
        let partial_limb_msb_col14 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [decode_instruction_ba944_output_tmp_62dfc_5_offset2, decode_instruction_ba944_output_tmp_62dfc_5_op1_base_ap] =
            DecodeInstructionBa944::evaluate(
                [input_pc_col0.clone()],
                offset2_col3.clone(),
                op1_base_fp_col4.clone(),
                ap_update_add_1_col5.clone(),
                &self.verify_instruction_lookup_elements,
                &mut eval,
            );
        // mem1_base.
        eval.add_constraint(
            (mem1_base_col6.clone()
                - ((op1_base_fp_col4.clone() * input_fp_col2.clone())
                    + (decode_instruction_ba944_output_tmp_62dfc_5_op1_base_ap.clone()
                        * input_ap_col1.clone()))),
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [read_small_output_tmp_62dfc_15_limb_0] = ReadSmall::evaluate(
            [(mem1_base_col6.clone()
                + decode_instruction_ba944_output_tmp_62dfc_5_offset2.clone())],
            next_pc_id_col7.clone(),
            msb_col8.clone(),
            mid_limbs_set_col9.clone(),
            next_pc_limb_0_col10.clone(),
            next_pc_limb_1_col11.clone(),
            next_pc_limb_2_col12.clone(),
            remainder_bits_col13.clone(),
            partial_limb_msb_col14.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
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
                (input_pc_col0.clone() + read_small_output_tmp_62dfc_15_limb_0.clone()),
                (input_ap_col1.clone() + ap_update_add_1_col5.clone()),
                input_fp_col2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
