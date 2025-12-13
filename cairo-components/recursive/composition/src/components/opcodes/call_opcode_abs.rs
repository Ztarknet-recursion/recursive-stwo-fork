// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::decode_instruction_f1edd::DecodeInstructionF1Edd;
use crate::components::subroutines::read_positive_num_bits_29::ReadPositiveNumBits29;

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
        let M31_2 = E::F::from(M31::from(2));
        let M31_262144 = E::F::from(M31::from(262144));
        let M31_512 = E::F::from(M31::from(512));
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let offset2_col3 = eval.next_trace_mask();
        let op1_base_fp_col4 = eval.next_trace_mask();
        let stored_fp_id_col5 = eval.next_trace_mask();
        let stored_fp_limb_0_col6 = eval.next_trace_mask();
        let stored_fp_limb_1_col7 = eval.next_trace_mask();
        let stored_fp_limb_2_col8 = eval.next_trace_mask();
        let stored_fp_limb_3_col9 = eval.next_trace_mask();
        let partial_limb_msb_col10 = eval.next_trace_mask();
        let stored_ret_pc_id_col11 = eval.next_trace_mask();
        let stored_ret_pc_limb_0_col12 = eval.next_trace_mask();
        let stored_ret_pc_limb_1_col13 = eval.next_trace_mask();
        let stored_ret_pc_limb_2_col14 = eval.next_trace_mask();
        let stored_ret_pc_limb_3_col15 = eval.next_trace_mask();
        let partial_limb_msb_col16 = eval.next_trace_mask();
        let mem1_base_col17 = eval.next_trace_mask();
        let next_pc_id_col18 = eval.next_trace_mask();
        let next_pc_limb_0_col19 = eval.next_trace_mask();
        let next_pc_limb_1_col20 = eval.next_trace_mask();
        let next_pc_limb_2_col21 = eval.next_trace_mask();
        let next_pc_limb_3_col22 = eval.next_trace_mask();
        let partial_limb_msb_col23 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [decode_instruction_f1edd_output_tmp_32b66_4_offset2, decode_instruction_f1edd_output_tmp_32b66_4_op1_base_ap] =
            DecodeInstructionF1Edd::evaluate(
                [input_pc_col0.clone()],
                offset2_col3.clone(),
                op1_base_fp_col4.clone(),
                &self.verify_instruction_lookup_elements,
                &mut eval,
            );
        ReadPositiveNumBits29::evaluate(
            [input_ap_col1.clone()],
            stored_fp_id_col5.clone(),
            stored_fp_limb_0_col6.clone(),
            stored_fp_limb_1_col7.clone(),
            stored_fp_limb_2_col8.clone(),
            stored_fp_limb_3_col9.clone(),
            partial_limb_msb_col10.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        //[ap] = fp.
        eval.add_constraint(
            ((((stored_fp_limb_0_col6.clone()
                + (stored_fp_limb_1_col7.clone() * M31_512.clone()))
                + (stored_fp_limb_2_col8.clone() * M31_262144.clone()))
                + (stored_fp_limb_3_col9.clone() * M31_134217728.clone()))
                - input_fp_col2.clone()),
        );
        ReadPositiveNumBits29::evaluate(
            [(input_ap_col1.clone() + M31_1.clone())],
            stored_ret_pc_id_col11.clone(),
            stored_ret_pc_limb_0_col12.clone(),
            stored_ret_pc_limb_1_col13.clone(),
            stored_ret_pc_limb_2_col14.clone(),
            stored_ret_pc_limb_3_col15.clone(),
            partial_limb_msb_col16.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        //[ap+1] = return_pc.
        eval.add_constraint(
            ((((stored_ret_pc_limb_0_col12.clone()
                + (stored_ret_pc_limb_1_col13.clone() * M31_512.clone()))
                + (stored_ret_pc_limb_2_col14.clone() * M31_262144.clone()))
                + (stored_ret_pc_limb_3_col15.clone() * M31_134217728.clone()))
                - (input_pc_col0.clone() + M31_1.clone())),
        );
        // mem1_base.
        eval.add_constraint(
            (mem1_base_col17.clone()
                - ((op1_base_fp_col4.clone() * input_fp_col2.clone())
                    + (decode_instruction_f1edd_output_tmp_32b66_4_op1_base_ap.clone()
                        * input_ap_col1.clone()))),
        );
        ReadPositiveNumBits29::evaluate(
            [(mem1_base_col17.clone()
                + decode_instruction_f1edd_output_tmp_32b66_4_offset2.clone())],
            next_pc_id_col18.clone(),
            next_pc_limb_0_col19.clone(),
            next_pc_limb_1_col20.clone(),
            next_pc_limb_2_col21.clone(),
            next_pc_limb_3_col22.clone(),
            partial_limb_msb_col23.clone(),
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
                (((next_pc_limb_0_col19.clone()
                    + (next_pc_limb_1_col20.clone() * M31_512.clone()))
                    + (next_pc_limb_2_col21.clone() * M31_262144.clone()))
                    + (next_pc_limb_3_col22.clone() * M31_134217728.clone())),
                (input_ap_col1.clone() + M31_2.clone()),
                (input_ap_col1.clone() + M31_2.clone()),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
