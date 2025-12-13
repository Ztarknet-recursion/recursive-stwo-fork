// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::decode_instruction_7ebc4::DecodeInstruction7Ebc4;
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
        let M31_1 = E::F::from(M31::from(1));
        let input_pc_col0 = eval.next_trace_mask();
        let input_ap_col1 = eval.next_trace_mask();
        let input_fp_col2 = eval.next_trace_mask();
        let ap_update_add_1_col3 = eval.next_trace_mask();
        let next_pc_id_col4 = eval.next_trace_mask();
        let msb_col5 = eval.next_trace_mask();
        let mid_limbs_set_col6 = eval.next_trace_mask();
        let next_pc_limb_0_col7 = eval.next_trace_mask();
        let next_pc_limb_1_col8 = eval.next_trace_mask();
        let next_pc_limb_2_col9 = eval.next_trace_mask();
        let remainder_bits_col10 = eval.next_trace_mask();
        let partial_limb_msb_col11 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        DecodeInstruction7Ebc4::evaluate(
            [input_pc_col0.clone()],
            ap_update_add_1_col3.clone(),
            &self.verify_instruction_lookup_elements,
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [read_small_output_tmp_81a39_13_limb_0] = ReadSmall::evaluate(
            [(input_pc_col0.clone() + M31_1.clone())],
            next_pc_id_col4.clone(),
            msb_col5.clone(),
            mid_limbs_set_col6.clone(),
            next_pc_limb_0_col7.clone(),
            next_pc_limb_1_col8.clone(),
            next_pc_limb_2_col9.clone(),
            remainder_bits_col10.clone(),
            partial_limb_msb_col11.clone(),
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
                (input_pc_col0.clone() + read_small_output_tmp_81a39_13_limb_0.clone()),
                (input_ap_col1.clone() + ap_update_add_1_col3.clone()),
                input_fp_col2.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
