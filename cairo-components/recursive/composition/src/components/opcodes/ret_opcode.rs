// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::decode_instruction_15a61::DecodeInstruction15A61;
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
        let next_pc_id_col3 = eval.next_trace_mask();
        let next_pc_limb_0_col4 = eval.next_trace_mask();
        let next_pc_limb_1_col5 = eval.next_trace_mask();
        let next_pc_limb_2_col6 = eval.next_trace_mask();
        let next_pc_limb_3_col7 = eval.next_trace_mask();
        let partial_limb_msb_col8 = eval.next_trace_mask();
        let next_fp_id_col9 = eval.next_trace_mask();
        let next_fp_limb_0_col10 = eval.next_trace_mask();
        let next_fp_limb_1_col11 = eval.next_trace_mask();
        let next_fp_limb_2_col12 = eval.next_trace_mask();
        let next_fp_limb_3_col13 = eval.next_trace_mask();
        let partial_limb_msb_col14 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        DecodeInstruction15A61::evaluate(
            [input_pc_col0.clone()],
            &self.verify_instruction_lookup_elements,
            &mut eval,
        );
        ReadPositiveNumBits29::evaluate(
            [(input_fp_col2.clone() - M31_1.clone())],
            next_pc_id_col3.clone(),
            next_pc_limb_0_col4.clone(),
            next_pc_limb_1_col5.clone(),
            next_pc_limb_2_col6.clone(),
            next_pc_limb_3_col7.clone(),
            partial_limb_msb_col8.clone(),
            &self.memory_address_to_id_lookup_elements,
            &self.memory_id_to_big_lookup_elements,
            &mut eval,
        );
        ReadPositiveNumBits29::evaluate(
            [(input_fp_col2.clone() - M31_2.clone())],
            next_fp_id_col9.clone(),
            next_fp_limb_0_col10.clone(),
            next_fp_limb_1_col11.clone(),
            next_fp_limb_2_col12.clone(),
            next_fp_limb_3_col13.clone(),
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
                (((next_pc_limb_0_col4.clone() + (next_pc_limb_1_col5.clone() * M31_512.clone()))
                    + (next_pc_limb_2_col6.clone() * M31_262144.clone()))
                    + (next_pc_limb_3_col7.clone() * M31_134217728.clone())),
                input_ap_col1.clone(),
                (((next_fp_limb_0_col10.clone()
                    + (next_fp_limb_1_col11.clone() * M31_512.clone()))
                    + (next_fp_limb_2_col12.clone() * M31_262144.clone()))
                    + (next_fp_limb_3_col13.clone() * M31_134217728.clone())),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
