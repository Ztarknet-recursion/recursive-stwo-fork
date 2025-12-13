// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::bitwise_xor_num_bits_8::BitwiseXorNumBits8;
use crate::components::subroutines::bitwise_xor_num_bits_8_b::BitwiseXorNumBits8B;
use crate::components::subroutines::split_16_low_part_size_8::Split16LowPartSize8;

pub struct Component {
    pub verify_bitwise_xor_8_lookup_elements: VerifyBitwiseXor8Var,
    pub verify_bitwise_xor_8_b_lookup_elements: VerifyBitwiseXor8BVar,
    pub triple_xor_32_lookup_elements: TripleXor32Var,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let M31_256 = E::F::from(M31::from(256));
        let input_limb_0_col0 = eval.next_trace_mask();
        let input_limb_1_col1 = eval.next_trace_mask();
        let input_limb_2_col2 = eval.next_trace_mask();
        let input_limb_3_col3 = eval.next_trace_mask();
        let input_limb_4_col4 = eval.next_trace_mask();
        let input_limb_5_col5 = eval.next_trace_mask();
        let ms_8_bits_col6 = eval.next_trace_mask();
        let ms_8_bits_col7 = eval.next_trace_mask();
        let ms_8_bits_col8 = eval.next_trace_mask();
        let ms_8_bits_col9 = eval.next_trace_mask();
        let ms_8_bits_col10 = eval.next_trace_mask();
        let ms_8_bits_col11 = eval.next_trace_mask();
        let xor_col12 = eval.next_trace_mask();
        let xor_col13 = eval.next_trace_mask();
        let xor_col14 = eval.next_trace_mask();
        let xor_col15 = eval.next_trace_mask();
        let xor_col16 = eval.next_trace_mask();
        let xor_col17 = eval.next_trace_mask();
        let xor_col18 = eval.next_trace_mask();
        let xor_col19 = eval.next_trace_mask();
        let enabler = eval.next_trace_mask();

        eval.add_constraint(enabler.clone() * enabler.clone() - enabler.clone());

        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_1_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_0_col0.clone()],
            ms_8_bits_col6.clone(),
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_3_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_1_col1.clone()],
            ms_8_bits_col7.clone(),
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_5_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_2_col2.clone()],
            ms_8_bits_col8.clone(),
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_7_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_3_col3.clone()],
            ms_8_bits_col9.clone(),
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_9_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_4_col4.clone()],
            ms_8_bits_col10.clone(),
            &mut eval,
        );
        #[allow(clippy::unused_unit)]
        #[allow(unused_variables)]
        let [split_16_low_part_size_8_output_tmp_298db_11_limb_0] = Split16LowPartSize8::evaluate(
            [input_limb_5_col5.clone()],
            ms_8_bits_col11.clone(),
            &mut eval,
        );
        BitwiseXorNumBits8::evaluate(
            [
                split_16_low_part_size_8_output_tmp_298db_1_limb_0.clone(),
                split_16_low_part_size_8_output_tmp_298db_5_limb_0.clone(),
            ],
            xor_col12.clone(),
            &self.verify_bitwise_xor_8_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8::evaluate(
            [
                xor_col12.clone(),
                split_16_low_part_size_8_output_tmp_298db_9_limb_0.clone(),
            ],
            xor_col13.clone(),
            &self.verify_bitwise_xor_8_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8::evaluate(
            [ms_8_bits_col6.clone(), ms_8_bits_col8.clone()],
            xor_col14.clone(),
            &self.verify_bitwise_xor_8_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8::evaluate(
            [xor_col14.clone(), ms_8_bits_col10.clone()],
            xor_col15.clone(),
            &self.verify_bitwise_xor_8_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8B::evaluate(
            [
                split_16_low_part_size_8_output_tmp_298db_3_limb_0.clone(),
                split_16_low_part_size_8_output_tmp_298db_7_limb_0.clone(),
            ],
            xor_col16.clone(),
            &self.verify_bitwise_xor_8_b_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8B::evaluate(
            [
                xor_col16.clone(),
                split_16_low_part_size_8_output_tmp_298db_11_limb_0.clone(),
            ],
            xor_col17.clone(),
            &self.verify_bitwise_xor_8_b_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8B::evaluate(
            [ms_8_bits_col7.clone(), ms_8_bits_col9.clone()],
            xor_col18.clone(),
            &self.verify_bitwise_xor_8_b_lookup_elements,
            &mut eval,
        );
        BitwiseXorNumBits8B::evaluate(
            [xor_col18.clone(), ms_8_bits_col11.clone()],
            xor_col19.clone(),
            &self.verify_bitwise_xor_8_b_lookup_elements,
            &mut eval,
        );
        let triple_xor32_output_tmp_298db_28_limb_0 =
            eval.add_intermediate((xor_col13.clone() + (xor_col15.clone() * M31_256.clone())));
        let triple_xor32_output_tmp_298db_28_limb_1 =
            eval.add_intermediate((xor_col17.clone() + (xor_col19.clone() * M31_256.clone())));
        eval.add_to_relation(RelationEntry::new(
            &self.triple_xor_32_lookup_elements,
            -E::EF::from(enabler.clone()),
            &[
                input_limb_0_col0.clone(),
                input_limb_1_col1.clone(),
                input_limb_2_col2.clone(),
                input_limb_3_col3.clone(),
                input_limb_4_col4.clone(),
                input_limb_5_col5.clone(),
                triple_xor32_output_tmp_298db_28_limb_0.clone(),
                triple_xor32_output_tmp_298db_28_limb_1.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
