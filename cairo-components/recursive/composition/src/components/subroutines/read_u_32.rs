// This file was created by the AIR team.

use crate::components::prelude::*;
use crate::components::subroutines::verify_u_32::VerifyU32;

#[derive(Copy, Clone, Serialize, Deserialize, CairoSerialize)]
pub struct ReadU32 {}

impl ReadU32 {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    #[allow(clippy::unused_unit)]
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(
        [read_u_32_input]: [E::F; 1],
        low_16_bits_col0: E::F,
        high_16_bits_col1: E::F,
        low_7_ms_bits_col2: E::F,
        high_14_ms_bits_col3: E::F,
        high_5_ms_bits_col4: E::F,
        id_col5: E::F,
        range_check_7_2_5_lookup_elements: &RangeCheck725Var,
        memory_address_to_id_lookup_elements: &MemoryAddressToIdVar,
        memory_id_to_big_lookup_elements: &MemoryIdToBigVar,
        eval: &mut E,
    ) -> [E::F; 0] {
        VerifyU32::evaluate(
            [
                read_u_32_input.clone(),
                low_16_bits_col0.clone(),
                high_16_bits_col1.clone(),
            ],
            low_7_ms_bits_col2.clone(),
            high_14_ms_bits_col3.clone(),
            high_5_ms_bits_col4.clone(),
            id_col5.clone(),
            range_check_7_2_5_lookup_elements,
            memory_address_to_id_lookup_elements,
            memory_id_to_big_lookup_elements,
            eval,
        );
        []
    }
}
