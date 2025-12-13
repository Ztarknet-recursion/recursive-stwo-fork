use crate::components::prelude::*;

#[derive(Copy, Clone, Serialize, Deserialize, CairoSerialize)]
pub struct RangeCheckAp {}

impl RangeCheckAp {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    #[allow(clippy::unused_unit)]
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(
        [range_check_ap_input]: [E::F; 1],
        range_check_ap_bot11bits_col0: E::F,
        range_check_18_lookup_elements: &RangeCheck18Var,
        range_check_11_lookup_elements: &RangeCheck11Var,
        eval: &mut E,
    ) -> [E::F; 0] {
        let M31_1048576 = E::F::from(M31::from(1048576));

        eval.add_to_relation(RelationEntry::new(
            range_check_18_lookup_elements,
            E::EF::one(),
            std::slice::from_ref(
                &((range_check_ap_input.clone() - range_check_ap_bot11bits_col0.clone())
                    * M31_1048576.clone()),
            ),
        ));

        eval.add_to_relation(RelationEntry::new(
            range_check_11_lookup_elements,
            E::EF::one(),
            std::slice::from_ref(&range_check_ap_bot11bits_col0),
        ));

        []
    }
}
