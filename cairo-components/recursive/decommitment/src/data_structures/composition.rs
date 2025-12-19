use cairo_plonk_dsl_hints::CompositionQueryResult;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::QM31Var;

pub struct CompositionQueryResultVar(pub [QM31Var; 2]);

impl Var for CompositionQueryResultVar {
    type Value = CompositionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.0[0].cs()
    }
}

impl AllocVar for CompositionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self(std::array::from_fn(|i| {
            QM31Var::new_variables(cs, &value.0[i], mode)
        }))
    }
}
