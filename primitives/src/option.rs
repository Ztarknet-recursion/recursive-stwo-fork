use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};

use crate::BitVar;

pub struct OptionVar<T: Var + AllocVar> {
    pub is_some: BitVar,
    pub value: T,
}

impl<T: Var + AllocVar> Var for OptionVar<T> {
    type Value = Option<T::Value>;

    fn cs(&self) -> ConstraintSystemRef {
        self.is_some.cs().and(&self.value.cs())
    }
}

impl<T: Var<Value: Default> + AllocVar> AllocVar for OptionVar<T> {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let is_some = BitVar::new_variables(cs, &value.is_some(), mode);
        let value = T::new_variables(cs, value.as_ref().unwrap_or(&T::Value::default()), mode);
        Self { is_some, value }
    }
}
