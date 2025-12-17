use crate::ConstraintSystemRef;

pub trait Var: Sized {
    /// The type of the "native" value that `Self` represents in the constraint
    /// system.
    type Value;

    /// Returns the underlying `ConstraintSystemRef`.
    fn cs(&self) -> ConstraintSystemRef;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocationMode {
    PublicInput,
    Witness,
    Constant,
}

pub trait AllocVar: Var {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self;

    fn new_constant(cs: &ConstraintSystemRef, value: &Self::Value) -> Self {
        Self::new_variables(cs, value, AllocationMode::Constant)
    }

    fn new_public_input(cs: &ConstraintSystemRef, value: &Self::Value) -> Self {
        Self::new_variables(cs, value, AllocationMode::PublicInput)
    }

    fn new_witness(cs: &ConstraintSystemRef, value: &Self::Value) -> Self {
        Self::new_variables(cs, value, AllocationMode::Witness)
    }
}

impl<T: Var> Var for (T, T) {
    type Value = (T::Value, T::Value);

    fn cs(&self) -> ConstraintSystemRef {
        self.0.cs().and(&self.1.cs())
    }
}

impl<T: AllocVar> AllocVar for (T, T) {
    fn new_variables(
        cs: &ConstraintSystemRef,
        value: &<Self as Var>::Value,
        mode: AllocationMode,
    ) -> Self {
        let left = T::new_variables(cs, &value.0, mode);
        let right = T::new_variables(cs, &value.1, mode);
        (left, right)
    }
}
