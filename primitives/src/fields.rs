use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use num_traits::{One, Zero};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::{m31::BaseField, qm31::SecureField, FieldExpOps};
use stwo_constraint_framework::RelationEFTraitBound;

use crate::QM31Var;

pub trait EvalAtRowFieldVar {
    type F: FieldExpOps
        + Clone
        + Debug
        + Zero
        + Neg<Output = Self::F>
        + AddAssign
        + AddAssign<BaseField>
        + Add<Self::F, Output = Self::F>
        + Sub<Self::F, Output = Self::F>
        + Mul<BaseField, Output = Self::F>
        + Add<SecureField, Output = Self::EF>
        + Mul<SecureField, Output = Self::EF>
        + Neg<Output = Self::F>
        + From<BaseField>;

    type EF: One
        + Clone
        + Debug
        + Zero
        + Neg<Output = Self::EF>
        + AddAssign
        + Add<BaseField, Output = Self::EF>
        + Mul<BaseField, Output = Self::EF>
        + Add<SecureField, Output = Self::EF>
        + Sub<SecureField, Output = Self::EF>
        + Mul<SecureField, Output = Self::EF>
        + Add<Self::F, Output = Self::EF>
        + Mul<Self::F, Output = Self::EF>
        + Sub<Self::EF, Output = Self::EF>
        + Mul<Self::EF, Output = Self::EF>
        + From<SecureField>
        + From<Self::F>
        + RelationEFTraitBound<Self::F>;
}

#[derive(Debug, Clone)]
pub enum WrappedQM31Var {
    Constant(QM31),
    Allocated(QM31Var),
}

impl FieldExpOps for WrappedQM31Var {
    fn inverse(&self) -> Self {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value.inverse()),
            WrappedQM31Var::Allocated(variable) => WrappedQM31Var::Allocated(variable.inv()),
        }
    }
}

impl One for WrappedQM31Var {
    fn one() -> Self {
        WrappedQM31Var::Constant(QM31::one())
    }
}

impl Zero for WrappedQM31Var {
    fn zero() -> Self {
        WrappedQM31Var::Constant(QM31::zero())
    }

    fn is_zero(&self) -> bool {
        unimplemented!()
    }
}

impl Neg for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn neg(self) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value.neg()),
            WrappedQM31Var::Allocated(variable) => WrappedQM31Var::Allocated(variable.neg()),
        }
    }
}

impl AddAssign for WrappedQM31Var {
    fn add_assign(&mut self, rhs: WrappedQM31Var) {
        let res = match (&self, &rhs) {
            (WrappedQM31Var::Constant(value), WrappedQM31Var::Constant(rhs)) => {
                WrappedQM31Var::Constant(*value + *rhs)
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Constant(rhs))
            | (WrappedQM31Var::Constant(rhs), WrappedQM31Var::Allocated(variable)) => {
                WrappedQM31Var::Allocated(variable + &QM31Var::new_constant(&variable.cs(), rhs))
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Allocated(rhs)) => {
                WrappedQM31Var::Allocated(variable + rhs)
            }
        };
        *self = res;
    }
}

impl Add for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn add(self, rhs: WrappedQM31Var) -> Self::Output {
        let mut lhs = self.clone();
        lhs += rhs;
        lhs
    }
}

impl Add<BaseField> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn add(self, rhs: BaseField) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value + rhs),
            WrappedQM31Var::Allocated(variable) => WrappedQM31Var::Allocated(
                &variable + &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
            ),
        }
    }
}

impl Mul<BaseField> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn mul(self, rhs: BaseField) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value * rhs),
            WrappedQM31Var::Allocated(variable) => WrappedQM31Var::Allocated(
                &variable * &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
            ),
        }
    }
}

impl Add<SecureField> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn add(self, rhs: SecureField) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value + rhs),
            WrappedQM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(&variable + &QM31Var::new_constant(&variable.cs(), &rhs))
            }
        }
    }
}

impl Sub<SecureField> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn sub(self, rhs: SecureField) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value - rhs),
            WrappedQM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(&variable - &QM31Var::new_constant(&variable.cs(), &rhs))
            }
        }
    }
}

impl Mul<SecureField> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn mul(self, rhs: SecureField) -> Self::Output {
        match self {
            WrappedQM31Var::Constant(value) => WrappedQM31Var::Constant(value * rhs),
            WrappedQM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(&variable * &QM31Var::new_constant(&variable.cs(), &rhs))
            }
        }
    }
}

impl Sub<WrappedQM31Var> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn sub(self, rhs: WrappedQM31Var) -> Self::Output {
        match (self, rhs) {
            (WrappedQM31Var::Constant(value), WrappedQM31Var::Constant(rhs)) => {
                WrappedQM31Var::Constant(value - rhs)
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Constant(rhs)) => {
                WrappedQM31Var::Allocated(
                    &variable - &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
                )
            }
            (WrappedQM31Var::Constant(rhs), WrappedQM31Var::Allocated(variable)) => {
                WrappedQM31Var::Allocated(&QM31Var::new_constant(&variable.cs(), &rhs) - &variable)
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Allocated(rhs)) => {
                WrappedQM31Var::Allocated(&variable - &rhs)
            }
        }
    }
}

impl Mul<WrappedQM31Var> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn mul(self, rhs: WrappedQM31Var) -> Self::Output {
        match (self, rhs) {
            (WrappedQM31Var::Constant(value), WrappedQM31Var::Constant(rhs)) => {
                WrappedQM31Var::Constant(value * rhs)
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Constant(rhs))
            | (WrappedQM31Var::Constant(rhs), WrappedQM31Var::Allocated(variable)) => {
                WrappedQM31Var::Allocated(
                    &variable * &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
                )
            }
            (WrappedQM31Var::Allocated(variable), WrappedQM31Var::Allocated(rhs)) => {
                WrappedQM31Var::Allocated(&variable * &rhs)
            }
        }
    }
}

impl MulAssign for WrappedQM31Var {
    fn mul_assign(&mut self, rhs: WrappedQM31Var) {
        *self = self.clone() * rhs;
    }
}

impl From<SecureField> for WrappedQM31Var {
    fn from(value: SecureField) -> Self {
        WrappedQM31Var::Constant(value)
    }
}

impl WrappedQM31Var {
    pub fn unwrap(&self, cs: &ConstraintSystemRef) -> QM31Var {
        match self {
            WrappedQM31Var::Constant(value) => QM31Var::new_constant(cs, &value),
            WrappedQM31Var::Allocated(variable) => variable.clone(),
        }
    }

    pub fn unwrap_constant(&self) -> QM31 {
        match self {
            WrappedQM31Var::Constant(value) => value.clone(),
            WrappedQM31Var::Allocated(_) => panic!("Cannot unwrap allocated QM31 variable"),
        }
    }

    pub fn wrap(variable: QM31Var) -> Self {
        WrappedQM31Var::Allocated(variable)
    }
}

impl AddAssign<M31> for WrappedQM31Var {
    fn add_assign(&mut self, rhs: M31) {
        *self = self.clone() + WrappedQM31Var::from(rhs);
    }
}

impl From<M31> for WrappedQM31Var {
    fn from(value: M31) -> Self {
        WrappedQM31Var::Constant(QM31::from(value))
    }
}

pub struct EvalAtRowField {}

impl EvalAtRowFieldVar for EvalAtRowField {
    type F = WrappedQM31Var;
    type EF = WrappedQM31Var;
}
