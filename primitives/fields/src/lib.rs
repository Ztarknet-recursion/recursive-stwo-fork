pub mod m31;

use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
pub use m31::*;

pub mod cm31;
pub use cm31::*;

pub mod qm31;
pub use qm31::*;

use num_traits::{One, Zero};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::{m31::BaseField, qm31::SecureField, FieldExpOps};

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
        + From<Self::F>;
}

#[derive(Debug, Clone)]
pub enum WrappedM31Var {
    Constant(M31),
    Allocated(M31Var),
}

impl FieldExpOps for WrappedM31Var {
    fn inverse(&self) -> Self {
        match self {
            WrappedM31Var::Constant(value) => WrappedM31Var::Constant(value.inverse()),
            WrappedM31Var::Allocated(variable) => WrappedM31Var::Allocated(variable.inv()),
        }
    }
}

impl Zero for WrappedM31Var {
    fn zero() -> Self {
        WrappedM31Var::Constant(M31::zero())
    }

    fn is_zero(&self) -> bool {
        unimplemented!()
    }
}

impl One for WrappedM31Var {
    fn one() -> Self {
        WrappedM31Var::Constant(M31::one())
    }
}

impl Neg for WrappedM31Var {
    type Output = WrappedM31Var;

    fn neg(self) -> Self::Output {
        match self {
            WrappedM31Var::Constant(value) => WrappedM31Var::Constant(value.neg()),
            WrappedM31Var::Allocated(variable) => WrappedM31Var::Allocated(variable.neg()),
        }
    }
}

impl AddAssign for WrappedM31Var {
    fn add_assign(&mut self, rhs: Self) {
        let res = match (&self, rhs) {
            (WrappedM31Var::Constant(value), WrappedM31Var::Constant(rhs)) => {
                WrappedM31Var::Constant(value.clone() + rhs)
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Constant(rhs)) => {
                WrappedM31Var::Allocated(&*variable + &M31Var::new_constant(&variable.cs(), &rhs))
            }
            (WrappedM31Var::Constant(rhs), WrappedM31Var::Allocated(variable)) => {
                WrappedM31Var::Allocated(&variable + &M31Var::new_constant(&variable.cs(), &rhs))
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Allocated(rhs)) => {
                WrappedM31Var::Allocated(&*variable + &rhs)
            }
        };
        *self = res;
    }
}

impl AddAssign<BaseField> for WrappedM31Var {
    fn add_assign(&mut self, rhs: BaseField) {
        match self {
            WrappedM31Var::Constant(value) => {
                *self = WrappedM31Var::Constant(*value + rhs);
            }
            WrappedM31Var::Allocated(variable) => {
                *self = WrappedM31Var::Allocated(
                    &*variable + &M31Var::new_constant(&variable.cs(), &rhs),
                );
            }
        }
    }
}

impl Add<WrappedM31Var> for WrappedM31Var {
    type Output = WrappedM31Var;

    fn add(self, rhs: WrappedM31Var) -> Self::Output {
        let mut lhs = self.clone();
        lhs += rhs;
        lhs
    }
}

impl Sub<WrappedM31Var> for WrappedM31Var {
    type Output = WrappedM31Var;

    fn sub(self, rhs: WrappedM31Var) -> Self::Output {
        match (self, rhs) {
            (WrappedM31Var::Constant(value), WrappedM31Var::Constant(rhs)) => {
                WrappedM31Var::Constant(value - rhs)
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Constant(rhs)) => {
                WrappedM31Var::Allocated(&variable - &M31Var::new_constant(&variable.cs(), &rhs))
            }
            (WrappedM31Var::Constant(rhs), WrappedM31Var::Allocated(variable)) => {
                WrappedM31Var::Allocated(&M31Var::new_constant(&variable.cs(), &rhs) - &variable)
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Allocated(rhs)) => {
                WrappedM31Var::Allocated(&variable - &rhs)
            }
        }
    }
}

impl MulAssign for WrappedM31Var {
    fn mul_assign(&mut self, rhs: WrappedM31Var) {
        let res = match (&self, &rhs) {
            (WrappedM31Var::Constant(value), WrappedM31Var::Constant(rhs)) => {
                WrappedM31Var::Constant(*value * *rhs)
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Constant(rhs))
            | (WrappedM31Var::Constant(rhs), WrappedM31Var::Allocated(variable)) => {
                WrappedM31Var::Allocated(variable * &M31Var::new_constant(&variable.cs(), rhs))
            }
            (WrappedM31Var::Allocated(variable), WrappedM31Var::Allocated(rhs)) => {
                WrappedM31Var::Allocated(variable * rhs)
            }
        };
        *self = res;
    }
}

impl Mul for WrappedM31Var {
    type Output = WrappedM31Var;

    fn mul(self, rhs: WrappedM31Var) -> Self::Output {
        let mut lhs = self.clone();
        lhs *= rhs;
        lhs
    }
}

impl Mul<BaseField> for WrappedM31Var {
    type Output = WrappedM31Var;

    fn mul(self, rhs: BaseField) -> Self::Output {
        match self {
            WrappedM31Var::Constant(value) => WrappedM31Var::Constant(value * rhs),
            WrappedM31Var::Allocated(variable) => {
                WrappedM31Var::Allocated(variable.mul_constant(rhs))
            }
        }
    }
}

impl From<BaseField> for WrappedM31Var {
    fn from(value: BaseField) -> Self {
        WrappedM31Var::Constant(value)
    }
}

impl Add<SecureField> for WrappedM31Var {
    type Output = WrappedQM31Var;

    fn add(self, rhs: SecureField) -> Self::Output {
        match self {
            WrappedM31Var::Constant(value) => WrappedQM31Var::Constant(rhs + value),
            WrappedM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(&QM31Var::new_constant(&variable.cs, &rhs) + &variable)
            }
        }
    }
}

impl Mul<SecureField> for WrappedM31Var {
    type Output = WrappedQM31Var;

    fn mul(self, rhs: SecureField) -> Self::Output {
        match self {
            WrappedM31Var::Constant(value) => WrappedQM31Var::Constant(value * rhs),
            WrappedM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(&QM31Var::new_constant(&variable.cs, &rhs) * &variable)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum WrappedQM31Var {
    Constant(QM31),
    Allocated(QM31Var),
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

impl Add<WrappedM31Var> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn add(self, rhs: WrappedM31Var) -> Self::Output {
        match (self, rhs) {
            (WrappedQM31Var::Constant(value), WrappedM31Var::Constant(rhs)) => {
                WrappedQM31Var::Constant(value + rhs)
            }
            (WrappedQM31Var::Allocated(variable), WrappedM31Var::Constant(rhs)) => {
                WrappedQM31Var::Allocated(
                    &variable + &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
                )
            }
            (WrappedQM31Var::Constant(rhs), WrappedM31Var::Allocated(variable)) => {
                WrappedQM31Var::Allocated(&variable + &QM31Var::new_constant(&variable.cs(), &rhs))
            }
            (WrappedQM31Var::Allocated(variable), WrappedM31Var::Allocated(rhs)) => {
                WrappedQM31Var::Allocated(&variable + &rhs)
            }
        }
    }
}

impl Mul<WrappedM31Var> for WrappedQM31Var {
    type Output = WrappedQM31Var;

    fn mul(self, rhs: WrappedM31Var) -> Self::Output {
        match (self, rhs) {
            (WrappedQM31Var::Constant(value), WrappedM31Var::Constant(rhs)) => {
                WrappedQM31Var::Constant(value * rhs)
            }
            (WrappedQM31Var::Allocated(variable), WrappedM31Var::Constant(rhs)) => {
                WrappedQM31Var::Allocated(
                    &variable * &QM31Var::new_constant(&variable.cs(), &QM31::from(rhs)),
                )
            }
            (WrappedQM31Var::Constant(rhs), WrappedM31Var::Allocated(variable)) => {
                WrappedQM31Var::Allocated(&QM31Var::new_constant(&variable.cs(), &rhs) * &variable)
            }
            (WrappedQM31Var::Allocated(variable), WrappedM31Var::Allocated(rhs)) => {
                WrappedQM31Var::Allocated(&variable * &rhs)
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

impl From<SecureField> for WrappedQM31Var {
    fn from(value: SecureField) -> Self {
        WrappedQM31Var::Constant(value)
    }
}

impl From<WrappedM31Var> for WrappedQM31Var {
    fn from(value: WrappedM31Var) -> Self {
        match value {
            WrappedM31Var::Constant(value) => WrappedQM31Var::Constant(QM31::from(value)),
            WrappedM31Var::Allocated(variable) => {
                WrappedQM31Var::Allocated(QM31Var::from(&variable))
            }
        }
    }
}

pub struct EvalAtRowField {}

impl EvalAtRowFieldVar for EvalAtRowField {
    type F = WrappedM31Var;
    type EF = WrappedQM31Var;
}
