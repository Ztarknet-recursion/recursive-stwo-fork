use circle_plonk_dsl_constraint_system::var::{AllocVar, AllocationMode, Var};
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use num_traits::{One, Zero};
use std::ops::{Add, Mul, Neg, Sub};
use stwo::core::fields::m31::{M31, P};

use crate::BitVar;

#[derive(Debug, Clone)]
pub struct M31Var {
    pub cs: ConstraintSystemRef,
    pub value: M31,
    pub variable: usize,
}

impl Var for M31Var {
    type Value = M31;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for M31Var {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        if mode != AllocationMode::Constant {
            Self {
                cs: cs.clone(),
                value: *value,
                variable: cs.new_m31(*value, mode),
            }
        } else {
            Self::new_constant(cs, value)
        }
    }

    fn new_constant(cs: &ConstraintSystemRef, value: &Self::Value) -> Self {
        if value.is_zero() {
            return Self::zero(&cs);
        }
        if value.is_one() {
            return Self::one(&cs);
        }

        let exist = cs.get_cache(format!("m31 {}", value.0));
        if let Some(variable) = exist {
            Self {
                cs: cs.clone(),
                value: *value,
                variable,
            }
        } else {
            let res = Self {
                cs: cs.clone(),
                value: *value,
                variable: cs.new_m31(*value, AllocationMode::Constant),
            };
            cs.set_cache(format!("m31 {}", value.0), res.variable);
            res
        }
    }
}

impl Add<&M31Var> for &M31Var {
    type Output = M31Var;

    fn add(self, rhs: &M31Var) -> M31Var {
        let cs = self.cs.and(&rhs.cs);
        let value = self.value + rhs.value;
        let variable = cs.add(self.variable, rhs.variable);

        M31Var {
            cs,
            value,
            variable,
        }
    }
}

impl Sub<&M31Var> for &M31Var {
    type Output = M31Var;

    fn sub(self, rhs: &M31Var) -> M31Var {
        self + &(-rhs)
    }
}

impl Neg for &M31Var {
    type Output = M31Var;

    fn neg(self) -> M31Var {
        let value = -self.value;
        let variable = self.cs.mul_constant(self.variable, M31::one().neg());

        M31Var {
            cs: self.cs.clone(),
            value,
            variable,
        }
    }
}

impl Mul<&M31Var> for &M31Var {
    type Output = M31Var;

    fn mul(self, rhs: &M31Var) -> M31Var {
        let cs = self.cs.and(&rhs.cs);
        let value = self.value * rhs.value;
        let variable = cs.mul(self.variable, rhs.variable);

        M31Var {
            cs,
            value,
            variable,
        }
    }
}

impl M31Var {
    pub fn zero(cs: &ConstraintSystemRef) -> M31Var {
        M31Var {
            cs: cs.clone(),
            value: M31::zero(),
            variable: 0,
        }
    }

    pub fn one(cs: &ConstraintSystemRef) -> M31Var {
        M31Var {
            cs: cs.clone(),
            value: M31::one(),
            variable: 1,
        }
    }

    pub fn equalverify(&self, rhs: &M31Var) {
        assert_eq!(self.value, rhs.value);
        let cs = self.cs.and(&rhs.cs);
        cs.insert_gate(self.variable, 0, rhs.variable, M31::one());
    }

    pub fn inv(&self) -> M31Var {
        let cs = self.cs.clone();

        let value = self.value.inverse();
        let res = M31Var::new_witness(&cs, &value);
        cs.insert_gate(self.variable, res.variable, 1, M31::zero());

        res
    }

    pub fn mul_constant(&self, constant: M31) -> M31Var {
        let cs = self.cs();
        let value = self.value * constant;
        let variable = cs.mul_constant(self.variable, constant);

        M31Var {
            cs,
            value,
            variable,
        }
    }

    pub fn is_eq(&self, rhs: &M31Var) -> BitVar {
        (self - rhs).is_zero()
    }

    pub fn is_zero(&self) -> BitVar {
        let cs = self.cs();
        let inv = M31Var::new_witness(&self.cs, &{
            if self.value.is_zero() {
                M31::zero()
            } else {
                self.value.inverse()
            }
        });
        let out = &(self * &inv).neg() + &M31Var::one(&cs);
        cs.insert_gate(self.variable, out.variable, 0, M31::zero());

        BitVar(out)
    }

    pub fn exp2(&self) -> M31Var {
        assert!(self.value.0 <= 30);

        let cs = self.cs();

        let mut sum = M31Var::one(&cs);
        let mut cur = self.clone();

        for _ in 0..30 {
            let is_zero = cur.is_zero();
            let is_not_zero = &M31Var::one(&cs) - &is_zero.0;

            cur = &cur - &is_not_zero;
            sum = &sum + &(&sum * &is_not_zero);
        }

        sum
    }

    pub fn add_assert_no_overflow(&self, rhs: &M31Var) -> M31Var {
        let max = M31Var::new_constant(&self.cs, &M31::from(P - 1));
        let remaining = &max - self;

        let rhs_bits = crate::BitsVar::from_m31(rhs, 31);
        let remaining_bits = crate::BitsVar::from_m31(&remaining, 31);

        rhs_bits
            .is_greater_than(&remaining_bits)
            .equalverify(&crate::BitVar::new_false(&self.cs));

        self + rhs
    }

    pub fn select(a: &Self, b: &Self, bit: &BitVar) -> Self {
        let cs = a.cs().and(&b.cs()).and(&bit.cs());

        let bit_value = bit.0.value.0 != 0;
        let value = if !bit_value { a.value } else { b.value };

        // the result is a + (b - a) * bit_value
        let b_minus_a = b - a;
        let mut variable = cs.mul(b_minus_a.variable, bit.0.variable);
        variable = cs.add(a.variable, variable);

        M31Var {
            cs,
            value,
            variable,
        }
    }

    pub fn max(&self, rhs: &M31Var, log_size: usize) -> M31Var {
        let shift = M31Var::new_constant(&self.cs, &M31::from(1 << log_size));
        let v = &(self + &shift) - rhs;

        let bits = crate::BitsVar::from_m31(&v, log_size + 1);
        let is_lhs_no_less_than_rhs = &bits.0[log_size];

        M31Var::select(rhs, self, &is_lhs_no_less_than_rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp2() {
        let cs = ConstraintSystemRef::new();
        let m31 = M31Var::new_witness(&cs, &M31::from(30));
        let result = m31.exp2();
        result.equalverify(&M31Var::new_constant(&cs, &M31::from(1 << 30)));

        cs.pad();
        cs.check_arithmetics();
    }
}
