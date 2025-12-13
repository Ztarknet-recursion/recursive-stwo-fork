use crate::M31Var;
use circle_plonk_dsl_constraint_system::var::{AllocVar, AllocationMode, Var};
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use num_traits::{One, Zero};
use std::ops::{BitAnd, BitOr, Neg, Range, RangeFrom};
use stwo::core::fields::m31::M31;

#[derive(Clone, Debug)]
pub struct BitVar(pub M31Var);

impl Var for BitVar {
    type Value = bool;

    fn cs(&self) -> ConstraintSystemRef {
        self.0.cs()
    }
}

impl AllocVar for BitVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let bit = M31Var::new_variables(cs, &M31::from(if *value { 1 } else { 0 }), mode);
        if mode != AllocationMode::Constant {
            let minus_one = M31Var::new_constant(cs, &M31::one().neg());
            let bit_minus_one = cs.add(bit.variable, minus_one.variable);
            cs.insert_gate(bit.variable, bit_minus_one, 0, M31::zero());
        }
        Self(bit)
    }
}

impl BitOr<&BitVar> for &BitVar {
    type Output = BitVar;

    fn bitor(self, rhs: &BitVar) -> BitVar {
        BitVar(&(&self.0 + &rhs.0) - &(&self.0 * &rhs.0))
    }
}

impl BitAnd<&BitVar> for &BitVar {
    type Output = BitVar;

    fn bitand(self, rhs: &BitVar) -> BitVar {
        BitVar(&self.0 * &rhs.0)
    }
}

impl Neg for &BitVar {
    type Output = BitVar;

    fn neg(self) -> Self::Output {
        BitVar(&M31Var::one(&self.cs()) - &self.0)
    }
}

impl BitVar {
    pub fn equalverify(&self, rhs: &BitVar) {
        self.0.equalverify(&rhs.0);
    }

    pub fn new_true(cs: &ConstraintSystemRef) -> BitVar {
        BitVar(M31Var::one(cs))
    }

    pub fn new_false(cs: &ConstraintSystemRef) -> BitVar {
        BitVar(M31Var::zero(cs))
    }
}

#[derive(Clone, Debug)]
pub struct BitsVar(pub Vec<BitVar>);

impl Var for BitsVar {
    type Value = Vec<bool>;

    fn cs(&self) -> ConstraintSystemRef {
        self.0[0].cs()
    }
}

impl AllocVar for BitsVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let mut bits = vec![];
        for i in 0..value.len() {
            bits.push(BitVar::new_variables(cs, &value[i], mode));
        }
        Self(bits)
    }
}

impl BitsVar {
    pub fn from_m31(v: &M31Var, l: usize) -> BitsVar {
        let cs = v.cs();
        let mut bools = Vec::with_capacity(l);

        let mut cur = v.value.0;
        for _ in 0..l {
            bools.push(cur & 1 != 0);
            cur >>= 1;
        }

        let res = BitsVar::new_witness(&cs, &bools);

        let mut reconstructed = res.0[0].0.clone();
        for i in 1..l {
            reconstructed = &reconstructed + &res.0[i].0.mul_constant(M31::from(1 << i));
        }
        reconstructed.equalverify(v);

        if l == 31 {
            let mut product = cs.mul(res.0[0].0.variable, res.0[1].0.variable);
            for i in 2..l {
                product = cs.mul(product, res.0[i].0.variable);
            }
            cs.enforce_zero(product);
        }

        res
    }

    pub fn get_value(&self) -> M31 {
        let mut sum_value = M31::zero();

        for (shift, i) in self.0.iter().enumerate() {
            if i.0.value.0 != 0 {
                sum_value += M31::from(1 << shift);
            }
        }

        sum_value
    }

    pub fn compose_range(&self, range: Range<usize>) -> M31Var {
        let mut sum = self.0[range.start].0.clone();

        for (shift, i) in (range.start + 1..range.end).enumerate() {
            sum = &sum + &self.0[i].0.mul_constant(M31::from(1 << (shift + 1)));
        }
        sum
    }

    pub fn compose(&self) -> M31Var {
        assert!(
            self.0.len() <= 31,
            "BitsVar::compose: length must be no larger than 31, got {}",
            self.0.len()
        );
        self.compose_range(0..self.0.len())
    }
}

impl BitsVar {
    pub fn index_range(&self, range: Range<usize>) -> BitsVar {
        BitsVar(self.0[range].to_vec())
    }

    pub fn index_range_from(&self, range: RangeFrom<usize>) -> BitsVar {
        BitsVar(self.0[range].to_vec())
    }

    pub fn is_greater_than(&self, rhs: &BitsVar) -> BitVar {
        assert_eq!(
            self.0.len(),
            rhs.0.len(),
            "BitsVar::is_greater_than: self and rhs must have the same number of bits"
        );

        let cs = self.cs();
        let n = self.0.len();

        let mut eq = BitVar::new_constant(&cs, &true);
        let mut gt = BitVar::new_constant(&cs, &false);

        for i in (0..n).rev() {
            let self_bit = &self.0[i];
            let rhs_bit = &rhs.0[i];

            let self_one_rhs_zero = self_bit & &rhs_bit.neg();
            let new_gt = &gt | &(&eq & &self_one_rhs_zero);

            let both_one = self_bit & rhs_bit;
            let both_zero = &self_bit.neg() & &rhs_bit.neg();
            let bits_equal = &both_one | &both_zero;
            let new_eq = &eq.clone() & &bits_equal;
            gt = new_gt;
            eq = new_eq;
        }

        gt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::M31Var;
    use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
    use stwo::core::fields::m31::M31;

    #[test]
    fn test_is_greater_than() {
        let cs = ConstraintSystemRef::new();

        // Test: 5 > 3 (should return true)
        let a_m31 = M31Var::new_witness(&cs, &M31::from(5));
        let b_m31 = M31Var::new_witness(&cs, &M31::from(3));
        let a = BitsVar::from_m31(&a_m31, 4);
        let b = BitsVar::from_m31(&b_m31, 4);
        let result = a.is_greater_than(&b);
        result.equalverify(&BitVar::new_true(&cs));

        // Test: 3 < 5 (should return false)
        let a_m31 = M31Var::new_witness(&cs, &M31::from(3));
        let b_m31 = M31Var::new_witness(&cs, &M31::from(5));
        let a = BitsVar::from_m31(&a_m31, 4);
        let b = BitsVar::from_m31(&b_m31, 4);
        let result = a.is_greater_than(&b);
        result.equalverify(&BitVar::new_false(&cs));

        // Test: 5 == 5 (should return false)
        let a_m31 = M31Var::new_witness(&cs, &M31::from(5));
        let b_m31 = M31Var::new_witness(&cs, &M31::from(5));
        let a = BitsVar::from_m31(&a_m31, 4);
        let b = BitsVar::from_m31(&b_m31, 4);
        let result = a.is_greater_than(&b);
        result.equalverify(&BitVar::new_false(&cs));

        cs.pad();
        cs.check_arithmetics();
    }
}
