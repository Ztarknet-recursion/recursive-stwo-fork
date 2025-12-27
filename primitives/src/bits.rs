use crate::{ChannelVar, M31Var, QM31Var};
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

    // Bit-AND is implemented as multiplication in the base field since bits are constrained to {0,1}.
    #[allow(clippy::suspicious_arithmetic_impl)]
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
    pub fn value(&self) -> bool {
        self.0.value.0 != 0
    }

    pub fn equalverify(&self, rhs: &BitVar) {
        self.0.equalverify(&rhs.0);
    }

    pub fn new_true(cs: &ConstraintSystemRef) -> BitVar {
        BitVar(M31Var::one(cs))
    }

    pub fn new_false(cs: &ConstraintSystemRef) -> BitVar {
        BitVar(M31Var::zero(cs))
    }

    pub fn select(a: &BitVar, b: &BitVar, bit: &BitVar) -> BitVar {
        BitVar(M31Var::select(&a.0, &b.0, bit))
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
        let mut bits = Vec::with_capacity(value.len());
        for bit in value.iter() {
            bits.push(BitVar::new_variables(cs, bit, mode));
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

    pub fn select(a: &BitsVar, b: &BitsVar, bit: &BitVar) -> BitsVar {
        assert_eq!(a.0.len(), b.0.len());
        let mut bits = vec![];
        for i in 0..a.0.len() {
            bits.push(BitVar::select(&a.0[i], &b.0[i], bit));
        }
        BitsVar(bits)
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

#[derive(Clone, Debug)]
pub struct BitIntVar<const N: usize> {
    pub bits: BitsVar,
}

impl<const N: usize> Var for BitIntVar<N> {
    type Value = u64;

    fn cs(&self) -> ConstraintSystemRef {
        self.bits.cs()
    }
}

impl<const N: usize> AllocVar for BitIntVar<N> {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let mut bools = Vec::with_capacity(N);
        let mut cur = *value;
        for _ in 0..N {
            bools.push(cur & 1 != 0);
            cur >>= 1;
        }
        assert_eq!(cur, 0);

        let bits = BitsVar::new_variables(cs, &bools, mode);

        Self { bits }
    }
}

impl<const N: usize> BitIntVar<N> {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        let cs = self.cs();
        let zero = M31Var::zero(&cs);

        let first = if N > 0 {
            let end = N.min(22);
            if end > 0 {
                self.bits.compose_range(0..end)
            } else {
                zero.clone()
            }
        } else {
            zero.clone()
        };

        let second = if N > 22 {
            let end = N.min(43);
            self.bits.compose_range(22..end)
        } else {
            zero.clone()
        };

        let third = if N > 43 {
            let end = N.min(64);
            self.bits.compose_range(43..end)
        } else {
            zero.clone()
        };

        let felt = QM31Var::from_m31(&first, &second, &third, &zero);
        channel.mix_one_felt(&felt);
    }

    pub fn enforce_equal(&self, other: &BitIntVar<N>) {
        assert_eq!(self.bits.0.len(), other.bits.0.len());
        for (self_bit, other_bit) in self.bits.0.iter().zip(other.bits.0.iter()) {
            self_bit.equalverify(other_bit);
        }
    }

    pub fn enforce_not_equal(&self, other: &BitIntVar<N>) {
        assert_eq!(self.bits.0.len(), other.bits.0.len());
        let mut flags = Vec::new();
        for (self_bit, other_bit) in self.bits.0.iter().zip(other.bits.0.iter()) {
            let flag = self_bit.0.is_eq(&other_bit.0);
            flags.push(flag);
        }

        let mut product = flags[0].0.clone();
        for flag in flags.iter().skip(1) {
            product = &product * &flag.0;
        }
        product.equalverify(&M31Var::zero(&self.cs()));
    }

    pub fn to_m31(&self) -> M31Var {
        assert!(N <= 31, "BitIntVar::to_m31 requires N <= 31, got N = {}", N);
        self.bits.compose()
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
