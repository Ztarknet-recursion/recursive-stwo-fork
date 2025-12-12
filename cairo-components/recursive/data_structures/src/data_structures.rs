use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::BitsVar;
use circle_plonk_dsl_primitives::ChannelVar;
use circle_plonk_dsl_primitives::{M31Var, QM31Var};
use stwo::core::fields::m31::M31;

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

#[derive(Debug, Clone)]
pub struct LogSizeVar {
    pub bits: BitIntVar<5>,
    pub m31: M31Var,
    pub pow2: M31Var,
}

impl Var for LogSizeVar {
    type Value = u32;

    fn cs(&self) -> ConstraintSystemRef {
        self.bits.cs().and(&self.pow2.cs()).and(&self.m31.cs())
    }
}

impl AllocVar for LogSizeVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let bits = BitIntVar::<5>::new_variables(cs, &(*value as u64), mode);
        let m31 = if mode == AllocationMode::Constant {
            M31Var::new_constant(cs, &M31::from(*value))
        } else {
            bits.to_m31()
        };
        let pow2 = if mode == AllocationMode::Constant {
            M31Var::new_constant(cs, &M31::from(1 << value))
        } else {
            m31.exp2()
        };
        Self { bits, m31, pow2 }
    }
}

impl LogSizeVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.bits.mix_into(channel);
    }

    pub fn to_m31(&self) -> M31Var {
        self.m31.clone()
    }
}
