use crate::{BitIntVar, BitVar, ChannelVar, CirclePointQM31Var, M31Var, Poseidon2HalfVar, QM31Var};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use indexmap::IndexMap;
use stwo::core::fields::{m31::M31, qm31::QM31};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;
use stwo_cairo_common::prover_types::simd::LOG_N_LANES;

#[derive(Debug, Clone)]
pub struct LogSizeVar {
    pub bits: BitIntVar<5>,
    pub m31: M31Var,
    pub pow2: M31Var,
    pub bitmap: IndexMap<u32, BitVar>,
}

impl Var for LogSizeVar {
    type Value = u32;

    fn cs(&self) -> ConstraintSystemRef {
        self.bits.cs()
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

        // Construct bitmap for k from LOG_N_LANES to MAX_SEQUENCE_LOG_SIZE
        let mut bitmap = IndexMap::new();
        for k in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
            let bit = if mode == AllocationMode::Constant {
                if *value == k {
                    BitVar::new_true(cs)
                } else {
                    BitVar::new_false(cs)
                }
            } else {
                m31.is_eq(&M31Var::new_constant(cs, &M31::from(k)))
            };
            bitmap.insert(k, bit);
        }

        Self {
            bits,
            m31,
            pow2,
            bitmap,
        }
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

pub trait SelectVar {
    type SelectSession;
    type Output;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession;
    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar);
    fn select_end(session: Self::SelectSession) -> Self::Output;
}

pub struct ObliviousMapVar<T: SelectVar>(pub IndexMap<u32, T>);

impl<T: SelectVar> ObliviousMapVar<T> {
    pub fn new(map: IndexMap<u32, T>) -> Self {
        Self(map)
    }

    pub fn select(&self, key: &LogSizeVar) -> T::Output {
        let cs = key.cs();
        let mut session = T::select_start(&cs);
        for (k, v) in self.0.iter() {
            let bit = key.bitmap.get(k).unwrap();
            T::select_add(&mut session, v, bit);
        }
        T::select_end(session)
    }
}

impl SelectVar for M31 {
    type SelectSession = M31Var;
    type Output = M31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        M31Var::zero(cs)
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        *session = &*session + &bit.0.mul_constant(*new);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        session
    }
}

impl SelectVar for QM31 {
    type SelectSession = QM31Var;
    type Output = QM31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        QM31Var::zero(cs)
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        let bit = QM31Var::from(&bit.0);
        *session = &*session + &bit.mul_constant_qm31(*new);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        session
    }
}

impl SelectVar for M31Var {
    type SelectSession = M31Var;
    type Output = M31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        M31Var::zero(cs)
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        *session = &*session + &(&bit.0 * new);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        session
    }
}

impl SelectVar for QM31Var {
    type SelectSession = QM31Var;
    type Output = QM31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        QM31Var::zero(cs)
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        *session = &*session + &(&bit.0 * new);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        session
    }
}

impl<T: SelectVar> SelectVar for (T, T) {
    type SelectSession = (T::SelectSession, T::SelectSession);
    type Output = (T::Output, T::Output);

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        (T::select_start(cs), T::select_start(cs))
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        T::select_add(&mut session.0, &new.0, bit);
        T::select_add(&mut session.1, &new.1, bit);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        (T::select_end(session.0), T::select_end(session.1))
    }
}

impl SelectVar for ChannelVar {
    type SelectSession = [QM31Var; 2];
    type Output = ChannelVar;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        [QM31Var::zero(cs), QM31Var::zero(cs)]
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        let new_qm31 = new.digest.to_qm31();
        session[0] = QM31Var::select(&session[0], &new_qm31[0], bit);
        session[1] = QM31Var::select(&session[1], &new_qm31[1], bit);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        ChannelVar {
            digest: Poseidon2HalfVar::from_qm31(&session[0], &session[1]),
            n_sent: 0,
        }
    }
}

impl SelectVar for CirclePointQM31Var {
    type SelectSession = (QM31Var, QM31Var);
    type Output = CirclePointQM31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        (QM31Var::zero(cs), QM31Var::zero(cs))
    }

    fn select_add(session: &mut Self::SelectSession, new: &Self, bit: &BitVar) {
        session.0 = &session.0 + &(&new.x * &bit.0);
        session.1 = &session.1 + &(&new.y * &bit.0);
    }

    fn select_end(session: Self::SelectSession) -> Self::Output {
        CirclePointQM31Var {
            x: session.0,
            y: session.1,
        }
    }
}
