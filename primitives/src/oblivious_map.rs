use crate::{BitVar, M31Var, QM31Var};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, Var},
    ConstraintSystemRef,
};
use indexmap::IndexMap;
use stwo::core::fields::{m31::M31, qm31::QM31};

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

    pub fn select(&self, key: &M31Var) -> T::Output {
        let cs = key.cs();
        let mut session = T::select_start(&cs);
        for (k, v) in self.0.iter() {
            let bit = key.is_eq(&M31Var::new_constant(&cs, &M31::from(*k)));
            T::select_add(&mut session, v, &bit);
        }
        T::select_end(session)
    }
}

impl SelectVar for M31 {
    type SelectSession = M31Var;
    type Output = M31Var;

    fn select_start(cs: &ConstraintSystemRef) -> Self::SelectSession {
        M31Var::zero(&cs)
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
        QM31Var::zero(&cs)
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
        M31Var::zero(&cs)
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
        QM31Var::zero(&cs)
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
