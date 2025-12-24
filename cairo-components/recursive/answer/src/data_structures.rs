mod composition;
mod interaction;
mod preprocessed;
mod trace;

pub use composition::*;
pub use interaction::*;
pub use preprocessed::*;
pub use trace::*;

use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    BitVar, BitsVar, CM31Var, CirclePointQM31Var, LogSizeVar, M31Var, PointCarryingQueryVar,
    QM31Var,
};
use indexmap::IndexMap;
use num_traits::Zero;
use std::ops::Neg;
use stwo::core::{
    circle::CirclePoint,
    fields::{m31::M31, qm31::QM31, ComplexConjugate},
};
use stwo_cairo_common::{
    preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
    prover_types::simd::LOG_N_LANES,
};

pub struct AnswerAccumulator {
    pub cs: ConstraintSystemRef,
    pub random_coeff: QM31Var,
    pub map: IndexMap<usize, (QM31Var, QM31Var)>,
}

impl AnswerAccumulator {
    pub fn new(cs: &ConstraintSystemRef, random_coeff: &QM31Var) -> Self {
        let mut map = IndexMap::new();
        for i in (LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE).rev() {
            map.insert(
                i as usize,
                (
                    QM31Var::zero(&cs),
                    QM31Var::new_constant(
                        &cs,
                        &QM31::from_m31(M31::zero(), M31::zero(), M31::from(2).neg(), M31::zero()),
                    ),
                ),
            );
        }
        Self {
            cs: cs.clone(),
            random_coeff: random_coeff.clone(),
            map,
        }
    }

    pub fn update_fix_log_size(&mut self, log_size: usize, column_results: &[CM31Var]) {
        let (answer, multiplier) = self.map.get_mut(&log_size).unwrap();

        for result in column_results.iter() {
            *answer = &*answer + &(result * &*multiplier);
            *multiplier = &*multiplier * &self.random_coeff;
        }
    }

    pub fn update_fix_log_size_conditional(
        &mut self,
        log_size: usize,
        column_results: &[CM31Var],
        condition: &BitVar,
    ) {
        let (old_answer, old_multiplier) = self.map.get(&log_size).unwrap().clone();

        let mut answer = old_answer.clone();
        let mut multiplier = old_multiplier.clone();

        for result in column_results.iter() {
            answer = &answer + &(result * &multiplier);
            multiplier = &multiplier * &self.random_coeff;
        }

        let new_answer = QM31Var::select(&old_answer, &answer, condition);
        let new_multiplier = QM31Var::select(&old_multiplier, &multiplier, condition);

        self.map.insert(log_size, (new_answer, new_multiplier));
    }

    pub fn update(&mut self, log_size: &LogSizeVar, column_results: &[CM31Var]) {
        let cs = &self.cs;

        let mut bits = vec![];
        for (k, _) in self.map.iter() {
            let bit = log_size.bitmap.get(&(*k as u32)).unwrap();
            bits.push(bit);
        }

        let mut entry_answer = QM31Var::zero(cs);
        let mut entry_multiplier = QM31Var::zero(cs);

        for ((_, (answer, multiplier)), bit) in self.map.iter().zip(bits.iter()) {
            entry_answer = &entry_answer + &(answer * &bit.0);
            entry_multiplier = &entry_multiplier + &(multiplier * &bit.0);
        }

        for result in column_results.iter() {
            entry_answer = &entry_answer + &(result * &entry_multiplier);
            entry_multiplier = &entry_multiplier * &self.random_coeff;
        }

        for ((_, v), bit) in self.map.iter_mut().zip(bits.iter()) {
            v.0 = QM31Var::select(&v.0, &entry_answer, bit);
            v.1 = QM31Var::select(&v.1, &entry_multiplier, bit);
        }
    }

    pub fn update_conditional(
        &mut self,
        log_size: &LogSizeVar,
        column_results: &[CM31Var],
        condition: &BitVar,
    ) {
        let cs = &self.cs;

        let mut bits = vec![];
        for (k, _) in self.map.iter() {
            let bit = log_size.bitmap.get(&(*k as u32)).unwrap();
            bits.push(bit);
        }

        let mut entry_answer = QM31Var::zero(cs);
        let mut entry_multiplier = QM31Var::zero(cs);

        for ((_, (answer, multiplier)), bit) in self.map.iter().zip(bits.iter()) {
            entry_answer = &entry_answer + &(answer * &bit.0);
            entry_multiplier = &entry_multiplier + &(multiplier * &bit.0);
        }

        for result in column_results.iter() {
            entry_answer = &entry_answer + &(result * &entry_multiplier);
            entry_multiplier = &entry_multiplier * &self.random_coeff;
        }

        for ((_, v), bit) in self.map.iter_mut().zip(bits.iter()) {
            let bit = *bit & condition;
            v.0 = QM31Var::select(&v.0, &entry_answer, &bit);
            v.1 = QM31Var::select(&v.1, &entry_multiplier, &bit);
        }
    }

    pub fn finalize(&self) -> IndexMap<usize, QM31Var> {
        self.map
            .iter()
            .map(|(k, (answer, _))| (*k, answer.clone()))
            .collect()
    }
}

pub fn complex_conjugate_line_coeffs_var(
    point: &CirclePointQM31Var,
    value: &QM31Var,
) -> [CM31Var; 3] {
    assert_ne!(
        point.y.value(),
        point.y.value().complex_conjugate(),
        "Cannot evaluate a line with a single point ({:?}).",
        CirclePoint {
            x: point.x.value(),
            y: point.y.value()
        }
    );

    let [value0, value1] = value.decompose_cm31();
    let [y0, y1] = point.y.decompose_cm31();

    let a = value1.clone();
    let c = y1.clone();
    let b = &(&value0 * &y1) - &(&value1 * &y0);

    [a, b, c]
}

pub struct CairoQueryPositionsPerLogSizeVar {
    pub points: IndexMap<u32, Vec<PointCarryingQueryVar>>,
}

impl CairoQueryPositionsPerLogSizeVar {
    pub fn new(raw_queries: &[BitsVar], log_blowup_factor: u32, query_log_size: &M31Var) -> Self {
        let cs = query_log_size.cs();

        let mut elems = vec![];
        for raw_query in raw_queries {
            let mut query = raw_query.compose();
            let mut cur =
                &M31Var::new_constant(&cs, &M31::from(MAX_SEQUENCE_LOG_SIZE + log_blowup_factor))
                    - query_log_size;

            for _ in 0..MAX_SEQUENCE_LOG_SIZE - LOG_N_LANES {
                let is_cur_nonzero = cur.is_zero().neg();
                query = M31Var::select(&query, &(&query + &query), &is_cur_nonzero);
                cur = &cur - &is_cur_nonzero.0;
            }

            elems.push(PointCarryingQueryVar::new(BitsVar::from_m31(
                &query,
                (MAX_SEQUENCE_LOG_SIZE + log_blowup_factor) as usize,
            )));
        }
        let mut points = IndexMap::new();
        points.insert(MAX_SEQUENCE_LOG_SIZE + log_blowup_factor, elems.clone());

        for log_size in (2..MAX_SEQUENCE_LOG_SIZE + log_blowup_factor).rev() {
            elems.iter_mut().for_each(|e| e.next());
            points.insert(log_size, elems.clone());
        }

        Self { points }
    }
}
