use circle_plonk_dsl_constraint_system::var::Var;
use circle_plonk_dsl_primitives::QM31Var;

#[derive(Debug, Clone)]
pub struct PointEvaluationAccumulatorVar {
    pub random_coeff: QM31Var,
    pub accumulation: QM31Var,
}

impl PointEvaluationAccumulatorVar {
    pub fn new(random_coeff: &QM31Var) -> Self {
        let cs = random_coeff.cs();
        Self {
            random_coeff: random_coeff.clone(),
            accumulation: QM31Var::zero(&cs),
        }
    }

    pub fn accumulate(&mut self, evaluation: QM31Var) {
        self.accumulation = &(&self.accumulation * &self.random_coeff) + &evaluation;
    }

    pub fn finalize(self) -> QM31Var {
        self.accumulation
    }
}
