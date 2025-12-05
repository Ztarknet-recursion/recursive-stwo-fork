use cairo_air::opcodes_air::OpcodeInteractionClaim;
use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::{AllocVar, AllocationMode, Var}};
use circle_plonk_dsl_fields::QM31Var;

pub struct CairoInteractionClaimVar {
    pub opcodes: OpcodeInteractionClaimVar,
}

pub struct OpcodeInteractionClaimVar {
    pub add: QM31Var,
    pub add_small: QM31Var,
    pub add_ap: QM31Var,
    pub assert_eq: QM31Var,
    pub assert_eq_imm: QM31Var,
    pub assert_eq_double_deref: QM31Var,
    pub blake: QM31Var,
    pub call: QM31Var,
    pub call_rel_imm: QM31Var,
    pub jnz: QM31Var,
    pub jnz_taken: QM31Var,
    pub jump_rel: QM31Var,
    pub jump_rel_imm: QM31Var,
    pub mul: QM31Var,
    pub mul_small: QM31Var,
    pub qm31: QM31Var,
    pub ret: QM31Var,
}

impl Var for OpcodeInteractionClaimVar {
    type Value = OpcodeInteractionClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.add.cs()
    }
}

impl AllocVar for OpcodeInteractionClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            add: QM31Var::new_variables(cs, &value.add[0].claimed_sum, mode),
            add_small: QM31Var::new_variables(cs, &value.add_small[0].claimed_sum, mode),
            add_ap: QM31Var::new_variables(cs, &value.add_ap[0].claimed_sum, mode),
            assert_eq: QM31Var::new_variables(cs, &value.assert_eq[0].claimed_sum, mode),
            assert_eq_imm: QM31Var::new_variables(cs, &value.assert_eq_imm[0].claimed_sum, mode),
            assert_eq_double_deref: QM31Var::new_variables(cs, &value.assert_eq_double_deref[0].claimed_sum, mode),
            blake: QM31Var::new_variables(cs, &value.blake[0].claimed_sum, mode),
            call: QM31Var::new_variables(cs, &value.call[0].claimed_sum, mode),
            call_rel_imm: QM31Var::new_variables(cs, &value.call_rel_imm[0].claimed_sum, mode),
            jnz: QM31Var::new_variables(cs, &value.jnz[0].claimed_sum, mode),
            jnz_taken: QM31Var::new_variables(cs, &value.jnz_taken[0].claimed_sum, mode),
            jump_rel: QM31Var::new_variables(cs, &value.jump_rel[0].claimed_sum, mode),
            jump_rel_imm: QM31Var::new_variables(cs, &value.jump_rel_imm[0].claimed_sum, mode),
            mul: QM31Var::new_variables(cs, &value.mul[0].claimed_sum, mode),
            mul_small: QM31Var::new_variables(cs, &value.mul_small[0].claimed_sum, mode),
            qm31: QM31Var::new_variables(cs, &value.qm31[0].claimed_sum, mode),
            ret: QM31Var::new_variables(cs, &value.ret[0].claimed_sum, mode),
        }
    }
}