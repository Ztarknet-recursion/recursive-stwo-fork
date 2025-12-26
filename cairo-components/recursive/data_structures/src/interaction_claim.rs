use cairo_air::{air::CairoInteractionClaim, opcodes_air::OpcodeInteractionClaim};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::ChannelVar;
use circle_plonk_dsl_primitives::QM31Var;

#[derive(Debug, Clone)]
pub struct CairoInteractionClaimVar {
    pub opcodes: OpcodeInteractionClaimVar,
    pub verify_instruction: QM31Var,
    pub blake_context: BlakeContextInteractionClaimVar,
    pub builtins: QM31Var,
    pub memory_address_to_id: QM31Var,
    pub memory_id_to_value: MemoryIdToValueClaimVar,
    pub range_checks: RangeChecksInteractionClaimVar,
    pub verify_bitwise_xor_4: QM31Var,
    pub verify_bitwise_xor_7: QM31Var,
    pub verify_bitwise_xor_8: QM31Var,
    pub verify_bitwise_xor_8_b: QM31Var,
    pub verify_bitwise_xor_9: QM31Var,
}

impl Var for CairoInteractionClaimVar {
    type Value = CairoInteractionClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.opcodes.cs()
    }
}

impl AllocVar for CairoInteractionClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            opcodes: OpcodeInteractionClaimVar::new_variables(cs, &value.opcodes, mode),
            verify_instruction: QM31Var::new_variables(
                cs,
                &value.verify_instruction.claimed_sum,
                mode,
            ),
            blake_context: BlakeContextInteractionClaimVar::new_variables(
                cs,
                value.blake_context.claim.as_ref().unwrap(),
                mode,
            ),
            builtins: QM31Var::new_variables(
                cs,
                &value
                    .builtins
                    .range_check_128_builtin
                    .as_ref()
                    .unwrap()
                    .claimed_sum,
                mode,
            ),
            memory_address_to_id: QM31Var::new_variables(
                cs,
                &value.memory_address_to_id.claimed_sum,
                mode,
            ),
            memory_id_to_value: MemoryIdToValueClaimVar::new_variables(
                cs,
                &value.memory_id_to_value,
                mode,
            ),
            range_checks: RangeChecksInteractionClaimVar::new_variables(
                cs,
                &value.range_checks,
                mode,
            ),
            verify_bitwise_xor_4: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_4.claimed_sum,
                mode,
            ),
            verify_bitwise_xor_7: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_7.claimed_sum,
                mode,
            ),
            verify_bitwise_xor_8: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_8.claimed_sum,
                mode,
            ),
            verify_bitwise_xor_8_b: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_8_b.claimed_sum,
                mode,
            ),
            verify_bitwise_xor_9: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_9.claimed_sum,
                mode,
            ),
        }
    }
}

impl CairoInteractionClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.opcodes.mix_into(channel);
        channel.mix_one_felt(&self.verify_instruction);
        self.blake_context.mix_into(channel);
        channel.mix_one_felt(&self.builtins);
        channel.mix_one_felt(&self.memory_address_to_id);
        self.memory_id_to_value.mix_into(channel);
        self.range_checks.mix_into(channel);
        channel.mix_one_felt(&self.verify_bitwise_xor_4);
        channel.mix_one_felt(&self.verify_bitwise_xor_7);
        channel.mix_one_felt(&self.verify_bitwise_xor_8);
        channel.mix_one_felt(&self.verify_bitwise_xor_8_b);
        channel.mix_one_felt(&self.verify_bitwise_xor_9);
    }
}

#[derive(Debug, Clone)]
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
            assert_eq_double_deref: QM31Var::new_variables(
                cs,
                &value.assert_eq_double_deref[0].claimed_sum,
                mode,
            ),
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

impl OpcodeInteractionClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        channel.mix_one_felt(&self.add);
        channel.mix_one_felt(&self.add_small);
        channel.mix_one_felt(&self.add_ap);
        channel.mix_one_felt(&self.assert_eq);
        channel.mix_one_felt(&self.assert_eq_imm);
        channel.mix_one_felt(&self.assert_eq_double_deref);
        channel.mix_one_felt(&self.blake);
        channel.mix_one_felt(&self.call);
        channel.mix_one_felt(&self.call_rel_imm);
        channel.mix_one_felt(&self.jnz);
        channel.mix_one_felt(&self.jnz_taken);
        channel.mix_one_felt(&self.jump_rel);
        channel.mix_one_felt(&self.jump_rel_imm);
        channel.mix_one_felt(&self.mul);
        channel.mix_one_felt(&self.mul_small);
        channel.mix_one_felt(&self.qm31);
        channel.mix_one_felt(&self.ret);
    }

    pub fn sum(&self) -> QM31Var {
        let mut sum = self.add.clone();
        sum = &sum + &self.add_small;
        sum = &sum + &self.add_ap;
        sum = &sum + &self.assert_eq;
        sum = &sum + &self.assert_eq_imm;
        sum = &sum + &self.assert_eq_double_deref;
        sum = &sum + &self.blake;
        sum = &sum + &self.call;
        sum = &sum + &self.call_rel_imm;
        sum = &sum + &self.jnz;
        sum = &sum + &self.jnz_taken;
        sum = &sum + &self.jump_rel;
        sum = &sum + &self.jump_rel_imm;
        sum = &sum + &self.mul;
        sum = &sum + &self.mul_small;
        sum = &sum + &self.qm31;
        sum = &sum + &self.ret;

        sum
    }
}

#[derive(Debug, Clone)]
pub struct BlakeContextInteractionClaimVar {
    pub blake_round: QM31Var,
    pub blake_g: QM31Var,
    pub blake_sigma: QM31Var,
    pub triple_xor_32: QM31Var,
    pub verify_bitwise_xor_12: QM31Var,
}

impl Var for BlakeContextInteractionClaimVar {
    type Value = cairo_air::blake::air::InteractionClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.blake_round.cs()
    }
}

impl AllocVar for BlakeContextInteractionClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            blake_round: QM31Var::new_variables(cs, &value.blake_round.claimed_sum, mode),
            blake_g: QM31Var::new_variables(cs, &value.blake_g.claimed_sum, mode),
            blake_sigma: QM31Var::new_variables(cs, &value.blake_sigma.claimed_sum, mode),
            triple_xor_32: QM31Var::new_variables(cs, &value.triple_xor_32.claimed_sum, mode),
            verify_bitwise_xor_12: QM31Var::new_variables(
                cs,
                &value.verify_bitwise_xor_12.claimed_sum,
                mode,
            ),
        }
    }
}

impl BlakeContextInteractionClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        channel.mix_one_felt(&self.blake_round);
        channel.mix_one_felt(&self.blake_g);
        channel.mix_one_felt(&self.blake_sigma);
        channel.mix_one_felt(&self.triple_xor_32);
        channel.mix_one_felt(&self.verify_bitwise_xor_12);
    }

    pub fn sum(&self) -> QM31Var {
        let mut sum = self.blake_round.clone();
        sum = &sum + &self.blake_g;
        sum = &sum + &self.blake_sigma;
        sum = &sum + &self.triple_xor_32;
        sum = &sum + &self.verify_bitwise_xor_12;
        sum
    }
}

#[derive(Debug, Clone)]
pub struct MemoryIdToValueClaimVar {
    pub big_claimed_sum: QM31Var,
    pub small_claimed_sum: QM31Var,
}

impl Var for MemoryIdToValueClaimVar {
    type Value = cairo_air::components::memory_id_to_big::InteractionClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.big_claimed_sum.cs()
    }
}

impl AllocVar for MemoryIdToValueClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            big_claimed_sum: QM31Var::new_variables(cs, &value.big_claimed_sums[0], mode),
            small_claimed_sum: QM31Var::new_variables(cs, &value.small_claimed_sum, mode),
        }
    }
}

impl MemoryIdToValueClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        channel.mix_one_felt(&self.big_claimed_sum);
        channel.mix_one_felt(&self.small_claimed_sum);
    }

    pub fn sum(&self) -> QM31Var {
        let mut sum = self.big_claimed_sum.clone();
        sum = &sum + &self.small_claimed_sum;
        sum
    }
}

#[derive(Debug, Clone)]
pub struct RangeChecksInteractionClaimVar {
    pub rc_6: QM31Var,
    pub rc_8: QM31Var,
    pub rc_11: QM31Var,
    pub rc_12: QM31Var,
    pub rc_18: QM31Var,
    pub rc_18_b: QM31Var,
    pub rc_20: QM31Var,
    pub rc_20_b: QM31Var,
    pub rc_20_c: QM31Var,
    pub rc_20_d: QM31Var,
    pub rc_20_e: QM31Var,
    pub rc_20_f: QM31Var,
    pub rc_20_g: QM31Var,
    pub rc_20_h: QM31Var,
    pub rc_4_3: QM31Var,
    pub rc_4_4: QM31Var,
    pub rc_5_4: QM31Var,
    pub rc_9_9: QM31Var,
    pub rc_9_9_b: QM31Var,
    pub rc_9_9_c: QM31Var,
    pub rc_9_9_d: QM31Var,
    pub rc_9_9_e: QM31Var,
    pub rc_9_9_f: QM31Var,
    pub rc_9_9_g: QM31Var,
    pub rc_9_9_h: QM31Var,
    pub rc_7_2_5: QM31Var,
    pub rc_3_6_6_3: QM31Var,
    pub rc_4_4_4_4: QM31Var,
    pub rc_3_3_3_3_3: QM31Var,
}

impl Var for RangeChecksInteractionClaimVar {
    type Value = cairo_air::range_checks_air::RangeChecksInteractionClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.rc_6.cs()
    }
}

impl AllocVar for RangeChecksInteractionClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            rc_6: QM31Var::new_variables(cs, &value.rc_6.claimed_sum, mode),
            rc_8: QM31Var::new_variables(cs, &value.rc_8.claimed_sum, mode),
            rc_11: QM31Var::new_variables(cs, &value.rc_11.claimed_sum, mode),
            rc_12: QM31Var::new_variables(cs, &value.rc_12.claimed_sum, mode),
            rc_18: QM31Var::new_variables(cs, &value.rc_18.claimed_sum, mode),
            rc_18_b: QM31Var::new_variables(cs, &value.rc_18_b.claimed_sum, mode),
            rc_20: QM31Var::new_variables(cs, &value.rc_20.claimed_sum, mode),
            rc_20_b: QM31Var::new_variables(cs, &value.rc_20_b.claimed_sum, mode),
            rc_20_c: QM31Var::new_variables(cs, &value.rc_20_c.claimed_sum, mode),
            rc_20_d: QM31Var::new_variables(cs, &value.rc_20_d.claimed_sum, mode),
            rc_20_e: QM31Var::new_variables(cs, &value.rc_20_e.claimed_sum, mode),
            rc_20_f: QM31Var::new_variables(cs, &value.rc_20_f.claimed_sum, mode),
            rc_20_g: QM31Var::new_variables(cs, &value.rc_20_g.claimed_sum, mode),
            rc_20_h: QM31Var::new_variables(cs, &value.rc_20_h.claimed_sum, mode),
            rc_4_3: QM31Var::new_variables(cs, &value.rc_4_3.claimed_sum, mode),
            rc_4_4: QM31Var::new_variables(cs, &value.rc_4_4.claimed_sum, mode),
            rc_5_4: QM31Var::new_variables(cs, &value.rc_5_4.claimed_sum, mode),
            rc_9_9: QM31Var::new_variables(cs, &value.rc_9_9.claimed_sum, mode),
            rc_9_9_b: QM31Var::new_variables(cs, &value.rc_9_9_b.claimed_sum, mode),
            rc_9_9_c: QM31Var::new_variables(cs, &value.rc_9_9_c.claimed_sum, mode),
            rc_9_9_d: QM31Var::new_variables(cs, &value.rc_9_9_d.claimed_sum, mode),
            rc_9_9_e: QM31Var::new_variables(cs, &value.rc_9_9_e.claimed_sum, mode),
            rc_9_9_f: QM31Var::new_variables(cs, &value.rc_9_9_f.claimed_sum, mode),
            rc_9_9_g: QM31Var::new_variables(cs, &value.rc_9_9_g.claimed_sum, mode),
            rc_9_9_h: QM31Var::new_variables(cs, &value.rc_9_9_h.claimed_sum, mode),
            rc_7_2_5: QM31Var::new_variables(cs, &value.rc_7_2_5.claimed_sum, mode),
            rc_3_6_6_3: QM31Var::new_variables(cs, &value.rc_3_6_6_3.claimed_sum, mode),
            rc_4_4_4_4: QM31Var::new_variables(cs, &value.rc_4_4_4_4.claimed_sum, mode),
            rc_3_3_3_3_3: QM31Var::new_variables(cs, &value.rc_3_3_3_3_3.claimed_sum, mode),
        }
    }
}

impl RangeChecksInteractionClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        channel.mix_one_felt(&self.rc_6);
        channel.mix_one_felt(&self.rc_8);
        channel.mix_one_felt(&self.rc_11);
        channel.mix_one_felt(&self.rc_12);
        channel.mix_one_felt(&self.rc_18);
        channel.mix_one_felt(&self.rc_18_b);
        channel.mix_one_felt(&self.rc_20);
        channel.mix_one_felt(&self.rc_20_b);
        channel.mix_one_felt(&self.rc_20_c);
        channel.mix_one_felt(&self.rc_20_d);
        channel.mix_one_felt(&self.rc_20_e);
        channel.mix_one_felt(&self.rc_20_f);
        channel.mix_one_felt(&self.rc_20_g);
        channel.mix_one_felt(&self.rc_20_h);
        channel.mix_one_felt(&self.rc_4_3);
        channel.mix_one_felt(&self.rc_4_4);
        channel.mix_one_felt(&self.rc_5_4);
        channel.mix_one_felt(&self.rc_9_9);
        channel.mix_one_felt(&self.rc_9_9_b);
        channel.mix_one_felt(&self.rc_9_9_c);
        channel.mix_one_felt(&self.rc_9_9_d);
        channel.mix_one_felt(&self.rc_9_9_e);
        channel.mix_one_felt(&self.rc_9_9_f);
        channel.mix_one_felt(&self.rc_9_9_g);
        channel.mix_one_felt(&self.rc_9_9_h);
        channel.mix_one_felt(&self.rc_7_2_5);
        channel.mix_one_felt(&self.rc_3_6_6_3);
        channel.mix_one_felt(&self.rc_4_4_4_4);
        channel.mix_one_felt(&self.rc_3_3_3_3_3);
    }

    pub fn sum(&self) -> QM31Var {
        let mut sum = self.rc_6.clone();
        sum = &sum + &self.rc_8;
        sum = &sum + &self.rc_11;
        sum = &sum + &self.rc_12;
        sum = &sum + &self.rc_18;
        sum = &sum + &self.rc_18_b;
        sum = &sum + &self.rc_20;
        sum = &sum + &self.rc_20_b;
        sum = &sum + &self.rc_20_c;
        sum = &sum + &self.rc_20_d;
        sum = &sum + &self.rc_20_e;
        sum = &sum + &self.rc_20_f;
        sum = &sum + &self.rc_20_g;
        sum = &sum + &self.rc_20_h;
        sum = &sum + &self.rc_4_3;
        sum = &sum + &self.rc_4_4;
        sum = &sum + &self.rc_5_4;
        sum = &sum + &self.rc_9_9;
        sum = &sum + &self.rc_9_9_b;
        sum = &sum + &self.rc_9_9_c;
        sum = &sum + &self.rc_9_9_d;
        sum = &sum + &self.rc_9_9_e;
        sum = &sum + &self.rc_9_9_f;
        sum = &sum + &self.rc_9_9_g;
        sum = &sum + &self.rc_9_9_h;
        sum = &sum + &self.rc_7_2_5;
        sum = &sum + &self.rc_3_6_6_3;
        sum = &sum + &self.rc_4_4_4_4;
        sum = &sum + &self.rc_3_3_3_3_3;
        sum
    }
}
