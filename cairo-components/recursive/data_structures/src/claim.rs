use std::collections::HashMap;

use cairo_air::{
    air::CairoClaim, blake::air::BlakeContextClaim, builtins_air::BuiltinsClaim,
    components::memory_id_to_big, opcodes_air::OpcodeClaim,
};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{ChannelVar, LogSizeVar, M31Var, QM31Var};
use stwo::core::fields::m31::M31;

use crate::{public_data::PublicDataVar, BitIntVar};

macro_rules! accumulate_component {
    ($component_name:ident, $expr:expr, $relation_uses:ident) => {{
        let pow2_var = &($expr.pow2);
        let zero = M31Var::zero(&pow2_var.cs());
        for entry in cairo_air::components::$component_name::RELATION_USES_PER_ROW {
            let cur = $relation_uses.get(entry.relation_id).unwrap_or(&zero);
            let new = pow2_var.mul_constant(M31::from(entry.uses as u32));
            $relation_uses.insert(entry.relation_id, cur.add_assert_no_overflow(&new));
        }
    }};
}

#[derive(Debug, Clone)]
pub struct OpcodeClaimVar {
    pub add: LogSizeVar,
    pub add_small: LogSizeVar,
    pub add_ap: LogSizeVar,
    pub assert_eq: LogSizeVar,
    pub assert_eq_imm: LogSizeVar,
    pub assert_eq_double_deref: LogSizeVar,
    pub blake: LogSizeVar,
    pub call: LogSizeVar,
    pub call_rel_imm: LogSizeVar,
    pub jnz: LogSizeVar,
    pub jnz_taken: LogSizeVar,
    pub jump_rel: LogSizeVar,
    pub jump_rel_imm: LogSizeVar,
    pub mul: LogSizeVar,
    pub mul_small: LogSizeVar,
    pub qm31: LogSizeVar,
    pub ret: LogSizeVar,
}

impl Var for OpcodeClaimVar {
    type Value = OpcodeClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.add.cs()
    }
}

impl AllocVar for OpcodeClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let add = LogSizeVar::new_variables(cs, &value.add[0].log_size, mode);
        let add_small = LogSizeVar::new_variables(cs, &value.add_small[0].log_size, mode);
        let add_ap = LogSizeVar::new_variables(cs, &value.add_ap[0].log_size, mode);
        let assert_eq = LogSizeVar::new_variables(cs, &value.assert_eq[0].log_size, mode);
        let assert_eq_imm = LogSizeVar::new_variables(cs, &value.assert_eq_imm[0].log_size, mode);
        let assert_eq_double_deref =
            LogSizeVar::new_variables(cs, &value.assert_eq_double_deref[0].log_size, mode);
        let blake = LogSizeVar::new_variables(cs, &value.blake[0].log_size, mode);
        let call = LogSizeVar::new_variables(cs, &value.call[0].log_size, mode);
        let call_rel_imm = LogSizeVar::new_variables(cs, &value.call_rel_imm[0].log_size, mode);
        let jnz = LogSizeVar::new_variables(cs, &value.jnz[0].log_size, mode);
        let jnz_taken = LogSizeVar::new_variables(cs, &value.jnz_taken[0].log_size, mode);
        let jump_rel = LogSizeVar::new_variables(cs, &value.jump_rel[0].log_size, mode);
        let jump_rel_imm = LogSizeVar::new_variables(cs, &value.jump_rel_imm[0].log_size, mode);
        let mul = LogSizeVar::new_variables(cs, &value.mul[0].log_size, mode);
        let mul_small = LogSizeVar::new_variables(cs, &value.mul_small[0].log_size, mode);
        let qm31 = LogSizeVar::new_variables(cs, &value.qm31[0].log_size, mode);
        let ret = LogSizeVar::new_variables(cs, &value.ret[0].log_size, mode);

        Self {
            add,
            add_small,
            add_ap,
            assert_eq,
            assert_eq_imm,
            assert_eq_double_deref,
            blake,
            call,
            call_rel_imm,
            jnz,
            jnz_taken,
            jump_rel,
            jump_rel_imm,
            mul,
            mul_small,
            qm31,
            ret,
        }
    }
}

impl OpcodeClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.add.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.add_small.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.add_ap.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.assert_eq.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.assert_eq_imm.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.assert_eq_double_deref.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.blake.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.call.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.call_rel_imm.mix_into(channel);
        channel.mix_one_felt(&QM31Var::zero(&self.cs()));
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.jnz.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.jnz_taken.mix_into(channel);
        channel.mix_one_felt(&QM31Var::zero(&self.cs()));
        channel.mix_one_felt(&QM31Var::zero(&self.cs()));
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.jump_rel.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.jump_rel_imm.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.mul.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.mul_small.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.qm31.mix_into(channel);
        channel.mix_one_felt(&QM31Var::one(&self.cs()));
        self.ret.mix_into(channel);
    }

    pub fn accumulate_relation_uses(&self, relation_uses: &mut HashMap<&str, M31Var>) {
        accumulate_component!(add_opcode, self.add, relation_uses);
        accumulate_component!(add_opcode_small, self.add_small, relation_uses);
        accumulate_component!(add_ap_opcode, self.add_ap, relation_uses);
        accumulate_component!(assert_eq_opcode, self.assert_eq, relation_uses);
        accumulate_component!(assert_eq_opcode_imm, self.assert_eq_imm, relation_uses);
        accumulate_component!(
            assert_eq_opcode_double_deref,
            self.assert_eq_double_deref,
            relation_uses
        );
        accumulate_component!(blake_compress_opcode, self.blake, relation_uses);
        accumulate_component!(call_opcode_abs, self.call, relation_uses);
        accumulate_component!(call_opcode_rel_imm, self.call_rel_imm, relation_uses);
        accumulate_component!(jnz_opcode_non_taken, self.jnz, relation_uses);
        accumulate_component!(jnz_opcode_taken, self.jnz_taken, relation_uses);
        accumulate_component!(jump_opcode_rel, self.jump_rel, relation_uses);
        accumulate_component!(jump_opcode_rel_imm, self.jump_rel_imm, relation_uses);
        accumulate_component!(mul_opcode, self.mul, relation_uses);
        accumulate_component!(mul_opcode_small, self.mul_small, relation_uses);
        accumulate_component!(qm_31_add_mul_opcode, self.qm31, relation_uses);
        accumulate_component!(ret_opcode, self.ret, relation_uses);
    }

    pub fn max_log_size(&self) -> M31Var {
        let mut max = self.add.m31.clone();
        max = max.max(&self.add_small.m31, 5);
        max = max.max(&self.add_ap.m31, 5);
        max = max.max(&self.assert_eq.m31, 5);
        max = max.max(&self.assert_eq_imm.m31, 5);
        max = max.max(&self.assert_eq_double_deref.m31, 5);
        max = max.max(&self.blake.m31, 5);
        max = max.max(&self.call.m31, 5);
        max = max.max(&self.call_rel_imm.m31, 5);
        max = max.max(&self.jnz.m31, 5);
        max = max.max(&self.jnz_taken.m31, 5);
        max = max.max(&self.jump_rel.m31, 5);
        max = max.max(&self.jump_rel_imm.m31, 5);
        max = max.max(&self.mul.m31, 5);
        max = max.max(&self.mul_small.m31, 5);
        max = max.max(&self.qm31.m31, 5);
        max = max.max(&self.ret.m31, 5);

        max
    }
}

#[derive(Debug, Clone)]
pub struct BlakeContextClaimVar {
    pub blake_round: LogSizeVar,
    pub blake_g: LogSizeVar,
    pub triple_xor_32: LogSizeVar,
}

impl Var for BlakeContextClaimVar {
    type Value = BlakeContextClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.blake_round.cs()
    }
}

impl AllocVar for BlakeContextClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let value = value.claim.as_ref().unwrap();

        let blake_round = LogSizeVar::new_variables(cs, &value.blake_round.log_size, mode);
        let blake_g = LogSizeVar::new_variables(cs, &value.blake_g.log_size, mode);
        let triple_xor_32 = LogSizeVar::new_variables(cs, &value.triple_xor_32.log_size, mode);
        Self {
            blake_round,
            blake_g,
            triple_xor_32,
        }
    }
}

impl BlakeContextClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.blake_round.mix_into(channel);
        self.blake_g.mix_into(channel);
        self.triple_xor_32.mix_into(channel);
    }

    pub fn accumulate_relation_uses(&self, relation_uses: &mut HashMap<&str, M31Var>) {
        accumulate_component!(blake_round, self.blake_round, relation_uses);
        accumulate_component!(blake_g, self.blake_g, relation_uses);
        accumulate_component!(triple_xor_32, self.triple_xor_32, relation_uses);
    }

    pub fn max_log_size(&self) -> M31Var {
        let mut max = self.blake_round.m31.clone();
        max = max.max(&self.blake_g.m31, 5);
        max = max.max(&self.triple_xor_32.m31, 5);

        max
    }
}

#[derive(Debug, Clone)]
pub struct BuiltinsClaimVar {
    pub range_check_128_builtin_log_size: LogSizeVar,
    pub range_check_builtin_segment_start: BitIntVar<31>,
}

impl Var for BuiltinsClaimVar {
    type Value = BuiltinsClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.range_check_128_builtin_log_size.cs()
    }
}

impl AllocVar for BuiltinsClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let range_check_128_builtin_log_size = LogSizeVar::new_variables(
            cs,
            &value.range_check_128_builtin.as_ref().unwrap().log_size,
            mode,
        );
        let range_check_builtin_segment_start: BitIntVar<31> = BitIntVar::<31>::new_variables(
            cs,
            &(value
                .range_check_128_builtin
                .as_ref()
                .unwrap()
                .range_check_builtin_segment_start as u64),
            mode,
        );
        Self {
            range_check_128_builtin_log_size,
            range_check_builtin_segment_start,
        }
    }
}

impl BuiltinsClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.range_check_128_builtin_log_size.mix_into(channel);
        self.range_check_builtin_segment_start.mix_into(channel);
    }

    pub fn max_log_size(&self) -> M31Var {
        self.range_check_128_builtin_log_size.m31.clone()
    }
}

#[derive(Debug, Clone)]
pub struct MemoryIdToBigClaimVar {
    pub big_log_size: LogSizeVar,
    pub small_log_size: LogSizeVar,
}

impl Var for MemoryIdToBigClaimVar {
    type Value = memory_id_to_big::Claim;

    fn cs(&self) -> ConstraintSystemRef {
        self.big_log_size.cs()
    }
}

impl AllocVar for MemoryIdToBigClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let big_log_size = LogSizeVar::new_variables(cs, &value.big_log_sizes[0], mode);
        let small_log_size = LogSizeVar::new_variables(cs, &value.small_log_size, mode);
        Self {
            big_log_size,
            small_log_size,
        }
    }
}

impl MemoryIdToBigClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.big_log_size.mix_into(channel);
        self.small_log_size.mix_into(channel);
    }

    pub fn max_log_size(&self) -> M31Var {
        let mut max = self.big_log_size.m31.clone();
        max = max.max(&self.small_log_size.m31, 5);

        max
    }
}

#[derive(Debug, Clone)]
pub struct CairoClaimVar {
    pub cs: ConstraintSystemRef,
    pub public_data: PublicDataVar,
    pub opcode_claim: OpcodeClaimVar,
    pub verify_instruction: LogSizeVar,
    pub blake_context: BlakeContextClaimVar,
    pub builtins: BuiltinsClaimVar,
    pub memory_address_to_id: LogSizeVar,
    pub memory_id_to_value: MemoryIdToBigClaimVar,
}

impl Var for CairoClaimVar {
    type Value = CairoClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for CairoClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let public_data = PublicDataVar::new_variables(cs, &value.public_data, mode);
        let opcode_claim = OpcodeClaimVar::new_variables(cs, &value.opcodes, mode);
        let verify_instruction =
            LogSizeVar::new_variables(cs, &value.verify_instruction.log_size, mode);
        let blake_context = BlakeContextClaimVar::new_variables(cs, &value.blake_context, mode);
        let builtins = BuiltinsClaimVar::new_variables(cs, &value.builtins, mode);
        let memory_address_to_id =
            LogSizeVar::new_variables(cs, &value.memory_address_to_id.log_size, mode);
        let memory_id_to_value =
            MemoryIdToBigClaimVar::new_variables(cs, &value.memory_id_to_value, mode);
        Self {
            cs: cs.clone(),
            public_data,
            opcode_claim,
            verify_instruction,
            blake_context,
            builtins,
            memory_address_to_id,
            memory_id_to_value,
        }
    }
}

impl CairoClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.public_data.mix_into(channel);
        self.opcode_claim.mix_into(channel);
        self.verify_instruction.mix_into(channel);
        self.blake_context.mix_into(channel);
        self.builtins.mix_into(channel);
        self.memory_address_to_id.mix_into(channel);
        self.memory_id_to_value.mix_into(channel);
    }

    pub fn accumulate_relation_uses(&self, relation_uses: &mut HashMap<&str, M31Var>) {
        self.opcode_claim.accumulate_relation_uses(relation_uses);
        accumulate_component!(
            range_check_builtin_bits_128,
            self.builtins.range_check_128_builtin_log_size,
            relation_uses
        );
        accumulate_component!(verify_instruction, self.verify_instruction, relation_uses);
        self.blake_context.accumulate_relation_uses(relation_uses);

        let m31_var = self.memory_id_to_value.big_log_size.to_m31();
        let zero = M31Var::zero(&m31_var.cs());
        for entry in cairo_air::components::memory_id_to_big::RELATION_USES_PER_ROW_BIG {
            let cur = relation_uses.get(entry.relation_id).unwrap_or(&zero);
            let new = m31_var.exp2().mul_constant(M31::from(entry.uses as u32));
            relation_uses.insert(entry.relation_id, cur.add_assert_no_overflow(&new));
        }
        let m31_var = self.memory_id_to_value.small_log_size.to_m31();
        for entry in cairo_air::components::memory_id_to_big::RELATION_USES_PER_ROW_SMALL {
            let cur = relation_uses.get(entry.relation_id).unwrap_or(&zero);
            let new = m31_var.exp2().mul_constant(M31::from(entry.uses as u32));
            relation_uses.insert(entry.relation_id, cur.add_assert_no_overflow(&new));
        }
    }

    pub fn max_trace_and_interaction_log_size(&self) -> M31Var {
        let mut max = self.opcode_claim.max_log_size();
        max = max.max(&self.verify_instruction.m31, 5);
        max = max.max(&self.blake_context.max_log_size(), 5);
        max = max.max(&self.builtins.max_log_size(), 5);
        max = max.max(&self.memory_address_to_id.m31, 5);
        max = max.max(&self.memory_id_to_value.max_log_size(), 5);
        max
    }
}
