use cairo_air::{air::{MemorySection, MemorySmallValue, PublicData, PublicMemory, PublicSegmentRanges, SegmentRange}, blake::air::BlakeContextClaim, builtins_air::BuiltinsClaim, components::memory_id_to_big, opcodes_air::OpcodeClaim};
use circle_plonk_dsl_channel::ChannelVar;
use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::{AllocVar, AllocationMode, Var}};
use circle_plonk_dsl_fields::{M31Var, QM31Var};
use stwo::core::fields::m31::M31;
use stwo_cairo_common::prover_types::cpu::CasmState;

#[derive(Debug, Clone)]
pub struct ChannelU64Var (pub [M31Var; 3]);

impl Var for ChannelU64Var {
    type Value = u64;

    fn cs(&self) -> ConstraintSystemRef {
        self.0[0].cs()
    }
}

impl AllocVar for ChannelU64Var {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let value = [M31Var::new_variables(
                cs,
                &M31::from((value & ((1 << 22) - 1)) as u32),
                mode,
            ),
            M31Var::new_variables(
                cs,
                &M31::from(((value >> 22) & ((1 << 21) - 1)) as u32),
                mode,
            ),
            M31Var::new_variables(
                cs,
                &M31::from(((value >> 43) & ((1 << 21) - 1)) as u32),
                mode,
            ),
        ];
        Self(value)
    }
}

impl ChannelU64Var {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        let felt = QM31Var::from_m31(
            &self.0[0],
            &self.0[1],
            &self.0[2],
            &M31Var::zero(&self.cs()),
        );
        channel.mix_one_felt(&felt);
    }

    pub fn enforce_equal(&self, other: &ChannelU64Var) {
        self.0[0].equalverify(&other.0[0]);
        self.0[1].equalverify(&other.0[1]);
        self.0[2].equalverify(&other.0[2]);
    }

    pub fn enforce_not_equal(&self, other: &ChannelU64Var) {
        let flag0 = self.0[0].is_eq(&other.0[0]);
        let flag1 = self.0[1].is_eq(&other.0[1]);
        let flag2 = self.0[2].is_eq(&other.0[2]);

        let flag = &(&flag0 * &flag1) * &flag2;
        flag.equalverify(&M31Var::zero(&self.cs()));
    }
}


#[derive(Debug, Clone)]
pub struct ChannelU22Var (pub M31Var);

impl Var for ChannelU22Var {
    type Value = u32;

    fn cs(&self) -> ConstraintSystemRef {
        self.0.cs()
    }
}

impl AllocVar for ChannelU22Var {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let value = M31Var::new_variables(
            cs,
            &M31::from(*value as u32),
            mode,);
        Self(value)
    }
}

impl ChannelU22Var {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        let felt = QM31Var::from_m31(
            &self.0,
            &M31Var::zero(&self.cs()),
            &M31Var::zero(&self.cs()),
            &M31Var::zero(&self.cs()),
        );
        channel.mix_one_felt(&felt);
    }

    pub fn enforce_equal(&self, other: &ChannelU22Var) {
        self.0.equalverify(&other.0);
    }

    pub fn enforce_not_equal(&self, other: &ChannelU22Var) {
        let flag = self.0.is_eq(&other.0);
        flag.equalverify(&M31Var::zero(&self.cs()));
    }
}

#[derive(Debug, Clone)]
pub struct PublicSegmentRangesVar {
    pub output: SegmentRangeVar,
    pub pedersen: SegmentRangeVar,
    pub range_check_128: SegmentRangeVar,
    pub ecdsa: SegmentRangeVar,
    pub bitwise: SegmentRangeVar,
    pub ec_op: SegmentRangeVar,
    pub keccak: SegmentRangeVar,
    pub poseidon: SegmentRangeVar,
    pub range_check_96: SegmentRangeVar,
    pub add_mod: SegmentRangeVar,
    pub mul_mod: SegmentRangeVar,
}

impl Var for PublicSegmentRangesVar {
    type Value = PublicSegmentRanges;

    fn cs(&self) -> ConstraintSystemRef {
        self.output.cs()
    }
}

impl AllocVar for PublicSegmentRangesVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let output = SegmentRangeVar::new_variables(cs, &value.output, mode);

        let pedersen = SegmentRangeVar::new_variables(cs, &value.pedersen.as_ref().unwrap(), mode);
        let range_check_128 = SegmentRangeVar::new_variables(cs, &value.range_check_128.as_ref().unwrap(), mode);
        let ecdsa = SegmentRangeVar::new_variables(cs, &value.ecdsa.as_ref().unwrap(), mode);
        let bitwise = SegmentRangeVar::new_variables(cs, &value.bitwise.as_ref().unwrap(), mode);
        let ec_op = SegmentRangeVar::new_variables(cs, &value.ec_op.as_ref().unwrap(), mode);
        let keccak = SegmentRangeVar::new_variables(cs, &value.keccak.as_ref().unwrap(), mode);
        let poseidon = SegmentRangeVar::new_variables(cs, &value.poseidon.as_ref().unwrap(), mode);
        let range_check_96 = SegmentRangeVar::new_variables(cs, &value.range_check_96.as_ref().unwrap(), mode);
        let add_mod = SegmentRangeVar::new_variables(cs, &value.add_mod.as_ref().unwrap(), mode);
        let mul_mod = SegmentRangeVar::new_variables(cs, &value.mul_mod.as_ref().unwrap(), mode);
        
        Self { output, pedersen, range_check_128, ecdsa, bitwise, ec_op, keccak, poseidon, range_check_96, add_mod, mul_mod }
    }
}

impl PublicSegmentRangesVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.output.mix_into(channel);
        self.pedersen.mix_into(channel);
        self.range_check_128.mix_into(channel);
        self.ecdsa.mix_into(channel);
        self.bitwise.mix_into(channel);
        self.ec_op.mix_into(channel);
        self.keccak.mix_into(channel);
        self.poseidon.mix_into(channel);
        self.range_check_96.mix_into(channel);
        self.add_mod.mix_into(channel);
        self.mul_mod.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct SegmentRangeVar {
    pub start_ptr: MemorySmallValueVar,
    pub stop_ptr: MemorySmallValueVar,
}

impl Var for SegmentRangeVar {
    type Value = SegmentRange;

    fn cs(&self) -> ConstraintSystemRef {
        self.start_ptr.cs()
    }
}

impl AllocVar for SegmentRangeVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let start_ptr = MemorySmallValueVar::new_variables(cs, &value.start_ptr, mode);
        let stop_ptr = MemorySmallValueVar::new_variables(cs, &value.stop_ptr, mode);
        Self { start_ptr, stop_ptr }
    }
}

impl SegmentRangeVar {
    pub fn enforce_is_empty(&self) {
        self.start_ptr.value.enforce_equal(&self.stop_ptr.value);
    }

    pub fn enforce_is_not_empty(&self) {
        self.start_ptr.value.enforce_not_equal(&self.stop_ptr.value);
    }
}

impl SegmentRangeVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.start_ptr.mix_into(channel);
        self.stop_ptr.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct MemorySmallValueVar {
    pub id: ChannelU64Var,
    pub value: ChannelU64Var,
}

impl Var for MemorySmallValueVar {
    type Value = MemorySmallValue;

    fn cs(&self) -> ConstraintSystemRef {
        self.id.cs()
    }
}

impl AllocVar for MemorySmallValueVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let id = ChannelU64Var::new_variables(cs, &(value.id as u64), mode);
        let value = ChannelU64Var::new_variables(cs, &(value.value as u64), mode);
        Self { id, value }
    }
}

impl MemorySmallValueVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.id.mix_into(channel);
        self.value.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct CasmStateVar {
    pub pc: ChannelU64Var,
    pub ap: ChannelU64Var,
    pub fp: ChannelU64Var,
}

impl Var for CasmStateVar {
    type Value = CasmState;

    fn cs(&self) -> ConstraintSystemRef {
        self.pc.cs()
    }
}

impl AllocVar for CasmStateVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let pc = ChannelU64Var::new_variables(cs, &(value.pc.0 as u64), mode);
        let ap = ChannelU64Var::new_variables(cs, &(value.ap.0 as u64), mode);
        let fp = ChannelU64Var::new_variables(cs, &(value.fp.0 as u64), mode);

        Self {
            pc,
            ap,
            fp,
        }
    }
}

impl CasmStateVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.pc.mix_into(channel);
        self.ap.mix_into(channel);
        self.fp.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct PublicDataVar {
    pub public_memory: PublicMemoryVar,
    pub initial_state: CasmStateVar,
    pub final_state: CasmStateVar,
}

impl Var for PublicDataVar {
    type Value = PublicData;

    fn cs(&self) -> ConstraintSystemRef {
        self.public_memory.cs()
    }
}

impl AllocVar for PublicDataVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let public_memory = PublicMemoryVar::new_variables(cs, &value.public_memory, mode);
        let initial_state = CasmStateVar::new_variables(cs, &value.initial_state, mode);
        let final_state = CasmStateVar::new_variables(cs, &value.final_state, mode);

        Self {
            public_memory,
            initial_state,
            final_state,
        }
    }
}

impl PublicDataVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.public_memory.mix_into(channel);
        self.initial_state.mix_into(channel);
        self.final_state.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct PublicMemoryVar {
    pub public_segments: PublicSegmentRangesVar,
    pub output: MemorySectionVar,
    pub safe_call_ids: [ChannelU64Var; 2],
}

impl Var for PublicMemoryVar {
    type Value = PublicMemory;

    fn cs(&self) -> ConstraintSystemRef {
        self.public_segments.cs()
    }
}

impl AllocVar for PublicMemoryVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let public_segments = PublicSegmentRangesVar::new_variables(cs, &value.public_segments, mode);
        let output = MemorySectionVar::new_variables(cs, &value.output, mode);
        let safe_call_ids = value.safe_call_ids.map(|id| ChannelU64Var::new_variables(cs, &(id as u64), mode));
        Self { public_segments, output, safe_call_ids }
    }
}

impl PublicMemoryVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.public_segments.mix_into(channel);
        self.output.mix_into(channel);
        self.safe_call_ids.iter().for_each(|id| id.mix_into(channel));
    }
}

#[derive(Debug, Clone)]
pub struct MemorySectionVar {
    pub ids: Vec<ChannelU64Var>,
    pub values: Vec<[ChannelU64Var; 8]>,
}

impl Var for MemorySectionVar {
    type Value = MemorySection;

    fn cs(&self) -> ConstraintSystemRef {
        self.ids[0].cs()
    }
}

impl AllocVar for MemorySectionVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let ids = value.iter().map(|(id, _)| ChannelU64Var::new_variables(cs, &(*id as u64), mode)).collect();
        let values = value.iter().map(|(_, value)| [
            ChannelU64Var::new_variables(cs, &(value[0] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[1] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[2] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[3] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[4] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[5] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[6] as u64), mode),
            ChannelU64Var::new_variables(cs, &(value[7] as u64), mode),
        ]).collect();
        Self { ids, values }
    }
}

impl MemorySectionVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.ids.iter().for_each(|id| id.mix_into(channel));
        self.values.iter().for_each(|value| value.iter().for_each(|v| v.mix_into(channel)));
    }
}

pub struct ClaimLogVar(pub ChannelU22Var);

#[derive(Debug, Clone)]
pub struct OpcodeClaimVar {
    pub add: ChannelU22Var,
    pub add_small: ChannelU22Var,
    pub add_ap: ChannelU22Var,
    pub assert_eq: ChannelU22Var,
    pub assert_eq_imm: ChannelU22Var,
    pub assert_eq_double_deref: ChannelU22Var,
    pub blake: ChannelU22Var,
    pub call: ChannelU22Var,
    pub call_rel_imm: ChannelU22Var,
    pub jnz: ChannelU22Var,
    pub jnz_taken: ChannelU22Var,
    pub jump_rel: ChannelU22Var,
    pub jump_rel_imm: ChannelU22Var,
    pub mul: ChannelU22Var,
    pub mul_small: ChannelU22Var,
    pub qm31: ChannelU22Var,
    pub ret: ChannelU22Var,
}

impl Var for OpcodeClaimVar {
    type Value = OpcodeClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.add.cs()
    }
}

impl AllocVar for OpcodeClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let add = ChannelU22Var::new_variables(cs, &(value.add[0].log_size as u32), mode);
        let add_small = ChannelU22Var::new_variables(cs, &(value.add_small[0].log_size as u32), mode);
        let add_ap = ChannelU22Var::new_variables(cs, &(value.add_ap[0].log_size as u32), mode);
        let assert_eq = ChannelU22Var::new_variables(cs, &(value.assert_eq[0].log_size as u32), mode);
        let assert_eq_imm = ChannelU22Var::new_variables(cs, &(value.assert_eq_imm[0].log_size as u32), mode);
        let assert_eq_double_deref = ChannelU22Var::new_variables(cs, &(value.assert_eq_double_deref[0].log_size as u32), mode);
        let blake = ChannelU22Var::new_variables(cs, &(value.blake[0].log_size as u32), mode);
        let call = ChannelU22Var::new_variables(cs, &(value.call[0].log_size as u32), mode);
        let call_rel_imm = ChannelU22Var::new_variables(cs, &(value.call_rel_imm[0].log_size as u32), mode);
        let jnz = ChannelU22Var::new_variables(cs, &(value.jnz[0].log_size as u32), mode);
        let jnz_taken = ChannelU22Var::new_variables(cs, &(value.jnz_taken[0].log_size as u32), mode);
        let jump_rel = ChannelU22Var::new_variables(cs, &(value.jump_rel[0].log_size as u32), mode);
        let jump_rel_imm = ChannelU22Var::new_variables(cs, &(value.jump_rel_imm[0].log_size as u32), mode);
        let mul = ChannelU22Var::new_variables(cs, &(value.mul[0].log_size as u32), mode);
        let mul_small = ChannelU22Var::new_variables(cs, &(value.mul_small[0].log_size as u32), mode);
        let qm31 = ChannelU22Var::new_variables(cs, &(value.qm31[0].log_size as u32), mode);
        let ret = ChannelU22Var::new_variables(cs, &(value.ret[0].log_size as u32), mode);

        Self { add, add_small, add_ap, assert_eq, assert_eq_imm, assert_eq_double_deref, blake, call, call_rel_imm, jnz, jnz_taken, jump_rel, jump_rel_imm, mul, mul_small, qm31, ret }
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
}

#[derive(Debug, Clone)]
pub struct BlakeContextClaimVar { 
    pub blake_round: ChannelU22Var,
    pub blake_g: ChannelU22Var,
    pub triple_xor_32: ChannelU22Var,
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

        let blake_round = ChannelU22Var::new_variables(cs, &(value.blake_round.log_size as u32), mode);
        let blake_g = ChannelU22Var::new_variables(cs, &(value.blake_g.log_size as u32), mode);
        let triple_xor_32 = ChannelU22Var::new_variables(cs, &(value.triple_xor_32.log_size as u32), mode);
        Self { blake_round, blake_g, triple_xor_32 }
    }
}

impl BlakeContextClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.blake_round.mix_into(channel);
        self.blake_g.mix_into(channel);
        self.triple_xor_32.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct BuiltinsClaimVar {
    pub range_check_128_builtin_log_size: ChannelU22Var,
    pub range_check_builtin_segment_start: ChannelU64Var,
}

impl Var for BuiltinsClaimVar {
    type Value = BuiltinsClaim;

    fn cs(&self) -> ConstraintSystemRef {
        self.range_check_128_builtin_log_size.cs()
    }
}

impl AllocVar for BuiltinsClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let range_check_128_builtin_log_size = ChannelU22Var::new_variables(cs, &(value.range_check_128_builtin.as_ref().unwrap().log_size as u32), mode);
        let range_check_builtin_segment_start = ChannelU64Var::new_variables(cs, &(value.range_check_128_builtin.as_ref().unwrap().range_check_builtin_segment_start as u64), mode);
        Self { range_check_128_builtin_log_size, range_check_builtin_segment_start }
    }
}

impl BuiltinsClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.range_check_128_builtin_log_size.mix_into(channel);
        self.range_check_builtin_segment_start.mix_into(channel);
    }
}

#[derive(Debug, Clone)]
pub struct MemoryIdToBigClaimVar {
    pub big_log_size: ChannelU22Var,
    pub small_log_size: ChannelU22Var,
}

impl Var for MemoryIdToBigClaimVar {
    type Value = memory_id_to_big::Claim;

    fn cs(&self) -> ConstraintSystemRef {
        self.big_log_size.cs()
    }
}

impl AllocVar for MemoryIdToBigClaimVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let big_log_size = ChannelU22Var::new_variables(cs, &(value.big_log_sizes[0] as u32), mode);
        let small_log_size = ChannelU22Var::new_variables(cs, &(value.small_log_size as u32), mode);
        Self { big_log_size, small_log_size }
    }
}

impl MemoryIdToBigClaimVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.big_log_size.mix_into(channel);
        self.small_log_size.mix_into(channel);
    }
}