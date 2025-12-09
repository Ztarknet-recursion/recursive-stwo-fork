use cairo_air::air::{
    MemorySection, MemorySmallValue, PublicData, PublicMemory, PublicSegmentRanges, SegmentRange,
};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::ChannelVar;
use stwo_cairo_common::prover_types::cpu::CasmState;

use crate::data_structures::BitIntVar;

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
        let range_check_128 =
            SegmentRangeVar::new_variables(cs, &value.range_check_128.as_ref().unwrap(), mode);
        let ecdsa = SegmentRangeVar::new_variables(cs, &value.ecdsa.as_ref().unwrap(), mode);
        let bitwise = SegmentRangeVar::new_variables(cs, &value.bitwise.as_ref().unwrap(), mode);
        let ec_op = SegmentRangeVar::new_variables(cs, &value.ec_op.as_ref().unwrap(), mode);
        let keccak = SegmentRangeVar::new_variables(cs, &value.keccak.as_ref().unwrap(), mode);
        let poseidon = SegmentRangeVar::new_variables(cs, &value.poseidon.as_ref().unwrap(), mode);
        let range_check_96 =
            SegmentRangeVar::new_variables(cs, &value.range_check_96.as_ref().unwrap(), mode);
        let add_mod = SegmentRangeVar::new_variables(cs, &value.add_mod.as_ref().unwrap(), mode);
        let mul_mod = SegmentRangeVar::new_variables(cs, &value.mul_mod.as_ref().unwrap(), mode);

        Self {
            output,
            pedersen,
            range_check_128,
            ecdsa,
            bitwise,
            ec_op,
            keccak,
            poseidon,
            range_check_96,
            add_mod,
            mul_mod,
        }
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
        Self {
            start_ptr,
            stop_ptr,
        }
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
    pub id: BitIntVar<31>,
    pub value: BitIntVar<31>,
}

impl Var for MemorySmallValueVar {
    type Value = MemorySmallValue;

    fn cs(&self) -> ConstraintSystemRef {
        self.id.cs()
    }
}

impl AllocVar for MemorySmallValueVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let id = BitIntVar::<31>::new_variables(cs, &(value.id as u64), mode);
        let value = BitIntVar::<31>::new_variables(cs, &(value.value as u64), mode);
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
    pub pc: BitIntVar<31>,
    pub ap: BitIntVar<31>,
    pub fp: BitIntVar<31>,
}

impl Var for CasmStateVar {
    type Value = CasmState;

    fn cs(&self) -> ConstraintSystemRef {
        self.pc.cs()
    }
}

impl AllocVar for CasmStateVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let pc = BitIntVar::<31>::new_variables(cs, &(value.pc.0 as u64), mode);
        let ap = BitIntVar::<31>::new_variables(cs, &(value.ap.0 as u64), mode);
        let fp = BitIntVar::<31>::new_variables(cs, &(value.fp.0 as u64), mode);

        Self { pc, ap, fp }
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
    pub safe_call_ids: [BitIntVar<64>; 2],
}

impl Var for PublicMemoryVar {
    type Value = PublicMemory;

    fn cs(&self) -> ConstraintSystemRef {
        self.public_segments.cs()
    }
}

impl AllocVar for PublicMemoryVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let public_segments =
            PublicSegmentRangesVar::new_variables(cs, &value.public_segments, mode);
        let output = MemorySectionVar::new_variables(cs, &value.output, mode);
        let safe_call_ids = value
            .safe_call_ids
            .map(|id| BitIntVar::<64>::new_variables(cs, &(id as u64), mode));
        Self {
            public_segments,
            output,
            safe_call_ids,
        }
    }
}

impl PublicMemoryVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.public_segments.mix_into(channel);
        self.output.mix_into(channel);
        self.safe_call_ids
            .iter()
            .for_each(|id| id.mix_into(channel));
    }
}

#[derive(Debug, Clone)]
pub struct MemorySectionVar {
    pub ids: Vec<BitIntVar<64>>,
    pub values: Vec<[BitIntVar<64>; 8]>,
}

impl Var for MemorySectionVar {
    type Value = MemorySection;

    fn cs(&self) -> ConstraintSystemRef {
        self.ids[0].cs()
    }
}

impl AllocVar for MemorySectionVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let ids = value
            .iter()
            .map(|(id, _)| BitIntVar::<64>::new_variables(cs, &(*id as u64), mode))
            .collect();
        let values = value
            .iter()
            .map(|(_, value)| {
                [
                    BitIntVar::<64>::new_variables(cs, &(value[0] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[1] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[2] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[3] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[4] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[5] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[6] as u64), mode),
                    BitIntVar::<64>::new_variables(cs, &(value[7] as u64), mode),
                ]
            })
            .collect();
        Self { ids, values }
    }
}

impl MemorySectionVar {
    pub fn mix_into(&self, channel: &mut ChannelVar) {
        self.ids.iter().for_each(|id| id.mix_into(channel));
        self.values
            .iter()
            .for_each(|value| value.iter().for_each(|v| v.mix_into(channel)));
    }
}
