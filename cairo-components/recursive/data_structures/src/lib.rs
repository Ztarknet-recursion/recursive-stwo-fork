use cairo_air::{CairoProof, air::CairoClaim};
use circle_plonk_dsl_channel::ChannelVar;
use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::{AllocVar, AllocationMode, Var}};
use stwo::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;

use crate::{fiat_shamir::{BlakeContextClaimVar, BuiltinsClaimVar, ChannelU64Var, ChannelU22Var, MemoryIdToBigClaimVar, OpcodeClaimVar, PublicDataVar}, stark_proof::StarkProofVar};

pub mod fiat_shamir;
pub mod stark_proof; 
pub mod lookup;
pub mod interaction_claim;

#[derive(Debug, Clone)]
pub struct CairoProofVar {
    pub cs: ConstraintSystemRef,
    pub claim: CairoClaimVar,
    pub stark_proof: StarkProofVar,
    pub interaction_pow: ChannelU64Var,
}

impl Var for CairoProofVar {
    type Value = CairoProof<Poseidon31MerkleHasher>;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for CairoProofVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let stark_proof = StarkProofVar::new_variables(cs, &value.stark_proof, mode);
        let claim = CairoClaimVar::new_constant(cs, &value.claim);
        let interaction_pow = ChannelU64Var::new_variables(cs, &value.interaction_pow, mode);

        Self {
            cs: cs.clone(),
            claim,
            stark_proof,
            interaction_pow,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CairoClaimVar {
    pub cs: ConstraintSystemRef,
    pub public_data: PublicDataVar,
    pub opcode_claim: OpcodeClaimVar,
    pub verify_instruction: ChannelU22Var,
    pub blake_context: BlakeContextClaimVar,
    pub builtins: BuiltinsClaimVar,
    pub memory_address_to_id: ChannelU22Var,
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
        let verify_instruction = ChannelU22Var::new_variables(cs, &(value.verify_instruction.log_size as u32), mode);
        let blake_context = BlakeContextClaimVar::new_variables(cs, &value.blake_context, mode);
        let builtins = BuiltinsClaimVar::new_variables(cs, &value.builtins, mode);
        let memory_address_to_id = ChannelU22Var::new_variables(cs, &(value.memory_address_to_id.log_size as u32), mode);
        let memory_id_to_value = MemoryIdToBigClaimVar::new_variables(cs, &value.memory_id_to_value, mode);
        Self { cs: cs.clone(), public_data, opcode_claim, verify_instruction, blake_context, builtins, memory_address_to_id, memory_id_to_value }
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
}