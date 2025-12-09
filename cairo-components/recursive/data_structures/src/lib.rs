use cairo_air::CairoProof;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use stwo::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;

use crate::{interaction_claim::CairoInteractionClaimVar, stark_proof::StarkProofVar};

pub mod claim;
pub mod data_structures;
pub mod interaction_claim;
pub mod lookup;
pub mod mask;
pub mod public_data;
pub mod stark_proof;

// Re-export commonly used types
pub use claim::*;
pub use data_structures::BitIntVar;
pub use public_data::PublicDataVar;

#[derive(Debug, Clone)]
pub struct CairoProofVar {
    pub cs: ConstraintSystemRef,
    pub claim: CairoClaimVar,
    pub stark_proof: StarkProofVar,
    pub interaction_pow: BitIntVar<64>,
    pub interaction_claim: CairoInteractionClaimVar,
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
        let interaction_pow = BitIntVar::<64>::new_variables(cs, &value.interaction_pow, mode);
        let interaction_claim =
            CairoInteractionClaimVar::new_variables(cs, &value.interaction_claim, mode);

        Self {
            cs: cs.clone(),
            claim,
            stark_proof,
            interaction_pow,
            interaction_claim,
        }
    }
}
