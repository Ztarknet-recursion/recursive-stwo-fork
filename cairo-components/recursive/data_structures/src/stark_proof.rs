use circle_plonk_dsl_channel::HashVar;
use circle_plonk_dsl_constraint_system::{ConstraintSystemRef, var::{AllocVar, AllocationMode, Var}};
use stwo::core::{proof::StarkProof, vcs::poseidon31_merkle::Poseidon31MerkleHasher};

#[derive(Debug, Clone)]
pub struct StarkProofVar {
    pub cs: ConstraintSystemRef,

    pub trace_commitment: HashVar,
    pub interaction_commitment: HashVar,
    pub composition_commitment: HashVar,
}

impl Var for StarkProofVar {
    type Value = StarkProof<Poseidon31MerkleHasher>;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for StarkProofVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let trace_commitment = HashVar::new_variables(cs, &value.commitments[1].0, mode);
        let interaction_commitment = HashVar::new_variables(cs, &value.commitments[2].0, mode);
        let composition_commitment = HashVar::new_variables(cs, &value.commitments[3].0, mode);

        Self {
            cs: cs.clone(),
            trace_commitment,
            interaction_commitment,
            composition_commitment,
        }
    }
}