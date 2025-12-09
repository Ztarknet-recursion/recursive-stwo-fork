use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::HashVar;
use circle_plonk_dsl_primitives::QM31Var;
use stwo::core::{
    pcs::TreeVec, proof::StarkProof, vcs::poseidon31_merkle::Poseidon31MerkleHasher, ColumnVec,
};

#[derive(Debug, Clone)]
pub struct StarkProofVar {
    pub cs: ConstraintSystemRef,

    pub trace_commitment: HashVar,
    pub interaction_commitment: HashVar,
    pub composition_commitment: HashVar,

    pub sampled_values: TreeVec<ColumnVec<Vec<QM31Var>>>,
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

        let mut sampled_values = TreeVec::new(vec![]);
        for round in value.sampled_values.iter() {
            let mut round_res = ColumnVec::new();
            for column in round.iter() {
                let mut column_res = Vec::with_capacity(column.len());
                for eval in column.iter() {
                    column_res.push(QM31Var::new_variables(cs, eval, mode));
                }
                round_res.push(column_res);
            }
            sampled_values.push(round_res);
        }

        Self {
            cs: cs.clone(),
            trace_commitment,
            interaction_commitment,
            composition_commitment,
            sampled_values,
        }
    }
}
