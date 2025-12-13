use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::QM31Var;
use circle_plonk_dsl_primitives::{BitVar, HashVar};
use num_traits::Zero;
use stwo::core::{
    fields::qm31::QM31, pcs::TreeVec, proof::StarkProof,
    vcs::poseidon31_merkle::Poseidon31MerkleHasher, ColumnVec,
};

#[derive(Debug, Clone)]
pub struct StarkProofVar {
    pub cs: ConstraintSystemRef,

    pub trace_commitment: HashVar,
    pub interaction_commitment: HashVar,
    pub composition_commitment: HashVar,

    pub sampled_values: TreeVec<ColumnVec<Vec<QM31Var>>>,
    pub is_preprocessed_trace_present: ColumnVec<BitVar>,
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
        let mut is_preprocessed_trace_present = ColumnVec::new();

        {
            let mut round_res = ColumnVec::new();
            for column in value.sampled_values[0].iter() {
                if column.len() == 1 {
                    round_res.push(vec![QM31Var::new_variables(cs, &column[0], mode)]);
                    is_preprocessed_trace_present.push(BitVar::new_true(cs));
                } else if column.is_empty() {
                    round_res.push(vec![QM31Var::new_variables(cs, &QM31::zero(), mode)]);
                    is_preprocessed_trace_present.push(BitVar::new_false(cs));
                } else {
                    unimplemented!()
                }
            }
            sampled_values.push(round_res);
        }

        for round in value.sampled_values.iter().skip(1) {
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
            is_preprocessed_trace_present,
        }
    }
}
