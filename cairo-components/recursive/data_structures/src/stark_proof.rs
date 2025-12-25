use cairo_air::PreProcessedTraceVariant;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{BitVar, HashVar};
use circle_plonk_dsl_primitives::{M31Var, QM31Var};
use indexmap::IndexMap;
use num_traits::Zero;
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    fri::FriProof,
    pcs::TreeVec,
    proof::StarkProof,
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
    ColumnVec,
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

use crate::BitIntVar;

#[derive(Debug, Clone)]
pub struct StarkProofVar {
    pub cs: ConstraintSystemRef,

    pub trace_commitment: HashVar,
    pub interaction_commitment: HashVar,
    pub composition_commitment: HashVar,

    pub sampled_values: TreeVec<ColumnVec<Vec<QM31Var>>>,
    pub is_preprocessed_trace_present: ColumnVec<BitVar>,

    pub fri_proof: FriProofVar,
    pub proof_of_work: BitIntVar<64>,
}

impl Var for StarkProofVar {
    type Value = StarkProof<Poseidon31MerkleHasher>;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for StarkProofVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let trace_commitment = HashVar::new_variables(cs, &value.commitments[1], mode);
        let interaction_commitment = HashVar::new_variables(cs, &value.commitments[2], mode);
        let composition_commitment = HashVar::new_variables(cs, &value.commitments[3], mode);

        let mut sampled_values = TreeVec::new(vec![]);
        let mut is_preprocessed_trace_present = ColumnVec::new();

        {
            let mut round_res = ColumnVec::new();
            for column in value.sampled_values[0].iter() {
                if column.len() == 1 {
                    round_res.push(vec![QM31Var::new_variables(cs, &column[0], mode)]);
                    is_preprocessed_trace_present.push(BitVar::new_variables(cs, &true, mode));
                } else if column.is_empty() {
                    round_res.push(vec![QM31Var::new_variables(cs, &QM31::zero(), mode)]);
                    is_preprocessed_trace_present.push(BitVar::new_variables(cs, &false, mode));
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

        let fri_proof = FriProofVar::new_variables(cs, &value.fri_proof, mode);
        let proof_of_work = BitIntVar::<64>::new_variables(cs, &value.proof_of_work, mode);

        Self {
            cs: cs.clone(),
            trace_commitment,
            interaction_commitment,
            composition_commitment,
            sampled_values,
            is_preprocessed_trace_present,
            fri_proof,
            proof_of_work,
        }
    }
}

impl StarkProofVar {
    pub fn max_preprocessed_trace_log_size(&self) -> M31Var {
        let cs = self.cs.clone();
        let preprocessed_trace =
            PreProcessedTraceVariant::CanonicalWithoutPedersen.to_preprocessed_trace();
        let log_sizes = preprocessed_trace.log_sizes();

        assert_eq!(log_sizes.len(), self.is_preprocessed_trace_present.len());

        let mut max = M31Var::zero(&self.cs);
        for (log_size, is_present) in log_sizes
            .iter()
            .zip(self.is_preprocessed_trace_present.iter())
        {
            let current_log_size = M31Var::new_constant(&cs, &M31::from(*log_size));
            let candidate_max = max.max(&current_log_size, 5);
            max = M31Var::select(&max, &candidate_max, &is_present);
        }
        max
    }
}

#[derive(Debug, Clone)]
pub struct FriProofVar {
    pub first_layer: FriLayerProofVar,
    pub inner_layers: IndexMap<u32, FriLayerProofVar>,
    pub last_layer_constant: QM31Var,
}

impl Var for FriProofVar {
    type Value = FriProof<Poseidon31MerkleHasher>;
    fn cs(&self) -> ConstraintSystemRef {
        self.last_layer_constant.cs()
    }
}

impl AllocVar for FriProofVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let first_layer = FriLayerProofVar {
            commitment: HashVar::new_variables(cs, &value.first_layer.commitment, mode),
        };

        let mut inner_layers = IndexMap::new();

        let mut layer_log_size = 1;
        for layer in value.inner_layers.iter().rev() {
            inner_layers.insert(
                layer_log_size,
                FriLayerProofVar {
                    commitment: HashVar::new_variables(cs, &layer.commitment, mode),
                },
            );
            layer_log_size += 1;
        }

        for _ in layer_log_size..=(MAX_SEQUENCE_LOG_SIZE - 1) {
            inner_layers.insert(
                layer_log_size,
                FriLayerProofVar {
                    commitment: HashVar::new_variables(cs, &Poseidon31Hash::default(), mode),
                },
            );
            layer_log_size += 1;
        }

        let last_layer_constant =
            QM31Var::new_variables(cs, &value.last_layer_poly.coeffs[0], mode);

        Self {
            first_layer,
            inner_layers,
            last_layer_constant,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FriLayerProofVar {
    pub commitment: HashVar,
}
