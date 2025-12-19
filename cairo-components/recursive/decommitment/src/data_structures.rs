mod composition;
mod interaction;
mod preprocessed;
mod trace;

pub use composition::*;
pub use interaction::*;
pub use preprocessed::PreprocessedTraceQueryResultVar;
pub use trace::*;

use cairo_plonk_dsl_hints::QueryDecommitmentProof;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    BitVar, BitsVar, HashVar, M31Var, Poseidon2HalfVar, Poseidon31MerkleHasherVar, QM31Var,
};
use indexmap::IndexMap;
use stwo::core::fields::m31::M31;

pub struct QueryDecommitmentProofVar {
    pub cs: ConstraintSystemRef,
    pub leaf_values: Vec<M31Var>,
    pub intermediate_layers: IndexMap<usize, (Poseidon2HalfVar, Poseidon2HalfVar)>,
}

impl Var for QueryDecommitmentProofVar {
    type Value = QueryDecommitmentProof;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for QueryDecommitmentProofVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        let mut intermediate_layers = IndexMap::new();
        let mut leaf_values = vec![];
        for value in value.leaf_values.iter() {
            leaf_values.push(M31Var::new_variables(cs, value, mode));
        }
        for (log_size, node) in value.intermediate_layers.iter() {
            let layer = AllocVar::new_variables(cs, &node.children, mode);
            intermediate_layers.insert(*log_size, layer);
        }
        Self {
            cs: cs.clone(),
            leaf_values,
            intermediate_layers,
        }
    }
}

impl QueryDecommitmentProofVar {
    pub fn verify(
        &self,
        log_blowup_factor: u32,
        query: &BitsVar,
        root: &HashVar,
        max_included_log_size: &M31Var,
        column_hashes: &IndexMap<usize, Poseidon2HalfVar>,
    ) {
        let cs = self.cs();
        let bottom_layer_log_size = *self.intermediate_layers.keys().max().unwrap();

        let mut expected_hash = if self.leaf_values.is_empty() {
            [QM31Var::zero(&cs), QM31Var::zero(&cs)]
        } else {
            Poseidon31MerkleHasherVar::hash_m31_columns_get_rate(&self.leaf_values).to_qm31()
        };

        let mut is_leaves_layer_included = BitVar::new_false(&cs);

        let mut query_bits = query.clone();
        for log_size in (log_blowup_factor as usize..=bottom_layer_log_size).rev() {
            let layer = self.intermediate_layers.get(&log_size).unwrap();

            is_leaves_layer_included = &is_leaves_layer_included
                | &max_included_log_size.is_eq(&M31Var::new_constant(
                    &cs,
                    &M31::from(log_size as i32 + 1 - log_blowup_factor as i32),
                ));

            let left_children = layer.0.to_qm31();
            let right_children = layer.1.to_qm31();
            let target = [
                QM31Var::select(&left_children[0], &right_children[0], &query_bits.0[0]),
                QM31Var::select(&left_children[1], &right_children[1], &query_bits.0[0]),
            ];

            let check = [
                QM31Var::select(&target[0], &expected_hash[0], &is_leaves_layer_included),
                QM31Var::select(&target[1], &expected_hash[1], &is_leaves_layer_included),
            ];

            let mut shifted_bits = query_bits.0[1..].to_vec();
            shifted_bits.push(BitVar::new_false(&cs));
            query_bits = BitsVar::select(
                &query_bits,
                &BitsVar(shifted_bits),
                &is_leaves_layer_included,
            );

            target[0].equalverify(&check[0]);
            target[1].equalverify(&check[1]);

            expected_hash = {
                match column_hashes.get(&(log_size - log_blowup_factor as usize)) {
                    Some(hash_column) => Poseidon31MerkleHasherVar::hash_tree_with_column(
                        &layer.0,
                        &layer.1,
                        hash_column,
                    )
                    .to_qm31(),
                    None => Poseidon31MerkleHasherVar::hash_tree(&layer.0, &layer.1).to_qm31(),
                }
            };
        }

        for log_size in 0..log_blowup_factor as usize {
            let layer = self.intermediate_layers.get(&log_size).unwrap();
            let left_children = layer.0.to_qm31();
            let right_children = layer.1.to_qm31();

            let target = [
                QM31Var::select(&left_children[0], &right_children[0], &query_bits.0[0]),
                QM31Var::select(&left_children[1], &right_children[1], &query_bits.0[0]),
            ];
            target[0].equalverify(&expected_hash[0]);
            target[1].equalverify(&expected_hash[1]);

            expected_hash = Poseidon31MerkleHasherVar::hash_tree(&layer.0, &layer.1).to_qm31();

            query_bits.0.remove(0);
        }

        let root = root.to_qm31();
        expected_hash[0].equalverify(&root[0]);
        expected_hash[1].equalverify(&root[1]);
    }
}
