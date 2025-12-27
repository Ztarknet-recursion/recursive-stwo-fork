mod composition;
mod interaction;
mod preprocessed;
mod trace;

pub use composition::*;
pub use interaction::*;
pub use preprocessed::PreprocessedTraceQueryResultVar;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;
pub use trace::*;

use cairo_plonk_dsl_hints::QueryDecommitmentProof;
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    option::OptionVar, BitVar, BitsVar, HashVar, M31Var, Poseidon2HalfVar,
    Poseidon31MerkleHasherVar, QM31Var,
};
use indexmap::IndexMap;
use stwo::core::{fields::m31::M31, vcs::poseidon31_hash::Poseidon31Hash};

pub struct QueryDecommitmentProofVar {
    pub cs: ConstraintSystemRef,
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

        let max_log_size_present = *value.intermediate_layers.keys().max().unwrap();

        for log_size in (max_log_size_present + 1
            ..(MAX_SEQUENCE_LOG_SIZE + value.log_blowup_factor) as usize)
            .rev()
        {
            intermediate_layers.insert(
                log_size,
                AllocVar::new_variables(
                    cs,
                    &(Poseidon31Hash::default(), Poseidon31Hash::default()),
                    mode,
                ),
            );
        }

        let mut query = value.query;
        let max_included_log_size = value.max_effective_log_size - value.log_blowup_factor;

        let mut query_lsb = IndexMap::new();
        let mut is_layer_included = false;
        for log_size in
            (0_usize..(MAX_SEQUENCE_LOG_SIZE + value.log_blowup_factor) as usize).rev()
        {
            is_layer_included |= max_included_log_size as i32
                == (log_size as i32 + 1 - value.log_blowup_factor as i32);
            query_lsb.insert(log_size, query % 2 == 1);
            if is_layer_included {
                query >>= 1;
            }
        }

        for (log_size, node) in value.intermediate_layers.iter() {
            let lsb = query_lsb.get(log_size).unwrap();
            let (cur, sibling) = if !lsb {
                (node.children.0, node.children.1)
            } else {
                (node.children.1, node.children.0)
            };

            let layer = if mode == AllocationMode::Witness {
                let cur_var = HashVar::new_witness(cs, &cur);
                let sibling_var = HashVar::new_single_use_witness_only(cs, &sibling.0);
                (cur_var, sibling_var)
            } else {
                AllocVar::new_variables(cs, &(cur, sibling), mode)
            };
            intermediate_layers.insert(*log_size, layer);
        }
        Self {
            cs: cs.clone(),
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
        max_tree_log_size: &M31Var,
        max_included_log_size: &M31Var,
        column_hashes: &IndexMap<usize, OptionVar<Poseidon2HalfVar>>,
    ) {
        let cs = self.cs();

        let bottom_layer_log_size = (MAX_SEQUENCE_LOG_SIZE + log_blowup_factor) as usize;

        let mut expected_hash = {
            let capacity = &column_hashes
                .get(&(bottom_layer_log_size - log_blowup_factor as usize))
                .unwrap()
                .value;
            let left = Poseidon2HalfVar::zero(&cs);
            Poseidon2HalfVar::permute_get_rate(&left, capacity).to_qm31()
        };

        let mut is_layer_included = BitVar::new_false(&cs);
        let mut is_layer_present = BitVar::new_false(&cs);

        let mut query_bits = query.clone();
        for log_size in (log_blowup_factor as usize..bottom_layer_log_size).rev() {
            let layer = self.intermediate_layers.get(&log_size).unwrap();

            is_layer_included = &is_layer_included
                | &max_included_log_size.is_eq(&M31Var::new_constant(
                    &cs,
                    &M31::from(log_size as i32 + 1 - log_blowup_factor as i32),
                ));
            is_layer_present = &is_layer_present
                | &max_tree_log_size.is_eq(&M31Var::new_constant(
                    &cs,
                    &M31::from(log_size as i32 + 1 - log_blowup_factor as i32),
                ));

            let target = layer.0.to_qm31();
            let check = [
                QM31Var::select(&target[0], &expected_hash[0], &is_layer_included),
                QM31Var::select(&target[1], &expected_hash[1], &is_layer_included),
            ];

            let swap_bit = query_bits.0[0].clone();

            let mut shifted_bits = query_bits.0[1..].to_vec();
            shifted_bits.push(BitVar::new_false(&cs));
            query_bits = BitsVar::select(&query_bits, &BitsVar(shifted_bits), &is_layer_included);

            target[0].equalverify(&check[0]);
            target[1].equalverify(&check[1]);

            match column_hashes.get(&(log_size - log_blowup_factor as usize)) {
                Some(hash_column) => {
                    let is_hash_column_present = &hash_column.is_some;

                    let case_without_column = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                        &layer.0, &layer.1, &swap_bit,
                    )
                    .to_qm31();

                    let tree_hash = [
                        &case_without_column[0] * &is_layer_present.0,
                        &case_without_column[1] * &is_layer_present.0,
                    ];

                    let case_with_column = Poseidon2HalfVar::permute_get_rate(
                        &Poseidon2HalfVar::from_qm31(&tree_hash[0], &tree_hash[1]),
                        &hash_column.value,
                    )
                    .to_qm31();

                    expected_hash = [
                        QM31Var::select(
                            &case_without_column[0],
                            &case_with_column[0],
                            is_hash_column_present,
                        ),
                        QM31Var::select(
                            &case_without_column[1],
                            &case_with_column[1],
                            is_hash_column_present,
                        ),
                    ];
                }
                None => {
                    expected_hash = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                        &layer.0, &layer.1, &swap_bit,
                    )
                    .to_qm31();
                }
            }
        }

        for log_size in 0..log_blowup_factor as usize {
            let layer = self.intermediate_layers.get(&log_size).unwrap();
            let target = layer.0.to_qm31();
            target[0].equalverify(&expected_hash[0]);
            target[1].equalverify(&expected_hash[1]);

            expected_hash = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                &layer.0,
                &layer.1,
                &query_bits.0[0],
            )
            .to_qm31();

            query_bits.0.remove(0);
        }

        let root = root.to_qm31();
        expected_hash[0].equalverify(&root[0]);
        expected_hash[1].equalverify(&root[1]);
    }
}
