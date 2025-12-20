mod composition;
mod interaction;
mod preprocessed;
mod trace;
pub mod utils;

pub use composition::*;
pub use interaction::*;
pub use preprocessed::{read_preprocessed_trace, PreprocessedTraceQueryResult};
pub use trace::*;

use std::collections::BTreeMap;

use cairo_air::CairoProof;
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::core::{
    fields::{
        m31::{BaseField, M31},
        qm31::SECURE_EXTENSION_DEGREE,
    },
    utils::PeekableExt,
    vcs::{
        poseidon31_hash::Poseidon31Hash,
        poseidon31_merkle::Poseidon31MerkleHasher,
        utils::{next_decommitment_node, option_flatten_peekable},
        verifier::{MerkleDecommitment, MerkleVerifier},
        MerkleHasher,
    },
};

use crate::CairoFiatShamirHints;

#[derive(Debug, Clone)]
pub struct QueryDecommitmentProof {
    pub query: usize,
    pub leaf_values: Vec<M31>,
    pub intermediate_layers: IndexMap<usize, QueryDecommitmentNode>,
}

impl QueryDecommitmentProof {
    pub fn leaf_hash(&self) -> Poseidon31Hash {
        if self.leaf_values.is_empty() {
            Poseidon31Hash::default()
        } else {
            Poseidon31MerkleHasher::hash_column_get_capacity(&self.leaf_values)
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryDecommitmentNode {
    pub children: (Poseidon31Hash, Poseidon31Hash),
    pub value: Vec<M31>,
}

impl QueryDecommitmentNode {
    pub fn hash(&self) -> Poseidon31Hash {
        Poseidon31MerkleHasher::hash_node(Some(self.children), &self.value)
    }
}

impl QueryDecommitmentProof {
    pub fn from_stwo_proof(
        merkle_verifier: &MerkleVerifier<Poseidon31MerkleHasher>,
        raw_queries: Vec<usize>,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment<Poseidon31MerkleHasher>,
    ) -> Vec<QueryDecommitmentProof> {
        let mut layers = IndexMap::new();

        let max_log_size = *merkle_verifier.column_log_sizes.iter().max().unwrap();
        let max_effective_log_size = *queries_per_log_size.keys().max().unwrap();

        let mut queried_values = queried_values.into_iter();
        let mut hash_witness = decommitment.hash_witness.into_iter();
        let mut column_witness = decommitment.column_witness.into_iter();

        let mut last_layer_hashes: Option<Vec<(usize, Poseidon31Hash)>> = None;
        for layer_log_size in (0..=max_log_size).rev() {
            let mut layer = IndexMap::new();

            let n_columns_in_layer = *merkle_verifier
                .n_columns_per_log_size
                .get(&layer_log_size)
                .unwrap_or(&0);

            let mut layer_total_queries = vec![];

            let mut prev_layer_queries = last_layer_hashes
                .iter()
                .flatten()
                .map(|(q, _)| *q)
                .collect_vec()
                .into_iter()
                .peekable();
            let mut prev_layer_hashes = last_layer_hashes.as_ref().map(|x| x.iter().peekable());
            let mut layer_column_queries =
                option_flatten_peekable(queries_per_log_size.get(&layer_log_size));

            // Merge previous layer queries and column queries.
            while let Some(node_index) =
                next_decommitment_node(&mut prev_layer_queries, &mut layer_column_queries)
            {
                prev_layer_queries
                    .peek_take_while(|q| q / 2 == node_index)
                    .for_each(drop);

                let node_hashes = prev_layer_hashes.as_mut().map(|prev_layer_hashes| {
                    {
                        // If the left child was not computed, read it from the witness.
                        let left_hash = prev_layer_hashes
                            .next_if(|(index, _)| *index == 2 * node_index)
                            .map(|(_, hash)| *hash)
                            .unwrap_or_else(|| hash_witness.next().unwrap());

                        // If the right child was not computed, read it to from the witness.
                        let right_hash = prev_layer_hashes
                            .next_if(|(index, _)| *index == 2 * node_index + 1)
                            .map(|(_, hash)| *hash)
                            .unwrap_or_else(|| hash_witness.next().unwrap());
                        (left_hash, right_hash)
                    }
                });

                // If the column values were queried, read them from `queried_value`.
                let node_values_iter = match layer_column_queries.next_if_eq(&node_index) {
                    Some(_) => &mut queried_values,
                    None => &mut column_witness,
                };

                let node_values = node_values_iter.take(n_columns_in_layer).collect_vec();
                if node_values.len() != n_columns_in_layer {
                    println!(
                        "node values: {:?}, n_columns_in_layer: {:?}",
                        node_values.len(),
                        n_columns_in_layer
                    );
                    panic!("node values length mismatch");
                }

                layer.insert(
                    node_index,
                    QueryDecommitmentNode {
                        children: node_hashes.unwrap_or_default(),
                        value: node_values.clone(),
                    },
                );

                layer_total_queries.push((
                    node_index,
                    Poseidon31MerkleHasher::hash_node(node_hashes, &node_values),
                ));
            }

            last_layer_hashes = Some(layer_total_queries);
            layers.insert(layer_log_size, layer);
        }

        // Check that all witnesses and values have been consumed.
        if hash_witness.next().is_some() {
            panic!("hash witness not consumed");
        }
        if queried_values.next().is_some() {
            panic!("queried values not consumed");
        }
        if column_witness.next().is_some() {
            panic!("column witness not consumed");
        }

        let [(_, computed_root)] = last_layer_hashes.unwrap().try_into().unwrap();
        if computed_root != merkle_verifier.root {
            panic!("computed root mismatch");
        }

        let mut proofs = vec![];
        for query in raw_queries.iter() {
            let mut nodes = IndexMap::new();
            let mut cur = *query;

            let leaf_values = {
                if max_log_size > max_effective_log_size {
                    vec![]
                } else {
                    cur >>= 1;
                    layers
                        .get(&max_log_size)
                        .unwrap()
                        .get(query)
                        .unwrap()
                        .value
                        .clone()
                }
            };

            for log_size in (0..max_log_size).rev() {
                if log_size > max_effective_log_size {
                    nodes.insert(
                        log_size as usize,
                        QueryDecommitmentNode {
                            children: Default::default(),
                            value: vec![],
                        },
                    );
                } else {
                    let layer = layers.get(&(log_size as u32)).unwrap();
                    let node = layer.get(&cur).unwrap();
                    nodes.insert(log_size as usize, node.clone());
                    cur >>= 1;
                }
            }

            let proof = QueryDecommitmentProof {
                query: *query,
                leaf_values,
                intermediate_layers: nodes,
            };
            proofs.push(proof);
        }
        proofs
    }
}

/// Reads query values from either queried_values or witness based on query positions,
/// organizing them into a pad structure indexed by query position and log size.
///
/// This is a generic function that can be reused for preprocessed trace, trace, composition, etc.
pub fn read_query_values_into_pad(
    log_sizes: &Vec<u32>,
    queried_values: &Vec<M31>,
    witness: &Vec<M31>,
    raw_queries: &Vec<usize>,
    query_positions_per_log_size: &BTreeMap<u32, Vec<usize>>,
    log_blowup_factor: u32,
    n_queries: usize,
) -> Vec<Vec<M31>> {
    let max_included_log_size =
        *query_positions_per_log_size.keys().max().unwrap() - log_blowup_factor;

    let mut pad = vec![vec![M31::default(); log_sizes.len()]; n_queries];

    let log_sizes_sorted = log_sizes
        .iter()
        .filter(|log_size| **log_size <= max_included_log_size)
        .sorted()
        .dedup()
        .cloned()
        .collect::<Vec<_>>();
    let counts_per_log_size = log_sizes.iter().cloned().counts();

    let mut queried_values_iter = queried_values.iter();
    let mut witness_iter = witness.iter();
    for log_size in log_sizes_sorted.iter().rev() {
        let queries = raw_queries
            .iter()
            .map(|query| *query >> (max_included_log_size - *log_size))
            .sorted()
            .dedup()
            .collect::<Vec<_>>();

        for query in queries.iter() {
            let mut results = vec![];

            if query_positions_per_log_size.contains_key(&(*log_size + log_blowup_factor)) {
                for _ in 0..*counts_per_log_size.get(log_size).unwrap() {
                    results.push(*queried_values_iter.next().unwrap());
                }
            } else {
                for _ in 0..*counts_per_log_size.get(log_size).unwrap() {
                    results.push(*witness_iter.next().unwrap());
                }
            }

            for pos in raw_queries
                .iter()
                .positions(|q| *q >> (max_included_log_size - *log_size) == *query)
            {
                for (i, loc) in log_sizes.iter().positions(|l| *l == *log_size).enumerate() {
                    pad[pos][loc] = results[i];
                }
            }
        }
    }
    assert!(queried_values_iter.next().is_none());
    assert!(witness_iter.next().is_none());

    pad
}

pub struct CairoDecommitmentHints {
    pub preprocessed_trace: Vec<PreprocessedTraceQueryResult>,
    pub preprocessed_trace_decommitment_proofs: Vec<QueryDecommitmentProof>,
    pub trace: Vec<TraceQueryResult>,
    pub trace_decommitment_proofs: Vec<QueryDecommitmentProof>,
    pub interaction: Vec<InteractionQueryResult>,
    pub interaction_decommitment_proofs: Vec<QueryDecommitmentProof>,
    pub composition: Vec<CompositionQueryResult>,
    pub composition_decommitment_proofs: Vec<QueryDecommitmentProof>,
}

impl CairoDecommitmentHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Self {
        let preprocessed_trace = read_preprocessed_trace(fiat_shamir_hints, proof);
        let trace = read_trace(fiat_shamir_hints, proof);
        let interaction = read_interaction(fiat_shamir_hints, proof);
        println!(
            "queried_values: {:?}",
            proof.stark_proof.queried_values[2].len()
        );
        println!(
            "queried_values: {:?}",
            proof.stark_proof.queried_values[3].len()
        );

        let column_log_sizes = fiat_shamir_hints.log_sizes[0]
            .iter()
            .map(|log_size| log_size + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            .collect_vec();
        let merkle_verifier =
            MerkleVerifier::new(proof.stark_proof.commitments[0], column_log_sizes);
        let preprocessed_trace_decommitment_proofs = QueryDecommitmentProof::from_stwo_proof(
            &merkle_verifier,
            fiat_shamir_hints.raw_queries.clone(),
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values[0].clone(),
            proof.stark_proof.decommitments[0].clone(),
        );

        let column_log_sizes = fiat_shamir_hints.log_sizes[1]
            .iter()
            .map(|log_size| log_size + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            .collect_vec();
        let merkle_verifier =
            MerkleVerifier::new(proof.stark_proof.commitments[1], column_log_sizes);
        let trace_decommitment_proofs = QueryDecommitmentProof::from_stwo_proof(
            &merkle_verifier,
            fiat_shamir_hints.raw_queries.clone(),
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values[1].clone(),
            proof.stark_proof.decommitments[1].clone(),
        );

        let column_log_sizes = fiat_shamir_hints.log_sizes[2]
            .iter()
            .map(|log_size| log_size + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            .collect_vec();
        let merkle_verifier =
            MerkleVerifier::new(proof.stark_proof.commitments[2], column_log_sizes);
        let interaction_decommitment_proofs = QueryDecommitmentProof::from_stwo_proof(
            &merkle_verifier,
            fiat_shamir_hints.raw_queries.clone(),
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values[2].clone(),
            proof.stark_proof.decommitments[2].clone(),
        );

        let column_log_sizes = [fiat_shamir_hints.composition_log_size - 1;
            2 * SECURE_EXTENSION_DEGREE]
            .iter()
            .map(|log_size| log_size + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            .collect_vec();
        let merkle_verifier =
            MerkleVerifier::new(proof.stark_proof.commitments[3], column_log_sizes);
        let composition = read_composition(fiat_shamir_hints, proof);
        let composition_decommitment_proofs = QueryDecommitmentProof::from_stwo_proof(
            &merkle_verifier,
            fiat_shamir_hints.raw_queries.clone(),
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values[3].clone(),
            proof.stark_proof.decommitments[3].clone(),
        );

        Self {
            preprocessed_trace,
            preprocessed_trace_decommitment_proofs,
            trace,
            trace_decommitment_proofs,
            interaction,
            interaction_decommitment_proofs,
            composition,
            composition_decommitment_proofs,
        }
    }
}

#[cfg(test)]
mod tests {
    use cairo_air::utils::deserialize_proof_from_file;
    use cairo_air::utils::ProofFormat;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_decommitment_hints() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, &proof);

        let decommitment_proof =
            decommitment_hints.preprocessed_trace_decommitment_proofs[0].clone();
        let column_hashes = decommitment_hints.preprocessed_trace[0].compute_column_hashes();
        for (idx, node) in decommitment_proof.intermediate_layers.iter() {
            if !node.value.is_empty() {
                assert_eq!(
                    column_hashes
                        .get(
                            &(idx
                                - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor
                                    as usize)
                        )
                        .unwrap(),
                    &Poseidon31MerkleHasher::hash_column_get_capacity(&node.value)
                );
            }
        }

        let decommitment_proof = decommitment_hints.trace_decommitment_proofs[0].clone();
        let column_hashes = decommitment_hints.trace[0].compute_hashes(&proof.claim);
        let leaf_layer_hash =
            Poseidon31MerkleHasher::hash_column_get_capacity(&decommitment_proof.leaf_values);
        assert_eq!(
            leaf_layer_hash,
            *column_hashes
                .get(
                    &(decommitment_proof.intermediate_layers.len()
                        - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor as usize)
                )
                .unwrap()
        );

        for (idx, node) in decommitment_proof.intermediate_layers.iter() {
            if !node.value.is_empty() {
                assert_eq!(
                    column_hashes
                        .get(
                            &(idx
                                - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor
                                    as usize)
                        )
                        .unwrap(),
                    &Poseidon31MerkleHasher::hash_column_get_capacity(&node.value)
                );
            }
        }

        let decommitment_proof = decommitment_hints.interaction_decommitment_proofs[0].clone();
        let column_hashes = decommitment_hints.interaction[0]
            .compute_hashes(&proof.interaction_claim, &proof.claim);
        let leaf_layer_hash =
            Poseidon31MerkleHasher::hash_column_get_capacity(&decommitment_proof.leaf_values);
        assert_eq!(
            leaf_layer_hash,
            *column_hashes
                .get(
                    &(decommitment_proof.intermediate_layers.len()
                        - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor as usize)
                )
                .unwrap()
        );

        for (idx, node) in decommitment_proof.intermediate_layers.iter() {
            if !node.value.is_empty() {
                assert_eq!(
                    column_hashes
                        .get(
                            &(idx
                                - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor
                                    as usize)
                        )
                        .unwrap(),
                    &Poseidon31MerkleHasher::hash_column_get_capacity(&node.value)
                );
            }
        }

        let decommitment_proof = decommitment_hints.composition_decommitment_proofs[0].clone();
        let column_hashes = decommitment_hints.composition[0]
            .compute_hashes(fiat_shamir_hints.composition_log_size);
        let leaf_layer_hash =
            Poseidon31MerkleHasher::hash_column_get_capacity(&decommitment_proof.leaf_values);
        assert_eq!(
            leaf_layer_hash,
            *column_hashes
                .get(
                    &(decommitment_proof.intermediate_layers.len()
                        - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor as usize)
                )
                .unwrap()
        );

        for (idx, node) in decommitment_proof.intermediate_layers.iter() {
            if !node.value.is_empty() {
                assert_eq!(
                    column_hashes
                        .get(
                            &(idx
                                - fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor
                                    as usize)
                        )
                        .unwrap(),
                    &Poseidon31MerkleHasher::hash_column_get_capacity(&node.value)
                );
            }
        }
    }
}
