use cairo_air::CairoProof;
use indexmap::IndexMap;
use itertools::{izip, multiunzip, Itertools};
use std::{cmp::Reverse, collections::BTreeMap};
use stwo::core::{
    fields::{m31::BaseField, qm31::SecureField},
    pcs::{
        quotients::{fri_answers_for_log_size, PointSample},
        TreeVec,
    },
    vcs::poseidon31_merkle::Poseidon31MerkleHasher,
};

use crate::CairoFiatShamirHints;

pub struct AnswerHints {
    pub answers_log_sizes: Vec<Vec<SecureField>>,
    pub queries_answers: Vec<IndexMap<u32, SecureField>>,
}

impl AnswerHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Self {
        let samples = fiat_shamir_hints
            .sample_points
            .clone()
            .zip_cols(proof.stark_proof.sampled_values.clone())
            .map_cols(|(sample_points, sampled_values)| {
                std::iter::zip(sample_points, sampled_values)
                    .map(|(point, value)| PointSample { point, value })
                    .collect_vec()
            });

        let n_columns_per_log_size = fiat_shamir_hints
            .commitment_scheme_verifier
            .trees
            .as_ref()
            .map(|tree| &tree.n_columns_per_log_size);

        // keep only the preprocessed trace
        let column_log_sizes = fiat_shamir_hints
            .commitment_scheme_verifier
            .column_log_sizes();

        let log_sizes = column_log_sizes
            .iter()
            .flatten()
            .sorted_by_key(|log_size| Reverse(*log_size))
            .dedup()
            .filter(|log_size| fiat_shamir_hints.query_positions_per_log_size.get(log_size) != None)
            .collect_vec();

        let answers_log_sizes = fri_answers(
            column_log_sizes.clone(),
            samples,
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values.clone(),
            n_columns_per_log_size,
        );

        let max_query = fiat_shamir_hints
            .query_positions_per_log_size
            .keys()
            .max()
            .unwrap();

        let mut queries_answers = Vec::new();
        for raw_query in fiat_shamir_hints.raw_queries.iter() {
            let mut map = IndexMap::new();
            for (log_size, answer) in log_sizes.iter().zip(answers_log_sizes.iter()) {
                let query_position = raw_query >> (*max_query - **log_size);

                let queries_for_log_size = fiat_shamir_hints
                    .query_positions_per_log_size
                    .get(&log_size)
                    .unwrap();

                let loc = queries_for_log_size
                    .iter()
                    .position(|q| *q == query_position)
                    .unwrap();
                map.insert(**log_size, answer[loc]);
            }
            queries_answers.push(map);
        }

        Self {
            answers_log_sizes,
            queries_answers,
        }
    }
}

pub fn fri_answers(
    column_log_sizes: TreeVec<Vec<u32>>,
    samples: TreeVec<Vec<Vec<PointSample>>>,
    random_coeff: SecureField,
    query_positions_per_log_size: &BTreeMap<u32, Vec<usize>>,
    queried_values: TreeVec<Vec<BaseField>>,
    n_columns_per_log_size: TreeVec<&BTreeMap<u32, usize>>,
) -> Vec<Vec<SecureField>> {
    let mut queried_values = queried_values.map(|values| values.into_iter());

    izip!(column_log_sizes.flatten(), samples.flatten().iter())
        .sorted_by_key(|(log_size, ..)| Reverse(*log_size))
        .chunk_by(|(log_size, ..)| *log_size)
        .into_iter()
        .filter_map(|(log_size, tuples)| {
            // Skip processing this log size if it does not have any associated queries.
            let queries_for_log_size = query_positions_per_log_size.get(&log_size)?;

            let (_, samples): (Vec<_>, Vec<_>) = multiunzip(tuples);
            Some(
                fri_answers_for_log_size(
                    log_size,
                    &samples,
                    random_coeff,
                    queries_for_log_size,
                    &mut queried_values,
                    n_columns_per_log_size
                        .as_ref()
                        .map(|columns_log_sizes| *columns_log_sizes.get(&log_size).unwrap_or(&0)),
                )
                .unwrap(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use std::path::PathBuf;

    #[test]
    fn test_answers_hints() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let _ = AnswerHints::new(&fiat_shamir_hints, &proof);
    }
}
