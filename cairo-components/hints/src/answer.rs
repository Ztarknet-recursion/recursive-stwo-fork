use cairo_air::CairoProof;
use itertools::{izip, multiunzip, zip_eq, Itertools};
use num_traits::Zero;
use std::{cmp::Reverse, collections::BTreeMap};
use stwo::core::{
    circle::CirclePoint,
    fields::{
        cm31::CM31,
        m31::{BaseField, M31},
        qm31::SecureField,
        FieldExpOps,
    },
    pcs::{
        quotients::{quotient_constants, ColumnSampleBatch, PointSample, QuotientConstants},
        TreeVec,
    },
    poly::circle::CanonicCoset,
    utils::bit_reverse_index,
    vcs::poseidon31_merkle::Poseidon31MerkleHasher,
    verifier::VerificationError,
    ColumnVec,
};

use crate::CairoFiatShamirHints;

pub struct AnswerHints {}

impl AnswerHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) {
        let _samples = fiat_shamir_hints
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

        let samples = fiat_shamir_hints.sample_points[0]
            .iter()
            .zip(proof.stark_proof.sampled_values[0].iter())
            .map(|(sample_points, sampled_values)| {
                std::iter::zip(sample_points, sampled_values)
                    .map(|(point, value)| PointSample {
                        point: point.clone(),
                        value: value.clone(),
                    })
                    .collect_vec()
            })
            .collect_vec();

        for (i, (log_size, sample)) in column_log_sizes[0]
            .iter()
            .zip(proof.stark_proof.sampled_values[0].iter())
            .enumerate()
        {
            if sample.is_empty() {
                println!("log_size: {:?}, i: {}", log_size, i);
            }
        }

        let log_sizes = column_log_sizes[0]
            .iter()
            .sorted_by_key(|log_size| Reverse(*log_size))
            .dedup()
            .filter(|log_size| fiat_shamir_hints.query_positions_per_log_size.get(log_size) != None)
            .collect_vec();

        let first_query = fiat_shamir_hints.raw_queries[0];

        let answers = fri_answers(
            TreeVec::new(vec![column_log_sizes[0].clone()]),
            TreeVec::new(vec![samples]),
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.query_positions_per_log_size,
            TreeVec::new(vec![proof.stark_proof.queried_values[0].clone()]),
            TreeVec::new(vec![n_columns_per_log_size[0]]),
        )
        .unwrap();

        let max_query = fiat_shamir_hints
            .query_positions_per_log_size
            .keys()
            .max()
            .unwrap();

        for (log_size, answer) in log_sizes.iter().zip(answers.iter()) {
            let queries_for_log_size = fiat_shamir_hints
                .query_positions_per_log_size
                .get(&log_size)
                .unwrap();

            for (query_position, answer) in queries_for_log_size.iter().zip(answer.iter()) {
                if *query_position == first_query >> (*max_query - **log_size) {
                    println!(
                        "log_size = {}, query_position: {:?}, answer: {:?}",
                        **log_size, *query_position, answer
                    );
                }
            }
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
) -> Result<ColumnVec<Vec<SecureField>>, VerificationError> {
    let mut queried_values = queried_values.map(|values| values.into_iter());

    izip!(column_log_sizes.flatten(), samples.flatten().iter())
        .sorted_by_key(|(log_size, ..)| Reverse(*log_size))
        .chunk_by(|(log_size, ..)| *log_size)
        .into_iter()
        .filter_map(|(log_size, tuples)| {
            // Skip processing this log size if it does not have any associated queries.
            let queries_for_log_size = query_positions_per_log_size.get(&log_size)?;

            let (_, samples): (Vec<_>, Vec<_>) = multiunzip(tuples);
            Some(fri_answers_for_log_size(
                log_size,
                &samples,
                random_coeff,
                queries_for_log_size,
                &mut queried_values,
                n_columns_per_log_size
                    .as_ref()
                    .map(|columns_log_sizes| *columns_log_sizes.get(&log_size).unwrap_or(&0)),
            ))
        })
        .collect()
}

pub fn fri_answers_for_log_size(
    log_size: u32,
    samples: &[&Vec<PointSample>],
    random_coeff: SecureField,
    query_positions: &[usize],
    queried_values: &mut TreeVec<impl Iterator<Item = BaseField>>,
    n_columns: TreeVec<usize>,
) -> Result<Vec<SecureField>, VerificationError> {
    let sample_batches = ColumnSampleBatch::new_vec(samples);
    // TODO(ilya): Is it ok to use the same `random_coeff` for all log sizes.
    let quotient_constants = quotient_constants(&sample_batches, random_coeff);
    let commitment_domain = CanonicCoset::new(log_size).circle_domain();

    let mut quotient_evals_at_queries: Vec<stwo::core::fields::qm31::QM31> = Vec::new();
    for &query_position in query_positions {
        let domain_point = commitment_domain.at(bit_reverse_index(query_position, log_size));

        let queried_values_at_row = queried_values
            .as_mut()
            .zip_eq(n_columns.as_ref())
            .map(|(queried_values, n_columns)| queried_values.take(*n_columns).collect())
            .flatten();

        let res = accumulate_row_quotients(
            &sample_batches,
            &queried_values_at_row,
            &quotient_constants,
            domain_point,
        );

        quotient_evals_at_queries.push(res);
    }

    Ok(quotient_evals_at_queries)
}

pub fn accumulate_row_quotients(
    sample_batches: &[ColumnSampleBatch],
    queried_values_at_row: &[BaseField],
    quotient_constants: &QuotientConstants,
    domain_point: CirclePoint<BaseField>,
) -> SecureField {
    let denominator_inverses = denominator_inverses(sample_batches, domain_point);
    let mut row_accumulator = SecureField::zero();
    for (sample_batch, line_coeffs, denominator_inverse) in izip!(
        sample_batches,
        &quotient_constants.line_coeffs,
        denominator_inverses
    ) {
        let mut numerator = SecureField::zero();
        for ((column_index, _), (a, b, c)) in zip_eq(&sample_batch.columns_and_values, line_coeffs)
        {
            let value = queried_values_at_row[*column_index] * *c;
            // The numerator is a line equation passing through
            //   (sample_point.y, sample_value), (conj(sample_point), conj(sample_value))
            // evaluated at (domain_point.y, value).
            // When substituting a polynomial in this line equation, we get a polynomial with a root
            // at sample_point and conj(sample_point) if the original polynomial had the values
            // sample_value and conj(sample_value) at these points.
            let linear_term = *a * domain_point.y + *b;
            numerator += value - linear_term;
        }
        row_accumulator += numerator.mul_cm31(denominator_inverse);
    }
    row_accumulator
}

fn denominator_inverses(
    sample_batches: &[ColumnSampleBatch],
    domain_point: CirclePoint<M31>,
) -> Vec<CM31> {
    let mut denominators = Vec::new();

    // We want a P to be on a line that passes through a point Pr + uPi in QM31^2, and its conjugate
    // Pr - uPi. Thus, Pr - P is parallel to Pi. Or, (Pr - P).x * Pi.y - (Pr - P).y * Pi.x = 0.
    for sample_batch in sample_batches {
        // Extract Pr, Pi.
        let prx = sample_batch.point.x.0;
        let pry = sample_batch.point.y.0;
        let pix = sample_batch.point.x.1;
        let piy = sample_batch.point.y.1;
        denominators.push((prx - domain_point.x) * piy - (pry - domain_point.y) * pix);
    }

    CM31::batch_inverse(&denominators)
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
