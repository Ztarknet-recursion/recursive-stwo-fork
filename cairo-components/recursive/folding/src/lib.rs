use cairo_plonk_dsl_answer::AnswerResults;
use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::{
    folding::{CairoFoldingHints, SinglePairMerkleProof},
    CairoFiatShamirHints,
};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    option::OptionVar, BitVar, BitsVar, HashVar, M31Var, Poseidon2HalfVar,
    Poseidon31MerkleHasherVar, QM31Var,
};
use indexmap::IndexMap;
use num_traits::Zero;
use std::ops::Neg;
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    vcs::poseidon31_hash::Poseidon31Hash,
};
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

pub struct PaddedQueryBits {
    pub lsb: IndexMap<u32, BitVar>,
}

impl PaddedQueryBits {
    pub fn compute(query: &BitsVar, log_blowup_factor: u32, max_log_size: &M31Var) -> Self {
        let cs = max_log_size.cs();
        let mut query_bits = query.clone();

        let mut is_hash_active = max_log_size.is_eq(&M31Var::new_constant(
            &cs,
            &M31::from(MAX_SEQUENCE_LOG_SIZE),
        ));
        let mut lsb = IndexMap::new();
        lsb.insert(
            MAX_SEQUENCE_LOG_SIZE + log_blowup_factor,
            query_bits.0[0].clone(),
        );

        for h in (0..MAX_SEQUENCE_LOG_SIZE + log_blowup_factor).rev() {
            lsb.insert(h, query_bits.0[0].clone());

            let mut shifted_bits = query_bits.0[1..].to_vec();
            shifted_bits.push(BitVar::new_false(&cs));
            query_bits = BitsVar::select(&query_bits, &BitsVar(shifted_bits), &is_hash_active);

            is_hash_active = &is_hash_active
                | &max_log_size.is_eq(&M31Var::new_constant(
                    &cs,
                    &M31::from(h as i32 - log_blowup_factor as i32),
                ));
        }

        Self { lsb }
    }
}

pub struct PaddedSinglePairMerkleProofVar {
    pub cs: ConstraintSystemRef,
    pub log_blowup_factor: u32,
    pub sibling_hashes: IndexMap<usize, HashVar>,
    pub columns: IndexMap<usize, OptionVar<(QM31Var, QM31Var)>>,
}

impl Var for PaddedSinglePairMerkleProofVar {
    type Value = SinglePairMerkleProof;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for PaddedSinglePairMerkleProofVar {
    fn new_variables(
        cs: &ConstraintSystemRef,
        value: &SinglePairMerkleProof,
        mode: AllocationMode,
    ) -> Self {
        let log_blowup_factor = value.log_blowup_factor;

        let l = value.sibling_hashes.len();

        let mut sibling_hashes = IndexMap::new();
        for i in 0..l {
            sibling_hashes.insert(
                i + 1,
                HashVar::new_variables(cs, &value.sibling_hashes[l - 1 - i], mode),
            );
        }
        for i in l + 1..(MAX_SEQUENCE_LOG_SIZE + log_blowup_factor) as usize {
            sibling_hashes.insert(
                i,
                HashVar::new_variables(cs, &Poseidon31Hash::default(), mode),
            );
        }

        let mut columns = IndexMap::new();
        // Pad columns for indices from LOG_N_LANES + 1..=MAX_SEQUENCE_LOG_SIZE + 1
        for index in (((LOG_N_LANES + log_blowup_factor) as usize)
            ..=((MAX_SEQUENCE_LOG_SIZE + log_blowup_factor) as usize))
            .rev()
        {
            let self_present = value.self_columns.contains_key(&index);
            let sibling_present = value.siblings_columns.contains_key(&index);

            // Assert that self_columns and siblings_columns are present or absent together
            assert_eq!(
                self_present, sibling_present,
                "self_columns and siblings_columns must be present or absent together at index {}",
                index
            );

            if self_present {
                // Both are present, allocate as OptionVar with is_some = true
                let self_qm31 = value.self_columns.get(&index).unwrap();
                let sibling_qm31 = value.siblings_columns.get(&index).unwrap();
                let self_var = QM31Var::new_variables(cs, self_qm31, mode);
                let sibling_var = QM31Var::new_variables(cs, sibling_qm31, mode);
                let is_some = BitVar::new_variables(cs, &true, mode);
                columns.insert(index, OptionVar::new(is_some, (self_var, sibling_var)));
            } else {
                // Both are not present, allocate as OptionVar with ZERO and is_some = false
                let self_var = QM31Var::new_variables(cs, &QM31::zero(), mode);
                let sibling_var = QM31Var::new_variables(cs, &QM31::zero(), mode);
                let is_some = BitVar::new_variables(cs, &false, mode);
                columns.insert(index, OptionVar::new(is_some, (self_var, sibling_var)));
            }
        }

        Self {
            cs: cs.clone(),
            log_blowup_factor,
            sibling_hashes,
            columns,
        }
    }
}

impl PaddedSinglePairMerkleProofVar {
    pub fn verify(&self, root: &HashVar, query: &PaddedQueryBits, max_log_size: &M31Var) {
        let cs = self.cs();

        let last_column = self
            .columns
            .get(&((MAX_SEQUENCE_LOG_SIZE + self.log_blowup_factor) as usize))
            .unwrap();

        let mut self_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[last_column.value.0.clone()]);
        let mut sibling_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[last_column.value.1.clone()]);

        let mut is_hash_active = max_log_size.is_eq(&M31Var::new_constant(
            &cs,
            &M31::from(MAX_SEQUENCE_LOG_SIZE),
        ));

        for h in (0..MAX_SEQUENCE_LOG_SIZE + self.log_blowup_factor).rev() {
            let query_bit = query.lsb.get(&h).unwrap();

            self_hash = if let Some(column_opt) = self.columns.get(&(h as usize)) {
                let (self_col, _, is_column_present) = (
                    &column_opt.value.0,
                    &column_opt.value.1,
                    &column_opt.is_some,
                );
                // Hash the columns to get column hash
                let self_column_hash =
                    Poseidon31MerkleHasherVar::hash_qm31_columns_get_capacity(&[self_col.clone()]);

                // Hash tree with swap
                let tree_hash = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                    &self_hash,
                    &sibling_hash,
                    query_bit,
                )
                .to_qm31();

                // If column is present (is_some = true), combine with column hash
                // Otherwise, just use the tree hash
                let case_without_column = [
                    &tree_hash[0] * &is_hash_active.0,
                    &tree_hash[1] * &is_hash_active.0,
                ];

                let case_with_column = Poseidon2HalfVar::permute_get_rate(
                    &Poseidon2HalfVar::from_qm31(&case_without_column[0], &case_without_column[1]),
                    &self_column_hash,
                )
                .to_qm31();

                // Select based on is_column_present
                let final_self_hash = [
                    QM31Var::select(
                        &case_without_column[0],
                        &case_with_column[0],
                        is_column_present,
                    ),
                    QM31Var::select(
                        &case_without_column[1],
                        &case_with_column[1],
                        is_column_present,
                    ),
                ];
                Poseidon2HalfVar::from_qm31(&final_self_hash[0], &final_self_hash[1])
            } else {
                is_hash_active.equalverify(&BitVar::new_true(&cs));
                Poseidon31MerkleHasherVar::hash_tree_with_swap(&self_hash, &sibling_hash, query_bit)
            };

            if h != 0 {
                sibling_hash = if let Some(column_opt) = self.columns.get(&(h as usize)) {
                    let (_, sibling_col, is_column_present) = (
                        &column_opt.value.0,
                        &column_opt.value.1,
                        &column_opt.is_some,
                    );
                    let sibling_column_hash =
                        Poseidon31MerkleHasherVar::hash_qm31_columns_get_capacity(&[
                            sibling_col.clone()
                        ]);

                    // Handle sibling hash - always combine with column hash if present
                    let sibling_tree_hash = self.sibling_hashes.get(&(h as usize)).unwrap().clone();

                    let sibling_with_column =
                        Poseidon31MerkleHasherVar::combine_hash_tree_with_column(
                            &sibling_tree_hash,
                            &sibling_column_hash,
                        );
                    let sibling_without_column = sibling_tree_hash;

                    // Select sibling hash based on is_column_present
                    let final_sibling_hash = [
                        QM31Var::select(
                            &sibling_without_column.to_qm31()[0],
                            &sibling_with_column.to_qm31()[0],
                            is_column_present,
                        ),
                        QM31Var::select(
                            &sibling_without_column.to_qm31()[1],
                            &sibling_with_column.to_qm31()[1],
                            is_column_present,
                        ),
                    ];

                    Poseidon2HalfVar::from_qm31(&final_sibling_hash[0], &final_sibling_hash[1])
                } else {
                    self.sibling_hashes.get(&(h as usize)).unwrap().clone()
                };
            }

            is_hash_active = &is_hash_active
                | &max_log_size.is_eq(&M31Var::new_constant(
                    &cs,
                    &M31::from(h as i32 - self.log_blowup_factor as i32),
                ));
        }

        assert_eq!(self_hash.value(), root.value());

        // check that the left_variable and right_variable are the same
        // as though in self.root
        self_hash.equalverify(root);
    }
}

pub struct LeafOnlySinglePairMerkleProofVar {
    pub cs: ConstraintSystemRef,
    pub max_log_size: usize,
    pub log_blowup_factor: u32,
    pub column: (QM31Var, QM31Var),
    pub sibling_hashes: IndexMap<usize, HashVar>,
}

impl Var for LeafOnlySinglePairMerkleProofVar {
    type Value = SinglePairMerkleProof;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for LeafOnlySinglePairMerkleProofVar {
    fn new_variables(
        cs: &ConstraintSystemRef,
        value: &SinglePairMerkleProof,
        mode: AllocationMode,
    ) -> Self {
        let log_blowup_factor = value.log_blowup_factor;

        let l = value.sibling_hashes.len();

        let mut sibling_hashes = IndexMap::new();
        for i in 0..l {
            sibling_hashes.insert(
                i + 1,
                HashVar::new_variables(cs, &value.sibling_hashes[l - 1 - i], mode),
            );
        }

        let max_log_size = l + 1;

        let self_column =
            QM31Var::new_variables(cs, value.self_columns.get(&max_log_size).unwrap(), mode);
        let sibling_column =
            QM31Var::new_variables(cs, value.siblings_columns.get(&max_log_size).unwrap(), mode);

        Self {
            cs: cs.clone(),
            max_log_size,
            log_blowup_factor,
            sibling_hashes,
            column: (self_column, sibling_column),
        }
    }
}

impl LeafOnlySinglePairMerkleProofVar {
    pub fn dummy(cs: &ConstraintSystemRef, max_log_size: usize, log_blowup_factor: u32) -> Self {
        let column = (
            QM31Var::new_witness(cs, &QM31::zero()),
            QM31Var::new_witness(cs, &QM31::zero()),
        );

        let mut sibling_hashes = IndexMap::new();
        for i in 0..max_log_size - 1 {
            sibling_hashes.insert(i + 1, HashVar::new_witness(cs, &Poseidon31Hash::default()));
        }

        Self {
            cs: cs.clone(),
            max_log_size,
            log_blowup_factor,
            sibling_hashes,
            column,
        }
    }

    pub fn verify(&self, root: &HashVar, query: &PaddedQueryBits) -> BitVar {
        let mut self_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[self.column.0.clone()]);
        let mut sibling_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[self.column.1.clone()]);

        for h in (0..self.max_log_size).rev() {
            let query_bit = query.lsb.get(&(h as u32)).unwrap();

            self_hash = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                &self_hash,
                &sibling_hash,
                query_bit,
            );

            if h != 0 {
                sibling_hash = self.sibling_hashes.get(&h).unwrap().clone();
            }
        }

        // check that the left_variable and right_variable are the same
        // as though in self.root
        let self_hash = self_hash.to_qm31();
        let root = root.to_qm31();

        &self_hash[0].is_eq(&root[0]) & &self_hash[1].is_eq(&root[1])
    }
}

pub struct FoldingResults {}

impl FoldingResults {
    pub fn compute(
        fiat_shamir_hints: &CairoFiatShamirHints,
        folding_hints: &CairoFoldingHints,
        fiat_shamir_results: &CairoFiatShamirResults,
        answer_results: &AnswerResults,
        proof_var: &CairoProofVar,
    ) {
        let cs = fiat_shamir_results.max_log_size.cs();
        let log_blowup_factor = fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor;

        for (i, proof) in folding_hints
            .first_layer_hints
            .merkle_proofs
            .iter()
            .enumerate()
        {
            let padded_query_bits = PaddedQueryBits::compute(
                &fiat_shamir_results.queries[i],
                log_blowup_factor,
                &fiat_shamir_results.max_log_size,
            );

            let proof = PaddedSinglePairMerkleProofVar::new_witness(&cs, proof);
            proof.verify(
                &proof_var.stark_proof.fri_proof.first_layer.commitment,
                &padded_query_bits,
                &fiat_shamir_results.max_log_size,
            );

            for h in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
                let proof_column = proof
                    .columns
                    .get(&((h + log_blowup_factor) as usize))
                    .unwrap();
                let answer_column = answer_results.answers[i].get(&(h as usize)).unwrap();

                let proof_is_some = &proof_column.is_some;
                let answer_is_some = &answer_column.is_some;
                proof_is_some.equalverify(answer_is_some);

                let proof_column = &proof_column.value.0;
                let answer_column = &answer_column.value;

                let expected = QM31Var::select(proof_column, answer_column, proof_is_some);
                proof_column.equalverify(&expected);
            }

            let mut f_primes = IndexMap::new();
            let mut alphas = IndexMap::new();

            for h in (LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE).rev() {
                let is_first_layer = fiat_shamir_results
                    .max_log_size
                    .is_eq(&M31Var::new_constant(&cs, &M31::from(h)));

                let proof_column = proof
                    .columns
                    .get(&((h + log_blowup_factor) as usize))
                    .unwrap();

                let self_var = &proof_column.value.0;
                let sibling_var = &proof_column.value.1;

                let bit = padded_query_bits.lsb.get(&h).unwrap();

                let point = &answer_results
                    .query_positions_var
                    .points
                    .get(&(h + log_blowup_factor))
                    .unwrap()[i]
                    .get_absolute_point()
                    .double();

                let y_inv = point.y.inv();

                let (left_var, right_var) = QM31Var::swap(self_var, sibling_var, bit);
                let new_left_var = &left_var + &right_var;
                let new_right_var = &(&left_var - &right_var) * &y_inv;

                let alpha = if fiat_shamir_results.inner_layers_alphas.contains_key(&h) {
                    let candidate_alpha = fiat_shamir_results.inner_layers_alphas.get(&h).unwrap();
                    (&is_first_layer | &candidate_alpha.is_some)
                        .equalverify(&BitVar::new_true(&cs));

                    QM31Var::select(
                        &candidate_alpha.value,
                        &fiat_shamir_results.first_layer_alpha,
                        &is_first_layer,
                    )
                } else {
                    fiat_shamir_results.first_layer_alpha.clone()
                };

                let f_prime = &new_left_var + &(&new_right_var * &alpha);
                f_primes.insert(h, OptionVar::new(proof_column.is_some.clone(), f_prime));
                alphas.insert(h, alpha);
            }

            let mut folded = QM31Var::zero(&cs);
            let mut is_layer_present =
                fiat_shamir_results
                    .max_log_size
                    .is_eq(&M31Var::new_constant(
                        &cs,
                        &M31::from(MAX_SEQUENCE_LOG_SIZE),
                    ));
            for h in (log_blowup_factor + 1..MAX_SEQUENCE_LOG_SIZE + log_blowup_factor).rev() {
                let proof = if folding_hints
                    .inner_layers_hints
                    .merkle_proofs
                    .contains_key(&h)
                {
                    let proof = LeafOnlySinglePairMerkleProofVar::new_witness(
                        &cs,
                        &folding_hints
                            .inner_layers_hints
                            .merkle_proofs
                            .get(&h)
                            .unwrap()[i],
                    );
                    assert_eq!(proof.max_log_size, h as usize);
                    proof
                } else {
                    LeafOnlySinglePairMerkleProofVar::dummy(&cs, h as usize, log_blowup_factor)
                };

                let verify_result = proof.verify(
                    &proof_var
                        .stark_proof
                        .fri_proof
                        .inner_layers
                        .get(&(h - log_blowup_factor))
                        .unwrap()
                        .commitment,
                    &padded_query_bits,
                );

                (&verify_result | &is_layer_present.neg()).equalverify(&BitVar::new_true(&cs));

                if f_primes.contains_key(&h) {
                    let folded_into = f_primes.get(&h).unwrap();
                    let alpha = alphas.get(&h).unwrap();

                    let new_folded = &(&folded * &(alpha * alpha)) + &folded_into.value;
                    folded = QM31Var::select(&folded, &new_folded, &folded_into.is_some);
                }

                let expected = QM31Var::select(&proof.column.0, &folded, &is_layer_present);
                expected.equalverify(&proof.column.0);

                let bit = padded_query_bits
                    .lsb
                    .get(&(h - 2 + log_blowup_factor))
                    .unwrap();

                let point = &answer_results
                    .query_positions_var
                    .points
                    .get(&(h - 1 + log_blowup_factor))
                    .unwrap()[i]
                    .get_absolute_point();

                let x_inv = point.x.inv();

                let (left_var, right_var) = QM31Var::swap(&proof.column.0, &proof.column.1, bit);
                let new_left_var = &left_var + &right_var;
                let new_right_var = &(&left_var - &right_var) * &x_inv;

                let alpha = if alphas.contains_key(&(h - 1)) {
                    alphas.get(&(h - 1)).unwrap()
                } else {
                    &fiat_shamir_results
                        .inner_layers_alphas
                        .get(&(h - 1))
                        .unwrap()
                        .value
                };

                let new_folded = &new_left_var + &(&new_right_var * alpha);
                folded = QM31Var::select(&folded, &new_folded, &is_layer_present);

                is_layer_present = &is_layer_present
                    | &fiat_shamir_results
                        .max_log_size
                        .is_eq(&M31Var::new_constant(&cs, &M31::from(h - 1)));
            }

            folded.equalverify(&proof_var.stark_proof.fri_proof.last_layer_constant);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_answer::AnswerResults;
    use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
    use cairo_plonk_dsl_hints::{AnswerHints, CairoDecommitmentHints, CairoFiatShamirHints};
    use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
    use std::path::PathBuf;

    #[test]
    fn test_folding_results() {
        let cs = ConstraintSystemRef::new();

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();

        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let answer_hints = AnswerHints::new(&fiat_shamir_hints, &proof);
        let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, &proof);

        let folding_hints = CairoFoldingHints::new(&fiat_shamir_hints, &answer_hints, &proof);
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);
        let decommitment_results = CairoDecommitmentResultsVar::compute(
            &fiat_shamir_hints,
            &decommitment_hints,
            &fiat_shamir_results,
            &proof_var,
        );
        let answer_results = AnswerResults::compute(
            &fiat_shamir_hints,
            &fiat_shamir_results,
            &decommitment_results,
            &proof_var,
        );
        FoldingResults::compute(
            &fiat_shamir_hints,
            &folding_hints,
            &fiat_shamir_results,
            &answer_results,
            &proof_var,
        );

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
