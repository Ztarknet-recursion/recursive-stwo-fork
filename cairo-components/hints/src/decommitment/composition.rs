use cairo_air::CairoProof;
use indexmap::IndexMap;
use stwo::core::{
    fields::{
        m31::M31,
        qm31::{QM31, SECURE_EXTENSION_DEGREE},
    },
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
};

use crate::{read_query_values_into_pad, CairoFiatShamirHints};

pub struct CompositionQueryResult(pub [QM31; 2]);

impl CompositionQueryResult {
    pub fn compute_hashes(&self, composition_log_size: u32) -> IndexMap<usize, Poseidon31Hash> {
        let mut arr = [M31::default(); 8];
        arr[0..4].copy_from_slice(&self.0[0].to_m31_array());
        arr[4..8].copy_from_slice(&self.0[1].to_m31_array());

        let mut map = IndexMap::new();
        map.insert(
            (composition_log_size - 1) as usize,
            Poseidon31MerkleHasher::hash_column_get_capacity(&arr),
        );
        map
    }
}

pub fn read_composition(
    fiat_shamir_hints: &CairoFiatShamirHints,
    proof: &CairoProof<Poseidon31MerkleHasher>,
) -> Vec<CompositionQueryResult> {
    let log_sizes = vec![fiat_shamir_hints.composition_log_size - 1; 2 * SECURE_EXTENSION_DEGREE];
    let queried_values = &proof.stark_proof.queried_values[3];
    let witness = &proof.stark_proof.decommitments[3].column_witness;

    let pad = read_query_values_into_pad(
        &log_sizes,
        queried_values,
        witness,
        &fiat_shamir_hints.raw_queries,
        &fiat_shamir_hints.query_positions_per_log_size,
        proof.stark_proof.config.fri_config.log_blowup_factor,
        proof.stark_proof.config.fri_config.n_queries,
    );

    let mut results = Vec::new();
    for c in pad
        .iter()
        .take(proof.stark_proof.config.fri_config.n_queries)
    {
        results.push(CompositionQueryResult([
            QM31::from_m31(c[0], c[1], c[2], c[3]),
            QM31::from_m31(c[4], c[5], c[6], c[7]),
        ]));
    }

    results
}
