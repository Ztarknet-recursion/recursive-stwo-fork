use cairo_air::CairoProof;
use indexmap::IndexMap;
use stwo::core::{
    fields::m31::M31,
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
};

use crate::CairoFiatShamirHints;

pub struct PreprocessedTraceQueryResult {
    pub seq_25: M31,
    pub seq_24: M31,
    pub seq_23: M31,
    pub seq_22: M31,
    pub seq_21: M31,
    pub seq_20: M31, /* used by range check 20, 20b, 20c, 20d, 20e, 20f, 20g, 20h */
    pub bitwise_xor_10_0: M31,
    pub bitwise_xor_10_1: M31,
    pub bitwise_xor_10_2: M31,
    pub seq_19: M31,
    pub seq_18: M31, /* used by range check 18, 18b */
    pub bitwise_xor_9_0: M31,
    pub bitwise_xor_9_1: M31,
    pub bitwise_xor_9_2: M31,
    pub range_check_9_9_column_0: M31,
    pub range_check_9_9_column_1: M31,
    pub range_check_3_6_6_3_column_0: M31,
    pub range_check_3_6_6_3_column_1: M31,
    pub range_check_3_6_6_3_column_2: M31,
    pub range_check_3_6_6_3_column_3: M31,
    pub seq_17: M31,
    pub seq_16: M31,
    pub bitwise_xor_8_0: M31,
    pub bitwise_xor_8_1: M31,
    pub bitwise_xor_8_2: M31,
    pub range_check_4_4_4_4_column_0: M31,
    pub range_check_4_4_4_4_column_1: M31,
    pub range_check_4_4_4_4_column_2: M31,
    pub range_check_4_4_4_4_column_3: M31,
    pub seq_15: M31,
    pub range_check_3_3_3_3_3_column_0: M31,
    pub range_check_3_3_3_3_3_column_1: M31,
    pub range_check_3_3_3_3_3_column_2: M31,
    pub range_check_3_3_3_3_3_column_3: M31,
    pub range_check_3_3_3_3_3_column_4: M31,
    pub seq_14: M31,
    pub bitwise_xor_7_0: M31,
    pub bitwise_xor_7_1: M31,
    pub bitwise_xor_7_2: M31,
    pub range_check_7_2_5_column_0: M31,
    pub range_check_7_2_5_column_1: M31,
    pub range_check_7_2_5_column_2: M31,
    pub seq_13: M31,
    pub seq_12: M31, /* used by range check 12 */
    pub seq_11: M31, /* used by range check 11 */
    pub seq_10: M31,
    pub seq_9: M31,
    pub range_check_5_4_column_0: M31,
    pub range_check_5_4_column_1: M31,
    pub seq_8: M31, /* used by range check 8 */
    pub bitwise_xor_4_0: M31,
    pub bitwise_xor_4_1: M31,
    pub bitwise_xor_4_2: M31,
    pub range_check_4_4_column_0: M31,
    pub range_check_4_4_column_1: M31,
    pub seq_7: M31,
    pub range_check_4_3_column_0: M31,
    pub range_check_4_3_column_1: M31,
    pub seq_6: M31, /* used by range check 6 */
    pub poseidon_round_keys_0: M31,
    pub poseidon_round_keys_1: M31,
    pub poseidon_round_keys_2: M31,
    pub poseidon_round_keys_3: M31,
    pub poseidon_round_keys_4: M31,
    pub poseidon_round_keys_5: M31,
    pub poseidon_round_keys_6: M31,
    pub poseidon_round_keys_7: M31,
    pub poseidon_round_keys_8: M31,
    pub poseidon_round_keys_9: M31,
    pub poseidon_round_keys_10: M31,
    pub poseidon_round_keys_11: M31,
    pub poseidon_round_keys_12: M31,
    pub poseidon_round_keys_13: M31,
    pub poseidon_round_keys_14: M31,
    pub poseidon_round_keys_15: M31,
    pub poseidon_round_keys_16: M31,
    pub poseidon_round_keys_17: M31,
    pub poseidon_round_keys_18: M31,
    pub poseidon_round_keys_19: M31,
    pub poseidon_round_keys_20: M31,
    pub poseidon_round_keys_21: M31,
    pub poseidon_round_keys_22: M31,
    pub poseidon_round_keys_23: M31,
    pub poseidon_round_keys_24: M31,
    pub poseidon_round_keys_25: M31,
    pub poseidon_round_keys_26: M31,
    pub poseidon_round_keys_27: M31,
    pub poseidon_round_keys_28: M31,
    pub poseidon_round_keys_29: M31,
    pub seq_5: M31,
    pub seq_4: M31, /* used by blake_round_sigma */
    pub blake_sigma_0: M31,
    pub blake_sigma_1: M31,
    pub blake_sigma_2: M31,
    pub blake_sigma_3: M31,
    pub blake_sigma_4: M31,
    pub blake_sigma_5: M31,
    pub blake_sigma_6: M31,
    pub blake_sigma_7: M31,
    pub blake_sigma_8: M31,
    pub blake_sigma_9: M31,
    pub blake_sigma_10: M31,
    pub blake_sigma_11: M31,
    pub blake_sigma_12: M31,
    pub blake_sigma_13: M31,
    pub blake_sigma_14: M31,
    pub blake_sigma_15: M31,
}

impl PreprocessedTraceQueryResult {
    pub fn compute_column_hashes(&self) -> IndexMap<usize, Poseidon31Hash> {
        let mut map = IndexMap::new();
        map.insert(
            25,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_25]),
        );
        map.insert(
            24,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_24]),
        );
        map.insert(
            23,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_23]),
        );
        map.insert(
            22,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_22]),
        );
        map.insert(
            21,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_21]),
        );
        map.insert(
            20,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_20,
                self.bitwise_xor_10_0,
                self.bitwise_xor_10_1,
                self.bitwise_xor_10_2,
            ]),
        );
        map.insert(
            19,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_19]),
        );
        map.insert(
            18,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_18,
                self.bitwise_xor_9_0,
                self.bitwise_xor_9_1,
                self.bitwise_xor_9_2,
                self.range_check_9_9_column_0,
                self.range_check_9_9_column_1,
                self.range_check_3_6_6_3_column_0,
                self.range_check_3_6_6_3_column_1,
                self.range_check_3_6_6_3_column_2,
                self.range_check_3_6_6_3_column_3,
            ]),
        );
        map.insert(
            17,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_17]),
        );
        map.insert(
            16,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_16,
                self.bitwise_xor_8_0,
                self.bitwise_xor_8_1,
                self.bitwise_xor_8_2,
                self.range_check_4_4_4_4_column_0,
                self.range_check_4_4_4_4_column_1,
                self.range_check_4_4_4_4_column_2,
                self.range_check_4_4_4_4_column_3,
            ]),
        );
        map.insert(
            15,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_15,
                self.range_check_3_3_3_3_3_column_0,
                self.range_check_3_3_3_3_3_column_1,
                self.range_check_3_3_3_3_3_column_2,
                self.range_check_3_3_3_3_3_column_3,
                self.range_check_3_3_3_3_3_column_4,
            ]),
        );
        map.insert(
            14,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_14,
                self.bitwise_xor_7_0,
                self.bitwise_xor_7_1,
                self.bitwise_xor_7_2,
                self.range_check_7_2_5_column_0,
                self.range_check_7_2_5_column_1,
                self.range_check_7_2_5_column_2,
            ]),
        );
        map.insert(
            13,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_13]),
        );
        map.insert(
            12,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_12]),
        );
        map.insert(
            11,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_11]),
        );
        map.insert(
            10,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_10]),
        );
        map.insert(
            9,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_9,
                self.range_check_5_4_column_0,
                self.range_check_5_4_column_1,
            ]),
        );
        map.insert(
            8,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_8,
                self.bitwise_xor_4_0,
                self.bitwise_xor_4_1,
                self.bitwise_xor_4_2,
                self.range_check_4_4_column_0,
                self.range_check_4_4_column_1,
            ]),
        );
        map.insert(
            7,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_7,
                self.range_check_4_3_column_0,
                self.range_check_4_3_column_1,
            ]),
        );
        map.insert(
            6,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_6,
                self.poseidon_round_keys_0,
                self.poseidon_round_keys_1,
                self.poseidon_round_keys_2,
                self.poseidon_round_keys_3,
                self.poseidon_round_keys_4,
                self.poseidon_round_keys_5,
                self.poseidon_round_keys_6,
                self.poseidon_round_keys_7,
                self.poseidon_round_keys_8,
                self.poseidon_round_keys_9,
                self.poseidon_round_keys_10,
                self.poseidon_round_keys_11,
                self.poseidon_round_keys_12,
                self.poseidon_round_keys_13,
                self.poseidon_round_keys_14,
                self.poseidon_round_keys_15,
                self.poseidon_round_keys_16,
                self.poseidon_round_keys_17,
                self.poseidon_round_keys_18,
                self.poseidon_round_keys_19,
                self.poseidon_round_keys_20,
                self.poseidon_round_keys_21,
                self.poseidon_round_keys_22,
                self.poseidon_round_keys_23,
                self.poseidon_round_keys_24,
                self.poseidon_round_keys_25,
                self.poseidon_round_keys_26,
                self.poseidon_round_keys_27,
                self.poseidon_round_keys_28,
                self.poseidon_round_keys_29,
            ]),
        );
        map.insert(
            5,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[self.seq_5]),
        );
        map.insert(
            4,
            Poseidon31MerkleHasher::hash_column_get_capacity(&[
                self.seq_4,
                self.blake_sigma_0,
                self.blake_sigma_1,
                self.blake_sigma_2,
                self.blake_sigma_3,
                self.blake_sigma_4,
                self.blake_sigma_5,
                self.blake_sigma_6,
                self.blake_sigma_7,
                self.blake_sigma_8,
                self.blake_sigma_9,
                self.blake_sigma_10,
                self.blake_sigma_11,
                self.blake_sigma_12,
                self.blake_sigma_13,
                self.blake_sigma_14,
                self.blake_sigma_15,
            ]),
        );
        map
    }

    pub fn get_num_enabled_preprocessed_columns(
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> usize {
        proof.stark_proof.sampled_values[0]
            .iter()
            .filter(|v| !v.is_empty())
            .count()
    }
}

pub fn read_preprocessed_trace(
    fiat_shamir_hints: &CairoFiatShamirHints,
    proof: &CairoProof<Poseidon31MerkleHasher>,
) -> Vec<PreprocessedTraceQueryResult> {
    use super::read_query_values_into_pad;

    let log_sizes = &fiat_shamir_hints.log_sizes[0];
    let queried_values = &proof.stark_proof.queried_values[0];
    let witness = &proof.stark_proof.decommitments[0].column_witness;

    let pad = read_query_values_into_pad(
        log_sizes,
        queried_values,
        witness,
        &fiat_shamir_hints.raw_queries,
        &fiat_shamir_hints.query_positions_per_log_size,
        proof.stark_proof.config.fri_config.log_blowup_factor,
        proof.stark_proof.config.fri_config.n_queries,
    );

    let mut results = vec![];
    for c in pad
        .iter()
        .take(proof.stark_proof.config.fri_config.n_queries)
    {
        results.push(PreprocessedTraceQueryResult {
            seq_25: c[0],
            seq_24: c[1],
            seq_23: c[2],
            seq_22: c[3],
            seq_21: c[4],
            seq_20: c[5],
            bitwise_xor_10_0: c[6],
            bitwise_xor_10_1: c[7],
            bitwise_xor_10_2: c[8],
            seq_19: c[9],
            seq_18: c[10],
            bitwise_xor_9_0: c[11],
            bitwise_xor_9_1: c[12],
            bitwise_xor_9_2: c[13],
            range_check_9_9_column_0: c[14],
            range_check_9_9_column_1: c[15],
            range_check_3_6_6_3_column_0: c[16],
            range_check_3_6_6_3_column_1: c[17],
            range_check_3_6_6_3_column_2: c[18],
            range_check_3_6_6_3_column_3: c[19],
            seq_17: c[20],
            seq_16: c[21],
            bitwise_xor_8_0: c[22],
            bitwise_xor_8_1: c[23],
            bitwise_xor_8_2: c[24],
            range_check_4_4_4_4_column_0: c[25],
            range_check_4_4_4_4_column_1: c[26],
            range_check_4_4_4_4_column_2: c[27],
            range_check_4_4_4_4_column_3: c[28],
            seq_15: c[29],
            range_check_3_3_3_3_3_column_0: c[30],
            range_check_3_3_3_3_3_column_1: c[31],
            range_check_3_3_3_3_3_column_2: c[32],
            range_check_3_3_3_3_3_column_3: c[33],
            range_check_3_3_3_3_3_column_4: c[34],
            seq_14: c[35],
            bitwise_xor_7_0: c[36],
            bitwise_xor_7_1: c[37],
            bitwise_xor_7_2: c[38],
            range_check_7_2_5_column_0: c[39],
            range_check_7_2_5_column_1: c[40],
            range_check_7_2_5_column_2: c[41],
            seq_13: c[42],
            seq_12: c[43],
            seq_11: c[44],
            seq_10: c[45],
            seq_9: c[46],
            range_check_5_4_column_0: c[47],
            range_check_5_4_column_1: c[48],
            seq_8: c[49],
            bitwise_xor_4_0: c[50],
            bitwise_xor_4_1: c[51],
            bitwise_xor_4_2: c[52],
            range_check_4_4_column_0: c[53],
            range_check_4_4_column_1: c[54],
            seq_7: c[55],
            range_check_4_3_column_0: c[56],
            range_check_4_3_column_1: c[57],
            seq_6: c[58],
            poseidon_round_keys_0: c[59],
            poseidon_round_keys_1: c[60],
            poseidon_round_keys_2: c[61],
            poseidon_round_keys_3: c[62],
            poseidon_round_keys_4: c[63],
            poseidon_round_keys_5: c[64],
            poseidon_round_keys_6: c[65],
            poseidon_round_keys_7: c[66],
            poseidon_round_keys_8: c[67],
            poseidon_round_keys_9: c[68],
            poseidon_round_keys_10: c[69],
            poseidon_round_keys_11: c[70],
            poseidon_round_keys_12: c[71],
            poseidon_round_keys_13: c[72],
            poseidon_round_keys_14: c[73],
            poseidon_round_keys_15: c[74],
            poseidon_round_keys_16: c[75],
            poseidon_round_keys_17: c[76],
            poseidon_round_keys_18: c[77],
            poseidon_round_keys_19: c[78],
            poseidon_round_keys_20: c[79],
            poseidon_round_keys_21: c[80],
            poseidon_round_keys_22: c[81],
            poseidon_round_keys_23: c[82],
            poseidon_round_keys_24: c[83],
            poseidon_round_keys_25: c[84],
            poseidon_round_keys_26: c[85],
            poseidon_round_keys_27: c[86],
            poseidon_round_keys_28: c[87],
            poseidon_round_keys_29: c[88],
            seq_5: c[89],
            seq_4: c[90],
            blake_sigma_0: c[91],
            blake_sigma_1: c[92],
            blake_sigma_2: c[93],
            blake_sigma_3: c[94],
            blake_sigma_4: c[95],
            blake_sigma_5: c[96],
            blake_sigma_6: c[97],
            blake_sigma_7: c[98],
            blake_sigma_8: c[99],
            blake_sigma_9: c[100],
            blake_sigma_10: c[101],
            blake_sigma_11: c[102],
            blake_sigma_12: c[103],
            blake_sigma_13: c[104],
            blake_sigma_14: c[105],
            blake_sigma_15: c[106],
        });
    }
    results
}
