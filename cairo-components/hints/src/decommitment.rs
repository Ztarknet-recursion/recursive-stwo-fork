use std::collections::BTreeMap;

use cairo_air::CairoProof;
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::{
    core::{
        fields::m31::{BaseField, M31},
        utils::PeekableExt,
        vcs::{
            poseidon31_hash::Poseidon31Hash,
            poseidon31_merkle::Poseidon31MerkleHasher,
            utils::{next_decommitment_node, option_flatten_peekable},
            verifier::{MerkleDecommitment, MerkleVerifier},
            MerkleHasher,
        },
    },
    prover::backend::simd::m31::LOG_N_LANES,
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

use crate::CairoFiatShamirHints;

#[derive(Debug, Clone)]
pub struct QueryDecommitmentProof {
    pub query: usize,
    pub nodes: IndexMap<usize, QueryDecommitmentNode>,
}

#[derive(Debug, Clone)]
pub struct QueryDecommitmentNode {
    pub children: Option<(Poseidon31Hash, Poseidon31Hash)>,
    pub value: Vec<M31>,
}

impl QueryDecommitmentNode {
    pub fn hash(&self) -> Poseidon31Hash {
        Poseidon31MerkleHasher::hash_node(self.children, &self.value)
    }
}

impl QueryDecommitmentProof {
    pub fn from_stwo_proof(
        merkle_verifier: &MerkleVerifier<Poseidon31MerkleHasher>,
        raw_queries: Vec<usize>,
        depth: usize,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment<Poseidon31MerkleHasher>,
    ) -> Vec<QueryDecommitmentProof> {
        let mut layers = IndexMap::new();

        let max_log_size = merkle_verifier.column_log_sizes.iter().max().unwrap();

        let mut queried_values = queried_values.into_iter();
        let mut hash_witness = decommitment.hash_witness.into_iter();
        let mut column_witness = decommitment.column_witness.into_iter();

        let mut last_layer_hashes: Option<Vec<(usize, Poseidon31Hash)>> = None;
        for layer_log_size in (0..=*max_log_size).rev() {
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
                        children: node_hashes,
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

            for log_size in (0..=depth).rev() {
                let layer = layers.get(&(log_size as u32)).unwrap();
                let node = layer.get(&cur).unwrap();
                nodes.insert(log_size as usize, node.clone());
                cur >>= 1;
            }

            let proof = QueryDecommitmentProof {
                query: *query,
                nodes,
            };
            proofs.push(proof);
        }
        proofs
    }
}

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
}

impl PreprocessedTraceQueryResult {
    pub fn get_num_enabled_preprocessed_columns(
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> usize {
        proof.stark_proof.sampled_values[0]
            .iter()
            .filter(|v| !v.is_empty())
            .count()
    }
}

pub struct TraceQueryResult {
    pub opcodes: OpcodesTraceQueryResult,
    pub verify_instruction: [M31; cairo_air::components::verify_instruction::N_TRACE_COLUMNS],
    pub blake: BlakeTraceQueryResult,
    pub range_check_128_builtin:
        [M31; cairo_air::components::range_check_builtin_bits_128::N_TRACE_COLUMNS],
    pub memory_address_to_id: [M31; cairo_air::components::memory_address_to_id::N_TRACE_COLUMNS],
    pub memory_id_to_big_big: [M31; cairo_air::components::memory_id_to_big::BIG_N_COLUMNS],
    pub memory_id_to_big_small: [M31; cairo_air::components::memory_id_to_big::SMALL_N_COLUMNS],
    pub range_checks: RangeChecksTraceQueryResult,
    pub verify_bitwise: VerifyBitwiseTraceQueryResult,
}

pub struct OpcodesTraceQueryResult {
    pub add: [M31; cairo_air::components::add_opcode::N_TRACE_COLUMNS],
    pub add_small: [M31; cairo_air::components::add_opcode_small::N_TRACE_COLUMNS],
    pub add_ap: [M31; cairo_air::components::add_ap_opcode::N_TRACE_COLUMNS],
    pub assert_eq: [M31; cairo_air::components::assert_eq_opcode::N_TRACE_COLUMNS],
    pub assert_eq_imm: [M31; cairo_air::components::assert_eq_opcode_imm::N_TRACE_COLUMNS],
    pub assert_eq_double_deref:
        [M31; cairo_air::components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS],
    pub blake: [M31; cairo_air::components::blake_compress_opcode::N_TRACE_COLUMNS],
    pub call: [M31; cairo_air::components::call_opcode_abs::N_TRACE_COLUMNS],
    pub call_rel_imm: [M31; cairo_air::components::call_opcode_rel_imm::N_TRACE_COLUMNS],
    pub jnz: [M31; cairo_air::components::jnz_opcode_non_taken::N_TRACE_COLUMNS],
    pub jnz_taken: [M31; cairo_air::components::jnz_opcode_taken::N_TRACE_COLUMNS],
    pub jump_rel: [M31; cairo_air::components::jump_opcode_rel::N_TRACE_COLUMNS],
    pub jump_rel_imm: [M31; cairo_air::components::jump_opcode_rel_imm::N_TRACE_COLUMNS],
    pub mul: [M31; cairo_air::components::mul_opcode::N_TRACE_COLUMNS],
    pub mul_small: [M31; cairo_air::components::mul_opcode_small::N_TRACE_COLUMNS],
    pub qm31: [M31; cairo_air::components::qm_31_add_mul_opcode::N_TRACE_COLUMNS],
    pub ret: [M31; cairo_air::components::ret_opcode::N_TRACE_COLUMNS],
}

pub struct BlakeTraceQueryResult {
    pub round: [M31; cairo_air::components::blake_round::N_TRACE_COLUMNS],
    pub g: [M31; cairo_air::components::blake_g::N_TRACE_COLUMNS],
    pub sigma: [M31; cairo_air::components::blake_round_sigma::N_TRACE_COLUMNS],
    pub triple_xor_32: [M31; cairo_air::components::triple_xor_32::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_12: [M31; cairo_air::components::verify_bitwise_xor_12::N_TRACE_COLUMNS],
}

pub struct RangeChecksTraceQueryResult {
    pub range_check_6: [M31; cairo_air::components::range_check_6::N_TRACE_COLUMNS],
    pub range_check_8: [M31; cairo_air::components::range_check_8::N_TRACE_COLUMNS],
    pub range_check_11: [M31; cairo_air::components::range_check_11::N_TRACE_COLUMNS],
    pub range_check_12: [M31; cairo_air::components::range_check_12::N_TRACE_COLUMNS],
    pub range_check_18: [M31; cairo_air::components::range_check_18::N_TRACE_COLUMNS],
    pub range_check_18_b: [M31; cairo_air::components::range_check_18_b::N_TRACE_COLUMNS],
    pub range_check_20: [M31; cairo_air::components::range_check_20::N_TRACE_COLUMNS],
    pub range_check_20_b: [M31; cairo_air::components::range_check_20_b::N_TRACE_COLUMNS],
    pub range_check_20_c: [M31; cairo_air::components::range_check_20_c::N_TRACE_COLUMNS],
    pub range_check_20_d: [M31; cairo_air::components::range_check_20_d::N_TRACE_COLUMNS],
    pub range_check_20_e: [M31; cairo_air::components::range_check_20_e::N_TRACE_COLUMNS],
    pub range_check_20_f: [M31; cairo_air::components::range_check_20_f::N_TRACE_COLUMNS],
    pub range_check_20_g: [M31; cairo_air::components::range_check_20_g::N_TRACE_COLUMNS],
    pub range_check_20_h: [M31; cairo_air::components::range_check_20_h::N_TRACE_COLUMNS],
    pub range_check_4_3: [M31; cairo_air::components::range_check_4_3::N_TRACE_COLUMNS],
    pub range_check_4_4: [M31; cairo_air::components::range_check_4_4::N_TRACE_COLUMNS],
    pub range_check_5_4: [M31; cairo_air::components::range_check_5_4::N_TRACE_COLUMNS],
    pub range_check_9_9: [M31; cairo_air::components::range_check_9_9::N_TRACE_COLUMNS],
    pub range_check_9_9_b: [M31; cairo_air::components::range_check_9_9_b::N_TRACE_COLUMNS],
    pub range_check_9_9_c: [M31; cairo_air::components::range_check_9_9_c::N_TRACE_COLUMNS],
    pub range_check_9_9_d: [M31; cairo_air::components::range_check_9_9_d::N_TRACE_COLUMNS],
    pub range_check_9_9_e: [M31; cairo_air::components::range_check_9_9_e::N_TRACE_COLUMNS],
    pub range_check_9_9_f: [M31; cairo_air::components::range_check_9_9_f::N_TRACE_COLUMNS],
    pub range_check_9_9_g: [M31; cairo_air::components::range_check_9_9_g::N_TRACE_COLUMNS],
    pub range_check_9_9_h: [M31; cairo_air::components::range_check_9_9_h::N_TRACE_COLUMNS],
    pub range_check_7_2_5: [M31; cairo_air::components::range_check_7_2_5::N_TRACE_COLUMNS],
    pub range_check_3_6_6_3: [M31; cairo_air::components::range_check_3_6_6_3::N_TRACE_COLUMNS],
    pub range_check_4_4_4_4: [M31; cairo_air::components::range_check_4_4_4_4::N_TRACE_COLUMNS],
    pub range_check_3_3_3_3_3: [M31; cairo_air::components::range_check_3_3_3_3_3::N_TRACE_COLUMNS],
}

pub struct VerifyBitwiseTraceQueryResult {
    pub verify_bitwise_xor_4: [M31; cairo_air::components::verify_bitwise_xor_4::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_7: [M31; cairo_air::components::verify_bitwise_xor_7::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8: [M31; cairo_air::components::verify_bitwise_xor_8::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8_b:
        [M31; cairo_air::components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_9: [M31; cairo_air::components::verify_bitwise_xor_9::N_TRACE_COLUMNS],
}

pub struct HashAccumulator {
    pub flags: u32,
    pub state: [M31; 16],
    pub hash: Poseidon31Hash,
}

pub struct DecommitmentHints {
    pub preprocessed_trace: Vec<PreprocessedTraceQueryResult>,
}

impl DecommitmentHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Self {
        let mut hash_accumulators = vec![];
        for _ in LOG_N_LANES..MAX_SEQUENCE_LOG_SIZE {
            hash_accumulators.push(HashAccumulator {
                flags: 0,
                state: [M31::default(); 16],
                hash: Poseidon31Hash::default(),
            });
        }

        let preprocessed_trace = Self::read_preprocessed_trace(fiat_shamir_hints, proof);
        println!(
            "queried_values: {:?}",
            proof.stark_proof.queried_values[1].len()
        );
        println!(
            "queried_values: {:?}",
            proof.stark_proof.queried_values[2].len()
        );
        println!(
            "queried_values: {:?}",
            proof.stark_proof.queried_values[3].len()
        );

        Self { preprocessed_trace }
    }

    pub fn read_preprocessed_trace(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Vec<PreprocessedTraceQueryResult> {
        let log_sizes = fiat_shamir_hints.preprocessed_log_sizes.clone();
        let max_included_log_size = *fiat_shamir_hints
            .query_positions_per_log_size
            .keys()
            .max()
            .unwrap()
            - proof.stark_proof.config.fri_config.log_blowup_factor;

        let mut pad = vec![
            vec![M31::default(); log_sizes.len()];
            proof.stark_proof.config.fri_config.n_queries
        ];
        let raw_queries = &fiat_shamir_hints.raw_queries;

        let log_sizes_sorted = log_sizes
            .iter()
            .filter(|log_size| **log_size <= max_included_log_size)
            .sorted()
            .dedup()
            .cloned()
            .collect::<Vec<_>>();
        let counts_per_log_size = log_sizes.iter().cloned().counts();

        let mut queried_values_iter = proof.stark_proof.queried_values[0].iter();
        let mut witness_iter = proof.stark_proof.decommitments[0].column_witness.iter();
        for log_size in log_sizes_sorted.iter().rev() {
            let queries = raw_queries
                .iter()
                .map(|query| *query >> (max_included_log_size - *log_size))
                .sorted()
                .dedup()
                .collect::<Vec<_>>();

            for query in queries.iter() {
                let mut results = vec![];

                if fiat_shamir_hints.query_positions_per_log_size.contains_key(
                    &(*log_size + proof.stark_proof.config.fri_config.log_blowup_factor),
                ) {
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

        let mut results = vec![];
        for i in 0..proof.stark_proof.config.fri_config.n_queries {
            let c = &pad[i];
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
}

#[cfg(test)]
mod tests {
    use cairo_air::utils::deserialize_proof_from_file;
    use cairo_air::utils::ProofFormat;
    use cairo_air::PreProcessedTraceVariant;
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
        let decommitment_hints = DecommitmentHints::new(&fiat_shamir_hints, &proof);

        let preprocessed_trace =
            PreProcessedTraceVariant::CanonicalWithoutPedersen.to_preprocessed_trace();
        let column_log_sizes = preprocessed_trace
            .log_sizes()
            .iter()
            .map(|log_size| log_size + fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor)
            .collect_vec();

        let merkle_verifier =
            MerkleVerifier::new(proof.stark_proof.commitments[0], column_log_sizes);
        let proofs = QueryDecommitmentProof::from_stwo_proof(
            &merkle_verifier,
            fiat_shamir_hints.raw_queries.clone(),
            fiat_shamir_hints.composition_log_size as usize,
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values[0].clone(),
            proof.stark_proof.decommitments[0].clone(),
        );

        let decommitment_proof = proofs[0].clone();
        let column_hashes = decommitment_hints.preprocessed_trace[0].compute_column_hashes();

        for (idx, node) in decommitment_proof.nodes.iter() {
            if !node.value.is_empty() {
                assert_eq!(
                    column_hashes
                        .get(
                            &(idx - proof.stark_proof.config.fri_config.log_blowup_factor as usize)
                        )
                        .unwrap(),
                    &Poseidon31MerkleHasher::hash_column_get_capacity(&node.value)
                );
            }
        }
    }
}
