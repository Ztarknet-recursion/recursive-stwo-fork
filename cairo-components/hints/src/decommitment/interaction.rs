use cairo_air::{
    air::CairoClaim, blake::air::BlakeContextClaim, opcodes_air::OpcodeClaim, CairoProof,
};
use indexmap::IndexMap;
use stwo::core::{
    fields::{cm31::CM31, m31::M31, qm31::QM31},
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
};

use crate::{decommitment::utils::ColumnsHasherQM31, CairoFiatShamirHints};

pub struct InteractionQueryResult {
    pub opcodes: OpcodesInteractionQueryResult,
    pub verify_instruction: [QM31; 3],
    pub blake: BlakeInteractionQueryResult,
    pub range_check_128_builtin: [QM31; 1],
    pub memory_address_to_id: [QM31; 8],
    pub memory_id_to_big_big: [QM31; 8],
    pub memory_id_to_big_small: [QM31; 3],
    pub range_checks: RangeChecksInteractionQueryResult,
    pub verify_bitwise: VerifyBitwiseInteractionQueryResult,
}

pub struct OpcodesInteractionQueryResult {
    pub add: [QM31; 5],
    pub add_small: [QM31; 5],
    pub add_ap: [QM31; 4],
    pub assert_eq: [QM31; 3],
    pub assert_eq_imm: [QM31; 3],
    pub assert_eq_double_deref: [QM31; 4],
    pub blake: [QM31; 37],
    pub call: [QM31; 5],
    pub call_rel_imm: [QM31; 5],
    pub jnz: [QM31; 3],
    pub jnz_taken: [QM31; 4],
    pub jump_rel: [QM31; 3],
    pub jump_rel_imm: [QM31; 3],
    pub mul: [QM31; 19],
    pub mul_small: [QM31; 6],
    pub qm31: [QM31; 6],
    pub ret: [QM31; 4],
}

pub struct BlakeInteractionQueryResult {
    pub round: [QM31; 30],
    pub g: [QM31; 9],
    pub sigma: [QM31; 1],
    pub triple_xor_32: [QM31; 5],
    pub verify_bitwise_xor_12: [QM31; 8],
}

pub struct RangeChecksInteractionQueryResult {
    pub range_check_6: [QM31; 1],
    pub range_check_8: [QM31; 1],
    pub range_check_11: [QM31; 1],
    pub range_check_12: [QM31; 1],
    pub range_check_18: [QM31; 1],
    pub range_check_18_b: [QM31; 1],
    pub range_check_20: [QM31; 1],
    pub range_check_20_b: [QM31; 1],
    pub range_check_20_c: [QM31; 1],
    pub range_check_20_d: [QM31; 1],
    pub range_check_20_e: [QM31; 1],
    pub range_check_20_f: [QM31; 1],
    pub range_check_20_g: [QM31; 1],
    pub range_check_20_h: [QM31; 1],
    pub range_check_4_3: [QM31; 1],
    pub range_check_4_4: [QM31; 1],
    pub range_check_5_4: [QM31; 1],
    pub range_check_9_9: [QM31; 1],
    pub range_check_9_9_b: [QM31; 1],
    pub range_check_9_9_c: [QM31; 1],
    pub range_check_9_9_d: [QM31; 1],
    pub range_check_9_9_e: [QM31; 1],
    pub range_check_9_9_f: [QM31; 1],
    pub range_check_9_9_g: [QM31; 1],
    pub range_check_9_9_h: [QM31; 1],
    pub range_check_7_2_5: [QM31; 1],
    pub range_check_3_6_6_3: [QM31; 1],
    pub range_check_4_4_4_4: [QM31; 1],
    pub range_check_3_3_3_3_3: [QM31; 1],
}

pub struct VerifyBitwiseInteractionQueryResult {
    pub verify_bitwise_xor_4: [QM31; 1],
    pub verify_bitwise_xor_7: [QM31; 1],
    pub verify_bitwise_xor_8: [QM31; 1],
    pub verify_bitwise_xor_8_b: [QM31; 1],
    pub verify_bitwise_xor_9: [QM31; 1],
}

impl InteractionQueryResult {
    pub fn compute_hashes(&self, claim: &CairoClaim) -> IndexMap<usize, Poseidon31Hash> {
        let mut columns_hasher = ColumnsHasherQM31::new();

        self.opcodes
            .update_hashes(&mut columns_hasher, &claim.opcodes);
        columns_hasher.update(claim.verify_instruction.log_size, &self.verify_instruction);
        self.blake
            .update_hashes(&mut columns_hasher, &claim.blake_context);
        columns_hasher.update(
            claim.builtins.range_check_128_builtin.unwrap().log_size,
            &self.range_check_128_builtin,
        );
        columns_hasher.update(
            claim.memory_address_to_id.log_size,
            &self.memory_address_to_id,
        );
        columns_hasher.update(
            claim.memory_id_to_value.big_log_sizes[0],
            &self.memory_id_to_big_big,
        );
        columns_hasher.update(
            claim.memory_id_to_value.small_log_size,
            &self.memory_id_to_big_small,
        );
        self.range_checks.update_hashes(&mut columns_hasher);
        self.verify_bitwise.update_hashes(&mut columns_hasher);

        let mut map = IndexMap::new();
        for (log_size, hash) in columns_hasher.0 {
            map.insert(log_size, Poseidon31Hash(hash.finalize()));
        }
        map
    }
}

impl OpcodesInteractionQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31, trace_claim: &OpcodeClaim) {
        columns_hasher.update(trace_claim.add[0].log_size, &self.add);
        columns_hasher.update(trace_claim.add_small[0].log_size, &self.add_small);
        columns_hasher.update(trace_claim.add_ap[0].log_size, &self.add_ap);
        columns_hasher.update(trace_claim.assert_eq[0].log_size, &self.assert_eq);
        columns_hasher.update(trace_claim.assert_eq_imm[0].log_size, &self.assert_eq_imm);
        columns_hasher.update(
            trace_claim.assert_eq_double_deref[0].log_size,
            &self.assert_eq_double_deref,
        );
        columns_hasher.update(trace_claim.blake[0].log_size, &self.blake);
        columns_hasher.update(trace_claim.call[0].log_size, &self.call);
        columns_hasher.update(trace_claim.call_rel_imm[0].log_size, &self.call_rel_imm);
        columns_hasher.update(trace_claim.jnz[0].log_size, &self.jnz);
        columns_hasher.update(trace_claim.jnz_taken[0].log_size, &self.jnz_taken);
        columns_hasher.update(trace_claim.jump_rel[0].log_size, &self.jump_rel);
        columns_hasher.update(trace_claim.jump_rel_imm[0].log_size, &self.jump_rel_imm);
        columns_hasher.update(trace_claim.mul[0].log_size, &self.mul);
        columns_hasher.update(trace_claim.mul_small[0].log_size, &self.mul_small);
        columns_hasher.update(trace_claim.qm31[0].log_size, &self.qm31);
        columns_hasher.update(trace_claim.ret[0].log_size, &self.ret);
    }
}

impl BlakeInteractionQueryResult {
    pub fn update_hashes(
        &self,
        columns_hasher: &mut ColumnsHasherQM31,
        trace_claim: &BlakeContextClaim,
    ) {
        let claim = &trace_claim.claim.as_ref().unwrap();
        columns_hasher.update(claim.blake_round.log_size, &self.round);
        columns_hasher.update(claim.blake_g.log_size, &self.g);
        columns_hasher.update(
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &self.sigma,
        );
        columns_hasher.update(claim.triple_xor_32.log_size, &self.triple_xor_32);
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &self.verify_bitwise_xor_12,
        );
    }
}

impl RangeChecksInteractionQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31) {
        columns_hasher.update(
            cairo_air::components::range_check_6::LOG_SIZE,
            &self.range_check_6,
        );
        columns_hasher.update(
            cairo_air::components::range_check_8::LOG_SIZE,
            &self.range_check_8,
        );
        columns_hasher.update(
            cairo_air::components::range_check_11::LOG_SIZE,
            &self.range_check_11,
        );
        columns_hasher.update(
            cairo_air::components::range_check_12::LOG_SIZE,
            &self.range_check_12,
        );
        columns_hasher.update(
            cairo_air::components::range_check_18::LOG_SIZE,
            &self.range_check_18,
        );
        columns_hasher.update(
            cairo_air::components::range_check_18_b::LOG_SIZE,
            &self.range_check_18_b,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20::LOG_SIZE,
            &self.range_check_20,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_b::LOG_SIZE,
            &self.range_check_20_b,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_c::LOG_SIZE,
            &self.range_check_20_c,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_d::LOG_SIZE,
            &self.range_check_20_d,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_e::LOG_SIZE,
            &self.range_check_20_e,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_f::LOG_SIZE,
            &self.range_check_20_f,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_g::LOG_SIZE,
            &self.range_check_20_g,
        );
        columns_hasher.update(
            cairo_air::components::range_check_20_h::LOG_SIZE,
            &self.range_check_20_h,
        );
        columns_hasher.update(
            cairo_air::components::range_check_4_3::LOG_SIZE,
            &self.range_check_4_3,
        );
        columns_hasher.update(
            cairo_air::components::range_check_4_4::LOG_SIZE,
            &self.range_check_4_4,
        );
        columns_hasher.update(
            cairo_air::components::range_check_5_4::LOG_SIZE,
            &self.range_check_5_4,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9::LOG_SIZE,
            &self.range_check_9_9,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_b::LOG_SIZE,
            &self.range_check_9_9_b,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_c::LOG_SIZE,
            &self.range_check_9_9_c,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_d::LOG_SIZE,
            &self.range_check_9_9_d,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_e::LOG_SIZE,
            &self.range_check_9_9_e,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_f::LOG_SIZE,
            &self.range_check_9_9_f,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_g::LOG_SIZE,
            &self.range_check_9_9_g,
        );
        columns_hasher.update(
            cairo_air::components::range_check_9_9_h::LOG_SIZE,
            &self.range_check_9_9_h,
        );
        columns_hasher.update(
            cairo_air::components::range_check_7_2_5::LOG_SIZE,
            &self.range_check_7_2_5,
        );
        columns_hasher.update(
            cairo_air::components::range_check_3_6_6_3::LOG_SIZE,
            &self.range_check_3_6_6_3,
        );
        columns_hasher.update(
            cairo_air::components::range_check_4_4_4_4::LOG_SIZE,
            &self.range_check_4_4_4_4,
        );
        columns_hasher.update(
            cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE,
            &self.range_check_3_3_3_3_3,
        );
    }
}

impl VerifyBitwiseInteractionQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31) {
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_4::LOG_SIZE,
            &self.verify_bitwise_xor_4,
        );
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_7::LOG_SIZE,
            &self.verify_bitwise_xor_7,
        );
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_8::LOG_SIZE,
            &self.verify_bitwise_xor_8,
        );
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
            &self.verify_bitwise_xor_8_b,
        );
        columns_hasher.update(
            cairo_air::components::verify_bitwise_xor_9::LOG_SIZE,
            &self.verify_bitwise_xor_9,
        );
    }
}

/// Convert a slice of M31 values to QM31 values by grouping 4 M31 into 1 QM31
/// QM31 is constructed as QM31(CM31(m0, m1), CM31(m2, m3))
fn convert_m31_to_qm31(slice: &[M31]) -> Vec<QM31> {
    assert_eq!(slice.len() % 4, 0, "Slice length must be a multiple of 4");
    let mut result = Vec::new();
    for chunk in slice.chunks_exact(4) {
        let qm31 = QM31(CM31(chunk[0], chunk[1]), CM31(chunk[2], chunk[3]));
        result.push(qm31);
    }
    result
}

/// Helper function to extract a fixed-size array of QM31 from a slice
fn extract_qm31_array<const N: usize>(slice: &[QM31], offset: &mut usize) -> [QM31; N] {
    let end = *offset + N;
    let arr: [QM31; N] = slice[*offset..end].try_into().unwrap();
    *offset = end;
    arr
}

/// Allocate OpcodesInteractionQueryResult from QM31 slice
fn allocate_opcodes(slice: &[QM31], offset: &mut usize) -> OpcodesInteractionQueryResult {
    OpcodesInteractionQueryResult {
        add: extract_qm31_array::<5>(slice, offset),
        add_small: extract_qm31_array::<5>(slice, offset),
        add_ap: extract_qm31_array::<4>(slice, offset),
        assert_eq: extract_qm31_array::<3>(slice, offset),
        assert_eq_imm: extract_qm31_array::<3>(slice, offset),
        assert_eq_double_deref: extract_qm31_array::<4>(slice, offset),
        blake: extract_qm31_array::<37>(slice, offset),
        call: extract_qm31_array::<5>(slice, offset),
        call_rel_imm: extract_qm31_array::<5>(slice, offset),
        jnz: extract_qm31_array::<3>(slice, offset),
        jnz_taken: extract_qm31_array::<4>(slice, offset),
        jump_rel: extract_qm31_array::<3>(slice, offset),
        jump_rel_imm: extract_qm31_array::<3>(slice, offset),
        mul: extract_qm31_array::<19>(slice, offset),
        mul_small: extract_qm31_array::<6>(slice, offset),
        qm31: extract_qm31_array::<6>(slice, offset),
        ret: extract_qm31_array::<4>(slice, offset),
    }
}

/// Allocate BlakeInteractionQueryResult from QM31 slice
fn allocate_blake(slice: &[QM31], offset: &mut usize) -> BlakeInteractionQueryResult {
    BlakeInteractionQueryResult {
        round: extract_qm31_array::<30>(slice, offset),
        g: extract_qm31_array::<9>(slice, offset),
        sigma: extract_qm31_array::<1>(slice, offset),
        triple_xor_32: extract_qm31_array::<5>(slice, offset),
        verify_bitwise_xor_12: extract_qm31_array::<8>(slice, offset),
    }
}

/// Allocate RangeChecksInteractionQueryResult from QM31 slice
fn allocate_range_checks(slice: &[QM31], offset: &mut usize) -> RangeChecksInteractionQueryResult {
    RangeChecksInteractionQueryResult {
        range_check_6: extract_qm31_array::<1>(slice, offset),
        range_check_8: extract_qm31_array::<1>(slice, offset),
        range_check_11: extract_qm31_array::<1>(slice, offset),
        range_check_12: extract_qm31_array::<1>(slice, offset),
        range_check_18: extract_qm31_array::<1>(slice, offset),
        range_check_18_b: extract_qm31_array::<1>(slice, offset),
        range_check_20: extract_qm31_array::<1>(slice, offset),
        range_check_20_b: extract_qm31_array::<1>(slice, offset),
        range_check_20_c: extract_qm31_array::<1>(slice, offset),
        range_check_20_d: extract_qm31_array::<1>(slice, offset),
        range_check_20_e: extract_qm31_array::<1>(slice, offset),
        range_check_20_f: extract_qm31_array::<1>(slice, offset),
        range_check_20_g: extract_qm31_array::<1>(slice, offset),
        range_check_20_h: extract_qm31_array::<1>(slice, offset),
        range_check_4_3: extract_qm31_array::<1>(slice, offset),
        range_check_4_4: extract_qm31_array::<1>(slice, offset),
        range_check_5_4: extract_qm31_array::<1>(slice, offset),
        range_check_9_9: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_b: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_c: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_d: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_e: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_f: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_g: extract_qm31_array::<1>(slice, offset),
        range_check_9_9_h: extract_qm31_array::<1>(slice, offset),
        range_check_7_2_5: extract_qm31_array::<1>(slice, offset),
        range_check_3_6_6_3: extract_qm31_array::<1>(slice, offset),
        range_check_4_4_4_4: extract_qm31_array::<1>(slice, offset),
        range_check_3_3_3_3_3: extract_qm31_array::<1>(slice, offset),
    }
}

/// Allocate VerifyBitwiseInteractionQueryResult from QM31 slice
fn allocate_verify_bitwise(
    slice: &[QM31],
    offset: &mut usize,
) -> VerifyBitwiseInteractionQueryResult {
    VerifyBitwiseInteractionQueryResult {
        verify_bitwise_xor_4: extract_qm31_array::<1>(slice, offset),
        verify_bitwise_xor_7: extract_qm31_array::<1>(slice, offset),
        verify_bitwise_xor_8: extract_qm31_array::<1>(slice, offset),
        verify_bitwise_xor_8_b: extract_qm31_array::<1>(slice, offset),
        verify_bitwise_xor_9: extract_qm31_array::<1>(slice, offset),
    }
}

/// Allocate InteractionQueryResult from QM31 slice following the exact field order
fn allocate_interaction_query_result(slice: &[QM31]) -> InteractionQueryResult {
    let mut offset = 0;

    // Allocate in the exact order as defined in InteractionQueryResult
    let opcodes = allocate_opcodes(slice, &mut offset);
    let verify_instruction = extract_qm31_array::<3>(slice, &mut offset);
    let blake = allocate_blake(slice, &mut offset);
    let range_check_128_builtin = extract_qm31_array::<1>(slice, &mut offset);
    let memory_address_to_id = extract_qm31_array::<8>(slice, &mut offset);
    let memory_id_to_big_big = extract_qm31_array::<8>(slice, &mut offset);
    let memory_id_to_big_small = extract_qm31_array::<3>(slice, &mut offset);
    let range_checks = allocate_range_checks(slice, &mut offset);
    let verify_bitwise = allocate_verify_bitwise(slice, &mut offset);

    assert_eq!(offset, slice.len(),);

    InteractionQueryResult {
        opcodes,
        verify_instruction,
        blake,
        range_check_128_builtin,
        memory_address_to_id,
        memory_id_to_big_big,
        memory_id_to_big_small,
        range_checks,
        verify_bitwise,
    }
}

pub fn read_interaction(
    fiat_shamir_hints: &CairoFiatShamirHints,
    proof: &CairoProof<Poseidon31MerkleHasher>,
) -> Vec<InteractionQueryResult> {
    use super::read_query_values_into_pad;

    let log_sizes = &fiat_shamir_hints.log_sizes[2];
    let queried_values = &proof.stark_proof.queried_values[2];
    let witness = &proof.stark_proof.decommitments[2].column_witness;

    let pad = read_query_values_into_pad(
        log_sizes,
        queried_values,
        witness,
        &fiat_shamir_hints.raw_queries,
        &fiat_shamir_hints.query_positions_per_log_size,
        proof.stark_proof.config.fri_config.log_blowup_factor,
        proof.stark_proof.config.fri_config.n_queries,
    );

    let mut results = Vec::new();
    for m31_slice in pad
        .iter()
        .take(proof.stark_proof.config.fri_config.n_queries)
    {
        // Convert M31 slice to QM31 slice (4 M31 -> 1 QM31)
        let qm31_slice = convert_m31_to_qm31(m31_slice);
        let interaction_query_result = allocate_interaction_query_result(&qm31_slice);
        results.push(interaction_query_result);
    }

    results
}
