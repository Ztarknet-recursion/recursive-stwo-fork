use cairo_air::{
    air::CairoClaim, blake::air::BlakeContextClaim, opcodes_air::OpcodeClaim, CairoProof,
};
use indexmap::IndexMap;
use stwo::core::{
    fields::m31::M31,
    vcs::{poseidon31_hash::Poseidon31Hash, poseidon31_merkle::Poseidon31MerkleHasher},
};

use crate::{decommitment::utils::ColumnsHasher, CairoFiatShamirHints};

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

impl TraceQueryResult {
    pub fn compute_hashes(&self, claim: &CairoClaim) -> IndexMap<usize, Poseidon31Hash> {
        let mut columns_hasher = ColumnsHasher::new();

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

impl OpcodesTraceQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasher, claim: &OpcodeClaim) {
        columns_hasher.update(claim.add[0].log_size, &self.add);
        columns_hasher.update(claim.add_small[0].log_size, &self.add_small);
        columns_hasher.update(claim.add_ap[0].log_size, &self.add_ap);
        columns_hasher.update(claim.assert_eq[0].log_size, &self.assert_eq);
        columns_hasher.update(claim.assert_eq_imm[0].log_size, &self.assert_eq_imm);
        columns_hasher.update(
            claim.assert_eq_double_deref[0].log_size,
            &self.assert_eq_double_deref,
        );
        columns_hasher.update(claim.blake[0].log_size, &self.blake);
        columns_hasher.update(claim.call[0].log_size, &self.call);
        columns_hasher.update(claim.call_rel_imm[0].log_size, &self.call_rel_imm);
        columns_hasher.update(claim.jnz[0].log_size, &self.jnz);
        columns_hasher.update(claim.jnz_taken[0].log_size, &self.jnz_taken);
        columns_hasher.update(claim.jump_rel[0].log_size, &self.jump_rel);
        columns_hasher.update(claim.jump_rel_imm[0].log_size, &self.jump_rel_imm);
        columns_hasher.update(claim.mul[0].log_size, &self.mul);
        columns_hasher.update(claim.mul_small[0].log_size, &self.mul_small);
        columns_hasher.update(claim.qm31[0].log_size, &self.qm31);
        columns_hasher.update(claim.ret[0].log_size, &self.ret);
    }
}

impl BlakeTraceQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasher, claim: &BlakeContextClaim) {
        let claim = &claim.claim.as_ref().unwrap();
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

impl RangeChecksTraceQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasher) {
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

impl VerifyBitwiseTraceQueryResult {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasher) {
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

/// Helper function to extract a fixed-size array from a slice
fn extract_array<const N: usize>(slice: &[M31], offset: &mut usize) -> [M31; N] {
    let end = *offset + N;
    let arr: [M31; N] = slice[*offset..end].try_into().unwrap();
    *offset = end;
    arr
}

/// Allocate OpcodesTraceQueryResult from pad slice
fn allocate_opcodes(slice: &[M31], offset: &mut usize) -> OpcodesTraceQueryResult {
    OpcodesTraceQueryResult {
        add: extract_array::<{ cairo_air::components::add_opcode::N_TRACE_COLUMNS }>(slice, offset),
        add_small: extract_array::<{ cairo_air::components::add_opcode_small::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        add_ap: extract_array::<{ cairo_air::components::add_ap_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        assert_eq: extract_array::<{ cairo_air::components::assert_eq_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        assert_eq_imm: extract_array::<
            { cairo_air::components::assert_eq_opcode_imm::N_TRACE_COLUMNS },
        >(slice, offset),
        assert_eq_double_deref: extract_array::<
            { cairo_air::components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS },
        >(slice, offset),
        blake: extract_array::<{ cairo_air::components::blake_compress_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        call: extract_array::<{ cairo_air::components::call_opcode_abs::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        call_rel_imm: extract_array::<
            { cairo_air::components::call_opcode_rel_imm::N_TRACE_COLUMNS },
        >(slice, offset),
        jnz: extract_array::<{ cairo_air::components::jnz_opcode_non_taken::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        jnz_taken: extract_array::<{ cairo_air::components::jnz_opcode_taken::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        jump_rel: extract_array::<{ cairo_air::components::jump_opcode_rel::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        jump_rel_imm: extract_array::<
            { cairo_air::components::jump_opcode_rel_imm::N_TRACE_COLUMNS },
        >(slice, offset),
        mul: extract_array::<{ cairo_air::components::mul_opcode::N_TRACE_COLUMNS }>(slice, offset),
        mul_small: extract_array::<{ cairo_air::components::mul_opcode_small::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        qm31: extract_array::<{ cairo_air::components::qm_31_add_mul_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        ret: extract_array::<{ cairo_air::components::ret_opcode::N_TRACE_COLUMNS }>(slice, offset),
    }
}

/// Allocate BlakeTraceQueryResult from pad slice
fn allocate_blake(slice: &[M31], offset: &mut usize) -> BlakeTraceQueryResult {
    BlakeTraceQueryResult {
        round: extract_array::<{ cairo_air::components::blake_round::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        g: extract_array::<{ cairo_air::components::blake_g::N_TRACE_COLUMNS }>(slice, offset),
        sigma: extract_array::<{ cairo_air::components::blake_round_sigma::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        triple_xor_32: extract_array::<{ cairo_air::components::triple_xor_32::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        verify_bitwise_xor_12: extract_array::<
            { cairo_air::components::verify_bitwise_xor_12::N_TRACE_COLUMNS },
        >(slice, offset),
    }
}

/// Allocate RangeChecksTraceQueryResult from pad slice
fn allocate_range_checks(slice: &[M31], offset: &mut usize) -> RangeChecksTraceQueryResult {
    RangeChecksTraceQueryResult {
        range_check_6: extract_array::<{ cairo_air::components::range_check_6::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_8: extract_array::<{ cairo_air::components::range_check_8::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_11: extract_array::<{ cairo_air::components::range_check_11::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_12: extract_array::<{ cairo_air::components::range_check_12::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_18: extract_array::<{ cairo_air::components::range_check_18::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_18_b: extract_array::<
            { cairo_air::components::range_check_18_b::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20: extract_array::<{ cairo_air::components::range_check_20::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_b: extract_array::<
            { cairo_air::components::range_check_20_b::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_c: extract_array::<
            { cairo_air::components::range_check_20_c::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_d: extract_array::<
            { cairo_air::components::range_check_20_d::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_e: extract_array::<
            { cairo_air::components::range_check_20_e::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_f: extract_array::<
            { cairo_air::components::range_check_20_f::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_g: extract_array::<
            { cairo_air::components::range_check_20_g::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_20_h: extract_array::<
            { cairo_air::components::range_check_20_h::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_4_3: extract_array::<{ cairo_air::components::range_check_4_3::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_4_4: extract_array::<{ cairo_air::components::range_check_4_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_5_4: extract_array::<{ cairo_air::components::range_check_5_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9: extract_array::<{ cairo_air::components::range_check_9_9::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_b: extract_array::<
            { cairo_air::components::range_check_9_9_b::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_c: extract_array::<
            { cairo_air::components::range_check_9_9_c::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_d: extract_array::<
            { cairo_air::components::range_check_9_9_d::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_e: extract_array::<
            { cairo_air::components::range_check_9_9_e::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_f: extract_array::<
            { cairo_air::components::range_check_9_9_f::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_g: extract_array::<
            { cairo_air::components::range_check_9_9_g::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_9_9_h: extract_array::<
            { cairo_air::components::range_check_9_9_h::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_7_2_5: extract_array::<
            { cairo_air::components::range_check_7_2_5::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_3_6_6_3: extract_array::<
            { cairo_air::components::range_check_3_6_6_3::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_4_4_4_4: extract_array::<
            { cairo_air::components::range_check_4_4_4_4::N_TRACE_COLUMNS },
        >(slice, offset),
        range_check_3_3_3_3_3: extract_array::<
            { cairo_air::components::range_check_3_3_3_3_3::N_TRACE_COLUMNS },
        >(slice, offset),
    }
}

/// Allocate VerifyBitwiseTraceQueryResult from pad slice
fn allocate_verify_bitwise(slice: &[M31], offset: &mut usize) -> VerifyBitwiseTraceQueryResult {
    VerifyBitwiseTraceQueryResult {
        verify_bitwise_xor_4: extract_array::<
            { cairo_air::components::verify_bitwise_xor_4::N_TRACE_COLUMNS },
        >(slice, offset),
        verify_bitwise_xor_7: extract_array::<
            { cairo_air::components::verify_bitwise_xor_7::N_TRACE_COLUMNS },
        >(slice, offset),
        verify_bitwise_xor_8: extract_array::<
            { cairo_air::components::verify_bitwise_xor_8::N_TRACE_COLUMNS },
        >(slice, offset),
        verify_bitwise_xor_8_b: extract_array::<
            { cairo_air::components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS },
        >(slice, offset),
        verify_bitwise_xor_9: extract_array::<
            { cairo_air::components::verify_bitwise_xor_9::N_TRACE_COLUMNS },
        >(slice, offset),
    }
}

/// Allocate TraceQueryResult from pad slice following the exact field order
fn allocate_trace_query_result(slice: &[M31]) -> TraceQueryResult {
    let mut offset = 0;

    // Allocate in the exact order as defined in TraceQueryResult
    let opcodes = allocate_opcodes(slice, &mut offset);
    let verify_instruction = extract_array::<
        { cairo_air::components::verify_instruction::N_TRACE_COLUMNS },
    >(slice, &mut offset);
    let blake = allocate_blake(slice, &mut offset);
    let range_check_128_builtin = extract_array::<
        { cairo_air::components::range_check_builtin_bits_128::N_TRACE_COLUMNS },
    >(slice, &mut offset);
    let memory_address_to_id = extract_array::<
        { cairo_air::components::memory_address_to_id::N_TRACE_COLUMNS },
    >(slice, &mut offset);
    let memory_id_to_big_big = extract_array::<
        { cairo_air::components::memory_id_to_big::BIG_N_COLUMNS },
    >(slice, &mut offset);
    let memory_id_to_big_small = extract_array::<
        { cairo_air::components::memory_id_to_big::SMALL_N_COLUMNS },
    >(slice, &mut offset);
    let range_checks = allocate_range_checks(slice, &mut offset);
    let verify_bitwise = allocate_verify_bitwise(slice, &mut offset);

    assert_eq!(offset, slice.len(),);

    TraceQueryResult {
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

pub fn read_trace(
    fiat_shamir_hints: &CairoFiatShamirHints,
    proof: &CairoProof<Poseidon31MerkleHasher>,
) -> Vec<TraceQueryResult> {
    use super::read_query_values_into_pad;

    let log_sizes = &fiat_shamir_hints.log_sizes[1];
    let queried_values = &proof.stark_proof.queried_values[1];
    let witness = &proof.stark_proof.decommitments[1].column_witness;

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
    for c in pad
        .iter()
        .take(proof.stark_proof.config.fri_config.n_queries)
    {
        let trace_query_result = allocate_trace_query_result(c);
        results.push(trace_query_result);
    }

    results
}
