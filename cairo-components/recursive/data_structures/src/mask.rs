use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;

use crate::{
    claim::CairoClaimVar,
    data_structures::{BitIntVar, LogSizeVar},
};

#[derive(Clone, Debug)]
pub enum MaskVar {
    NoMask,
    ConstantLogSize(u32),
    VariableLogSize(BitIntVar<5>),
}

pub struct MaskTableVar(pub Vec<(MaskVar, usize)>);

impl MaskTableVar {
    pub fn from_claim(claim: &CairoClaimVar) -> Self {
        let helper = |res: &mut Vec<(MaskVar, usize)>, log_size: &LogSizeVar, l: usize| {
            res.push((MaskVar::NoMask, (l - 1) * SECURE_EXTENSION_DEGREE));
            res.push((
                MaskVar::VariableLogSize(log_size.bits.clone()),
                SECURE_EXTENSION_DEGREE,
            ));
        };

        let helper2 = |res: &mut Vec<(MaskVar, usize)>, log_size: u32, l: usize| {
            res.push((MaskVar::NoMask, (l - 1) * SECURE_EXTENSION_DEGREE));
            res.push((MaskVar::ConstantLogSize(log_size), SECURE_EXTENSION_DEGREE));
        };

        let mut res = Vec::new();

        // opcodes
        helper(&mut res, &claim.opcode_claim.add, 5);
        helper(&mut res, &claim.opcode_claim.add_small, 5);
        helper(&mut res, &claim.opcode_claim.add_ap, 4);
        helper(&mut res, &claim.opcode_claim.assert_eq, 3);
        helper(&mut res, &claim.opcode_claim.assert_eq_imm, 3);
        helper(&mut res, &claim.opcode_claim.assert_eq_double_deref, 4);
        helper(&mut res, &claim.opcode_claim.blake, 37);
        helper(&mut res, &claim.opcode_claim.call, 5);
        helper(&mut res, &claim.opcode_claim.call_rel_imm, 5);
        helper(&mut res, &claim.opcode_claim.jnz, 3);
        helper(&mut res, &claim.opcode_claim.jnz_taken, 4);
        helper(&mut res, &claim.opcode_claim.jump_rel, 3);
        helper(&mut res, &claim.opcode_claim.jump_rel_imm, 3);
        helper(&mut res, &claim.opcode_claim.mul, 19);
        helper(&mut res, &claim.opcode_claim.mul_small, 6);
        helper(&mut res, &claim.opcode_claim.qm31, 6);
        helper(&mut res, &claim.opcode_claim.ret, 4);

        // verify_instruction
        helper(&mut res, &claim.verify_instruction, 3);

        // blake context
        helper(&mut res, &claim.blake_context.blake_round, 30);
        helper(&mut res, &claim.blake_context.blake_g, 9);
        helper2(&mut res, 4, 1);
        helper(&mut res, &claim.blake_context.triple_xor_32, 5);
        helper2(&mut res, 20, 8);

        // builtins
        helper(
            &mut res,
            &claim.builtins.range_check_128_builtin_log_size,
            1,
        );

        // memory_address_to_id
        helper(&mut res, &claim.memory_address_to_id, 8);

        // memory_id_to_value
        helper(&mut res, &claim.memory_id_to_value.big_log_size, 8);
        helper(&mut res, &claim.memory_id_to_value.small_log_size, 3);

        // range_checks
        helper2(&mut res, 6, 1);
        helper2(&mut res, 8, 1);
        helper2(&mut res, 11, 1);
        helper2(&mut res, 12, 1);
        for _ in 0..2 {
            helper2(&mut res, 18, 1);
        }
        for _ in 0..8 {
            helper2(&mut res, 20, 1);
        }
        helper2(&mut res, 7, 1);
        helper2(&mut res, 8, 1);
        helper2(&mut res, 9, 1);
        for _ in 0..8 {
            helper2(&mut res, 18, 1);
        }
        helper2(&mut res, 14, 1);
        helper2(&mut res, 18, 1);
        helper2(&mut res, 16, 1);
        helper2(&mut res, 15, 1);

        // verify_bitwise_xor_4
        helper2(&mut res, 8, 1);

        // verify_bitwise_xor_7
        helper2(&mut res, 14, 1);

        // verify_bitwise_xor_8
        helper2(&mut res, 16, 1);

        // verify_bitwise_xor_8_b
        helper2(&mut res, 16, 1);

        // verify_bitwise_xor_9
        helper2(&mut res, 18, 1);

        MaskTableVar(res)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cairo_air::utils::deserialize_proof_from_file;
    use cairo_air::utils::ProofFormat;
    use cairo_plonk_dsl_hints::CairoFiatShamirHints;
    use circle_plonk_dsl_constraint_system::var::AllocVar;
    use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
    use itertools::Itertools;
    use stwo::core::poly::circle::CanonicCoset;

    use crate::CairoProofVar;

    use super::*;

    #[test]
    fn test_mask_table_var() {
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

        let mask_table_var = MaskTableVar::from_claim(&proof_var.claim);

        let expanded_mask_table_var = mask_table_var
            .0
            .iter()
            .flat_map(|(mask_var, size)| (0..*size).map(move |_| mask_var.clone()))
            .collect::<Vec<MaskVar>>();

        for (l, (i, j)) in fiat_shamir_hints.sample_points[2]
            .iter()
            .zip_eq(expanded_mask_table_var.iter())
            .enumerate()
        {
            if i.len() == 2 {
                assert!(!matches!(j, MaskVar::NoMask));
                assert_eq!(i[1], fiat_shamir_hints.oods_point);

                let log_size = match j {
                    MaskVar::ConstantLogSize(log_size) => *log_size,
                    MaskVar::VariableLogSize(log_size) => log_size.bits.compose().value.0,
                    _ => panic!("Invalid mask var"),
                };
                let trace_step = CanonicCoset::new(log_size).step();
                let expected = fiat_shamir_hints.oods_point + trace_step.mul_signed(-1).into_ef();
                assert_eq!(i[0], expected, "l: {:?}", l);
            } else {
                assert_eq!(i.len(), 1);
                assert!(matches!(j, MaskVar::NoMask));
                assert_eq!(i[0], fiat_shamir_hints.oods_point);
            }
        }

        println!("mask_table_var length: {:?}", mask_table_var.0.len());
    }
}
