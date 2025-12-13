use cairo_air::CairoProof;
use stwo::core::{
    air::{accumulation::PointEvaluationAccumulator, Component, Components},
    fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE},
    vcs::poseidon31_merkle::Poseidon31MerkleHasher,
};

use crate::CairoFiatShamirHints;

pub struct CairoCompositionHints {}

impl CairoCompositionHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Self {
        let oods_point = fiat_shamir_hints.oods_point.clone();
        let random_coeff = &fiat_shamir_hints.random_coeff;
        let component_generator = &fiat_shamir_hints.component_generator;

        let mut evaluation_accumulator = PointEvaluationAccumulator::new(*random_coeff);

        // opcodes
        component_generator.opcodes.add[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.add_small[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.add_ap[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.assert_eq[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.assert_eq_imm[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.assert_eq_double_deref[0]
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator.opcodes.blake[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.call[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.call_rel_imm[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.jnz[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.jnz_taken[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.jump_rel[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.jump_rel_imm[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.mul[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.mul_small[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.qm31[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator.opcodes.ret[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );

        // verify_instruction
        component_generator
            .verify_instruction
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        // blake_context
        let blake_context_components = &component_generator
            .blake_context
            .components
            .as_ref()
            .unwrap();
        blake_context_components
            .blake_round
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        blake_context_components
            .blake_g
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        blake_context_components
            .blake_sigma
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        blake_context_components
            .triple_xor_32
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        blake_context_components
            .verify_bitwise_xor_12
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        // builtins
        let range_check_128_builtin = &component_generator
            .builtins
            .range_check_128_builtin
            .as_ref()
            .unwrap();
        range_check_128_builtin.evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );

        // memory_address_to_id
        component_generator
            .memory_address_to_id
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        // memory_id_to_value
        component_generator.memory_id_to_value.0[0].evaluate_constraint_quotients_at_point(
            oods_point,
            &proof.stark_proof.sampled_values,
            &mut evaluation_accumulator,
        );
        component_generator
            .memory_id_to_value
            .1
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        // range_checks
        component_generator
            .range_checks
            .rc_6
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_8
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_11
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_12
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_18
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_18_b
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_b
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_c
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_d
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_e
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_f
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_g
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_20_h
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_4_3
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_4_4
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_5_4
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_b
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_c
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_d
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_e
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_f
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_g
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_9_9_h
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_7_2_5
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_3_6_6_3
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_4_4_4_4
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .range_checks
            .rc_3_3_3_3_3
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        // verify_bitwise_xor
        component_generator
            .verify_bitwise_xor_4
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .verify_bitwise_xor_7
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .verify_bitwise_xor_8
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .verify_bitwise_xor_8_b
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );
        component_generator
            .verify_bitwise_xor_9
            .evaluate_constraint_quotients_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                &mut evaluation_accumulator,
            );

        let res = evaluation_accumulator.finalize();
        println!("current accumulated result: {:?}", res);

        // Calculate composition OODS evaluation
        let components_vec = component_generator.components();
        let components = Components {
            components: components_vec.to_vec(),
            n_preprocessed_columns: fiat_shamir_hints.n_preprocessed_columns,
        };

        let composition_oods_eval = {
            let left_and_right_composition_mask =
                proof.stark_proof.sampled_values.0.last().unwrap();
            let left_and_right_coordinate_evals: [SecureField; 2 * SECURE_EXTENSION_DEGREE] =
                left_and_right_composition_mask
                    .iter()
                    .map(|columns| {
                        let &[eval] = &columns[..] else {
                            return None;
                        };
                        Some(eval)
                    })
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
                    .try_into()
                    .unwrap();

            let (left_coordinate_evals, right_coordinate_evals) =
                left_and_right_coordinate_evals.split_at(SECURE_EXTENSION_DEGREE);

            let left_eval =
                SecureField::from_partial_evals(left_coordinate_evals.try_into().unwrap());
            let right_eval =
                SecureField::from_partial_evals(right_coordinate_evals.try_into().unwrap());
            left_eval
                + oods_point
                    .repeated_double(fiat_shamir_hints.composition_log_size - 2)
                    .x
                    * right_eval
        };

        println!("composition_oods_eval: {:?}", composition_oods_eval);

        assert_eq!(
            composition_oods_eval,
            components.eval_composition_polynomial_at_point(
                oods_point,
                &proof.stark_proof.sampled_values,
                *random_coeff,
            )
        );

        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use std::path::PathBuf;

    #[test]
    fn test_composition_hints() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let _ = CairoCompositionHints::new(&fiat_shamir_hints, &proof);
    }
}
