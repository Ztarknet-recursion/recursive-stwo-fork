pub mod data_structures;
use std::ops::Add;

use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::CairoFiatShamirHints;
use circle_plonk_dsl_primitives::oblivious_map::ObliviousMapVar;
use circle_plonk_dsl_primitives::CirclePointM31Var;
pub use data_structures::*;

use cairo_plonk_dsl_data_structures::stark_proof::StarkProofVar;
use circle_plonk_dsl_constraint_system::var::Var;
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

pub struct AnswerResults {}

impl AnswerResults {
    pub fn compute(
        fiat_shamir_hints: &CairoFiatShamirHints,
        fiat_shamir_results: &CairoFiatShamirResults,
        decommitment_results: &CairoDecommitmentResultsVar,
        stark_proof: &StarkProofVar,
    ) -> AnswerResults {
        let cs = stark_proof.cs();

        let preprocessed_trace_sample_result = PreprocessedTraceSampleResultVar::new(
            &cs,
            &stark_proof.sampled_values[0],
            &stark_proof.is_preprocessed_trace_present,
        );
        let trace_sample_result = TraceSampleResultVar::new(&cs, &stark_proof.sampled_values[1]);
        let _ = InteractionSampleResultVar::new(&cs, &stark_proof.sampled_values[2]);
        let _ = CompositionSampleResultVar::new(&stark_proof.sampled_values[3]);

        let preprocessed_trace_quotient_constants = PreprocessedTraceQuotientConstantsVar::new(
            &fiat_shamir_results.oods_point,
            &preprocessed_trace_sample_result,
        );
        let _trace_quotient_constants =
            TraceQuotientConstantsVar::new(&fiat_shamir_results.oods_point, &trace_sample_result);

        let shifted_points = {
            let mut map = IndexMap::new();
            let oods_point = &fiat_shamir_results.oods_point;
            for i in LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE {
                map.insert(
                    i,
                    oods_point.add(&CanonicCoset::new(i).step().mul_signed(-1)),
                );
            }
            ObliviousMapVar::new(map)
        };

        for (k, v) in shifted_points.0.iter() {
            println!("k: {}, v: {:?}, {:?}", k, v.x.value(), v.y.value());
        }

        let n_queries = fiat_shamir_hints.pcs_config.fri_config.n_queries as usize;
        let mut answer_accumulator = Vec::with_capacity(n_queries);
        for _ in 0..n_queries {
            answer_accumulator.push(AnswerAccumulator::new(
                &cs,
                &fiat_shamir_results.after_sampled_values_random_coeff,
            ));
        }

        let query_positions_var = CairoQueryPositionsPerLogSizeVar::new(
            &fiat_shamir_results.queries,
            fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor,
            &fiat_shamir_results.query_log_size,
        );
        let domain_points: IndexMap<u32, Vec<CirclePointM31Var>> = query_positions_var
            .points
            .iter()
            .map(|(k, v)| {
                let v = v.iter().map(|v| v.get_next_point()).collect_vec();
                (*k, v)
            })
            .collect();

        /*let mut first_query = fiat_shamir_results.queries[0].compose().value.0;
        for log_size in (LOG_N_LANES + 1..=25).rev() {
            println!("log_size: {}, first_query: {:?}", log_size, CanonicCoset::new(log_size).circle_domain().at(bit_reverse_index(first_query as usize, log_size)));
            first_query = first_query >> 1;
        }

        for log_size in (LOG_N_LANES..=24).rev() {
            !("log_size: {}, first_query: {:?}", log_size, domain_points[&(log_size + 1)][0].value());
        }*/

        let _ = compute_preprocessed_trace_answers(
            1,
            &mut answer_accumulator,
            &fiat_shamir_results.oods_point,
            &domain_points,
            &decommitment_results,
            &preprocessed_trace_quotient_constants,
        );

        /*
                log_size: 25, var value: (0 + 0i) + (0 + 0i)u
        log_size: 24, var value: (0 + 0i) + (0 + 0i)u
        log_size: 23, var value: (0 + 0i) + (1944166826 + 894738403i)u
        log_size: 22, var value: (0 + 0i) + (861751153 + 972660099i)u
        log_size: 21, var value: (0 + 0i) + (2103157637 + 1900325456i)u
        log_size: 20, var value: (1625292024 + 2058587991i) + (519521732 + 1717532880i)u
        log_size: 19, var value: (0 + 0i) + (0 + 0i)u
        log_size: 18, var value: (1979153284 + 538717160i) + (1516035543 + 900327726i)u
        log_size: 17, var value: (0 + 0i) + (1011589566 + 192960924i)u
        log_size: 16, var value: (1627409145 + 190359572i) + (290893429 + 533236351i)u
        log_size: 15, var value: (393985835 + 1978648156i) + (808010217 + 1485396030i)u
        log_size: 14, var value: (1371768794 + 1916623345i) + (90932277 + 1709762822i)u
        log_size: 13, var value: (0 + 0i) + (0 + 0i)u
        log_size: 12, var value: (0 + 0i) + (1874693069 + 474694534i)u
        log_size: 11, var value: (0 + 0i) + (2060517739 + 416729087i)u
        log_size: 10, var value: (0 + 0i) + (0 + 0i)u
        log_size: 9, var value: (1764556131 + 815989014i) + (842614346 + 1399271434i)u
        log_size: 8, var value: (2044074597 + 355670411i) + (769872717 + 1631555242i)u
        log_size: 7, var value: (1632611417 + 116463536i) + (749685714 + 1192653455i)u
        log_size: 6, var value: (0 + 0i) + (554929574 + 592631363i)u
        log_size: 5, var value: (0 + 0i) + (0 + 0i)u
        log_size: 4, var value: (1199936415 + 1131571730i) + (1126919949 + 586753485i)u
                 */

        Self {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use cairo_plonk_dsl_hints::{CairoDecommitmentHints, CairoFiatShamirHints};
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use std::path::PathBuf;

    #[test]
    fn test_answer_results() {
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
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);
        let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, &proof);
        let decommitment_results = CairoDecommitmentResultsVar::compute(
            &fiat_shamir_hints,
            &decommitment_hints,
            &fiat_shamir_results,
            &proof_var,
        );
        let _ = AnswerResults::compute(
            &fiat_shamir_hints,
            &fiat_shamir_results,
            &decommitment_results,
            &proof_var.stark_proof,
        );
    }
}
