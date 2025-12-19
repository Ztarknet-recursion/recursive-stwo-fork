use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::{CairoDecommitmentHints, CairoFiatShamirHints};
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{BitsVar, HashVar};

use crate::data_structures::{
    CompositionQueryResultVar, InteractionQueryResultVar, PreprocessedTraceQueryResultVar,
    QueryDecommitmentProofVar, TraceQueryResultVar,
};

pub mod data_structures;

pub struct CairoDecommitmentResults(pub Vec<CairoDecommitmentResultVar>);

pub struct CairoDecommitmentResultVar {
    pub query: BitsVar,
    pub preprocessed_trace_query_result: PreprocessedTraceQueryResultVar,
    pub trace_query_result: TraceQueryResultVar,
    pub interaction_query_result: InteractionQueryResultVar,
    pub composition_query_result: CompositionQueryResultVar,
}

impl CairoDecommitmentResults {
    pub fn compute(
        fiat_shamir_hints: &CairoFiatShamirHints,
        decommitment_hints: &CairoDecommitmentHints,
        fiat_shamir_results: &CairoFiatShamirResults,
        proof: &CairoProofVar,
    ) -> Self {
        let mut results = vec![];
        let cs = proof.cs();
        for i in 0..fiat_shamir_hints.pcs_config.fri_config.n_queries {
            let preprocessed_result_var = PreprocessedTraceQueryResultVar::new_witness(
                &cs,
                &decommitment_hints.preprocessed_trace[i],
            );
            let trace_result_var =
                TraceQueryResultVar::new_witness(&cs, &decommitment_hints.trace[i]);
            let interaction_result_var =
                InteractionQueryResultVar::new_witness(&cs, &decommitment_hints.interaction[i]);
            let composition_result_var =
                CompositionQueryResultVar::new_witness(&cs, &decommitment_hints.composition[i]);

            let preprocessed_trace_decommitment_proof_var = QueryDecommitmentProofVar::new_witness(
                &cs,
                &decommitment_hints.preprocessed_trace_decommitment_proofs[i],
            );
            preprocessed_trace_decommitment_proof_var.verify(
                fiat_shamir_hints.pcs_config.fri_config.log_blowup_factor,
                &fiat_shamir_results.queries[i],
                &HashVar::new_constant(&cs, &fiat_shamir_hints.preprocessed_commitment),
                &fiat_shamir_results.max_log_size,
                &preprocessed_result_var.compute_column_hashes(),
            );

            // TODO: compute their merkle column hashes
            let _trace_proof_var = QueryDecommitmentProofVar::new_witness(
                &cs,
                &decommitment_hints.trace_decommitment_proofs[i],
            );
            let _interaction_proof_var = QueryDecommitmentProofVar::new_witness(
                &cs,
                &decommitment_hints.interaction_decommitment_proofs[i],
            );
            let _composition_proof_var = QueryDecommitmentProofVar::new_witness(
                &cs,
                &decommitment_hints.composition_decommitment_proofs[i],
            );

            results.push(CairoDecommitmentResultVar {
                query: fiat_shamir_results.queries[i].clone(),
                preprocessed_trace_query_result: preprocessed_result_var,
                trace_query_result: trace_result_var,
                interaction_query_result: interaction_result_var,
                composition_query_result: composition_result_var,
            });
        }
        Self(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
    use cairo_plonk_dsl_hints::{CairoDecommitmentHints, CairoFiatShamirHints};
    use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
    use std::path::PathBuf;

    #[test]
    fn test_decommitment() {
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
        let decommitment_hints = CairoDecommitmentHints::new(&fiat_shamir_hints, &proof);

        let cs = ConstraintSystemRef::new();

        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);

        let _ = CairoDecommitmentResults::compute(
            &fiat_shamir_hints,
            &decommitment_hints,
            &fiat_shamir_results,
            &proof_var,
        );

        cs.pad();
        cs.check_arithmetics();
        cs.populate_logup_arguments();
        cs.check_poseidon_invocations();
    }
}
