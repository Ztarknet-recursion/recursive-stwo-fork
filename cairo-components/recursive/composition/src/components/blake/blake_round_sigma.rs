// This file was created by the AIR team.

use crate::components::prelude::*;

pub struct Component {
    pub blake_round_sigma_lookup_elements: BlakeRoundSigmaVar,
}

impl ComponentVar for Component {
    #[allow(unused_parens)]
    #[allow(clippy::double_parens)]
    #[allow(non_snake_case)]
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let seq_4 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "seq_4".to_owned(),
        });
        let blake_sigma_0 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_0".to_owned(),
        });
        let blake_sigma_1 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_1".to_owned(),
        });
        let blake_sigma_2 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_2".to_owned(),
        });
        let blake_sigma_3 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_3".to_owned(),
        });
        let blake_sigma_4 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_4".to_owned(),
        });
        let blake_sigma_5 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_5".to_owned(),
        });
        let blake_sigma_6 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_6".to_owned(),
        });
        let blake_sigma_7 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_7".to_owned(),
        });
        let blake_sigma_8 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_8".to_owned(),
        });
        let blake_sigma_9 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_9".to_owned(),
        });
        let blake_sigma_10 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_10".to_owned(),
        });
        let blake_sigma_11 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_11".to_owned(),
        });
        let blake_sigma_12 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_12".to_owned(),
        });
        let blake_sigma_13 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_13".to_owned(),
        });
        let blake_sigma_14 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_14".to_owned(),
        });
        let blake_sigma_15 = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "blake_sigma_15".to_owned(),
        });
        let multiplicity = eval.next_trace_mask();

        eval.add_to_relation(RelationEntry::new(
            &self.blake_round_sigma_lookup_elements,
            -E::EF::from(multiplicity),
            &[
                seq_4.clone(),
                blake_sigma_0.clone(),
                blake_sigma_1.clone(),
                blake_sigma_2.clone(),
                blake_sigma_3.clone(),
                blake_sigma_4.clone(),
                blake_sigma_5.clone(),
                blake_sigma_6.clone(),
                blake_sigma_7.clone(),
                blake_sigma_8.clone(),
                blake_sigma_9.clone(),
                blake_sigma_10.clone(),
                blake_sigma_11.clone(),
                blake_sigma_12.clone(),
                blake_sigma_13.clone(),
                blake_sigma_14.clone(),
                blake_sigma_15.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
