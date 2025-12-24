use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_primitives::{
    option::OptionVar, BitVar, CM31Var, CirclePointM31Var, CirclePointQM31Var, M31Var, QM31Var,
};
use indexmap::IndexMap;
use itertools::Itertools;

use crate::AnswerAccumulator;

pub struct PreprocessedTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub seq_25: OptionVar<QM31Var>,
    pub seq_24: OptionVar<QM31Var>,
    pub seq_23: OptionVar<QM31Var>,
    pub seq_22: OptionVar<QM31Var>,
    pub seq_21: OptionVar<QM31Var>,
    pub seq_20: QM31Var, /* used by range check 20, 20b, 20c, 20d, 20e, 20f, 20g, 20h */
    pub bitwise_xor_10_0: QM31Var,
    pub bitwise_xor_10_1: QM31Var,
    pub bitwise_xor_10_2: QM31Var,
    pub seq_19: OptionVar<QM31Var>,
    pub seq_18: QM31Var, /* used by range check 18, 18b */
    pub bitwise_xor_9_0: QM31Var,
    pub bitwise_xor_9_1: QM31Var,
    pub bitwise_xor_9_2: QM31Var,
    pub range_check_9_9_column_0: QM31Var,
    pub range_check_9_9_column_1: QM31Var,
    pub range_check_3_6_6_3_column_0: QM31Var,
    pub range_check_3_6_6_3_column_1: QM31Var,
    pub range_check_3_6_6_3_column_2: QM31Var,
    pub range_check_3_6_6_3_column_3: QM31Var,
    pub seq_17: OptionVar<QM31Var>,
    pub seq_16: OptionVar<QM31Var>,
    pub bitwise_xor_8_0: QM31Var,
    pub bitwise_xor_8_1: QM31Var,
    pub bitwise_xor_8_2: QM31Var,
    pub range_check_4_4_4_4_column_0: QM31Var,
    pub range_check_4_4_4_4_column_1: QM31Var,
    pub range_check_4_4_4_4_column_2: QM31Var,
    pub range_check_4_4_4_4_column_3: QM31Var,
    pub seq_15: OptionVar<QM31Var>,
    pub range_check_3_3_3_3_3_column_0: QM31Var,
    pub range_check_3_3_3_3_3_column_1: QM31Var,
    pub range_check_3_3_3_3_3_column_2: QM31Var,
    pub range_check_3_3_3_3_3_column_3: QM31Var,
    pub range_check_3_3_3_3_3_column_4: QM31Var,
    pub seq_14: OptionVar<QM31Var>,
    pub bitwise_xor_7_0: QM31Var,
    pub bitwise_xor_7_1: QM31Var,
    pub bitwise_xor_7_2: QM31Var,
    pub range_check_7_2_5_column_0: QM31Var,
    pub range_check_7_2_5_column_1: QM31Var,
    pub range_check_7_2_5_column_2: QM31Var,
    pub seq_13: OptionVar<QM31Var>,
    pub seq_12: QM31Var, /* used by range check 12 */
    pub seq_11: QM31Var, /* used by range check 11 */
    pub seq_10: OptionVar<QM31Var>,
    pub seq_9: OptionVar<QM31Var>,
    pub range_check_5_4_column_0: QM31Var,
    pub range_check_5_4_column_1: QM31Var,
    pub seq_8: QM31Var, /* used by range check 8 */
    pub bitwise_xor_4_0: QM31Var,
    pub bitwise_xor_4_1: QM31Var,
    pub bitwise_xor_4_2: QM31Var,
    pub range_check_4_4_column_0: QM31Var,
    pub range_check_4_4_column_1: QM31Var,
    pub seq_7: OptionVar<QM31Var>,
    pub range_check_4_3_column_0: QM31Var,
    pub range_check_4_3_column_1: QM31Var,
    pub seq_6: QM31Var, /* used by range check 6 */
    pub seq_5: OptionVar<QM31Var>,
    pub seq_4: QM31Var, /* used by blake_round_sigma */
    pub blake_sigma_0: QM31Var,
    pub blake_sigma_1: QM31Var,
    pub blake_sigma_2: QM31Var,
    pub blake_sigma_3: QM31Var,
    pub blake_sigma_4: QM31Var,
    pub blake_sigma_5: QM31Var,
    pub blake_sigma_6: QM31Var,
    pub blake_sigma_7: QM31Var,
    pub blake_sigma_8: QM31Var,
    pub blake_sigma_9: QM31Var,
    pub blake_sigma_10: QM31Var,
    pub blake_sigma_11: QM31Var,
    pub blake_sigma_12: QM31Var,
    pub blake_sigma_13: QM31Var,
    pub blake_sigma_14: QM31Var,
    pub blake_sigma_15: QM31Var,
}

impl PreprocessedTraceSampleResultVar {
    pub fn new(
        cs: &ConstraintSystemRef,
        sampled_values: &Vec<Vec<QM31Var>>,
        is_preprocessed_trace_present: &Vec<BitVar>,
    ) -> Self {
        let sampled_values = sampled_values.iter().map(|v| &v[0]).collect_vec();

        Self {
            cs: cs.clone(),
            seq_25: OptionVar::new(
                is_preprocessed_trace_present[0].clone(),
                sampled_values[0].clone(),
            ),
            seq_24: OptionVar::new(
                is_preprocessed_trace_present[1].clone(),
                sampled_values[1].clone(),
            ),
            seq_23: OptionVar::new(
                is_preprocessed_trace_present[2].clone(),
                sampled_values[2].clone(),
            ),
            seq_22: OptionVar::new(
                is_preprocessed_trace_present[3].clone(),
                sampled_values[3].clone(),
            ),
            seq_21: OptionVar::new(
                is_preprocessed_trace_present[4].clone(),
                sampled_values[4].clone(),
            ),
            seq_20: sampled_values[5].clone(),
            bitwise_xor_10_0: sampled_values[6].clone(),
            bitwise_xor_10_1: sampled_values[7].clone(),
            bitwise_xor_10_2: sampled_values[8].clone(),
            seq_19: OptionVar::new(
                is_preprocessed_trace_present[9].clone(),
                sampled_values[9].clone(),
            ),
            seq_18: sampled_values[10].clone(),
            bitwise_xor_9_0: sampled_values[11].clone(),
            bitwise_xor_9_1: sampled_values[12].clone(),
            bitwise_xor_9_2: sampled_values[13].clone(),
            range_check_9_9_column_0: sampled_values[14].clone(),
            range_check_9_9_column_1: sampled_values[15].clone(),
            range_check_3_6_6_3_column_0: sampled_values[16].clone(),
            range_check_3_6_6_3_column_1: sampled_values[17].clone(),
            range_check_3_6_6_3_column_2: sampled_values[18].clone(),
            range_check_3_6_6_3_column_3: sampled_values[19].clone(),
            seq_17: OptionVar::new(
                is_preprocessed_trace_present[20].clone(),
                sampled_values[20].clone(),
            ),
            seq_16: OptionVar::new(
                is_preprocessed_trace_present[21].clone(),
                sampled_values[21].clone(),
            ),
            bitwise_xor_8_0: sampled_values[22].clone(),
            bitwise_xor_8_1: sampled_values[23].clone(),
            bitwise_xor_8_2: sampled_values[24].clone(),
            range_check_4_4_4_4_column_0: sampled_values[25].clone(),
            range_check_4_4_4_4_column_1: sampled_values[26].clone(),
            range_check_4_4_4_4_column_2: sampled_values[27].clone(),
            range_check_4_4_4_4_column_3: sampled_values[28].clone(),
            seq_15: OptionVar::new(
                is_preprocessed_trace_present[29].clone(),
                sampled_values[29].clone(),
            ),
            range_check_3_3_3_3_3_column_0: sampled_values[30].clone(),
            range_check_3_3_3_3_3_column_1: sampled_values[31].clone(),
            range_check_3_3_3_3_3_column_2: sampled_values[32].clone(),
            range_check_3_3_3_3_3_column_3: sampled_values[33].clone(),
            range_check_3_3_3_3_3_column_4: sampled_values[34].clone(),
            seq_14: OptionVar::new(
                is_preprocessed_trace_present[35].clone(),
                sampled_values[35].clone(),
            ),
            bitwise_xor_7_0: sampled_values[36].clone(),
            bitwise_xor_7_1: sampled_values[37].clone(),
            bitwise_xor_7_2: sampled_values[38].clone(),
            range_check_7_2_5_column_0: sampled_values[39].clone(),
            range_check_7_2_5_column_1: sampled_values[40].clone(),
            range_check_7_2_5_column_2: sampled_values[41].clone(),
            seq_13: OptionVar::new(
                is_preprocessed_trace_present[42].clone(),
                sampled_values[42].clone(),
            ),
            seq_12: sampled_values[43].clone(),
            seq_11: sampled_values[44].clone(),
            seq_10: OptionVar::new(
                is_preprocessed_trace_present[45].clone(),
                sampled_values[45].clone(),
            ),
            seq_9: OptionVar::new(
                is_preprocessed_trace_present[46].clone(),
                sampled_values[46].clone(),
            ),
            range_check_5_4_column_0: sampled_values[47].clone(),
            range_check_5_4_column_1: sampled_values[48].clone(),
            seq_8: sampled_values[49].clone(),
            bitwise_xor_4_0: sampled_values[50].clone(),
            bitwise_xor_4_1: sampled_values[51].clone(),
            bitwise_xor_4_2: sampled_values[52].clone(),
            range_check_4_4_column_0: sampled_values[53].clone(),
            range_check_4_4_column_1: sampled_values[54].clone(),
            seq_7: OptionVar::new(
                is_preprocessed_trace_present[55].clone(),
                sampled_values[55].clone(),
            ),
            range_check_4_3_column_0: sampled_values[56].clone(),
            range_check_4_3_column_1: sampled_values[57].clone(),
            seq_6: sampled_values[58].clone(),
            seq_5: OptionVar::new(
                is_preprocessed_trace_present[89].clone(),
                sampled_values[89].clone(),
            ),
            seq_4: sampled_values[90].clone(),
            blake_sigma_0: sampled_values[91].clone(),
            blake_sigma_1: sampled_values[92].clone(),
            blake_sigma_2: sampled_values[93].clone(),
            blake_sigma_3: sampled_values[94].clone(),
            blake_sigma_4: sampled_values[95].clone(),
            blake_sigma_5: sampled_values[96].clone(),
            blake_sigma_6: sampled_values[97].clone(),
            blake_sigma_7: sampled_values[98].clone(),
            blake_sigma_8: sampled_values[99].clone(),
            blake_sigma_9: sampled_values[100].clone(),
            blake_sigma_10: sampled_values[101].clone(),
            blake_sigma_11: sampled_values[102].clone(),
            blake_sigma_12: sampled_values[103].clone(),
            blake_sigma_13: sampled_values[104].clone(),
            blake_sigma_14: sampled_values[105].clone(),
            blake_sigma_15: sampled_values[106].clone(),
        }
    }
}

pub struct PreprocessedTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub seq_25: OptionVar<[CM31Var; 3]>,
    pub seq_24: OptionVar<[CM31Var; 3]>,
    pub seq_23: OptionVar<[CM31Var; 3]>,
    pub seq_22: OptionVar<[CM31Var; 3]>,
    pub seq_21: OptionVar<[CM31Var; 3]>,
    pub seq_20: [CM31Var; 3], /* used by range check 20, 20b, 20c, 20d, 20e, 20f, 20g, 20h */
    pub bitwise_xor_10_0: [CM31Var; 3],
    pub bitwise_xor_10_1: [CM31Var; 3],
    pub bitwise_xor_10_2: [CM31Var; 3],
    pub seq_19: OptionVar<[CM31Var; 3]>,
    pub seq_18: [CM31Var; 3],
    pub bitwise_xor_9_0: [CM31Var; 3],
    pub bitwise_xor_9_1: [CM31Var; 3],
    pub bitwise_xor_9_2: [CM31Var; 3],
    pub range_check_9_9_column_0: [CM31Var; 3],
    pub range_check_9_9_column_1: [CM31Var; 3],
    pub range_check_3_6_6_3_column_0: [CM31Var; 3],
    pub range_check_3_6_6_3_column_1: [CM31Var; 3],
    pub range_check_3_6_6_3_column_2: [CM31Var; 3],
    pub range_check_3_6_6_3_column_3: [CM31Var; 3],
    pub seq_17: OptionVar<[CM31Var; 3]>,
    pub seq_16: OptionVar<[CM31Var; 3]>,
    pub bitwise_xor_8_0: [CM31Var; 3],
    pub bitwise_xor_8_1: [CM31Var; 3],
    pub bitwise_xor_8_2: [CM31Var; 3],
    pub range_check_4_4_4_4_column_0: [CM31Var; 3],
    pub range_check_4_4_4_4_column_1: [CM31Var; 3],
    pub range_check_4_4_4_4_column_2: [CM31Var; 3],
    pub range_check_4_4_4_4_column_3: [CM31Var; 3],
    pub seq_15: OptionVar<[CM31Var; 3]>,
    pub range_check_3_3_3_3_3_column_0: [CM31Var; 3],
    pub range_check_3_3_3_3_3_column_1: [CM31Var; 3],
    pub range_check_3_3_3_3_3_column_2: [CM31Var; 3],
    pub range_check_3_3_3_3_3_column_3: [CM31Var; 3],
    pub range_check_3_3_3_3_3_column_4: [CM31Var; 3],
    pub seq_14: OptionVar<[CM31Var; 3]>,
    pub bitwise_xor_7_0: [CM31Var; 3],
    pub bitwise_xor_7_1: [CM31Var; 3],
    pub bitwise_xor_7_2: [CM31Var; 3],
    pub range_check_7_2_5_column_0: [CM31Var; 3],
    pub range_check_7_2_5_column_1: [CM31Var; 3],
    pub range_check_7_2_5_column_2: [CM31Var; 3],
    pub seq_13: OptionVar<[CM31Var; 3]>,
    pub seq_12: [CM31Var; 3], /* used by range check 12 */
    pub seq_11: [CM31Var; 3], /* used by range check 11 */
    pub seq_10: OptionVar<[CM31Var; 3]>,
    pub seq_9: OptionVar<[CM31Var; 3]>,
    pub range_check_5_4_column_0: [CM31Var; 3],
    pub range_check_5_4_column_1: [CM31Var; 3],
    pub seq_8: [CM31Var; 3], /* used by range check 8 */
    pub bitwise_xor_4_0: [CM31Var; 3],
    pub bitwise_xor_4_1: [CM31Var; 3],
    pub bitwise_xor_4_2: [CM31Var; 3],
    pub range_check_4_4_column_0: [CM31Var; 3],
    pub range_check_4_4_column_1: [CM31Var; 3],
    pub seq_7: OptionVar<[CM31Var; 3]>,
    pub range_check_4_3_column_0: [CM31Var; 3],
    pub range_check_4_3_column_1: [CM31Var; 3],
    pub seq_6: [CM31Var; 3], /* used by range check 6 */
    pub seq_5: OptionVar<[CM31Var; 3]>,
    pub seq_4: [CM31Var; 3], /* used by blake_round_sigma */
    pub blake_sigma_0: [CM31Var; 3],
    pub blake_sigma_1: [CM31Var; 3],
    pub blake_sigma_2: [CM31Var; 3],
    pub blake_sigma_3: [CM31Var; 3],
    pub blake_sigma_4: [CM31Var; 3],
    pub blake_sigma_5: [CM31Var; 3],
    pub blake_sigma_6: [CM31Var; 3],
    pub blake_sigma_7: [CM31Var; 3],
    pub blake_sigma_8: [CM31Var; 3],
    pub blake_sigma_9: [CM31Var; 3],
    pub blake_sigma_10: [CM31Var; 3],
    pub blake_sigma_11: [CM31Var; 3],
    pub blake_sigma_12: [CM31Var; 3],
    pub blake_sigma_13: [CM31Var; 3],
    pub blake_sigma_14: [CM31Var; 3],
    pub blake_sigma_15: [CM31Var; 3],
}

impl PreprocessedTraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &PreprocessedTraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            seq_25: OptionVar::new(
                sample_result.seq_25.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_25.value),
            ),
            seq_24: OptionVar::new(
                sample_result.seq_24.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_24.value),
            ),
            seq_23: OptionVar::new(
                sample_result.seq_23.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_23.value),
            ),
            seq_22: OptionVar::new(
                sample_result.seq_22.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_22.value),
            ),
            seq_21: OptionVar::new(
                sample_result.seq_21.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_21.value),
            ),
            seq_20: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_20),
            bitwise_xor_10_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_10_0,
            ),
            bitwise_xor_10_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_10_1,
            ),
            bitwise_xor_10_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_10_2,
            ),
            seq_19: OptionVar::new(
                sample_result.seq_19.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_19.value),
            ),
            seq_18: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_18),
            bitwise_xor_9_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_9_0,
            ),
            bitwise_xor_9_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_9_1,
            ),
            bitwise_xor_9_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_9_2,
            ),
            range_check_9_9_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_9_9_column_0,
            ),
            range_check_9_9_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_9_9_column_1,
            ),
            range_check_3_6_6_3_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_6_6_3_column_0,
            ),
            range_check_3_6_6_3_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_6_6_3_column_1,
            ),
            range_check_3_6_6_3_column_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_6_6_3_column_2,
            ),
            range_check_3_6_6_3_column_3: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_6_6_3_column_3,
            ),
            seq_17: OptionVar::new(
                sample_result.seq_17.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_17.value),
            ),
            seq_16: OptionVar::new(
                sample_result.seq_16.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_16.value),
            ),
            bitwise_xor_8_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_8_0,
            ),
            bitwise_xor_8_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_8_1,
            ),
            bitwise_xor_8_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_8_2,
            ),
            range_check_4_4_4_4_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_4_4_column_0,
            ),
            range_check_4_4_4_4_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_4_4_column_1,
            ),
            range_check_4_4_4_4_column_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_4_4_column_2,
            ),
            range_check_4_4_4_4_column_3: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_4_4_column_3,
            ),
            seq_15: OptionVar::new(
                sample_result.seq_15.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_15.value),
            ),
            range_check_3_3_3_3_3_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_3_3_3_3_column_0,
            ),
            range_check_3_3_3_3_3_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_3_3_3_3_column_1,
            ),
            range_check_3_3_3_3_3_column_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_3_3_3_3_column_2,
            ),
            range_check_3_3_3_3_3_column_3: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_3_3_3_3_column_3,
            ),
            range_check_3_3_3_3_3_column_4: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_3_3_3_3_3_column_4,
            ),
            seq_14: OptionVar::new(
                sample_result.seq_14.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_14.value),
            ),
            bitwise_xor_7_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_7_0,
            ),
            bitwise_xor_7_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_7_1,
            ),
            bitwise_xor_7_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_7_2,
            ),
            range_check_7_2_5_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_7_2_5_column_0,
            ),
            range_check_7_2_5_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_7_2_5_column_1,
            ),
            range_check_7_2_5_column_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_7_2_5_column_2,
            ),
            seq_13: OptionVar::new(
                sample_result.seq_13.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_13.value),
            ),
            seq_12: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_12),
            seq_11: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_11),
            seq_10: OptionVar::new(
                sample_result.seq_10.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_10.value),
            ),
            seq_9: OptionVar::new(
                sample_result.seq_9.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_9.value),
            ),
            range_check_5_4_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_5_4_column_0,
            ),
            range_check_5_4_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_5_4_column_1,
            ),
            seq_8: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_8),
            bitwise_xor_4_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_4_0,
            ),
            bitwise_xor_4_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_4_1,
            ),
            bitwise_xor_4_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.bitwise_xor_4_2,
            ),
            range_check_4_4_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_column_0,
            ),
            range_check_4_4_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_4_column_1,
            ),
            seq_7: OptionVar::new(
                sample_result.seq_7.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_7.value),
            ),
            range_check_4_3_column_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_3_column_0,
            ),
            range_check_4_3_column_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.range_check_4_3_column_1,
            ),
            seq_6: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_6),
            seq_5: OptionVar::new(
                sample_result.seq_5.is_some.clone(),
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_5.value),
            ),
            seq_4: complex_conjugate_line_coeffs_var(oods_point, &sample_result.seq_4),
            blake_sigma_0: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_0,
            ),
            blake_sigma_1: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_1,
            ),
            blake_sigma_2: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_2,
            ),
            blake_sigma_3: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_3,
            ),
            blake_sigma_4: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_4,
            ),
            blake_sigma_5: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_5,
            ),
            blake_sigma_6: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_6,
            ),
            blake_sigma_7: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_7,
            ),
            blake_sigma_8: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_8,
            ),
            blake_sigma_9: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_9,
            ),
            blake_sigma_10: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_10,
            ),
            blake_sigma_11: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_11,
            ),
            blake_sigma_12: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_12,
            ),
            blake_sigma_13: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_13,
            ),
            blake_sigma_14: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_14,
            ),
            blake_sigma_15: complex_conjugate_line_coeffs_var(
                oods_point,
                &sample_result.blake_sigma_15,
            ),
        }
    }
}

pub fn compute_preprocessed_trace_answers(
    num_queries: usize,
    answer_accumulator: &mut Vec<AnswerAccumulator>,
    oods_point: &CirclePointQM31Var,
    domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
    query_result: &CairoDecommitmentResultsVar,
    quotient_constants: &PreprocessedTraceQuotientConstantsVar,
) {
    let [prx, pix] = oods_point.x.decompose_cm31();
    let [pry, piy] = oods_point.y.decompose_cm31();

    let update = |answer_accumulator: &mut AnswerAccumulator,
                  log_size: usize,
                  query: &[&M31Var],
                  quotient_constants: &[&[CM31Var; 3]],
                  query_point: &CirclePointM31Var| {
        let denominator_inverse =
            (&(&(&prx - &query_point.x) * &piy) - &(&(&pry - &query_point.y) * &pix)).inv();
        let update = quotient_constants
            .iter()
            .zip_eq(query.iter())
            .map(|(quotient_constants, query)| {
                &denominator_inverse
                    * &(&(&(&quotient_constants[2] * *query)
                        - &(&quotient_constants[0] * &query_point.y))
                        - &quotient_constants[1])
            })
            .collect_vec();
        answer_accumulator.update_fix_log_size(log_size, &update);
    };

    let update_conditional = |answer_accumulator: &mut AnswerAccumulator,
                              log_size: usize,
                              query: &[&M31Var],
                              quotient_constants: &[&[CM31Var; 3]],
                              query_point: &CirclePointM31Var,
                              condition: &BitVar| {
        let denominator_inverse =
            (&(&(&prx - &query_point.x) * &piy) - &(&(&pry - &query_point.y) * &pix)).inv();
        let update = quotient_constants
            .iter()
            .zip_eq(query.iter())
            .map(|(quotient_constants, query)| {
                &denominator_inverse
                    * &(&(&(&quotient_constants[2] * *query)
                        - &(&quotient_constants[0] * &query_point.y))
                        - &quotient_constants[1])
            })
            .collect_vec();
        answer_accumulator.update_fix_log_size_conditional(log_size, &update, condition);
    };

    for idx in 0..num_queries {
        let answer_accumulator = &mut answer_accumulator[idx];

        update_conditional(
            answer_accumulator,
            25,
            &[&query_result[idx].preprocessed_trace_query_result.seq_25],
            &[&quotient_constants.seq_25.value],
            &domain_points.get(&(25 + 1)).unwrap()[idx],
            &quotient_constants.seq_25.is_some,
        );
        update_conditional(
            answer_accumulator,
            24,
            &[&query_result[idx].preprocessed_trace_query_result.seq_24],
            &[&quotient_constants.seq_24.value],
            &domain_points.get(&(24 + 1)).unwrap()[idx],
            &quotient_constants.seq_24.is_some,
        );
        update_conditional(
            answer_accumulator,
            23,
            &[&query_result[idx].preprocessed_trace_query_result.seq_23],
            &[&quotient_constants.seq_23.value],
            &domain_points.get(&(23 + 1)).unwrap()[idx],
            &quotient_constants.seq_23.is_some,
        );
        update_conditional(
            answer_accumulator,
            22,
            &[&query_result[idx].preprocessed_trace_query_result.seq_22],
            &[&quotient_constants.seq_22.value],
            &domain_points.get(&(22 + 1)).unwrap()[idx],
            &quotient_constants.seq_22.is_some,
        );
        update_conditional(
            answer_accumulator,
            21,
            &[&query_result[idx].preprocessed_trace_query_result.seq_21],
            &[&quotient_constants.seq_21.value],
            &domain_points.get(&(21 + 1)).unwrap()[idx],
            &quotient_constants.seq_21.is_some,
        );
        update(
            answer_accumulator,
            20,
            &[
                &query_result[idx].preprocessed_trace_query_result.seq_20,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_10_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_10_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_10_2,
            ],
            &[
                &quotient_constants.seq_20,
                &quotient_constants.bitwise_xor_10_0,
                &quotient_constants.bitwise_xor_10_1,
                &quotient_constants.bitwise_xor_10_2,
            ],
            &domain_points.get(&(20 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            19,
            &[&query_result[idx].preprocessed_trace_query_result.seq_19],
            &[&quotient_constants.seq_19.value],
            &domain_points.get(&(19 + 1)).unwrap()[idx],
            &quotient_constants.seq_19.is_some,
        );
        update(
            answer_accumulator,
            18,
            &[
                &query_result[idx].preprocessed_trace_query_result.seq_18,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_9_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_9_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_9_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_9_9_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_9_9_column_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_6_6_3_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_6_6_3_column_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_6_6_3_column_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_6_6_3_column_3,
            ],
            &[
                &quotient_constants.seq_18,
                &quotient_constants.bitwise_xor_9_0,
                &quotient_constants.bitwise_xor_9_1,
                &quotient_constants.bitwise_xor_9_2,
                &quotient_constants.range_check_9_9_column_0,
                &quotient_constants.range_check_9_9_column_1,
                &quotient_constants.range_check_3_6_6_3_column_0,
                &quotient_constants.range_check_3_6_6_3_column_1,
                &quotient_constants.range_check_3_6_6_3_column_2,
                &quotient_constants.range_check_3_6_6_3_column_3,
            ],
            &domain_points.get(&(18 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            17,
            &[&query_result[idx].preprocessed_trace_query_result.seq_17],
            &[&quotient_constants.seq_17.value],
            &domain_points.get(&(17 + 1)).unwrap()[idx],
            &quotient_constants.seq_17.is_some,
        );
        update_conditional(
            answer_accumulator,
            16,
            &[&query_result[idx].preprocessed_trace_query_result.seq_16],
            &[&quotient_constants.seq_16.value],
            &domain_points.get(&(16 + 1)).unwrap()[idx],
            &quotient_constants.seq_16.is_some,
        );
        update(
            answer_accumulator,
            16,
            &[
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_8_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_8_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_8_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_4_4_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_4_4_column_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_4_4_column_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_4_4_column_3,
            ],
            &[
                &quotient_constants.bitwise_xor_8_0,
                &quotient_constants.bitwise_xor_8_1,
                &quotient_constants.bitwise_xor_8_2,
                &quotient_constants.range_check_4_4_4_4_column_0,
                &quotient_constants.range_check_4_4_4_4_column_1,
                &quotient_constants.range_check_4_4_4_4_column_2,
                &quotient_constants.range_check_4_4_4_4_column_3,
            ],
            &domain_points.get(&(16 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            15,
            &[&query_result[idx].preprocessed_trace_query_result.seq_15],
            &[&quotient_constants.seq_15.value],
            &domain_points.get(&(15 + 1)).unwrap()[idx],
            &quotient_constants.seq_15.is_some,
        );
        update(
            answer_accumulator,
            15,
            &[
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_3_3_3_3_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_3_3_3_3_column_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_3_3_3_3_column_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_3_3_3_3_column_3,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_3_3_3_3_3_column_4,
            ],
            &[
                &quotient_constants.range_check_3_3_3_3_3_column_0,
                &quotient_constants.range_check_3_3_3_3_3_column_1,
                &quotient_constants.range_check_3_3_3_3_3_column_2,
                &quotient_constants.range_check_3_3_3_3_3_column_3,
                &quotient_constants.range_check_3_3_3_3_3_column_4,
            ],
            &domain_points.get(&(15 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            14,
            &[&query_result[idx].preprocessed_trace_query_result.seq_14],
            &[&quotient_constants.seq_14.value],
            &domain_points.get(&(14 + 1)).unwrap()[idx],
            &quotient_constants.seq_14.is_some,
        );
        update(
            answer_accumulator,
            14,
            &[
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_7_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_7_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_7_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_7_2_5_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_7_2_5_column_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_7_2_5_column_2,
            ],
            &[
                &quotient_constants.bitwise_xor_7_0,
                &quotient_constants.bitwise_xor_7_1,
                &quotient_constants.bitwise_xor_7_2,
                &quotient_constants.range_check_7_2_5_column_0,
                &quotient_constants.range_check_7_2_5_column_1,
                &quotient_constants.range_check_7_2_5_column_2,
            ],
            &domain_points.get(&(14 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            13,
            &[&query_result[idx].preprocessed_trace_query_result.seq_13],
            &[&quotient_constants.seq_13.value],
            &domain_points.get(&(13 + 1)).unwrap()[idx],
            &quotient_constants.seq_13.is_some,
        );
        update(
            answer_accumulator,
            12,
            &[&query_result[idx].preprocessed_trace_query_result.seq_12],
            &[&quotient_constants.seq_12],
            &domain_points.get(&(12 + 1)).unwrap()[idx],
        );
        update(
            answer_accumulator,
            11,
            &[&query_result[idx].preprocessed_trace_query_result.seq_11],
            &[&quotient_constants.seq_11],
            &domain_points.get(&(11 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            10,
            &[&query_result[idx].preprocessed_trace_query_result.seq_10],
            &[&quotient_constants.seq_10.value],
            &domain_points.get(&(10 + 1)).unwrap()[idx],
            &quotient_constants.seq_10.is_some,
        );
        update_conditional(
            answer_accumulator,
            9,
            &[&query_result[idx].preprocessed_trace_query_result.seq_9],
            &[&quotient_constants.seq_9.value],
            &domain_points.get(&(9 + 1)).unwrap()[idx],
            &quotient_constants.seq_9.is_some,
        );
        update(
            answer_accumulator,
            9,
            &[
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_5_4_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_5_4_column_1,
            ],
            &[
                &quotient_constants.range_check_5_4_column_0,
                &quotient_constants.range_check_5_4_column_1,
            ],
            &domain_points.get(&(9 + 1)).unwrap()[idx],
        );
        update(
            answer_accumulator,
            8,
            &[
                &query_result[idx].preprocessed_trace_query_result.seq_8,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_4_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_4_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .bitwise_xor_4_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_4_column_1,
            ],
            &[
                &quotient_constants.seq_8,
                &quotient_constants.bitwise_xor_4_0,
                &quotient_constants.bitwise_xor_4_1,
                &quotient_constants.bitwise_xor_4_2,
                &quotient_constants.range_check_4_4_column_0,
                &quotient_constants.range_check_4_4_column_1,
            ],
            &domain_points.get(&(8 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            7,
            &[&query_result[idx].preprocessed_trace_query_result.seq_7],
            &[&quotient_constants.seq_7.value],
            &domain_points.get(&(7 + 1)).unwrap()[idx],
            &quotient_constants.seq_7.is_some,
        );
        update(
            answer_accumulator,
            7,
            &[
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_3_column_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .range_check_4_3_column_1,
            ],
            &[
                &quotient_constants.range_check_4_3_column_0,
                &quotient_constants.range_check_4_3_column_1,
            ],
            &domain_points.get(&(7 + 1)).unwrap()[idx],
        );
        update(
            answer_accumulator,
            6,
            &[&query_result[idx].preprocessed_trace_query_result.seq_6],
            &[&quotient_constants.seq_6],
            &domain_points.get(&(6 + 1)).unwrap()[idx],
        );
        update_conditional(
            answer_accumulator,
            5,
            &[&query_result[idx].preprocessed_trace_query_result.seq_5],
            &[&quotient_constants.seq_5.value],
            &domain_points.get(&(5 + 1)).unwrap()[idx],
            &quotient_constants.seq_5.is_some,
        );
        update(
            answer_accumulator,
            4,
            &[
                &query_result[idx].preprocessed_trace_query_result.seq_4,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_0,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_1,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_2,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_3,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_4,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_5,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_6,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_7,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_8,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_9,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_10,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_11,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_12,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_13,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_14,
                &query_result[idx]
                    .preprocessed_trace_query_result
                    .blake_sigma_15,
            ],
            &[
                &quotient_constants.seq_4,
                &quotient_constants.blake_sigma_0,
                &quotient_constants.blake_sigma_1,
                &quotient_constants.blake_sigma_2,
                &quotient_constants.blake_sigma_3,
                &quotient_constants.blake_sigma_4,
                &quotient_constants.blake_sigma_5,
                &quotient_constants.blake_sigma_6,
                &quotient_constants.blake_sigma_7,
                &quotient_constants.blake_sigma_8,
                &quotient_constants.blake_sigma_9,
                &quotient_constants.blake_sigma_10,
                &quotient_constants.blake_sigma_11,
                &quotient_constants.blake_sigma_12,
                &quotient_constants.blake_sigma_13,
                &quotient_constants.blake_sigma_14,
                &quotient_constants.blake_sigma_15,
            ],
            &domain_points.get(&(4 + 1)).unwrap()[idx],
        );
    }

    for (k, v) in answer_accumulator[0].map.iter() {
        println!("log_size: {}, var value: {:?}", k, v.0.value());
    }
}
