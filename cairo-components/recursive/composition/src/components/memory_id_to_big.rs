use itertools::{chain, Itertools};
use stwo_cairo_common::memory::{
    LARGE_MEMORY_VALUE_ID_BASE, N_M31_IN_FELT252, N_M31_IN_SMALL_FELT252,
};

use crate::components::prelude::*;

// TODO(AlonH): Make memory size configurable.
pub const MEMORY_ID_SIZE: usize = 1;
pub const N_MULTIPLICITY_COLUMNS: usize = 1;
pub const BIG_N_COLUMNS: usize = N_M31_IN_FELT252 + N_MULTIPLICITY_COLUMNS;
pub const SMALL_N_COLUMNS: usize = N_M31_IN_SMALL_FELT252 + N_MULTIPLICITY_COLUMNS;

/// IDs are continuous and start from 0.
/// Values are Felt252 stored as `N_M31_IN_FELT252` M31 values (each value containing 9 bits).
#[derive(Clone)]
pub struct BigComponent {
    pub log_size: u32,
    // Internal offset of the ids when there are multiple components.
    pub offset: u32,
    pub lookup_elements: MemoryIdToBigVar,
    pub range_check_9_9_lookup_elements: RangeCheck99Var,
    pub range_check_9_9_b_lookup_elements: RangeCheck99BVar,
    pub range_check_9_9_c_lookup_elements: RangeCheck99CVar,
    pub range_check_9_9_d_lookup_elements: RangeCheck99DVar,
    pub range_check_9_9_e_lookup_elements: RangeCheck99EVar,
    pub range_check_9_9_f_lookup_elements: RangeCheck99FVar,
    pub range_check_9_9_g_lookup_elements: RangeCheck99GVar,
    pub range_check_9_9_h_lookup_elements: RangeCheck99HVar,
}

#[allow(clippy::too_many_arguments)]
impl BigComponent {
    pub fn new(
        log_size: u32,
        offset: u32,
        lookup_elements: MemoryIdToBigVar,
        range_check_9_9_lookup_elements: RangeCheck99Var,
        range_check_9_9_b_lookup_elements: RangeCheck99BVar,
        range_check_9_9_c_lookup_elements: RangeCheck99CVar,
        range_check_9_9_d_lookup_elements: RangeCheck99DVar,
        range_check_9_9_e_lookup_elements: RangeCheck99EVar,
        range_check_9_9_f_lookup_elements: RangeCheck99FVar,
        range_check_9_9_g_lookup_elements: RangeCheck99GVar,
        range_check_9_9_h_lookup_elements: RangeCheck99HVar,
    ) -> Self {
        Self {
            log_size,
            offset,
            lookup_elements,
            range_check_9_9_lookup_elements,
            range_check_9_9_b_lookup_elements,
            range_check_9_9_c_lookup_elements,
            range_check_9_9_d_lookup_elements,
            range_check_9_9_e_lookup_elements,
            range_check_9_9_f_lookup_elements,
            range_check_9_9_g_lookup_elements,
            range_check_9_9_h_lookup_elements,
        }
    }
}

impl ComponentVar for BigComponent {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let seq = eval.get_preprocessed_column(Seq::new(self.log_size).id());
        let value: [E::F; N_M31_IN_FELT252] = std::array::from_fn(|_| eval.next_trace_mask());
        let multiplicity = eval.next_trace_mask();

        // Range check limbs.
        for (i, (l, r)) in value.iter().tuples().enumerate() {
            let limb_pair = [l.clone(), r.clone()];
            match i % 8 {
                0 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                1 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_b_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                2 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_c_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                3 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_d_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                4 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_e_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                5 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_f_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                6 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_g_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                7 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_h_lookup_elements,
                    E::EF::one(),
                    &limb_pair,
                )),
                _ => {
                    unreachable!("There are only 8 possible values for i % 8.",)
                }
            };
        }

        // Yield the value.
        let id = seq
            + E::F::from(M31::from(LARGE_MEMORY_VALUE_ID_BASE))
            + E::F::from(M31::from(self.offset));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::from(-multiplicity),
            &chain!([id], value).collect_vec(),
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}

pub struct SmallComponent {
    pub log_size: u32,
    pub lookup_elements: MemoryIdToBigVar,
    pub range_check_9_9_relation: RangeCheck99Var,
    pub range_check_9_9_b_relation: RangeCheck99BVar,
    pub range_check_9_9_c_relation: RangeCheck99CVar,
    pub range_check_9_9_d_relation: RangeCheck99DVar,
}
impl SmallComponent {
    pub fn new(
        log_size: u32,
        lookup_elements: MemoryIdToBigVar,
        range_check_9_9_relation: RangeCheck99Var,
        range_check_9_9_b_relation: RangeCheck99BVar,
        range_check_9_9_c_relation: RangeCheck99CVar,
        range_check_9_9_d_relation: RangeCheck99DVar,
    ) -> Self {
        Self {
            log_size,
            lookup_elements,
            range_check_9_9_relation,
            range_check_9_9_b_relation,
            range_check_9_9_c_relation,
            range_check_9_9_d_relation,
        }
    }
}
impl ComponentVar for SmallComponent {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        let seq = eval.get_preprocessed_column(Seq::new(self.log_size).id());
        let value: [E::F; N_M31_IN_SMALL_FELT252] = std::array::from_fn(|_| eval.next_trace_mask());
        let multiplicity = eval.next_trace_mask();

        // Range check limbs.
        for (i, (l, r)) in value.iter().tuples().enumerate() {
            let limb_pair = [l.clone(), r.clone()];
            match i % 4 {
                0 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_relation,
                    E::EF::one(),
                    &limb_pair,
                )),
                1 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_b_relation,
                    E::EF::one(),
                    &limb_pair,
                )),
                2 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_c_relation,
                    E::EF::one(),
                    &limb_pair,
                )),
                3 => eval.add_to_relation(RelationEntry::new(
                    &self.range_check_9_9_d_relation,
                    E::EF::one(),
                    &limb_pair,
                )),
                _ => {
                    unreachable!("There are only 4 possible values for i % 4.",)
                }
            };
        }

        // Yield the value.
        let id = seq;
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::from(-multiplicity),
            &chain!([id], value).collect_vec(),
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}
