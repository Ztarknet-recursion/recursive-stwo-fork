use crate::components::prelude::*;

/// Split the (ID , Multiplicity) columns to shorter chunks. This is done to improve the performance
/// during The merkle commitment and FRI, as this component is usually the tallest in the Cairo AIR.
///
/// 1. The ID and Multiplicity vectors are split to 'MEMORY_ADDRESS_TO_ID_SPLIT' chunks of size
///    `ids.len()`/`MEMORY_ADDRESS_TO_ID_SPLIT`.
/// 2. The chunks are padded with 0s to the next power of 2.
///
/// #  Example
/// ID = [id0..id10], MEMORY_ADDRESS_TO_ID_SPLIT = 4:
/// ID0 = [id0, id1, id2, 0]
/// ID1 = [id3, id4, id5, 0]
/// ID2 = [id6, id7, id8, 0]
/// ID3 = [id9, id10, 0, 0]
pub const MEMORY_ADDRESS_TO_ID_SPLIT: usize = 16;
pub const N_ID_AND_MULT_COLUMNS_PER_CHUNK: usize = 2;
pub const N_TRACE_COLUMNS: usize = MEMORY_ADDRESS_TO_ID_SPLIT * N_ID_AND_MULT_COLUMNS_PER_CHUNK;

#[derive(Clone)]
pub struct Component {
    // The log size of the component after split.
    pub log_size: u32,
    pub pow2: WrappedQM31Var,
    pub lookup_elements: MemoryAddressToIdVar,
}

impl ComponentVar for Component {
    fn evaluate<E: EvalAtRow<F = WrappedQM31Var, EF = WrappedQM31Var>>(&self, mut eval: E) -> E {
        // Addresses are offsetted by 1, as 0 address is reserved.
        let seq_plus_one =
            eval.get_preprocessed_column(Seq::new(self.log_size).id()) + E::F::from(M31(1));
        for i in 0..MEMORY_ADDRESS_TO_ID_SPLIT {
            let id = eval.next_trace_mask();
            let multiplicity = eval.next_trace_mask();
            let address = seq_plus_one.clone() + self.pow2.clone() * E::F::from(M31(i as u32));
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                E::EF::from(-multiplicity),
                &[address, id],
            ));
        }

        eval.finalize_logup_in_pairs();
        eval
    }
}
