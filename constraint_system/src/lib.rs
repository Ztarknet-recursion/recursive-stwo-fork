use crate::var::AllocationMode;
use plonk_with_poseidon::PlonkWithPoseidonConstraintSystem;
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo_examples::plonk_with_poseidon::plonk::PlonkWithAcceleratorCircuitTrace;
use stwo_examples::plonk_with_poseidon::poseidon::{PoseidonEntry, PoseidonFlow, SwapOption};

pub mod var;

pub mod plonk_with_poseidon;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintSystemType {
    PlonkWithPoseidon,
    PlonkWithoutPoseidon,
}

/// A shared reference to a constraint system that can be stored in high level
/// variables.
#[derive(Clone, Debug)]
pub struct ConstraintSystemRef(pub(crate) Rc<RefCell<PlonkWithPoseidonConstraintSystem>>);

impl ConstraintSystemRef {
    pub fn new_plonk_with_poseidon_ref() -> Self {
        Self(Rc::new(RefCell::new(PlonkWithPoseidonConstraintSystem::new())))
    }

    pub fn get_value(&self, idx: usize) -> QM31 {
        self.0.borrow().variables[idx].clone()
    }

    pub fn get_cache(&self, str: impl ToString) -> Option<usize> {
        self.0.borrow().cache.get(&str.to_string()).cloned()
    }

    pub fn set_cache(&self, str: impl ToString, range: usize) {
        self.0.borrow_mut().cache.insert(str.to_string(), range);
    }

    pub fn new_m31(&self, variables: M31, mode: AllocationMode) -> usize {
        self.0.borrow_mut().new_m31(variables, mode)
    }

    pub fn new_qm31(&self, variable: QM31, mode: AllocationMode) -> usize {
        self.0.borrow_mut().new_qm31(variable, mode)
    }

    pub fn and(&self, other: &Self) -> Self {
        assert_eq!(self, other);
        self.clone()
    }

    pub fn insert_gate(&self, a_wire: usize, b_wire: usize, c_wire: usize, op: M31) {
        self.0.borrow_mut().insert_gate(a_wire, b_wire, c_wire, op)
    }

    pub fn add(&self, a_wire: usize, b_wire: usize) -> usize {
        self.0.borrow_mut().add(a_wire, b_wire)
    }

    pub fn mul(&self, a_wire: usize, b_wire: usize) -> usize {
        self.0.borrow_mut().mul(a_wire, b_wire)
    }

    pub fn mul_constant(&self, a_wire: usize, constant: M31) -> usize {
        self.0.borrow_mut().mul_constant(a_wire, constant)
    }

    pub fn enforce_zero(&self, var: usize) {
        self.0.borrow_mut().enforce_zero(var);
    }

    pub fn check_arithmetics(&self) {
        self.0.borrow().check_arithmetics()
    }

    pub fn populate_logup_arguments(&self) {
        self.0.borrow_mut().populate_logup_arguments()
    }

    pub fn check_poseidon_invocations(&self) {
        self.0.borrow().check_poseidon_invocations()
    }

    pub fn invoke_poseidon_accelerator(
        &self,
        entry_1: PoseidonEntry,
        entry_2: PoseidonEntry,
        entry_3: PoseidonEntry,
        entry_4: PoseidonEntry,
        swap_option: SwapOption,
    ) {
        self.0.borrow_mut().invoke_poseidon_accelerator(entry_1, entry_2, entry_3, entry_4, swap_option);
    }

    pub fn pad(&self) {
        self.0.borrow_mut().pad()
    }

    pub fn generate_plonk_with_poseidon_circuit(
        &self,
    ) -> (PlonkWithAcceleratorCircuitTrace, PoseidonFlow) {
        self.0.borrow_mut().generate_plonk_with_poseidon_circuit()
    }

    pub fn num_plonk_rows(&self) -> usize {
        self.0.borrow().a_wire.len()
    }

    pub fn num_poseidon_invocations(&self) -> usize {
        self.0.borrow().flow.0.len()
    }

    pub fn assemble_poseidon_gate(&self, a_wire: usize, b_wire: usize) -> usize {
        self.0.borrow_mut().assemble_poseidon_gate(a_wire, b_wire)
    }
}

impl PartialEq for ConstraintSystemRef {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

pub const LOG_CONSTRAINT_SYSTEM_RESERVED_SIZE: usize = 16;
