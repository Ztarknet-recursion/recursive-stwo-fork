use indexmap::IndexMap;
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    vcs::poseidon31_ref::poseidon2_permute,
};

pub struct HashAccumulator {
    pub size: usize,
    pub digest: [M31; 8],
    pub buffer: [M31; 8],
}

impl Default for HashAccumulator {
    fn default() -> Self {
        Self {
            size: 0,
            digest: [M31::default(); 8],
            buffer: [M31::default(); 8],
        }
    }
}

impl HashAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[M31]) {
        for elem in data.iter() {
            self.buffer[self.size as usize] = *elem;
            self.size += 1;
            if self.size == 8 {
                let mut state = std::array::from_fn(|i| {
                    if i < 8 {
                        self.buffer[i]
                    } else {
                        self.digest[i - 8]
                    }
                });
                poseidon2_permute(&mut state);
                self.digest.copy_from_slice(&state[8..16]);
                self.size = 0;
            }
        }
    }

    pub fn finalize(&self) -> [M31; 8] {
        if self.size != 0 {
            let mut state = [M31::default(); 16];
            for i in 0..self.size {
                state[i] = self.buffer[i];
            }
            for i in 0..8 {
                state[i + 8] = self.digest[i];
            }
            poseidon2_permute(&mut state);

            let mut res = [M31::default(); 8];
            res.copy_from_slice(&state[8..16]);
            res
        } else {
            self.digest
        }
    }
}

#[derive(Default)]
pub struct ColumnsHasher(pub IndexMap<usize, HashAccumulator>);

impl ColumnsHasher {
    pub fn new() -> Self {
        Self(IndexMap::new())
    }

    pub fn update(&mut self, log_size: u32, data: &[M31]) {
        self.0
            .entry(log_size as usize)
            .or_insert_with(HashAccumulator::new)
            .update(data);
    }
}

#[derive(Default)]
pub struct ColumnsHasherQM31(pub IndexMap<usize, HashAccumulatorQM31>);

impl ColumnsHasherQM31 {
    pub fn new() -> Self {
        Self(IndexMap::new())
    }

    pub fn update(&mut self, log_size: u32, data: &[QM31]) {
        self.0
            .entry(log_size as usize)
            .or_insert_with(HashAccumulatorQM31::new)
            .update(data);
    }
}

pub struct HashAccumulatorQM31 {
    pub size: usize,
    pub digest: [M31; 8],
    pub buffer: [QM31; 2],
}

impl Default for HashAccumulatorQM31 {
    fn default() -> Self {
        Self {
            size: 0,
            digest: [M31::default(); 8],
            buffer: [QM31::default(); 2],
        }
    }
}

impl HashAccumulatorQM31 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[QM31]) {
        for elem in data.iter() {
            self.buffer[self.size as usize] = *elem;
            self.size += 1;

            if self.size == 2 {
                let mut state = [M31::default(); 16];
                state[0..4].copy_from_slice(&self.buffer[0].to_m31_array());
                state[4..8].copy_from_slice(&self.buffer[1].to_m31_array());
                state[8..16].copy_from_slice(&self.digest);
                poseidon2_permute(&mut state);
                self.digest.copy_from_slice(&state[8..16]);
                self.size = 0;
            }
        }
    }

    pub fn finalize(&self) -> [M31; 8] {
        if self.size != 0 {
            let mut state = [M31::default(); 16];
            state[0..4].copy_from_slice(&self.buffer[0].to_m31_array());
            for i in 0..8 {
                state[i + 8] = self.digest[i];
            }
            poseidon2_permute(&mut state);

            let mut res = [M31::default(); 8];
            res.copy_from_slice(&state[8..16]);
            res
        } else {
            self.digest
        }
    }
}
