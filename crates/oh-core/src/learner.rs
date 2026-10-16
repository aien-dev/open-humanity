//! The learner seam and a tiny byte-level model that sits behind it.
//!
//! The coordinator and volunteers only see `Learner`. Version 0 ships
//! `TinyByteModel`, a toy that predicts the next byte from the previous one;
//! a real model plugs in later behind the same trait.

/// A model that can be trained on a shard of bytes and measured on held-out bytes.
///
/// `params` and `set_params` move the full parameter vector in a fixed order,
/// so two learners of the same shape can exchange and add parameter vectors.
pub trait Learner {
    fn params(&self) -> Vec<f32>;
    fn set_params(&mut self, p: &[f32]);
    /// Runs `steps` training steps on `shard`. The same seed, starting
    /// parameters and shard always give the same result.
    fn train_steps(&mut self, shard: &[u8], steps: usize, seed: u64);
    /// Bits needed to encode `data`: the sum of -log2 p over every byte the
    /// model predicts.
    fn heldout_bits(&self, data: &[u8]) -> f64;
}

/// SplitMix64: a small, fixed pseudo-random generator, so a seed gives the
/// same numbers on every machine and every crate version.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [-1, 1).
    pub(crate) fn next_signed_unit(&mut self) -> f32 {
        let unit = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32;
        unit * 2.0 - 1.0
    }
}

pub const VOCAB: usize = 256;

/// Next-byte model: embedding (256 x dim), one tanh hidden layer (dim x dim),
/// output layer (dim x 256), softmax over 256 bytes.
///
/// Flat parameter layout, row major, in this order:
/// `emb[256 * dim]`, `w1[dim * dim]`, `b1[dim]`, `w2[dim * 256]`, `b2[256]`.
/// Hidden unit j is `tanh(b1[j] + sum_i emb[x][i] * w1[i][j])`; logit k is
/// `b2[k] + sum_j h[j] * w2[j][k]`.
pub struct TinyByteModel {
    pub dim: usize,
    pub lr: f32,
    /// Byte pairs averaged per training step.
    pub batch: usize,
    params: Vec<f32>,
}

struct Offsets {
    w1: usize,
    b1: usize,
    w2: usize,
    b2: usize,
    total: usize,
}

impl TinyByteModel {
    pub fn new(dim: usize, seed: u64) -> Self {
        let mut model = Self {
            dim,
            lr: 0.1,
            batch: 8,
            params: Vec::new(),
        };
        let off = model.offsets();
        let mut rng = SplitMix64::new(seed);
        let mut params = vec![0f32; off.total];
        let emb_scale = 0.5;
        let w1_scale = 1.0 / (dim as f32).sqrt();
        let w2_scale = 1.0 / (dim as f32).sqrt();
        for v in &mut params[..off.w1] {
            *v = rng.next_signed_unit() * emb_scale;
        }
        for v in &mut params[off.w1..off.b1] {
            *v = rng.next_signed_unit() * w1_scale;
        }
        for v in &mut params[off.w2..off.b2] {
            *v = rng.next_signed_unit() * w2_scale;
        }
        model.params = params;
        model
    }

    pub fn num_params(dim: usize) -> usize {
        VOCAB * dim + dim * dim + dim + dim * VOCAB + VOCAB
    }

    fn offsets(&self) -> Offsets {
        let d = self.dim;
        let w1 = VOCAB * d;
        let b1 = w1 + d * d;
        let w2 = b1 + d;
        let b2 = w2 + d * VOCAB;
        Offsets {
            w1,
            b1,
            w2,
            b2,
            total: b2 + VOCAB,
        }
    }

    /// Hidden activations for input byte `x`.
    fn hidden(&self, x: u8, off: &Offsets) -> Vec<f32> {
        let d = self.dim;
        let p = &self.params;
        let e = &p[x as usize * d..(x as usize + 1) * d];
        (0..d)
            .map(|j| {
                let mut z = p[off.b1 + j];
                for (i, ei) in e.iter().enumerate() {
                    z += ei * p[off.w1 + i * d + j];
                }
                z.tanh()
            })
            .collect()
    }

    fn logits(&self, h: &[f32], off: &Offsets) -> Vec<f32> {
        let p = &self.params;
        let mut z: Vec<f32> = p[off.b2..off.b2 + VOCAB].to_vec();
        for (j, hj) in h.iter().enumerate() {
            let row = &p[off.w2 + j * VOCAB..off.w2 + (j + 1) * VOCAB];
            for (zk, wk) in z.iter_mut().zip(row) {
                *zk += hj * wk;
            }
        }
        z
    }
}

impl Learner for TinyByteModel {
    fn params(&self) -> Vec<f32> {
        self.params.clone()
    }

    /// Panics if `p` has the wrong length for this model's shape.
    fn set_params(&mut self, p: &[f32]) {
        assert_eq!(p.len(), self.params.len(), "parameter vector length mismatch");
        self.params.copy_from_slice(p);
    }

    fn train_steps(&mut self, shard: &[u8], steps: usize, seed: u64) {
        if shard.len() < 2 || self.batch == 0 {
            return;
        }
        let d = self.dim;
        let off = self.offsets();
        let pairs = (shard.len() - 1) as u64;
        let mut rng = SplitMix64::new(seed);
        let mut grad = vec![0f32; off.total];
        let step_scale = self.lr / self.batch as f32;

        for _ in 0..steps {
            grad.iter_mut().for_each(|g| *g = 0.0);
            for _ in 0..self.batch {
                let i = (rng.next_u64() % pairs) as usize;
                let (x, y) = (shard[i] as usize, shard[i + 1] as usize);

                let h = self.hidden(shard[i], &off);
                let z = self.logits(&h, &off);
                let max = z.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                let exps: Vec<f32> = z.iter().map(|v| (v - max).exp()).collect();
                let sum: f32 = exps.iter().sum();

                // Cross-entropy gradient at the logits: softmax minus one-hot.
                let mut dz: Vec<f32> = exps.iter().map(|v| v / sum).collect();
                dz[y] -= 1.0;

                let mut dh = vec![0f32; d];
                for j in 0..d {
                    let row = off.w2 + j * VOCAB;
                    let mut acc = 0.0;
                    for k in 0..VOCAB {
                        grad[row + k] += h[j] * dz[k];
                        acc += self.params[row + k] * dz[k];
                    }
                    dh[j] = acc;
                }
                for k in 0..VOCAB {
                    grad[off.b2 + k] += dz[k];
                }

                let dz1: Vec<f32> = (0..d).map(|j| dh[j] * (1.0 - h[j] * h[j])).collect();
                for i in 0..d {
                    let e_i = self.params[x * d + i];
                    let mut de = 0.0;
                    for j in 0..d {
                        grad[off.w1 + i * d + j] += e_i * dz1[j];
                        de += self.params[off.w1 + i * d + j] * dz1[j];
                    }
                    grad[x * d + i] += de;
                }
                for j in 0..d {
                    grad[off.b1 + j] += dz1[j];
                }
            }
            for (p, g) in self.params.iter_mut().zip(&grad) {
                *p -= step_scale * g;
            }
        }
    }

    /// Computed in f64 throughout so the score is stable to well below a
    /// thousandth of a bit; training uses f32.
    fn heldout_bits(&self, data: &[u8]) -> f64 {
        let off = self.offsets();
        let (d, p) = (self.dim, &self.params);
        let mut h = vec![0f64; d];
        let mut z = vec![0f64; VOCAB];
        let mut bits = 0f64;
        for pair in data.windows(2) {
            let (x, y) = (pair[0] as usize, pair[1] as usize);
            for (j, hj) in h.iter_mut().enumerate() {
                let mut acc = p[off.b1 + j] as f64;
                for i in 0..d {
                    acc += p[x * d + i] as f64 * p[off.w1 + i * d + j] as f64;
                }
                *hj = acc.tanh();
            }
            for (k, zk) in z.iter_mut().enumerate() {
                let mut acc = p[off.b2 + k] as f64;
                for (j, hj) in h.iter().enumerate() {
                    acc += hj * p[off.w2 + j * VOCAB + k] as f64;
                }
                *zk = acc;
            }
            let max = z.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let sum: f64 = z.iter().map(|v| (v - max).exp()).sum();
            let log_p = (z[y] - max) - sum.ln();
            bits -= log_p / std::f64::consts::LN_2;
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repetitive_text(n: usize) -> Vec<u8> {
        b"hello world. ".iter().cycle().take(n).copied().collect()
    }

    #[test]
    fn test_training_lowers_bits_per_byte_on_repetitive_text() {
        let text = repetitive_text(4096);
        let mut model = TinyByteModel::new(16, 7);
        let before = model.heldout_bits(&text) / (text.len() - 1) as f64;
        model.train_steps(&text, 1500, 11);
        let after = model.heldout_bits(&text) / (text.len() - 1) as f64;
        eprintln!("bits per byte: {before:.3} before, {after:.3} after training");
        assert!(before > 7.0, "untrained model should be near 8 bits per byte, got {before}");
        assert!(after < 2.0, "trained model should be well under 2 bits per byte, got {after}");
    }

    /// Recomputes the forward pass by hand from the flat parameter vector,
    /// using the layout documented on `TinyByteModel`.
    #[test]
    fn test_heldout_bits_matches_independent_log2_sum() {
        let dim = 16;
        let model = TinyByteModel::new(dim, 3);
        let p = model.params();
        let (x, y) = (b'h' as usize, b'e' as usize);

        let emb = &p[0..256 * dim];
        let w1 = &p[256 * dim..256 * dim + dim * dim];
        let b1 = &p[256 * dim + dim * dim..256 * dim + dim * dim + dim];
        let w2_start = 256 * dim + dim * dim + dim;
        let w2 = &p[w2_start..w2_start + dim * 256];
        let b2 = &p[w2_start + dim * 256..];
        assert_eq!(b2.len(), 256);

        let mut h = vec![0f64; dim];
        for j in 0..dim {
            let mut z = b1[j] as f64;
            for i in 0..dim {
                z += emb[x * dim + i] as f64 * w1[i * dim + j] as f64;
            }
            h[j] = z.tanh();
        }
        let mut logits = vec![0f64; 256];
        for k in 0..256 {
            let mut z = b2[k] as f64;
            for j in 0..dim {
                z += h[j] * w2[j * 256 + k] as f64;
            }
            logits[k] = z;
        }
        let max = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let sum: f64 = logits.iter().map(|z| (z - max).exp()).sum();
        let p_y = (logits[y] - max).exp() / sum;
        let expected = -p_y.log2();

        let got = model.heldout_bits(&[x as u8, y as u8]);
        assert!((got - expected).abs() < 1e-6, "got {got}, expected {expected}");
    }

    #[test]
    fn test_short_input_has_zero_bits() {
        let model = TinyByteModel::new(16, 1);
        assert_eq!(model.heldout_bits(&[]), 0.0);
        assert_eq!(model.heldout_bits(b"a"), 0.0);
    }

    #[test]
    fn test_same_seed_gives_identical_params() {
        let text = repetitive_text(1024);
        let mut a = TinyByteModel::new(16, 5);
        let mut b = TinyByteModel::new(16, 5);
        assert_eq!(a.params(), b.params());
        a.train_steps(&text, 50, 9);
        b.train_steps(&text, 50, 9);
        assert_eq!(a.params(), b.params());

        let mut c = TinyByteModel::new(16, 5);
        c.train_steps(&text, 50, 10);
        assert_ne!(a.params(), c.params());
    }

    #[test]
    fn test_set_params_round_trip() {
        let a = TinyByteModel::new(16, 1);
        let mut b = TinyByteModel::new(16, 2);
        assert_ne!(a.params(), b.params());
        b.set_params(&a.params());
        assert_eq!(a.params(), b.params());
        assert_eq!(a.heldout_bits(b"abc"), b.heldout_bits(b"abc"));
    }
}
