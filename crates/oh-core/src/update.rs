//! Updates: the change a volunteer made to the model, and its compressed form.
//!
//! A volunteer sends back `after - before` (the pseudo-gradient), keeping only
//! the largest entries by size and storing each as an 8-bit integer times one
//! shared scale. This is the top-k plus quantization idea from SparseLoCo,
//! without its error feedback.

use serde::{Deserialize, Serialize};

/// The change training made: `after - before`, entry by entry.
///
/// Panics if the two vectors differ in length.
pub fn pseudo_gradient(before: &[f32], after: &[f32]) -> Vec<f32> {
    assert_eq!(
        before.len(),
        after.len(),
        "parameter vector length mismatch"
    );
    after.iter().zip(before).map(|(a, b)| a - b).collect()
}

/// `base + delta`, entry by entry.
///
/// Panics if the two vectors differ in length; check untrusted deltas with
/// `CompressedDelta::validate` first.
pub fn apply(base: &[f32], delta: &[f32]) -> Vec<f32> {
    assert_eq!(base.len(), delta.len(), "parameter vector length mismatch");
    base.iter().zip(delta).map(|(b, d)| b + d).collect()
}

/// A sparse, 8-bit copy of a dense delta.
///
/// Entry `indices[i]` of the dense delta is `values[i] as f32 * scale`; every
/// other entry is zero. `indices` is sorted and has no repeats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompressedDelta {
    pub len: u32,
    pub indices: Vec<u32>,
    pub values: Vec<i8>,
    pub scale: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeltaError {
    #[error("malformed delta: {0}")]
    Malformed(&'static str),
}

impl CompressedDelta {
    /// Keeps the `keep_fraction` largest entries by magnitude (at least one
    /// when the fraction is above zero) and quantizes them linearly with
    /// `scale = max |kept| / 127`. Zero, NaN and infinite entries are never kept.
    pub fn compress(delta: &[f32], keep_fraction: f64) -> Self {
        let frac = keep_fraction.clamp(0.0, 1.0);
        let mut candidates: Vec<u32> = (0..delta.len() as u32)
            .filter(|&i| {
                let v = delta[i as usize];
                v.is_finite() && v != 0.0
            })
            .collect();

        let mut k = (delta.len() as f64 * frac).round() as usize;
        if frac > 0.0 {
            k = k.max(1);
        }
        let k = k.min(candidates.len());

        if k < candidates.len() {
            // Largest magnitude first; ties broken by index so the result is stable.
            let by_size = |a: &u32, b: &u32| {
                let (va, vb) = (delta[*a as usize].abs(), delta[*b as usize].abs());
                vb.total_cmp(&va).then(a.cmp(b))
            };
            candidates.select_nth_unstable_by(k, by_size);
            candidates.truncate(k);
        }
        candidates.sort_unstable();

        let max = candidates
            .iter()
            .map(|&i| delta[i as usize].abs())
            .fold(0.0f32, f32::max);
        let scale = if max > 0.0 { max / 127.0 } else { 0.0 };
        let values = candidates
            .iter()
            .map(|&i| (delta[i as usize] / scale).round().clamp(-127.0, 127.0) as i8)
            .collect();

        Self {
            len: delta.len() as u32,
            indices: candidates,
            values,
            scale,
        }
    }

    /// Rebuilds the dense delta. Entries whose index is out of range, and
    /// indices without a matching value, are skipped; call `validate` first
    /// on anything that came over the network.
    pub fn decompress(&self) -> Vec<f32> {
        let mut out = vec![0f32; self.len as usize];
        for (&i, &v) in self.indices.iter().zip(&self.values) {
            if let Some(slot) = out.get_mut(i as usize) {
                *slot = v as f32 * self.scale;
            }
        }
        out
    }

    /// Checks a delta received from someone else before it is used.
    pub fn validate(&self, expected_len: usize) -> Result<(), DeltaError> {
        if self.len as usize != expected_len {
            return Err(DeltaError::Malformed("length does not match the model"));
        }
        if self.indices.len() != self.values.len() {
            return Err(DeltaError::Malformed("indices and values differ in count"));
        }
        if !self.scale.is_finite() || self.scale < 0.0 {
            return Err(DeltaError::Malformed(
                "scale is not a finite non-negative number",
            ));
        }
        if !self.indices.windows(2).all(|w| w[0] < w[1]) {
            return Err(DeltaError::Malformed("indices are not strictly increasing"));
        }
        if self.indices.last().is_some_and(|&i| i >= self.len) {
            return Err(DeltaError::Malformed("index out of range"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learner::SplitMix64;

    fn random_delta(n: usize, seed: u64) -> Vec<f32> {
        let mut rng = SplitMix64::new(seed);
        (0..n).map(|_| rng.next_signed_unit() * 0.01).collect()
    }

    #[test]
    fn test_pseudo_gradient_is_after_minus_before() {
        let before = [1.0f32, 2.0, 3.0];
        let after = [1.5f32, 2.0, 2.0];
        assert_eq!(pseudo_gradient(&before, &after), vec![0.5, 0.0, -1.0]);
        assert_eq!(
            apply(&before, &pseudo_gradient(&before, &after)),
            after.to_vec()
        );
    }

    #[test]
    fn test_kept_values_within_half_a_step() {
        let delta = random_delta(10_000, 1);
        let c = CompressedDelta::compress(&delta, 0.05);
        assert_eq!(c.len, 10_000);
        assert_eq!(c.indices.len(), 500);
        assert_eq!(c.values.len(), 500);
        assert!(
            c.indices.windows(2).all(|w| w[0] < w[1]),
            "indices sorted and unique"
        );

        let out = c.decompress();
        assert_eq!(out.len(), 10_000);
        let kept: std::collections::HashSet<u32> = c.indices.iter().copied().collect();
        for (i, (orig, got)) in delta.iter().zip(&out).enumerate() {
            if kept.contains(&(i as u32)) {
                assert!(
                    (orig - got).abs() <= c.scale / 2.0 + 1e-9,
                    "index {i}: {orig} vs {got}, scale {}",
                    c.scale
                );
            } else {
                assert_eq!(*got, 0.0);
            }
        }
    }

    #[test]
    fn test_keeps_the_largest_entries() {
        let delta = [0.1f32, -5.0, 0.2, 3.0, -0.3];
        let c = CompressedDelta::compress(&delta, 0.4);
        assert_eq!(c.indices, vec![1, 3]);
        assert_eq!(c.values, vec![-127, 76]);
    }

    #[test]
    fn test_compression_ratio_at_five_percent() {
        let delta = random_delta(10_000, 2);
        let c = CompressedDelta::compress(&delta, 0.05);
        let dense = bincode::serialize(&delta).unwrap().len();
        let sparse = bincode::serialize(&c).unwrap().len();
        let ratio = dense as f64 / sparse as f64;
        eprintln!("compression: {dense} bytes dense, {sparse} bytes sent, {ratio:.1}x");
        assert!(ratio >= 10.0, "ratio {ratio:.2} ({dense} / {sparse} bytes)");
    }

    #[test]
    fn test_zero_delta_compresses_to_nothing() {
        let c = CompressedDelta::compress(&vec![0.0f32; 1000], 0.05);
        assert!(c.indices.is_empty());
        assert!(c.values.is_empty());
        assert_eq!(c.decompress(), vec![0.0f32; 1000]);
    }

    #[test]
    fn test_non_finite_entries_are_dropped() {
        let delta = [f32::NAN, 1.0, f32::INFINITY, -2.0];
        let c = CompressedDelta::compress(&delta, 1.0);
        assert_eq!(c.indices, vec![1, 3]);
        assert!(c.decompress().iter().all(|v| v.is_finite()));
    }

    #[test]
    fn test_validate_rejects_malformed_deltas() {
        let good = CompressedDelta::compress(&random_delta(100, 3), 0.1);
        assert!(good.validate(100).is_ok());
        assert!(good.validate(99).is_err());

        let mut out_of_range = good.clone();
        *out_of_range.indices.last_mut().unwrap() = 100;
        assert!(out_of_range.validate(100).is_err());

        let mut unsorted = good.clone();
        unsorted.indices.swap(0, 1);
        assert!(unsorted.validate(100).is_err());

        let mut short_values = good.clone();
        short_values.values.pop();
        assert!(short_values.validate(100).is_err());

        let mut bad_scale = good.clone();
        bad_scale.scale = f32::NAN;
        assert!(bad_scale.validate(100).is_err());
    }
}
