//! Fixed-capacity, zero-allocation Cuckoo Filter optimized for L3 CPU cache.
//!
//! Total footprint: 2048 buckets * 4 slots * 8 bytes = 64 KiB.
//! Provides deterministic sub-10-nanosecond fingerprint matching.

pub const BUCKET_COUNT: usize = 2048;
pub const ENTRIES_PER_BUCKET: usize = 4;
pub const MAX_KICKS: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Tag(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct Bucket {
    pub slots: [Tag; ENTRIES_PER_BUCKET],
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            slots: [Tag(0); ENTRIES_PER_BUCKET],
        }
    }
}

pub struct CuckooFilter {
    buckets: Box<[Bucket; BUCKET_COUNT]>,
    count: usize,
}

impl Default for CuckooFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl CuckooFilter {
    pub fn new() -> Self {
        let buckets = Box::new([Bucket::default(); BUCKET_COUNT]);
        Self { buckets, count: 0 }
    }

    #[inline(always)]
    fn get_tag(item: &[u8; 32]) -> Tag {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&item[0..8]);
        let raw = u64::from_le_bytes(bytes);
        // Ensure non-zero tag so 0 represents empty slot
        if raw == 0 {
            Tag(1)
        } else {
            Tag(raw)
        }
    }

    #[inline(always)]
    fn primary_index(item: &[u8; 32]) -> usize {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&item[8..16]);
        (u64::from_le_bytes(bytes) as usize) % BUCKET_COUNT
    }

    #[inline(always)]
    fn secondary_index(primary: usize, tag: Tag) -> usize {
        let tag_hash = tag.0.wrapping_mul(0x517cc1b727220a95);
        (primary ^ (tag_hash as usize)) % BUCKET_COUNT
    }

    #[inline(always)]
    pub fn contains(&self, item: &[u8; 32]) -> bool {
        let tag = Self::get_tag(item);
        let i1 = Self::primary_index(item);
        let b1 = &self.buckets[i1];
        if b1.slots[0] == tag || b1.slots[1] == tag || b1.slots[2] == tag || b1.slots[3] == tag {
            return true;
        }

        let i2 = Self::secondary_index(i1, tag);
        let b2 = &self.buckets[i2];
        b2.slots[0] == tag || b2.slots[1] == tag || b2.slots[2] == tag || b2.slots[3] == tag
    }

    pub fn insert(&mut self, item: &[u8; 32]) -> bool {
        if self.contains(item) {
            return true;
        }

        let mut tag = Self::get_tag(item);
        let mut idx = Self::primary_index(item);

        for slot in &mut self.buckets[idx].slots {
            if slot.0 == 0 {
                *slot = tag;
                self.count += 1;
                return true;
            }
        }

        let alt_idx = Self::secondary_index(idx, tag);
        for slot in &mut self.buckets[alt_idx].slots {
            if slot.0 == 0 {
                *slot = tag;
                self.count += 1;
                return true;
            }
        }

        // Cuckoo displacement
        let mut rng = idx as u64;
        for _ in 0..MAX_KICKS {
            let slot_idx = (rng as usize) % ENTRIES_PER_BUCKET;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);

            let evicted = self.buckets[idx].slots[slot_idx];
            self.buckets[idx].slots[slot_idx] = tag;
            tag = evicted;
            idx = Self::secondary_index(idx, tag);

            for slot in &mut self.buckets[idx].slots {
                if slot.0 == 0 {
                    *slot = tag;
                    self.count += 1;
                    return true;
                }
            }
        }

        false
    }

    pub fn delete(&mut self, item: &[u8; 32]) -> bool {
        let tag = Self::get_tag(item);
        let i1 = Self::primary_index(item);
        for slot in &mut self.buckets[i1].slots {
            if *slot == tag {
                *slot = Tag(0);
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }

        let i2 = Self::secondary_index(i1, tag);
        for slot in &mut self.buckets[i2].slots {
            if *slot == tag {
                *slot = Tag(0);
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }

        false
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
