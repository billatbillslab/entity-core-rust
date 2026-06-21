//! FastCDC gear table + boundary finder (EXTENSION-CONTENT §3.6).
//!
//! Pure functions — no I/O, no allocations beyond the boxed gear table.
//! The gear table is computed once via `gear_table()` (or cached via
//! `GEAR_TABLE`) and reused across calls. The boundary finder follows
//! the two-phase normalized-chunking algorithm in §3.6.3 verbatim:
//! mask_s while below target, mask_l above target, forced cut at max.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// 256-entry FastCDC gear table — `uint64_le(SHA-256("FastCDC" || byte(i))[0:8])`
/// per §3.6.1. Mechanically derivable; lazy-cached for reuse across
/// chunker invocations.
static GEAR_TABLE: OnceLock<[u64; 256]> = OnceLock::new();

/// Return a reference to the cached gear table. Computes it on first
/// call (one SHA-256 per byte = 256 hashes), then re-uses thereafter.
pub fn gear_table() -> &'static [u64; 256] {
    GEAR_TABLE.get_or_init(compute_gear_table)
}

/// Recompute the gear table from scratch. Deterministic per §3.6.1.
pub fn compute_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(b"FastCDC");
        hasher.update([i as u8]);
        let digest = hasher.finalize();
        // first 8 bytes, little-endian
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[0..8]);
        *slot = u64::from_le_bytes(bytes);
    }
    table
}

/// Parameters derived from a target chunk size per §3.6.2. NC=2 fixed.
#[derive(Debug, Clone, Copy)]
pub struct CdcParams {
    pub target_size: usize,
    pub min_size: usize,
    pub max_size: usize,
    pub mask_s: u64,
    pub mask_l: u64,
}

impl CdcParams {
    /// Derive FastCDC/NC2 parameters from `target_size` per §3.6.2.
    ///
    /// `target_size` MUST be a positive power-of-two-ish value (the spec
    /// uses `floor(log2(target_size))` for `bits`). A `target_size` of
    /// zero is rejected.
    pub fn from_target(target_size: usize) -> Result<Self, &'static str> {
        if target_size == 0 {
            return Err("target_size must be > 0");
        }
        let min_size = target_size / 4;
        let max_size = target_size.saturating_mul(2);
        // bits = floor(log2(target_size))
        let bits = (usize::BITS as usize) - 1 - target_size.leading_zeros() as usize;
        // §3.6.2: mask_s = (1 << (bits + 2)) - 1; mask_l = (1 << (bits - 2)) - 1.
        // bits >= 2 is guaranteed for target_size >= 4; v3.6 default is 1 MiB
        // so we don't bother defending sub-4-byte inputs (they're nonsense).
        let mask_s = (1u64 << (bits + 2)) - 1;
        let mask_l = (1u64 << (bits.saturating_sub(2))) - 1;
        Ok(Self {
            target_size,
            min_size,
            max_size,
            mask_s,
            mask_l,
        })
    }
}

/// Find the next chunk boundary in `data[offset..]` per §3.6.3.
///
/// Returns the end offset of the chunk (an index into `data`). The chunk
/// is `data[offset..returned_end]`. Caller is responsible for the
/// `remaining <= min_size` short-final-chunk case (§3.6.3) — this
/// function assumes there is meaningful work to do above `min_size`.
pub fn find_boundary(data: &[u8], offset: usize, params: &CdcParams) -> usize {
    let gear = gear_table();
    let len = data.len();
    let mut fp: u64 = 0;
    // Skip the first `min_size` bytes — anything before that would
    // produce an undersized chunk anyway.
    let mut i = offset + params.min_size;

    // Phase 1: harder mask, until target.
    let limit1 = (offset + params.target_size).min(len);
    while i < limit1 {
        fp = (fp << 1).wrapping_add(gear[data[i] as usize]);
        if fp & params.mask_s == 0 {
            return i + 1;
        }
        i += 1;
    }

    // Phase 2: easier mask, between target and max.
    let limit2 = (offset + params.max_size).min(len);
    while i < limit2 {
        fp = (fp << 1).wrapping_add(gear[data[i] as usize]);
        if fp & params.mask_l == 0 {
            return i + 1;
        }
        i += 1;
    }

    // Forced cut at max_size (or end-of-data).
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gear_table_first_entry_matches_spec_derivation() {
        // First entry: SHA-256("FastCDC" || 0x00)[0..8] as u64 little-endian.
        let mut h = Sha256::new();
        h.update(b"FastCDC");
        h.update([0u8]);
        let d = h.finalize();
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[0..8]);
        let expected = u64::from_le_bytes(b);
        assert_eq!(gear_table()[0], expected);
    }

    #[test]
    fn cdc_params_defaults_4mib() {
        // Backward-compat verification: 4 MiB target still produces the
        // v3.5 parameters. Existing 4 MiB-chunked blobs remain valid
        // post v3.6 cutover (chunk_size is recorded per-blob).
        let p = CdcParams::from_target(4 * 1024 * 1024).unwrap();
        assert_eq!(p.min_size, 1024 * 1024);
        assert_eq!(p.max_size, 8 * 1024 * 1024);
        // bits = 22 → mask_s = (1 << 24) - 1, mask_l = (1 << 20) - 1
        assert_eq!(p.mask_s, 0x00FF_FFFF);
        assert_eq!(p.mask_l, 0x000F_FFFF);
    }

    #[test]
    fn cdc_params_v3_6_default_1mib() {
        // v3.6 §3.6.2 parameter table for the 1 MiB default. Locking
        // the spec table in code so a drift between spec and impl
        // surfaces immediately.
        let p = CdcParams::from_target(1024 * 1024).unwrap();
        assert_eq!(p.min_size, 256 * 1024); // 256 KiB
        assert_eq!(p.max_size, 2 * 1024 * 1024); // 2 MiB
        // bits = 20 → mask_s = (1 << 22) - 1, mask_l = (1 << 18) - 1
        assert_eq!(p.mask_s, 0x003F_FFFF);
        assert_eq!(p.mask_l, 0x0003_FFFF);
    }
}
