//! Kani formal verification harness for `strata_mir` (`PO-S10`).
//!
//! Discharges bounded model checking proofs over symbolic CSR broadphase cell offset arrays
//! ([`csr_cell_range`](crate::passes::spatial_csr::csr_cell_range)), proving monotonic partition
//! soundness and zero out-of-bounds panics on both well-formed and adversarial offset tables.

use crate::passes::spatial_csr::csr_cell_range;

/// PO-S10: For any 4-cell CSR offset table (`[u32; 5]`):
/// - If well-formed monotonic (`offsets[0] <= ... <= offsets[4] <= total_entries`), every valid cell
///   `0..4` yields `Some((s, e))` with `s <= e <= total_entries`, adjacent ranges are flush
///   (`end(c) == start(c+1)`), and `(e - s)` across all 4 cells sums to `offsets[4] - offsets[0]`.
/// - For arbitrary adversarial `offsets`, `cell`, and `total_entries`, `csr_cell_range` never
///   panics and any `Some((s, e))` strictly satisfies `s <= e && e <= total_entries`.
#[kani::proof]
fn po_s10_csr_cell_range_monotonic_partition_and_safety() {
    let offsets: [u32; 5] = kani::any();
    let total_entries: usize = kani::any();

    let is_monotonic = offsets[0] <= offsets[1]
        && offsets[1] <= offsets[2]
        && offsets[2] <= offsets[3]
        && offsets[3] <= offsets[4]
        && (offsets[4] as usize) <= total_entries;

    if is_monotonic {
        let mut total_covered = 0usize;
        let mut prev_end = offsets[0] as usize;
        for c in 0..4usize {
            let (s, e) = csr_cell_range(&offsets, c, total_entries).expect("valid cell range");
            assert!(s <= e && e <= total_entries);
            assert_eq!(s, prev_end);
            total_covered += e - s;
            prev_end = e;
        }
        assert_eq!(total_covered, (offsets[4] - offsets[0]) as usize);
        assert!(csr_cell_range(&offsets, 4, total_entries).is_none());
    }

    // Adversarial arbitrary lookup never panics and validates any returned bounds.
    let arb_cell: usize = kani::any();
    if let Some((s, e)) = csr_cell_range(&offsets, arb_cell, total_entries) {
        assert!(arb_cell < 4);
        assert!(s <= e && e <= total_entries);
    }
}
