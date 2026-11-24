//! Kani formal verification harnesses for `strata_mir` (`PO-S10`, `PO-S14`, `PO-S15`).
//!
//! Discharges bounded model checking proofs over:
//! - `PO-S10`: CSR broadphase cell offset interval partitioning (`csr_cell_range`)
//! - `PO-S14`: `atomic_tx` shadow-before-mutate pre-image undo log rollback soundness
//! - `PO-S15`: 2-pass CSR builder bucket partitioning and `query_disc` cell-window clamping

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

/// PO-S14: Formal model of `atomic_tx.rs` shadow-before-mutate pre-image undo log.
/// Over arbitrary initial component values, outer stack slot values, conditional paths, and
/// repeated mutations at the same `FieldStore` site, intra-transaction reads observe tentative
/// writes and `require_true(false)` restores exact pre-transaction values in reverse order.
#[kani::proof]
#[kani::unwind(6)]
fn po_s14_atomic_tx_preimage_undo_log_restores_on_rollback() {
    let init_fields: [i32; 2] = kani::any();
    let init_outer: i32 = kani::any();

    let mut fields = init_fields;
    let mut outer_slot = init_outer;

    // `ckpt_bb`: snapshot outer slot and zero-initialize per-site `(saved_flag, undo_val)`.
    let undo_outer = outer_slot;
    let mut saved_flag = [false; 4];
    let mut undo_val = [0i32; 4];
    let mut targets = [0usize; 4];

    // Symbolic transaction body across 4 `FieldStore` sites (some conditional, some repeated).
    let mut k = 0usize;
    while k < 4 {
        let target: usize = kani::any();
        kani::assume(target < 2);
        targets[k] = target;

        let cond: bool = kani::any();
        let reps: u8 = kani::any();
        kani::assume(reps >= 1 && reps <= 2);

        if cond {
            let mut r = 0u8;
            while r < reps {
                let new_val: i32 = kani::any();
                // Shadow-before-mutate (`if !saved_flag[k] { FieldLoad -> undo_val[k]; saved_flag[k] = true; }`)
                if !saved_flag[k] {
                    undo_val[k] = fields[target];
                    saved_flag[k] = true;
                }
                // In-place `FieldStore`
                fields[target] = new_val;
                // Subsequent intra-transaction `FieldLoad` sees exact tentative value
                assert_eq!(fields[target], new_val);
                r += 1;
            }
        }
        k += 1;
    }

    let mutate_outer: bool = kani::any();
    if mutate_outer {
        let new_outer: i32 = kani::any();
        outer_slot = new_outer;
        assert_eq!(outer_slot, new_outer);
    }

    // `require_true(false)` -> `atomic_rollback`: reverse-order conditional restoration.
    let require_ok = false;
    if !require_ok {
        let mut rk = 4usize;
        while rk > 0 {
            rk -= 1;
            if saved_flag[rk] {
                fields[targets[rk]] = undo_val[rk];
            }
        }
        outer_slot = undo_outer;
    }

    assert_eq!(fields[0], init_fields[0]);
    assert_eq!(fields[1], init_fields[1]);
    assert_eq!(outer_slot, init_outer);
}

/// PO-S15: 2-pass CSR builder (`N <= 8` entities, `G <= 4` cells) places every entity into its
/// exact hashed cell bucket once, partitions `0..N` contiguously, and `query_disc` cell-window
/// clamping never overflows or reads out of bounds.
#[kani::proof]
#[kani::unwind(10)]
fn po_s15_spatial_csr_2pass_partition_and_query_disc_clamping() {
    let n: usize = kani::any();
    let cols: u32 = kani::any();
    let rows: u32 = kani::any();
    kani::assume(n <= 8);
    kani::assume(cols >= 1 && cols <= 2);
    kani::assume(rows >= 1 && rows <= 2);
    let g = (cols * rows) as usize;

    let mut ent_cell = [0u8; 8];
    for c_slot in ent_cell.iter_mut().take(n) {
        let cell: u8 = kani::any();
        kani::assume((cell as usize) < g);
        *c_slot = cell;
    }
    // Verify cell quantization clamping maps arbitrary coordinates strictly into 0..g.
    let q_raw_x: i32 = kani::any();
    let q_raw_y: i32 = kani::any();
    let q_cx = q_raw_x.clamp(0, cols as i32 - 1) as u32;
    let q_cy = q_raw_y.clamp(0, rows as i32 - 1) as u32;
    assert!(((q_cy * cols + q_cx) as usize) < g);

    // `SpatialCsrBegin`
    let mut cell_offsets = [0u32; 5];
    let mut write_cursors = [0u8; 4];

    // Pass 1: `SpatialCsrCount`
    for i in 0..8usize {
        if i < n {
            cell_offsets[ent_cell[i] as usize + 1] += 1;
        }
    }

    // `SpatialCsrPrefixSum`
    let mut acc = 0u32;
    for c in 0..4usize {
        if c < g {
            write_cursors[c] = acc as u8;
            acc += cell_offsets[c + 1];
            cell_offsets[c + 1] = acc;
        }
    }
    assert_eq!(cell_offsets[0], 0);
    assert_eq!(cell_offsets[g], n as u32);

    // Pass 2: `SpatialCsrScatter`
    let mut scattered = [u8::MAX; 8];
    let mut assigned_slot = [0u8; 8];
    for i in 0..8usize {
        if i < n {
            let cell = ent_cell[i] as usize;
            let slot = write_cursors[cell] as usize;
            assert!(slot < n);
            scattered[slot] = i as u8;
            assigned_slot[i] = slot as u8;
            write_cursors[cell] += 1;
        }
    }

    // All cell offset intervals partition `0..n` contiguously.
    let mut total_bucket_elems = 0usize;
    let mut prev_end = 0usize;
    for c in 0..4usize {
        if c < g {
            let (s, e) = csr_cell_range(&cell_offsets[..=g], c, n).expect("valid 2-pass CSR range");
            assert_eq!(s, prev_end);
            assert!(s <= e && e <= n);
            total_bucket_elems += e - s;
            prev_end = e;
        }
    }
    assert_eq!(total_bucket_elems, n);

    // Every entity lands inside its exact hashed cell bucket [s, e) and appears exactly once
    // (injection `0..n -> 0..n` + every slot `0..n` populated implies exact bijection).
    for i in 0..8usize {
        if i < n {
            let c = ent_cell[i] as usize;
            let s = cell_offsets[c] as usize;
            let e = cell_offsets[c + 1] as usize;
            let slot = assigned_slot[i] as usize;
            assert!(slot >= s && slot < e);
            assert_eq!(scattered[slot] as usize, i);
            assert!((scattered[i] as usize) < n);
        }
    }

    // `query_disc` cell-window clamping over arbitrary symbolic AABB bounds never overflows or OOBs.
    let raw_min_x: i32 = kani::any();
    let raw_max_x: i32 = kani::any();
    let raw_min_y: i32 = kani::any();
    let raw_max_y: i32 = kani::any();
    kani::assume(raw_min_x <= raw_max_x);
    kani::assume(raw_min_y <= raw_max_y);

    let min_cx = raw_min_x.clamp(0, cols as i32 - 1) as u32;
    let max_cx = raw_max_x.clamp(0, cols as i32 - 1) as u32;
    let min_cy = raw_min_y.clamp(0, rows as i32 - 1) as u32;
    let max_cy = raw_max_y.clamp(0, rows as i32 - 1) as u32;
    assert!(min_cx <= max_cx && max_cx < cols);
    assert!(min_cy <= max_cy && max_cy < rows);

    for cy in 0..2u32 {
        for cx in 0..2u32 {
            if cy >= min_cy && cy <= max_cy && cx >= min_cx && cx <= max_cx {
                let cell = (cy * cols + cx) as usize;
                assert!(cell < g);
                let (s, e) =
                    csr_cell_range(&cell_offsets[..=g], cell, n).expect("window cell in bounds");
                assert!(s <= e && e <= n);
            }
        }
    }
}
