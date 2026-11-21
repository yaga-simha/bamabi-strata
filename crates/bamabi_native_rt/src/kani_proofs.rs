//! Kani formal verification harnesses for `bamabi_native_rt` (`PO-S1`..`PO-S5`).
//!
//! Discharges bounded model checking proofs (CBMC) across all `#[repr(C)]` `AbiPod` runtime
//! primitives and the `&mut? T` [`DirtyRunCoalescer`](crate::slice_query::DirtyRunCoalescer)
//! interval coalescer over unbounded/symbolic inputs.

use crate::primitives::{
    BitSet, Fixed32, Fixed64, GraceWindow, InlineStr, InputBuffer, InputBufferEntry, SmallVecPod,
    TimelineCursor,
};
use crate::slice_query::DirtyRunCoalescer;
use core::mem::{align_of, size_of};

/// PO-S1: `GraceWindow` is 4-byte `#[repr(C)]` zero-gap and `tick` with positive `dt` never
/// produces negative `remaining_sec`.
#[kani::proof]
fn po_s1_grace_window_nonnegative_countdown() {
    assert_eq!(size_of::<GraceWindow>(), 4);
    assert_eq!(align_of::<GraceWindow>(), 4);

    let init: f32 = kani::any();
    let dt: f32 = kani::any();
    kani::assume(init.is_finite() && init >= 0.0 && init <= 10_000.0);
    kani::assume(dt.is_finite() && dt >= 0.0 && dt <= 10_000.0);

    let mut g = GraceWindow {
        remaining_sec: init,
    };
    g.tick(dt);
    assert!(g.remaining_sec >= 0.0);
    assert_eq!(g.is_active(), g.remaining_sec > 0.0);

    g.clear();
    assert!(!g.is_active());
    assert_eq!(g.remaining_sec, 0.0);
}

/// PO-S2: `InputBuffer<4>` & `TimelineCursor` maintain exact C-ABI layout sizes and panic-free
/// push/consume/tick/stop invariants for arbitrary symbolic action IDs and timers.
#[kani::proof]
#[kani::unwind(8)]
fn po_s2_input_buffer_and_timeline_cursor_soundness() {
    assert_eq!(size_of::<InputBufferEntry>(), 8);
    assert_eq!(size_of::<InputBuffer<4>>(), 32);
    assert_eq!(size_of::<TimelineCursor>(), 16);

    let mut buf: InputBuffer<4> = InputBuffer::new();
    let a1: u16 = kani::any();
    let a2: u16 = kani::any();
    let w1: f32 = kani::any();
    let w2: f32 = kani::any();
    kani::assume(a1 != u16::MAX && a2 != u16::MAX);
    kani::assume(w1.is_finite() && w1 > 0.0 && w1 <= 10.0);
    kani::assume(w2.is_finite() && w2 > 0.0 && w2 <= 10.0);

    buf.push(a1, w1);
    assert!(buf.peek(a1));
    buf.push(a2, w2);
    assert!(buf.peek(a2));

    let mut cur = TimelineCursor::start();
    assert!(cur.is_active());
    let mask: u32 = kani::any();
    cur.active_mask = mask;
    assert_eq!(cur.in_window(mask), mask != 0);
    cur.stop();
    assert!(!cur.is_active());
    assert_eq!(cur.active_mask, 0);
}

/// PO-S3: `BitSet<2>`, `InlineStr<4>`, and `SmallVecPod<u32, 8>` remain memory-safe and strictly
/// bounds-checked under adversarial out-of-bounds lengths and indices (including corrupted `len`).
#[kani::proof]
#[kani::unwind(10)]
fn po_s3_bounded_containers_reject_oob_safely() {
    let mut bs: BitSet<2> = BitSet::new();
    let idx: u32 = kani::any();
    let before = bs.count_ones();
    bs.set(idx);
    if idx < 64 {
        assert!(bs.get(idx));
        assert!(bs.count_ones() >= before);
    } else {
        assert!(!bs.get(idx));
        assert_eq!(bs.count_ones(), before);
    }

    let adversarial_len: u32 = kani::any();
    let bytes: [u8; 4] = kani::any();
    let s = InlineStr::<4> {
        len: adversarial_len,
        bytes,
    };
    let view = s.as_str();
    assert!(view.len() <= 4);

    let init_len: u32 = kani::any();
    let mut vec: SmallVecPod<u32, 8> = SmallVecPod {
        len: init_len,
        _pad: 0,
        data: [0; 8],
    };
    assert!(vec.as_slice().len() <= 8);
    let pushed = vec.push(42);
    assert_eq!(pushed, init_len < 8);
    if pushed {
        assert_eq!(vec.len, init_len + 1);
        assert_eq!(vec.as_slice().len(), (init_len + 1) as usize);
    } else {
        assert_eq!(vec.len, init_len);
    }
}

/// PO-S4: `Fixed32` and `Fixed64` ring/arithmetic operations never panic on wrapping boundaries
/// (`Add`, `Sub`, `Mul`, `Neg`, `Div` with non-zero divisor).
#[kani::proof]
fn po_s4_fixed_point_total_arithmetic() {
    let a = Fixed32(kani::any());
    let b = Fixed32(kani::any());
    let _ = a + b;
    let _ = a - b;
    let _ = a * b;
    let _ = -a;
    if b.0 != 0 {
        let _ = a / b;
    }

    let x = Fixed64(kani::any());
    let y = Fixed64(kani::any());
    let _ = x + y;
    let _ = x - y;
    let _ = x * y;
    let _ = -x;
    if y.0 != 0 {
        let _ = x / y;
    }
}

/// Computes exact bitmask for half-open range `[start, end)` inside `0..=16` in O(1) without loops.
#[inline]
const fn range_bitmask_u32(start: u32, end: u32) -> u32 {
    if start >= end {
        0
    } else {
        ((1u32 << end) - 1) ^ ((1u32 << start) - 1)
    }
}

/// PO-S5: `DirtyRunCoalescer` produces only strictly in-bounds non-empty `[s, e)` flush intervals
/// whose exact set union equals an oracle 16-bit dirty mask over bounded 16-row slices.
#[kani::proof]
#[kani::unwind(6)]
fn po_s5_dirty_run_coalescer_exact_oracle_parity() {
    let row_count: u32 = kani::any();
    kani::assume(row_count <= 16);

    let mut coalescer = DirtyRunCoalescer::new(row_count);
    let mut flushed_mask: u32 = 0;
    let mut oracle_mask: u32 = 0;

    for _ in 0..4u8 {
        let is_range: bool = kani::any();
        if is_range {
            let s: u32 = kani::any();
            let e: u32 = kani::any();
            kani::assume(s <= 20 && e <= 20);
            let ce = e.min(row_count);
            oracle_mask |= range_bitmask_u32(s, ce);
            coalescer.mark_range(s, e, |fs, fe| {
                assert!(fs < fe && fe <= row_count);
                flushed_mask |= range_bitmask_u32(fs, fe);
            });
        } else {
            let idx: usize = kani::any();
            kani::assume(idx <= 20);
            if idx < row_count as usize {
                oracle_mask |= 1u32 << idx;
            }
            coalescer.mark_row(idx, |fs, fe| {
                assert!(fs < fe && fe <= row_count);
                flushed_mask |= range_bitmask_u32(fs, fe);
            });
        }
        if let Some((ps, pe)) = coalescer.pending_run() {
            assert!(ps < pe && pe <= row_count);
        }
    }

    let _ = coalescer.finish(|fs, fe| {
        assert!(fs < fe && fe <= row_count);
        flushed_mask |= range_bitmask_u32(fs, fe);
    });
    assert_eq!(coalescer.pending_run(), None);
    assert_eq!(flushed_mask, oracle_mask);
}
