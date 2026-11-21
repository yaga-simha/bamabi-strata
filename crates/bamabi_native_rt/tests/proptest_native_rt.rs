#![forbid(unsafe_code)]
//! Property-based (`proptest`) differential suites for [`bamabi_native_rt`] primitives and
//! [`DirtyRunCoalescer`].

use bamabi_native_rt::{BitSet, DirtyRunCoalescer, Fixed32, Fixed64, InlineStr};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum CoalescerOp {
    Row(usize),
    Range(u32, u32),
}

fn coalescer_op_strategy(max_rows: u32) -> impl Strategy<Value = CoalescerOp> {
    let hi = max_rows.saturating_add(8);
    prop_oneof![
        (0usize..=(hi as usize)).prop_map(CoalescerOp::Row),
        (0u32..=hi, 0u32..=hi).prop_map(|(s, e)| CoalescerOp::Range(s, e)),
    ]
}

proptest! {
    /// Verifies `DirtyRunCoalescer` flushed intervals cover the exact boolean oracle set of dirty
    /// rows for any sequence of single-row and range markings, with strictly valid in-bounds intervals.
    #[test]
    fn dirty_run_coalescer_matches_boolean_oracle(
        row_count in 0u32..=128,
        ops in prop::collection::vec(coalescer_op_strategy(128), 0..64),
    ) {
        let mut coalescer = DirtyRunCoalescer::new(row_count);
        let mut oracle = vec![false; row_count as usize];
        let mut flushed = vec![false; row_count as usize];

        for op in ops {
            match op {
                CoalescerOp::Row(idx) => {
                    if idx < oracle.len() {
                        oracle[idx] = true;
                    }
                    coalescer.mark_row(idx, |s, e| {
                        assert!(s < e && e <= row_count);
                        for slot in &mut flushed[s as usize..e as usize] {
                            *slot = true;
                        }
                    });
                }
                CoalescerOp::Range(s, e) => {
                    let ce = e.min(row_count);
                    if s < ce {
                        for slot in &mut oracle[s as usize..ce as usize] {
                            *slot = true;
                        }
                    }
                    coalescer.mark_range(s, e, |fs, fe| {
                        assert!(fs < fe && fe <= row_count);
                        for slot in &mut flushed[fs as usize..fe as usize] {
                            *slot = true;
                        }
                    });
                }
            }
        }
        let reported = coalescer.finish(|fs, fe| {
            assert!(fs < fe && fe <= row_count);
            for slot in &mut flushed[fs as usize..fe as usize] {
                *slot = true;
            }
        });
        prop_assert_eq!(flushed, oracle);
        prop_assert_eq!(coalescer.pending_run(), None);
        prop_assert_eq!(coalescer.flushed_rows(), reported);
    }

    /// Verifies `BitSet<4>` (128 bits) matches a `[bool; 128]` model across arbitrary set/clear sequences.
    #[test]
    fn bitset_matches_boolean_array_model(ops in prop::collection::vec((any::<bool>(), 0u32..160), 0..100)) {
        let mut bs: BitSet<4> = BitSet::new();
        let mut model = [false; 128];
        for (set_bit, idx) in ops {
            if set_bit {
                bs.set(idx);
                if (idx as usize) < model.len() {
                    model[idx as usize] = true;
                }
            } else {
                bs.clear(idx);
                if (idx as usize) < model.len() {
                    model[idx as usize] = false;
                }
            }
            prop_assert_eq!(bs.get(idx), (idx as usize) < 128 && model[idx as usize]);
        }
        let expected_ones: u32 = model.iter().map(|b| u32::from(*b)).sum();
        prop_assert_eq!(bs.count_ones(), expected_ones);
    }

    /// Verifies `InlineStr<16>::from_str_trunc` always preserves valid UTF-8 and prefix semantics.
    #[test]
    fn inline_str_truncation_preserves_utf8_prefix(s in ".*") {
        let inline = InlineStr::<16>::from_str_trunc(&s);
        let prefix = inline.as_str();
        prop_assert!(prefix.len() <= 16);
        prop_assert!(s.starts_with(prefix));
    }

    /// Verifies `Fixed32` and `Fixed64` integer conversions are exact inside their representable range.
    #[test]
    fn fixed_int_roundtrip(a in -1000i16..=1000i16, b in -1000i16..=1000i16) {
        let sum = Fixed32::from_int(a) + Fixed32::from_int(b);
        prop_assert_eq!(sum.to_f32(), f32::from(a) + f32::from(b));
        let sum64 = Fixed64::from_int(i32::from(a)) - Fixed64::from_int(i32::from(b));
        prop_assert_eq!(sum64.to_f64(), f64::from(a) - f64::from(b));
    }
}
