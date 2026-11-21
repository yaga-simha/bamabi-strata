//! Kani formal verification harnesses for `strata_sema` (`PO-S6`, `PO-S7`).
//!
//! Discharges bounded model checking proofs over symbolic integer layouts (`align_up`,
//! [`compute_field_placement`](crate::layout::compute_field_placement)) and symbolic Theorem 0.1
//! archetype disjointness bitmasks ([`archetype_masks_disjoint`](crate::access::archetype_masks_disjoint)
//! & [`modes_conflict`](crate::access::modes_conflict)).

use crate::access::{TermAccessMode, archetype_masks_disjoint, modes_conflict};
use crate::layout::{align_up, compute_field_placement};

/// PO-S6: For all symbolic power-of-two alignments `<= 64`, `align_up` and
/// `compute_field_placement` either return `None` cleanly on overflow or satisfy:
/// - `aligned_off >= cursor`, `aligned_off % align == 0`
/// - `pad_before + cursor == aligned_off` and `pad_before < align`
/// - contiguous non-overlapping end `next_cursor == aligned_off + field_size`
#[kani::proof]
fn po_s6_align_up_and_field_placement_zero_gap_invariants() {
    let cursor: usize = kani::any();
    let field_size: usize = kani::any();
    let shift: u32 = kani::any();
    kani::assume(shift <= 6);
    let align = 1usize << shift;

    match align_up(cursor, align) {
        Some(aligned) => {
            assert!(aligned >= cursor);
            assert_eq!(aligned % align, 0);
            assert!(aligned - cursor < align);
        }
        None => {
            assert!(cursor > usize::MAX - (align - 1));
        }
    }

    if let Some((pad_before, offset, next_cursor)) =
        compute_field_placement(cursor, field_size, align)
    {
        assert_eq!(cursor + pad_before, offset);
        assert_eq!(offset % align, 0);
        assert!(pad_before < align);
        assert_eq!(next_cursor - offset, field_size);
    }
}

/// Maps any `0..=13` byte into a [`TermAccessMode`] discriminator for full symbolic coverage.
#[inline]
const fn decode_mode(raw: u8) -> TermAccessMode {
    match raw {
        0 => TermAccessMode::Read,
        1 => TermAccessMode::Write,
        2 => TermAccessMode::SelectiveWrite,
        3 => TermAccessMode::OptionalRead,
        4 => TermAccessMode::OptionalWrite,
        5 => TermAccessMode::With,
        6 => TermAccessMode::Without,
        7 => TermAccessMode::Allow,
        8 => TermAccessMode::Has,
        9 => TermAccessMode::RemovedRead,
        10 => TermAccessMode::ResRead,
        11 => TermAccessMode::ResWrite,
        12 => TermAccessMode::StreamRead,
        _ => TermAccessMode::StreamWrite,
    }
}

/// PO-S7: Theorem 0.1 soundness over all symbolic access modes and all `u8` archetype masks:
/// 1. `modes_conflict(a, b) == modes_conflict(b, a)` (symmetry) and Read/Read never conflicts.
/// 2. If any concrete entity archetype `arch: u8` satisfies both queries (`(arch & with) == with`
///    and `(arch & without) == 0`), `archetype_masks_disjoint` MUST return `false`.
#[kani::proof]
fn po_s7_theorem01_disjointness_and_conflict_symmetry() {
    let raw_a: u8 = kani::any();
    let raw_b: u8 = kani::any();
    kani::assume(raw_a <= 13 && raw_b <= 13);
    let ma = decode_mode(raw_a);
    let mb = decode_mode(raw_b);
    assert_eq!(modes_conflict(ma, mb), modes_conflict(mb, ma));
    if !ma.is_mutable() && !mb.is_mutable() {
        assert!(!modes_conflict(ma, mb));
    }

    let with_a: u8 = kani::any();
    let without_a: u8 = kani::any();
    let with_b: u8 = kani::any();
    let without_b: u8 = kani::any();
    let arch: u8 = kani::any();

    let matches_a = (arch & with_a) == with_a && (arch & without_a) == 0;
    let matches_b = (arch & with_b) == with_b && (arch & without_b) == 0;
    if matches_a && matches_b {
        assert!(!archetype_masks_disjoint(
            with_a, without_a, with_b, without_b
        ));
    }
}
