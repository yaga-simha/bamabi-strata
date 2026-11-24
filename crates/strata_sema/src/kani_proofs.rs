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

/// **PO-S11**: Proves algebraic lattice laws (associative, commutative, idempotent, identity,
/// monotone) for [`crate::authority::AuthoritySet`] and [`crate::authority::PlaceOrigin`], plus
/// symbolic soundness and precision of copy-vs-borrow decay across storage constructors.
#[kani::proof]
fn po_s11_authority_lattice_and_place_origin_soundness() {
    use crate::authority::{AuthoritySet, PlaceOrigin};

    let a = AuthoritySet(kani::any::<u8>() & 0x03);
    let b = AuthoritySet(kani::any::<u8>() & 0x03);
    let c = AuthoritySet(kani::any::<u8>() & 0x03);

    // 1. AuthoritySet join-semilattice axioms
    assert_eq!(a.join(b).join(c), a.join(b.join(c)));
    assert_eq!(a.join(b), b.join(a));
    assert_eq!(a.join(a), a);
    assert_eq!(a.join(AuthoritySet::EMPTY), a);
    assert!(a.is_subset_of(a.join(b)));
    assert!(b.is_subset_of(a.join(b)));
    if a.is_subset_of(c) && b.is_subset_of(c) {
        assert!(a.join(b).is_subset_of(c));
    }

    // 2. PlaceOrigin join-semilattice axioms
    let mk_origin = |is_ecs: bool, auth: AuthoritySet| -> PlaceOrigin {
        if is_ecs {
            PlaceOrigin::EcsPlace(auth)
        } else {
            PlaceOrigin::TempValue
        }
    };
    let p1 = mk_origin(kani::any(), a);
    let p2 = mk_origin(kani::any(), b);
    let p3 = mk_origin(kani::any(), c);

    assert_eq!(p1.join(p2).join(p3), p1.join(p2.join(p3)));
    assert_eq!(p1.join(p2), p2.join(p1));
    assert_eq!(p1.join(p1), p1);
    assert_eq!(p1.join(PlaceOrigin::TempValue), p1);
    assert!(p1.authority().is_subset_of(p1.join(p2).authority()));
    assert!(p2.authority().is_subset_of(p1.join(p2).authority()));

    // 3. Copy-vs-borrow decay soundness & precision
    let is_copy_scalar: bool = kani::any();
    let decayed = p1.decay_on_storage_copy(is_copy_scalar);
    if is_copy_scalar {
        assert_eq!(decayed, PlaceOrigin::TempValue);
        assert!(!decayed.authority().contains_server());
    } else {
        assert_eq!(decayed, p1);
        assert_eq!(decayed.authority(), p1.authority());
    }
}

/// **PO-S12**: Proves `Ty::Option`, `Ty::Ref`, `Ty::Borrow`, and `Ty::Result` preserve inner
/// types and mutability without erasure across `Ty::is_compatible_with`.
#[kani::proof]
#[kani::unwind(1)]
fn po_s12_compound_ty_preservation_without_erasure() {
    use crate::types::Ty;
    use std::mem::ManuallyDrop;

    let kind: u8 = kani::any();
    let d1: u8 = kani::any();
    let d2: u8 = kani::any();
    kani::assume(kind < 5 && d1 < 4 && d2 < 4);
    let m1: bool = kani::any();
    let m2: bool = kani::any();

    let mk_leaf = |d: u8| -> Ty {
        match d {
            0 => Ty::I32,
            1 => Ty::F32,
            2 => Ty::Bool,
            _ => Ty::Unit,
        }
    };

    let (lhs, rhs, expected): (ManuallyDrop<Ty>, ManuallyDrop<Ty>, bool) = match kind {
        0 => (
            ManuallyDrop::new(Ty::Option(Box::new(mk_leaf(d1)))),
            ManuallyDrop::new(Ty::Option(Box::new(mk_leaf(d2)))),
            d1 == d2,
        ),
        1 => (
            ManuallyDrop::new(Ty::Option(Box::new(mk_leaf(d1)))),
            ManuallyDrop::new(Ty::Unit),
            false,
        ),
        2 => (
            ManuallyDrop::new(Ty::Borrow {
                mutable: m1,
                inner: Box::new(mk_leaf(d1)),
            }),
            ManuallyDrop::new(Ty::Borrow {
                mutable: m2,
                inner: Box::new(mk_leaf(d2)),
            }),
            m1 == m2 && d1 == d2,
        ),
        3 => (
            ManuallyDrop::new(Ty::Result {
                ok: Box::new(mk_leaf(d1)),
                err: Box::new(Ty::Bool),
            }),
            ManuallyDrop::new(Ty::Result {
                ok: Box::new(mk_leaf(d2)),
                err: Box::new(Ty::Bool),
            }),
            d1 == d2,
        ),
        _ => (
            ManuallyDrop::new(Ty::Ref(String::new())),
            ManuallyDrop::new(Ty::Ref(if m1 { String::new() } else { String::from("B") })),
            m1,
        ),
    };

    assert_eq!(lhs.is_compatible_with(&rhs), expected);
}
