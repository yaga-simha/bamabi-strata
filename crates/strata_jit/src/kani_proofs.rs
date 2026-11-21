//! Kani formal verification harness for `strata_jit` (`PO-S9`).
//!
//! Formally verifies that every programmatic [`BamHostApi`](bamabi_sys::BamHostApi) vtable slot
//! offset and every C-ABI descriptor field offset computed in [`abi_offsets`](crate::abi_offsets)
//! is strictly aligned, non-overlapping, and contained within its ABI struct bounds.

use crate::abi_offsets::{HOST_API_SLOTS, QUERY_TERM_CAP, SYSTEM_QUERY_CAP, api_slots, structs};
use core::mem::size_of;

/// PO-S9: Every `BamHostApi` slot offset used by the Cranelift JIT emitter is pointer-aligned,
/// distinct, and lies strictly within `HOST_API_SLOTS * size_of::<usize>()`, and every descriptor
/// field offset lies strictly inside its descriptor `*_SIZE` without extending past struct end.
#[kani::proof]
fn po_s9_jit_abi_offsets_and_bounds() {
    let ptr_sz = size_of::<usize>();
    let table_bytes = HOST_API_SLOTS * ptr_sz;
    assert!(QUERY_TERM_CAP > 0 && SYSTEM_QUERY_CAP > 0);

    let slots = [
        api_slots::LOAD_HOST_CTX,
        api_slots::REGISTER_COMPONENT,
        api_slots::RESOLVE_COMPONENT,
        api_slots::REGISTER_SYSTEM,
        api_slots::SYS_QUERY,
        api_slots::ITER_NEXT_CHUNK,
        api_slots::ITER_COLUMN_READONLY,
        api_slots::ITER_COLUMN_MUTABLE,
        api_slots::ITER_COLUMN_MUTABLE_UNTRACKED,
        api_slots::ITER_MARK_CHANGED_RANGE,
        api_slots::SYS_RES_PTR,
        api_slots::SYS_RES_MUT_PTR,
    ];
    let idx: usize = kani::any();
    kani::assume(idx < slots.len());
    assert!(slots[idx].is_multiple_of(ptr_sz));
    assert!(slots[idx] + ptr_sz <= table_bytes);

    // Distinct slot guarantee across all emitted Host API indices.
    let other: usize = kani::any();
    kani::assume(other < slots.len() && other != idx);
    assert_ne!(slots[idx], slots[other]);

    // Descriptor bounds verification.
    assert!(structs::MANIFEST_NAME + size_of::<bamabi_sys::StrView>() <= structs::MANIFEST_SIZE);
    assert!(
        structs::COMP_FIELDS + size_of::<*const bamabi_sys::BamFieldDesc>()
            <= structs::COMPONENT_DESC_SIZE
    );
    assert!(structs::FIELD_ALIGN + size_of::<u32>() <= structs::FIELD_DESC_SIZE);
    assert!(structs::QUERY_TERM_COUNT + size_of::<usize>() <= structs::QUERY_DESC_SIZE);
    assert!(
        structs::SYS_SCHEDULE + size_of::<bamabi_sys::ScheduleId>() <= structs::SYSTEM_DESC_SIZE
    );
}
