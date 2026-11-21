//! Programmatic ABI `0.3.0` wire offsets computed exclusively from `bamabi_sys` constants
//! and `core::mem::offset_of!`. Zero magic byte offsets are permitted in `strata_jit`.

use bamabi_sys::{
    ABI_VERSION, BAM_HOST_API_SLOT_COUNT, BamComponent, BamFieldDesc, BamHostApi, BamManifest,
    BamQueryDesc, BamSystemDesc, BamTermDesc, ComponentDesc, FfiResult, MAX_QUERIES_PER_SYSTEM,
    MAX_TERMS_PER_QUERY, StrView, offsets,
};
use core::mem::{offset_of, size_of};

/// Packed `bamabi_sys::ABI_VERSION` (`0x0003_0000`).
pub const WIRE_ABI_VERSION: u32 = ABI_VERSION;

/// `bamabi_sys::FfiResult::NOT_FOUND.0`.
pub const FFI_NOT_FOUND: u32 = FfiResult::NOT_FOUND.0;

/// Verified `bamabi_sys::BAM_HOST_API_SLOT_COUNT`.
pub const HOST_API_SLOTS: usize = BAM_HOST_API_SLOT_COUNT;

/// Verified query capacity limits from `bamabi_sys`.
pub const QUERY_TERM_CAP: usize = MAX_TERMS_PER_QUERY;
/// Verified query count cap per system from `bamabi_sys`.
pub const SYSTEM_QUERY_CAP: usize = MAX_QUERIES_PER_SYSTEM;

/// Byte offsets inside [`BamHostApi`] from `bamabi_sys::offsets`.
pub mod api_slots {
    use super::offsets;

    /// `BamHostApi::load_host_ctx`
    pub const LOAD_HOST_CTX: usize = offsets::LOAD_HOST_CTX;
    /// `BamHostApi::register_component`
    pub const REGISTER_COMPONENT: usize = offsets::REGISTER_COMPONENT;
    /// `BamHostApi::resolve_component`
    pub const RESOLVE_COMPONENT: usize = offsets::RESOLVE_COMPONENT;
    /// `BamHostApi::register_system`
    pub const REGISTER_SYSTEM: usize = offsets::REGISTER_SYSTEM;
    /// `BamHostApi::sys_query`
    pub const SYS_QUERY: usize = offsets::SYS_QUERY;
    /// `BamHostApi::iter_next_chunk`
    pub const ITER_NEXT_CHUNK: usize = offsets::ITER_NEXT_CHUNK;
    /// `BamHostApi::iter_column_readonly`
    pub const ITER_COLUMN_READONLY: usize = offsets::ITER_COLUMN_READONLY;
    /// `BamHostApi::iter_column_mutable`
    pub const ITER_COLUMN_MUTABLE: usize = offsets::ITER_COLUMN_MUTABLE;
    /// `BamHostApi::iter_column_mutable_untracked`
    pub const ITER_COLUMN_MUTABLE_UNTRACKED: usize = offsets::ITER_COLUMN_MUTABLE_UNTRACKED;
    /// `BamHostApi::iter_mark_changed_range`
    pub const ITER_MARK_CHANGED_RANGE: usize = offsets::ITER_MARK_CHANGED_RANGE;
    /// `BamHostApi::sys_res_ptr`
    pub const SYS_RES_PTR: usize = offsets::SYS_RES_PTR;
    /// `BamHostApi::sys_res_mut_ptr`
    pub const SYS_RES_MUT_PTR: usize = offsets::SYS_RES_MUT_PTR;
}

/// Sizes & field offsets of ABI descriptor structs from `core::mem`.
pub mod structs {
    use super::*;

    /// `sizeof(BamManifest)`
    pub const MANIFEST_SIZE: usize = size_of::<BamManifest>();
    /// `offsetof(BamManifest, struct_size)`
    pub const MANIFEST_STRUCT_SIZE: usize = offset_of!(BamManifest, struct_size);
    /// `offsetof(BamManifest, abi_version)`
    pub const MANIFEST_ABI_VERSION: usize = offset_of!(BamManifest, abi_version);
    /// `offsetof(BamManifest, name)`
    pub const MANIFEST_NAME: usize = offset_of!(BamManifest, name);
    /// `offsetof(BamManifest, version)`
    pub const MANIFEST_VERSION: usize = offset_of!(BamManifest, version);

    /// `sizeof(ComponentDesc)`
    pub const COMPONENT_DESC_SIZE: usize = size_of::<ComponentDesc>();
    /// `offsetof(ComponentDesc, struct_size)`
    pub const COMP_STRUCT_SIZE: usize = offset_of!(ComponentDesc, struct_size);
    /// `offsetof(ComponentDesc, flags)`
    pub const COMP_FLAGS: usize = offset_of!(ComponentDesc, flags);
    /// `offsetof(ComponentDesc, name)`
    pub const COMP_NAME: usize = offset_of!(ComponentDesc, name);
    /// `offsetof(ComponentDesc, uuid)`
    pub const COMP_UUID: usize = offset_of!(ComponentDesc, uuid);
    /// `offsetof(ComponentDesc, size)`
    pub const COMP_SIZE: usize = offset_of!(ComponentDesc, size);
    /// `offsetof(ComponentDesc, align)`
    pub const COMP_ALIGN: usize = offset_of!(ComponentDesc, align);
    /// `offsetof(ComponentDesc, schema_fingerprint)`
    pub const COMP_SCHEMA_FINGERPRINT: usize = offset_of!(ComponentDesc, schema_fingerprint);
    /// `offsetof(ComponentDesc, fields)`
    pub const COMP_FIELDS: usize = offset_of!(ComponentDesc, fields);
    /// `offsetof(ComponentDesc, field_count)`
    pub const COMP_FIELD_COUNT: usize = offset_of!(ComponentDesc, field_count);

    /// `sizeof(BamFieldDesc)`
    pub const FIELD_DESC_SIZE: usize = size_of::<BamFieldDesc>();
    /// `offsetof(BamFieldDesc, struct_size)`
    pub const FIELD_STRUCT_SIZE: usize = offset_of!(BamFieldDesc, struct_size);
    /// `offsetof(BamFieldDesc, kind)`
    pub const FIELD_KIND: usize = offset_of!(BamFieldDesc, kind);
    /// `offsetof(BamFieldDesc, name)`
    pub const FIELD_NAME: usize = offset_of!(BamFieldDesc, name);
    /// `offsetof(BamFieldDesc, type_tag)`
    pub const FIELD_TYPE_TAG: usize = offset_of!(BamFieldDesc, type_tag);
    /// `offsetof(BamFieldDesc, offset)`
    pub const FIELD_OFFSET: usize = offset_of!(BamFieldDesc, offset);
    /// `offsetof(BamFieldDesc, size)`
    pub const FIELD_SIZE: usize = offset_of!(BamFieldDesc, size);
    /// `offsetof(BamFieldDesc, align)`
    pub const FIELD_ALIGN: usize = offset_of!(BamFieldDesc, align);

    /// `offsetof(StrView, ptr)`
    pub const STRVIEW_PTR: usize = offset_of!(StrView, ptr);
    /// `offsetof(StrView, len)`
    pub const STRVIEW_LEN: usize = offset_of!(StrView, len);

    /// `sizeof(BamTermDesc)`
    pub const TERM_DESC_SIZE: usize = size_of::<BamTermDesc>();
    /// `offsetof(BamTermDesc, component)`
    pub const TERM_COMPONENT: usize = offset_of!(BamTermDesc, component);
    /// `offsetof(BamTermDesc, mode)`
    pub const TERM_MODE: usize = offset_of!(BamTermDesc, mode);

    /// `sizeof(BamQueryDesc)`
    pub const QUERY_DESC_SIZE: usize = size_of::<BamQueryDesc>();
    /// `offsetof(BamQueryDesc, struct_size)`
    pub const QUERY_STRUCT_SIZE: usize = offset_of!(BamQueryDesc, struct_size);
    /// `offsetof(BamQueryDesc, terms)`
    pub const QUERY_TERMS: usize = offset_of!(BamQueryDesc, terms);
    /// `offsetof(BamQueryDesc, term_count)`
    pub const QUERY_TERM_COUNT: usize = offset_of!(BamQueryDesc, term_count);

    /// `sizeof(BamSystemDesc)`
    pub const SYSTEM_DESC_SIZE: usize = size_of::<BamSystemDesc>();
    /// `offsetof(BamSystemDesc, struct_size)`
    pub const SYS_STRUCT_SIZE: usize = offset_of!(BamSystemDesc, struct_size);
    /// `offsetof(BamSystemDesc, name)`
    pub const SYS_NAME: usize = offset_of!(BamSystemDesc, name);
    /// `offsetof(BamSystemDesc, queries)`
    pub const SYS_QUERIES: usize = offset_of!(BamSystemDesc, queries);
    /// `offsetof(BamSystemDesc, query_count)`
    pub const SYS_QUERY_COUNT: usize = offset_of!(BamSystemDesc, query_count);
    /// `offsetof(BamSystemDesc, callback)`
    pub const SYS_CALLBACK: usize = offset_of!(BamSystemDesc, callback);
    /// `offsetof(BamSystemDesc, user_data)`
    pub const SYS_USER_DATA: usize = offset_of!(BamSystemDesc, user_data);
    /// `offsetof(BamSystemDesc, schedule)`
    pub const SYS_SCHEDULE: usize = offset_of!(BamSystemDesc, schedule);

    /// `sizeof(BamComponent)`
    pub const BAM_COMPONENT_SIZE: usize = size_of::<BamComponent>();
}

const _: () = {
    assert!(
        core::mem::size_of::<BamHostApi>() >= offsets::SLOT_COUNT * core::mem::size_of::<usize>()
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies every host API slot offset matches pointer stride bounds and alignment.
    #[test]
    fn host_api_slot_offsets_are_aligned_and_in_bounds() {
        let ptr_sz = size_of::<usize>();
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
        for s in slots {
            assert_eq!(s % ptr_sz, 0);
            assert!(s + ptr_sz <= HOST_API_SLOTS * ptr_sz);
        }
    }

    /// Verifies ABI descriptor struct sizes and capacities match `bamabi_sys` constants.
    #[test]
    fn descriptor_sizes_match_bamabi_sys() {
        assert_eq!(structs::MANIFEST_SIZE, size_of::<BamManifest>());
        assert_eq!(structs::COMPONENT_DESC_SIZE, size_of::<ComponentDesc>());
        assert_eq!(structs::SYSTEM_DESC_SIZE, size_of::<BamSystemDesc>());
        assert_eq!(QUERY_TERM_CAP, MAX_TERMS_PER_QUERY);
        assert_eq!(SYSTEM_QUERY_CAP, MAX_QUERIES_PER_SYSTEM);
    }
}
