//! Programmatic ABI `0.3.0` wire offsets computed exclusively from `bamabi_sys` constants
//! and `core::mem::offset_of!`. Zero magic byte offsets are permitted in `strata_jit`.

use bamabi_sys::{
    ABI_VERSION, BAM_COMPONENT_KNOWN_FLAGS, BAM_HOST_API_SLOT_COUNT, BAM_OBSERVER_FLAG_PROPAGATE,
    BAM_RELATION_FLAG_ACYCLIC, BAM_RELATION_FLAG_CASCADE_DESPAWN, BAM_RELATION_FLAG_CLEANUP_REMOVE,
    BAM_RELATION_FLAG_EXCLUSIVE, BAM_RELATION_FLAG_SYMMETRIC, BAM_SCHEDULE_SET_FLAG_AFTER_WEAK,
    BAM_SCHEDULE_SET_FLAG_BEFORE_WEAK, BAM_SCHEDULE_SET_FLAG_PARALLEL,
    BAM_SCHEDULE_SET_FLAG_SEQUENCE, BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK,
    BAM_TRIGGER_FLAG_PROPAGATE, BamComponent, BamEventKind, BamFieldDesc, BamHostApi,
    BamLayoutInfo, BamManifest, BamObserverDesc, BamQueryDesc, BamRelationDesc, BamScheduleSetDesc,
    BamSymbol, BamSystem, BamSystemDesc, BamSystemSet, BamTermDesc, BamTriggerDesc, ComponentDesc,
    FfiEntity, FfiResult, FfiSlice, MAX_QUERIES_PER_SYSTEM, MAX_TERMS_PER_QUERY, StrView, offsets,
};
use core::mem::{offset_of, size_of};

/// Frozen wire ABI version (`0x0003_0000`).
pub const WIRE_ABI_VERSION: u32 = ABI_VERSION;

/// Canonical wire success result code (`FfiResult::OK`).
pub const FFI_OK: u32 = FfiResult::OK.0;

/// Canonical wire error code returned when a component handle is invalid.
pub const FFI_INVALID_COMPONENT: u32 = FfiResult::INVALID_COMPONENT.0;

/// Canonical wire error code returned for null descriptor pointers.
pub const FFI_NULL_POINTER: u32 = FfiResult::NULL_POINTER.0;

/// Canonical wire result code returned when a component is not yet registered (`NOT_FOUND`).
pub const FFI_NOT_FOUND: u32 = FfiResult::NOT_FOUND.0;

/// Canonical wire error code returned when schema layout/fingerprint mismatches (`TYPE_MISMATCH`).
pub const FFI_TYPE_MISMATCH: u32 = FfiResult::TYPE_MISMATCH.0;

/// Total function pointer slots exposed in `BamHostApi`.
pub const HOST_API_SLOTS: usize = BAM_HOST_API_SLOT_COUNT;

/// Maximum terms per ECS query descriptor enforced by `bamabi_sys`.
pub const QUERY_TERM_CAP: usize = MAX_TERMS_PER_QUERY;

/// Maximum queries per system descriptor enforced by `bamabi_sys`.
pub const SYSTEM_QUERY_CAP: usize = MAX_QUERIES_PER_SYSTEM;

/// Sentinel invalid component handle (`BamComponent::INVALID`).
pub const BAM_COMPONENT_INVALID: u32 = BamComponent::INVALID.to_raw();

/// Sentinel invalid system handle (`BamSystem::INVALID`).
pub const BAM_SYSTEM_INVALID: u32 = BamSystem::INVALID.to_raw();

/// Sentinel invalid system-set handle (`BamSystemSet::INVALID`).
pub const BAM_SYSTEM_SET_INVALID: u32 = BamSystemSet::INVALID.to_raw();

/// Canonical null `FfiEntity` wire sentinel (`0`).
pub const FFI_ENTITY_NULL: u64 = FfiEntity::NULL.to_bits();

/// Custom user-defined event kind discriminant (`BamEventKind::CUSTOM`).
pub const BAM_EVENT_KIND_CUSTOM: u32 = BamEventKind::CUSTOM.0;

/// Lifecycle `ADD` event kind discriminant (`BamEventKind::ADD`).
pub const BAM_EVENT_KIND_ADD: u32 = BamEventKind::ADD.0;

/// Lifecycle `INSERT` event kind discriminant (`BamEventKind::INSERT`).
pub const BAM_EVENT_KIND_INSERT: u32 = BamEventKind::INSERT.0;

/// Lifecycle `DISCARD` event kind discriminant (`BamEventKind::DISCARD`).
pub const BAM_EVENT_KIND_DISCARD: u32 = BamEventKind::DISCARD.0;

/// Lifecycle `REMOVE` event kind discriminant (`BamEventKind::REMOVE`).
pub const BAM_EVENT_KIND_REMOVE: u32 = BamEventKind::REMOVE.0;

/// Lifecycle `DESPAWN` event kind discriminant (`BamEventKind::DESPAWN`).
pub const BAM_EVENT_KIND_DESPAWN: u32 = BamEventKind::DESPAWN.0;

/// Lifecycle `READY` event kind discriminant (`BamEventKind::READY`).
pub const BAM_EVENT_KIND_READY: u32 = BamEventKind::READY.0;

/// Observer relation-propagation flag (`BAM_OBSERVER_FLAG_PROPAGATE`).
pub const OBSERVER_FLAG_PROPAGATE: u32 = BAM_OBSERVER_FLAG_PROPAGATE;

/// Trigger relation-propagation flag (`BAM_TRIGGER_FLAG_PROPAGATE`).
pub const TRIGGER_FLAG_PROPAGATE: u32 = BAM_TRIGGER_FLAG_PROPAGATE;

/// Supported component descriptor bitmask (`BAM_COMPONENT_KNOWN_FLAGS`).
pub const COMPONENT_KNOWN_FLAGS: u32 = BAM_COMPONENT_KNOWN_FLAGS;

/// Exclusive (`1:1`) relationship flag.
pub const RELATION_FLAG_EXCLUSIVE: u32 = BAM_RELATION_FLAG_EXCLUSIVE;

/// Cascade-despawn relationship flag.
pub const RELATION_FLAG_CASCADE_DESPAWN: u32 = BAM_RELATION_FLAG_CASCADE_DESPAWN;

/// Symmetric relationship flag.
pub const RELATION_FLAG_SYMMETRIC: u32 = BAM_RELATION_FLAG_SYMMETRIC;

/// Acyclic DAG relationship flag.
pub const RELATION_FLAG_ACYCLIC: u32 = BAM_RELATION_FLAG_ACYCLIC;

/// Cleanup-remove relationship flag.
pub const RELATION_FLAG_CLEANUP_REMOVE: u32 = BAM_RELATION_FLAG_CLEANUP_REMOVE;

/// Ordered-chain schedule set flag.
pub const SCHEDULE_SET_FLAG_SEQUENCE: u32 = BAM_SCHEDULE_SET_FLAG_SEQUENCE;

/// Weak ordered-chain schedule set flag.
pub const SCHEDULE_SET_FLAG_SEQUENCE_WEAK: u32 = BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK;

/// Unordered parallel schedule set flag.
pub const SCHEDULE_SET_FLAG_PARALLEL: u32 = BAM_SCHEDULE_SET_FLAG_PARALLEL;

/// Weak `before` edges schedule set flag.
pub const SCHEDULE_SET_FLAG_BEFORE_WEAK: u32 = BAM_SCHEDULE_SET_FLAG_BEFORE_WEAK;

/// Weak `after` edges schedule set flag.
pub const SCHEDULE_SET_FLAG_AFTER_WEAK: u32 = BAM_SCHEDULE_SET_FLAG_AFTER_WEAK;

/// Programmatic `BamHostApi` vtable byte offsets derived directly from `bamabi_sys::offsets`.
pub mod api_slots {
    use super::offsets;

    /// Byte offset of `BamHostApi::load_host_ctx` (Slot 2).
    pub const LOAD_HOST_CTX: usize = offsets::LOAD_HOST_CTX;
    /// Byte offset of `BamHostApi::register_component` (Slot 3).
    pub const REGISTER_COMPONENT: usize = offsets::REGISTER_COMPONENT;
    /// Byte offset of `BamHostApi::resolve_component` (Slot 4).
    pub const RESOLVE_COMPONENT: usize = offsets::RESOLVE_COMPONENT;
    /// Byte offset of `BamHostApi::register_system` (Slot 5).
    pub const REGISTER_SYSTEM: usize = offsets::REGISTER_SYSTEM;
    /// Byte offset of `BamHostApi::sys_host_ctx` (Slot 6).
    pub const SYS_HOST_CTX: usize = offsets::SYS_HOST_CTX;
    /// Byte offset of `BamHostApi::sys_query` (Slot 7).
    pub const SYS_QUERY: usize = offsets::SYS_QUERY;
    /// Byte offset of `BamHostApi::sys_commands` (Slot 8).
    pub const SYS_COMMANDS: usize = offsets::SYS_COMMANDS;
    /// Byte offset of `BamHostApi::iter_next_chunk` (Slot 9).
    pub const ITER_NEXT_CHUNK: usize = offsets::ITER_NEXT_CHUNK;
    /// Byte offset of `BamHostApi::iter_reset` (Slot 10).
    pub const ITER_RESET: usize = offsets::ITER_RESET;
    /// Byte offset of `BamHostApi::iter_entities` (Slot 11).
    pub const ITER_ENTITIES: usize = offsets::ITER_ENTITIES;
    /// Byte offset of `BamHostApi::iter_column_readonly` (Slot 12).
    pub const ITER_COLUMN_READONLY: usize = offsets::ITER_COLUMN_READONLY;
    /// Byte offset of `BamHostApi::iter_column_mutable` (Slot 13).
    pub const ITER_COLUMN_MUTABLE: usize = offsets::ITER_COLUMN_MUTABLE;
    /// Byte offset of `BamHostApi::iter_column_mutable_untracked` (Slot 14).
    pub const ITER_COLUMN_MUTABLE_UNTRACKED: usize = offsets::ITER_COLUMN_MUTABLE_UNTRACKED;
    /// Byte offset of `BamHostApi::iter_mark_changed_range` (Slot 15).
    pub const ITER_MARK_CHANGED_RANGE: usize = offsets::ITER_MARK_CHANGED_RANGE;
    /// Byte offset of `BamHostApi::iter_column_rows_readonly` (Slot 16).
    pub const ITER_COLUMN_ROWS_READONLY: usize = offsets::ITER_COLUMN_ROWS_READONLY;
    /// Byte offset of `BamHostApi::iter_column_rows_mutable` (Slot 17).
    pub const ITER_COLUMN_ROWS_MUTABLE: usize = offsets::ITER_COLUMN_ROWS_MUTABLE;
    /// Byte offset of `BamHostApi::res_ptr` (Slot 19).
    pub const RES_PTR: usize = offsets::RES_PTR;
    /// Byte offset of `BamHostApi::res_mut_ptr` (Slot 20).
    pub const RES_MUT_PTR: usize = offsets::RES_MUT_PTR;
    /// Byte offset of `BamHostApi::cmd_spawn_empty` (Slot 21).
    pub const CMD_SPAWN_EMPTY: usize = offsets::CMD_SPAWN_EMPTY;
    /// Byte offset of `BamHostApi::cmd_spawn` (Slot 22).
    pub const CMD_SPAWN: usize = offsets::CMD_SPAWN;
    /// Byte offset of `BamHostApi::cmd_despawn` (Slot 23).
    pub const CMD_DESPAWN: usize = offsets::CMD_DESPAWN;
    /// Byte offset of `BamHostApi::cmd_insert` (Slot 24).
    pub const CMD_INSERT: usize = offsets::CMD_INSERT;
    /// Byte offset of `BamHostApi::cmd_insert_default` (Slot 25).
    pub const CMD_INSERT_DEFAULT: usize = offsets::CMD_INSERT_DEFAULT;
    /// Byte offset of `BamHostApi::cmd_remove` (Slot 26).
    pub const CMD_REMOVE: usize = offsets::CMD_REMOVE;
    /// Byte offset of `BamHostApi::par_for_each_chunk` (Slot 27).
    pub const PAR_FOR_EACH_CHUNK: usize = offsets::PAR_FOR_EACH_CHUNK;
    /// Byte offset of `BamHostApi::sys_entity_get` (Slot 28).
    pub const SYS_ENTITY_GET: usize = offsets::SYS_ENTITY_GET;
    /// Byte offset of `BamHostApi::sys_entity_get_mut` (Slot 29).
    pub const SYS_ENTITY_GET_MUT: usize = offsets::SYS_ENTITY_GET_MUT;
    /// Byte offset of `BamHostApi::msg_send` (Slot 31).
    pub const MSG_SEND: usize = offsets::MSG_SEND;
    /// Byte offset of `BamHostApi::sys_res_ptr` (Slot 34).
    pub const SYS_RES_PTR: usize = offsets::SYS_RES_PTR;
    /// Byte offset of `BamHostApi::sys_res_mut_ptr` (Slot 35).
    pub const SYS_RES_MUT_PTR: usize = offsets::SYS_RES_MUT_PTR;
    /// Byte offset of `BamHostApi::register_observer` (Slot 36).
    pub const REGISTER_OBSERVER: usize = offsets::REGISTER_OBSERVER;
    /// Byte offset of `BamHostApi::cmd_trigger` (Slot 37).
    pub const CMD_TRIGGER: usize = offsets::CMD_TRIGGER;
    /// Byte offset of `BamHostApi::cmd_spawn_persistent` (Slot 38).
    pub const CMD_SPAWN_PERSISTENT: usize = offsets::CMD_SPAWN_PERSISTENT;
    /// Byte offset of `BamHostApi::cmd_spawn_batch` (Slot 39).
    pub const CMD_SPAWN_BATCH: usize = offsets::CMD_SPAWN_BATCH;
    /// Byte offset of `BamHostApi::cmd_despawn_all` (Slot 40).
    pub const CMD_DESPAWN_ALL: usize = offsets::CMD_DESPAWN_ALL;
    /// Byte offset of `BamHostApi::cmd_insert_if_new` (Slot 41).
    pub const CMD_INSERT_IF_NEW: usize = offsets::CMD_INSERT_IF_NEW;
    /// Byte offset of `BamHostApi::cmd_trigger_ex` (Slot 42).
    pub const CMD_TRIGGER_EX: usize = offsets::CMD_TRIGGER_EX;
    /// Byte offset of `BamHostApi::resolve_component_by_uuid` (Slot 52).
    pub const RESOLVE_COMPONENT_BY_UUID: usize = offsets::RESOLVE_COMPONENT_BY_UUID;
    /// Byte offset of `BamHostApi::component_layout_info` (Slot 53).
    pub const COMPONENT_LAYOUT_INFO: usize = offsets::COMPONENT_LAYOUT_INFO;
    /// Byte offset of `BamHostApi::register_relation` (Slot 54).
    pub const REGISTER_RELATION: usize = offsets::REGISTER_RELATION;
    /// Byte offset of `BamHostApi::intern_symbol` (Slot 55).
    pub const INTERN_SYMBOL: usize = offsets::INTERN_SYMBOL;
    /// Byte offset of `BamHostApi::bind_named_object` (Slot 56).
    pub const BIND_NAMED_OBJECT: usize = offsets::BIND_NAMED_OBJECT;
    /// Byte offset of `BamHostApi::iter_count` (Slot 57).
    pub const ITER_COUNT: usize = offsets::ITER_COUNT;
    /// Byte offset of `BamHostApi::iter_up_cascade` (Slot 58).
    pub const ITER_UP_CASCADE: usize = offsets::ITER_UP_CASCADE;
    /// Byte offset of `BamHostApi::par_for_each_chunk_readonly` (Slot 59).
    pub const PAR_FOR_EACH_CHUNK_READONLY: usize = offsets::PAR_FOR_EACH_CHUNK_READONLY;
    /// Byte offset of `BamHostApi::register_system_handle` (Slot 60).
    pub const REGISTER_SYSTEM_HANDLE: usize = offsets::REGISTER_SYSTEM_HANDLE;
    /// Byte offset of `BamHostApi::configure_schedule_set` (Slot 61).
    pub const CONFIGURE_SCHEDULE_SET: usize = offsets::CONFIGURE_SCHEDULE_SET;
    /// Byte offset of `BamHostApi::mount_system_in_schedule` (Slot 62).
    pub const MOUNT_SYSTEM_IN_SCHEDULE: usize = offsets::MOUNT_SYSTEM_IN_SCHEDULE;
    /// Byte offset of `BamHostApi::cmd_checkpoint` (Slot 63).
    pub const CMD_CHECKPOINT: usize = offsets::CMD_CHECKPOINT;
    /// Byte offset of `BamHostApi::cmd_rollback` (Slot 64).
    pub const CMD_ROLLBACK: usize = offsets::CMD_ROLLBACK;
    /// Byte offset of `BamHostApi::cmd_insert_relation` (Slot 65).
    pub const CMD_INSERT_RELATION: usize = offsets::CMD_INSERT_RELATION;
    /// Byte offset of `BamHostApi::cmd_remove_relation` (Slot 66).
    pub const CMD_REMOVE_RELATION: usize = offsets::CMD_REMOVE_RELATION;
    /// Byte offset of `BamHostApi::migrate_component_column` (Slot 67).
    pub const MIGRATE_COMPONENT_COLUMN: usize = offsets::MIGRATE_COMPONENT_COLUMN;
}

/// Programmatic `core::mem::{size_of, offset_of}` descriptor layouts matching `bamabi_sys`.
pub mod structs {
    use super::*;

    /// Total byte size of `BamHostApi` vtable struct.
    pub const HOST_API_SIZE: usize = size_of::<BamHostApi>();

    /// Total byte size of `BamManifest`.
    pub const MANIFEST_SIZE: usize = size_of::<BamManifest>();
    /// Field offset of `BamManifest::struct_size`.
    pub const MANIFEST_STRUCT_SIZE: usize = offset_of!(BamManifest, struct_size);
    /// Field offset of `BamManifest::abi_version`.
    pub const MANIFEST_ABI_VERSION: usize = offset_of!(BamManifest, abi_version);
    /// Field offset of `BamManifest::name`.
    pub const MANIFEST_NAME: usize = offset_of!(BamManifest, name);
    /// Field offset of `BamManifest::version`.
    pub const MANIFEST_VERSION: usize = offset_of!(BamManifest, version);

    /// Total byte size of `ComponentDesc`.
    pub const COMPONENT_DESC_SIZE: usize = size_of::<ComponentDesc>();
    /// Field offset of `ComponentDesc::struct_size`.
    pub const COMP_STRUCT_SIZE: usize = offset_of!(ComponentDesc, struct_size);
    /// Field offset of `ComponentDesc::flags`.
    pub const COMP_FLAGS: usize = offset_of!(ComponentDesc, flags);
    /// Field offset of `ComponentDesc::name`.
    pub const COMP_NAME: usize = offset_of!(ComponentDesc, name);
    /// Field offset of `ComponentDesc::uuid`.
    pub const COMP_UUID: usize = offset_of!(ComponentDesc, uuid);
    /// Field offset of `ComponentDesc::size`.
    pub const COMP_SIZE: usize = offset_of!(ComponentDesc, size);
    /// Field offset of `ComponentDesc::align`.
    pub const COMP_ALIGN: usize = offset_of!(ComponentDesc, align);
    /// Field offset of `ComponentDesc::required_components`.
    pub const COMP_REQUIRED_COMPONENTS: usize = offset_of!(ComponentDesc, required_components);
    /// Field offset of `ComponentDesc::required_component_count`.
    pub const COMP_REQUIRED_COMPONENT_COUNT: usize =
        offset_of!(ComponentDesc, required_component_count);
    /// Field offset of `ComponentDesc::schema_fingerprint`.
    pub const COMP_SCHEMA_FINGERPRINT: usize = offset_of!(ComponentDesc, schema_fingerprint);
    /// Field offset of `ComponentDesc::fields`.
    pub const COMP_FIELDS: usize = offset_of!(ComponentDesc, fields);
    /// Field offset of `ComponentDesc::field_count`.
    pub const COMP_FIELD_COUNT: usize = offset_of!(ComponentDesc, field_count);

    /// Total byte size of `BamFieldDesc`.
    pub const FIELD_DESC_SIZE: usize = size_of::<BamFieldDesc>();
    /// Field offset of `BamFieldDesc::struct_size`.
    pub const FIELD_STRUCT_SIZE: usize = offset_of!(BamFieldDesc, struct_size);
    /// Field offset of `BamFieldDesc::kind`.
    pub const FIELD_KIND: usize = offset_of!(BamFieldDesc, kind);
    /// Field offset of `BamFieldDesc::name`.
    pub const FIELD_NAME: usize = offset_of!(BamFieldDesc, name);
    /// Field offset of `BamFieldDesc::type_tag`.
    pub const FIELD_TYPE_TAG: usize = offset_of!(BamFieldDesc, type_tag);
    /// Field offset of `BamFieldDesc::offset`.
    pub const FIELD_OFFSET: usize = offset_of!(BamFieldDesc, offset);
    /// Field offset of `BamFieldDesc::size`.
    pub const FIELD_SIZE: usize = offset_of!(BamFieldDesc, size);
    /// Field offset of `BamFieldDesc::align`.
    pub const FIELD_ALIGN: usize = offset_of!(BamFieldDesc, align);

    /// Total byte size of `StrView`.
    pub const STRVIEW_SIZE: usize = size_of::<StrView>();
    /// Field offset of `StrView::ptr`.
    pub const STRVIEW_PTR: usize = offset_of!(StrView, ptr);
    /// Field offset of `StrView::len`.
    pub const STRVIEW_LEN: usize = offset_of!(StrView, len);

    /// Total byte size of `FfiSlice<u8>`.
    pub const FFI_SLICE_SIZE: usize = size_of::<FfiSlice<u8>>();
    /// Field offset of `FfiSlice::ptr`.
    pub const FFI_SLICE_PTR: usize = offset_of!(FfiSlice<u8>, ptr);
    /// Field offset of `FfiSlice::len`.
    pub const FFI_SLICE_LEN: usize = offset_of!(FfiSlice<u8>, len);

    /// Total byte size of `BamTermDesc`.
    pub const TERM_DESC_SIZE: usize = size_of::<BamTermDesc>();
    /// Field offset of `BamTermDesc::component`.
    pub const TERM_COMPONENT: usize = offset_of!(BamTermDesc, component);
    /// Field offset of `BamTermDesc::mode`.
    pub const TERM_MODE: usize = offset_of!(BamTermDesc, mode);
    /// Field offset of `BamTermDesc::flags`.
    pub const TERM_FLAGS: usize = offset_of!(BamTermDesc, flags);
    /// Field offset of `BamTermDesc::or_group`.
    pub const TERM_OR_GROUP: usize = offset_of!(BamTermDesc, or_group);
    /// Field offset of `BamTermDesc::reserved0`.
    pub const TERM_RESERVED0: usize = offset_of!(BamTermDesc, reserved0);

    /// Total byte size of `BamQueryDesc`.
    pub const QUERY_DESC_SIZE: usize = size_of::<BamQueryDesc>();
    /// Field offset of `BamQueryDesc::struct_size`.
    pub const QUERY_STRUCT_SIZE: usize = offset_of!(BamQueryDesc, struct_size);
    /// Field offset of `BamQueryDesc::flags`.
    pub const QUERY_FLAGS: usize = offset_of!(BamQueryDesc, flags);
    /// Field offset of `BamQueryDesc::terms`.
    pub const QUERY_TERMS: usize = offset_of!(BamQueryDesc, terms);
    /// Field offset of `BamQueryDesc::term_count`.
    pub const QUERY_TERM_COUNT: usize = offset_of!(BamQueryDesc, term_count);

    /// Total byte size of `BamSystemDesc`.
    pub const SYSTEM_DESC_SIZE: usize = size_of::<BamSystemDesc>();
    /// Field offset of `BamSystemDesc::struct_size`.
    pub const SYS_STRUCT_SIZE: usize = offset_of!(BamSystemDesc, struct_size);
    /// Field offset of `BamSystemDesc::flags`.
    pub const SYS_FLAGS: usize = offset_of!(BamSystemDesc, flags);
    /// Field offset of `BamSystemDesc::name`.
    pub const SYS_NAME: usize = offset_of!(BamSystemDesc, name);
    /// Field offset of `BamSystemDesc::queries`.
    pub const SYS_QUERIES: usize = offset_of!(BamSystemDesc, queries);
    /// Field offset of `BamSystemDesc::query_count`.
    pub const SYS_QUERY_COUNT: usize = offset_of!(BamSystemDesc, query_count);
    /// Field offset of `BamSystemDesc::callback`.
    pub const SYS_CALLBACK: usize = offset_of!(BamSystemDesc, callback);
    /// Field offset of `BamSystemDesc::user_data`.
    pub const SYS_USER_DATA: usize = offset_of!(BamSystemDesc, user_data);
    /// Field offset of `BamSystemDesc::schedule`.
    pub const SYS_SCHEDULE: usize = offset_of!(BamSystemDesc, schedule);
    /// Field offset of `BamSystemDesc::reserved0`.
    pub const SYS_RESERVED0: usize = offset_of!(BamSystemDesc, reserved0);
    /// Field offset of `BamSystemDesc::after`.
    pub const SYS_AFTER: usize = offset_of!(BamSystemDesc, after);
    /// Field offset of `BamSystemDesc::after_count`.
    pub const SYS_AFTER_COUNT: usize = offset_of!(BamSystemDesc, after_count);
    /// Field offset of `BamSystemDesc::before`.
    pub const SYS_BEFORE: usize = offset_of!(BamSystemDesc, before);
    /// Field offset of `BamSystemDesc::before_count`.
    pub const SYS_BEFORE_COUNT: usize = offset_of!(BamSystemDesc, before_count);
    /// Field offset of `BamSystemDesc::run_if`.
    pub const SYS_RUN_IF: usize = offset_of!(BamSystemDesc, run_if);
    /// Field offset of `BamSystemDesc::run_if_user_data`.
    pub const SYS_RUN_IF_USER_DATA: usize = offset_of!(BamSystemDesc, run_if_user_data);
    /// Field offset of `BamSystemDesc::in_sets`.
    pub const SYS_IN_SETS: usize = offset_of!(BamSystemDesc, in_sets);
    /// Field offset of `BamSystemDesc::in_set_count`.
    pub const SYS_IN_SET_COUNT: usize = offset_of!(BamSystemDesc, in_set_count);
    /// Field offset of `BamSystemDesc::after_weak`.
    pub const SYS_AFTER_WEAK: usize = offset_of!(BamSystemDesc, after_weak);
    /// Field offset of `BamSystemDesc::after_weak_count`.
    pub const SYS_AFTER_WEAK_COUNT: usize = offset_of!(BamSystemDesc, after_weak_count);
    /// Field offset of `BamSystemDesc::before_weak`.
    pub const SYS_BEFORE_WEAK: usize = offset_of!(BamSystemDesc, before_weak);
    /// Field offset of `BamSystemDesc::before_weak_count`.
    pub const SYS_BEFORE_WEAK_COUNT: usize = offset_of!(BamSystemDesc, before_weak_count);

    /// Total byte size of `BamObserverDesc`.
    pub const OBSERVER_DESC_SIZE: usize = size_of::<BamObserverDesc>();
    /// Field offset of `BamObserverDesc::struct_size`.
    pub const OBS_STRUCT_SIZE: usize = offset_of!(BamObserverDesc, struct_size);
    /// Field offset of `BamObserverDesc::flags`.
    pub const OBS_FLAGS: usize = offset_of!(BamObserverDesc, flags);
    /// Field offset of `BamObserverDesc::name`.
    pub const OBS_NAME: usize = offset_of!(BamObserverDesc, name);
    /// Field offset of `BamObserverDesc::event`.
    pub const OBS_EVENT: usize = offset_of!(BamObserverDesc, event);
    /// Field offset of `BamObserverDesc::entity_lo`.
    pub const OBS_ENTITY_LO: usize = offset_of!(BamObserverDesc, entity_lo);
    /// Field offset of `BamObserverDesc::entity_hi`.
    pub const OBS_ENTITY_HI: usize = offset_of!(BamObserverDesc, entity_hi);
    /// Field offset of `BamObserverDesc::reserved0`.
    pub const OBS_RESERVED0: usize = offset_of!(BamObserverDesc, reserved0);
    /// Field offset of `BamObserverDesc::callback`.
    pub const OBS_CALLBACK: usize = offset_of!(BamObserverDesc, callback);
    /// Field offset of `BamObserverDesc::user_data`.
    pub const OBS_USER_DATA: usize = offset_of!(BamObserverDesc, user_data);
    /// Field offset of `BamObserverDesc::event_kind`.
    pub const OBS_EVENT_KIND: usize = offset_of!(BamObserverDesc, event_kind);
    /// Field offset of `BamObserverDesc::reserved1`.
    pub const OBS_RESERVED1: usize = offset_of!(BamObserverDesc, reserved1);
    /// Field offset of `BamObserverDesc::watched_components`.
    pub const OBS_WATCHED_COMPONENTS: usize = offset_of!(BamObserverDesc, watched_components);
    /// Field offset of `BamObserverDesc::watched_component_count`.
    pub const OBS_WATCHED_COMPONENT_COUNT: usize =
        offset_of!(BamObserverDesc, watched_component_count);
    /// Field offset of `BamObserverDesc::mut_callback`.
    pub const OBS_MUT_CALLBACK: usize = offset_of!(BamObserverDesc, mut_callback);
    /// Field offset of `BamObserverDesc::propagate_relationship`.
    pub const OBS_PROPAGATE_RELATIONSHIP: usize =
        offset_of!(BamObserverDesc, propagate_relationship);
    /// Field offset of `BamObserverDesc::reserved2`.
    pub const OBS_RESERVED2: usize = offset_of!(BamObserverDesc, reserved2);

    /// Total byte size of `BamTriggerDesc`.
    pub const TRIGGER_DESC_SIZE: usize = size_of::<BamTriggerDesc>();
    /// Field offset of `BamTriggerDesc::struct_size`.
    pub const TRG_STRUCT_SIZE: usize = offset_of!(BamTriggerDesc, struct_size);
    /// Field offset of `BamTriggerDesc::flags`.
    pub const TRG_FLAGS: usize = offset_of!(BamTriggerDesc, flags);
    /// Field offset of `BamTriggerDesc::event`.
    pub const TRG_EVENT: usize = offset_of!(BamTriggerDesc, event);
    /// Field offset of `BamTriggerDesc::event_kind`.
    pub const TRG_EVENT_KIND: usize = offset_of!(BamTriggerDesc, event_kind);
    /// Field offset of `BamTriggerDesc::entity_lo`.
    pub const TRG_ENTITY_LO: usize = offset_of!(BamTriggerDesc, entity_lo);
    /// Field offset of `BamTriggerDesc::entity_hi`.
    pub const TRG_ENTITY_HI: usize = offset_of!(BamTriggerDesc, entity_hi);
    /// Field offset of `BamTriggerDesc::data_ptr`.
    pub const TRG_DATA_PTR: usize = offset_of!(BamTriggerDesc, data_ptr);
    /// Field offset of `BamTriggerDesc::data_len`.
    pub const TRG_DATA_LEN: usize = offset_of!(BamTriggerDesc, data_len);
    /// Field offset of `BamTriggerDesc::watched_components`.
    pub const TRG_WATCHED_COMPONENTS: usize = offset_of!(BamTriggerDesc, watched_components);
    /// Field offset of `BamTriggerDesc::watched_component_count`.
    pub const TRG_WATCHED_COMPONENT_COUNT: usize =
        offset_of!(BamTriggerDesc, watched_component_count);
    /// Field offset of `BamTriggerDesc::propagate_relationship`.
    pub const TRG_PROPAGATE_RELATIONSHIP: usize =
        offset_of!(BamTriggerDesc, propagate_relationship);
    /// Field offset of `BamTriggerDesc::reserved0`.
    pub const TRG_RESERVED0: usize = offset_of!(BamTriggerDesc, reserved0);

    /// Total byte size of `BamRelationDesc`.
    pub const RELATION_DESC_SIZE: usize = size_of::<BamRelationDesc>();
    /// Field offset of `BamRelationDesc::struct_size`.
    pub const REL_STRUCT_SIZE: usize = offset_of!(BamRelationDesc, struct_size);
    /// Field offset of `BamRelationDesc::flags`.
    pub const REL_FLAGS: usize = offset_of!(BamRelationDesc, flags);
    /// Field offset of `BamRelationDesc::name`.
    pub const REL_NAME: usize = offset_of!(BamRelationDesc, name);
    /// Field offset of `BamRelationDesc::uuid`.
    pub const REL_UUID: usize = offset_of!(BamRelationDesc, uuid);
    /// Field offset of `BamRelationDesc::data_size`.
    pub const REL_DATA_SIZE: usize = offset_of!(BamRelationDesc, data_size);
    /// Field offset of `BamRelationDesc::data_align`.
    pub const REL_DATA_ALIGN: usize = offset_of!(BamRelationDesc, data_align);
    /// Field offset of `BamRelationDesc::max_degree`.
    pub const REL_MAX_DEGREE: usize = offset_of!(BamRelationDesc, max_degree);
    /// Field offset of `BamRelationDesc::reserved0`.
    pub const REL_RESERVED0: usize = offset_of!(BamRelationDesc, reserved0);

    /// Total byte size of `BamScheduleSetDesc`.
    pub const SCHEDULE_SET_DESC_SIZE: usize = size_of::<BamScheduleSetDesc>();
    /// Field offset of `BamScheduleSetDesc::struct_size`.
    pub const SSET_STRUCT_SIZE: usize = offset_of!(BamScheduleSetDesc, struct_size);
    /// Field offset of `BamScheduleSetDesc::flags`.
    pub const SSET_FLAGS: usize = offset_of!(BamScheduleSetDesc, flags);
    /// Field offset of `BamScheduleSetDesc::schedule`.
    pub const SSET_SCHEDULE: usize = offset_of!(BamScheduleSetDesc, schedule);
    /// Field offset of `BamScheduleSetDesc::before_count`.
    pub const SSET_BEFORE_COUNT: usize = offset_of!(BamScheduleSetDesc, before_count);
    /// Field offset of `BamScheduleSetDesc::after_count`.
    pub const SSET_AFTER_COUNT: usize = offset_of!(BamScheduleSetDesc, after_count);
    /// Field offset of `BamScheduleSetDesc::reserved0`.
    pub const SSET_RESERVED0: usize = offset_of!(BamScheduleSetDesc, reserved0);
    /// Field offset of `BamScheduleSetDesc::name`.
    pub const SSET_NAME: usize = offset_of!(BamScheduleSetDesc, name);
    /// Field offset of `BamScheduleSetDesc::before_sets`.
    pub const SSET_BEFORE_SETS: usize = offset_of!(BamScheduleSetDesc, before_sets);
    /// Field offset of `BamScheduleSetDesc::after_sets`.
    pub const SSET_AFTER_SETS: usize = offset_of!(BamScheduleSetDesc, after_sets);

    /// Total byte size of `BamLayoutInfo`.
    pub const LAYOUT_INFO_SIZE: usize = size_of::<BamLayoutInfo>();
    /// Field offset of `BamLayoutInfo::struct_size`.
    pub const LINFO_STRUCT_SIZE: usize = offset_of!(BamLayoutInfo, struct_size);
    /// Field offset of `BamLayoutInfo::flags`.
    pub const LINFO_FLAGS: usize = offset_of!(BamLayoutInfo, flags);
    /// Field offset of `BamLayoutInfo::uuid`.
    pub const LINFO_UUID: usize = offset_of!(BamLayoutInfo, uuid);
    /// Field offset of `BamLayoutInfo::schema_fingerprint`.
    pub const LINFO_SCHEMA_FINGERPRINT: usize = offset_of!(BamLayoutInfo, schema_fingerprint);
    /// Field offset of `BamLayoutInfo::size`.
    pub const LINFO_SIZE: usize = offset_of!(BamLayoutInfo, size);
    /// Field offset of `BamLayoutInfo::align`.
    pub const LINFO_ALIGN: usize = offset_of!(BamLayoutInfo, align);
    /// Field offset of `BamLayoutInfo::fields`.
    pub const LINFO_FIELDS: usize = offset_of!(BamLayoutInfo, fields);
    /// Field offset of `BamLayoutInfo::field_count`.
    pub const LINFO_FIELD_COUNT: usize = offset_of!(BamLayoutInfo, field_count);

    /// Byte size of an opaque `BamComponent` handle (`4`).
    pub const BAM_COMPONENT_SIZE: usize = size_of::<BamComponent>();
    /// Byte size of an opaque `BamSystem` handle (`4`).
    pub const BAM_SYSTEM_SIZE: usize = size_of::<BamSystem>();
    /// Byte size of an opaque `BamSystemSet` handle (`4`).
    pub const BAM_SYSTEM_SET_SIZE: usize = size_of::<BamSystemSet>();
    /// Byte size of an opaque `BamSymbol` handle (`4`).
    pub const BAM_SYMBOL_SIZE: usize = size_of::<BamSymbol>();
    /// Byte size of `FfiEntity` handle (`8`).
    pub const FFI_ENTITY_SIZE: usize = size_of::<FfiEntity>();
}

/// Returns every `BamHostApi` slot offset exposed via [`api_slots`] for bounds verification.
#[must_use]
pub const fn all_exposed_api_slots() -> &'static [usize] {
    &[
        api_slots::LOAD_HOST_CTX,
        api_slots::REGISTER_COMPONENT,
        api_slots::RESOLVE_COMPONENT,
        api_slots::REGISTER_SYSTEM,
        api_slots::SYS_HOST_CTX,
        api_slots::SYS_QUERY,
        api_slots::SYS_COMMANDS,
        api_slots::ITER_NEXT_CHUNK,
        api_slots::ITER_RESET,
        api_slots::ITER_ENTITIES,
        api_slots::ITER_COLUMN_READONLY,
        api_slots::ITER_COLUMN_MUTABLE,
        api_slots::ITER_COLUMN_MUTABLE_UNTRACKED,
        api_slots::ITER_MARK_CHANGED_RANGE,
        api_slots::ITER_COLUMN_ROWS_READONLY,
        api_slots::ITER_COLUMN_ROWS_MUTABLE,
        api_slots::RES_PTR,
        api_slots::RES_MUT_PTR,
        api_slots::CMD_SPAWN_EMPTY,
        api_slots::CMD_SPAWN,
        api_slots::CMD_DESPAWN,
        api_slots::CMD_INSERT,
        api_slots::CMD_INSERT_DEFAULT,
        api_slots::CMD_REMOVE,
        api_slots::PAR_FOR_EACH_CHUNK,
        api_slots::SYS_ENTITY_GET,
        api_slots::SYS_ENTITY_GET_MUT,
        api_slots::MSG_SEND,
        api_slots::SYS_RES_PTR,
        api_slots::SYS_RES_MUT_PTR,
        api_slots::REGISTER_OBSERVER,
        api_slots::CMD_TRIGGER,
        api_slots::CMD_SPAWN_PERSISTENT,
        api_slots::CMD_SPAWN_BATCH,
        api_slots::CMD_DESPAWN_ALL,
        api_slots::CMD_INSERT_IF_NEW,
        api_slots::CMD_TRIGGER_EX,
        api_slots::RESOLVE_COMPONENT_BY_UUID,
        api_slots::COMPONENT_LAYOUT_INFO,
        api_slots::REGISTER_RELATION,
        api_slots::INTERN_SYMBOL,
        api_slots::BIND_NAMED_OBJECT,
        api_slots::ITER_COUNT,
        api_slots::ITER_UP_CASCADE,
        api_slots::PAR_FOR_EACH_CHUNK_READONLY,
        api_slots::REGISTER_SYSTEM_HANDLE,
        api_slots::CONFIGURE_SCHEDULE_SET,
        api_slots::MOUNT_SYSTEM_IN_SCHEDULE,
        api_slots::CMD_CHECKPOINT,
        api_slots::CMD_ROLLBACK,
        api_slots::CMD_INSERT_RELATION,
        api_slots::CMD_REMOVE_RELATION,
        api_slots::MIGRATE_COMPONENT_COLUMN,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies every exposed `BamHostApi` vtable offset is pointer-aligned, distinct, and in bounds.
    #[test]
    fn host_api_slot_offsets_are_aligned_and_in_bounds() {
        let ptr_sz = size_of::<usize>();
        let slots = all_exposed_api_slots();
        assert!(slots.len() <= HOST_API_SLOTS);
        for (i, &off) in slots.iter().enumerate() {
            assert_eq!(
                off % ptr_sz,
                0,
                "slot offset {off} is not pointer-aligned ({ptr_sz})"
            );
            assert!(
                off + ptr_sz <= structs::HOST_API_SIZE,
                "slot offset {off} exceeds BamHostApi size {}",
                structs::HOST_API_SIZE
            );
            for (j, &other) in slots.iter().enumerate() {
                if i != j {
                    assert_ne!(off, other, "duplicate slot offset {off}");
                }
            }
        }
    }

    /// Verifies programmatic descriptor sizes and nested field bounds match `bamabi_sys`.
    #[test]
    fn descriptor_sizes_and_fields_match_bamabi_sys() {
        assert_eq!(structs::HOST_API_SIZE, size_of::<BamHostApi>());
        assert_eq!(structs::MANIFEST_SIZE, size_of::<BamManifest>());
        assert_eq!(structs::COMPONENT_DESC_SIZE, size_of::<ComponentDesc>());
        assert_eq!(structs::FIELD_DESC_SIZE, size_of::<BamFieldDesc>());
        assert_eq!(structs::TERM_DESC_SIZE, size_of::<BamTermDesc>());
        assert_eq!(structs::QUERY_DESC_SIZE, size_of::<BamQueryDesc>());
        assert_eq!(structs::SYSTEM_DESC_SIZE, size_of::<BamSystemDesc>());
        assert_eq!(structs::OBSERVER_DESC_SIZE, size_of::<BamObserverDesc>());
        assert_eq!(structs::TRIGGER_DESC_SIZE, size_of::<BamTriggerDesc>());
        assert_eq!(structs::RELATION_DESC_SIZE, size_of::<BamRelationDesc>());
        assert_eq!(
            structs::SCHEDULE_SET_DESC_SIZE,
            size_of::<BamScheduleSetDesc>()
        );
        assert_eq!(structs::LAYOUT_INFO_SIZE, size_of::<BamLayoutInfo>());
        assert_eq!(structs::STRVIEW_SIZE, size_of::<StrView>());
        assert_eq!(structs::FFI_SLICE_SIZE, size_of::<FfiSlice<u8>>());
        assert_eq!(structs::FFI_ENTITY_SIZE, size_of::<FfiEntity>());
        assert_eq!(structs::BAM_SYSTEM_SIZE, size_of::<BamSystem>());
        assert_eq!(structs::BAM_SYSTEM_SET_SIZE, size_of::<BamSystemSet>());

        assert!(
            structs::COMP_REQUIRED_COMPONENT_COUNT + size_of::<usize>()
                <= structs::COMPONENT_DESC_SIZE
        );
        assert!(structs::TERM_RESERVED0 + size_of::<u8>() <= structs::TERM_DESC_SIZE);
        assert!(structs::QUERY_TERM_COUNT + size_of::<usize>() <= structs::QUERY_DESC_SIZE);
        assert!(structs::SYS_BEFORE_WEAK_COUNT + size_of::<usize>() <= structs::SYSTEM_DESC_SIZE);
        assert!(structs::OBS_RESERVED2 + size_of::<u32>() <= structs::OBSERVER_DESC_SIZE);
        assert!(structs::TRG_RESERVED0 + size_of::<u32>() <= structs::TRIGGER_DESC_SIZE);
        assert!(structs::REL_RESERVED0 + size_of::<u32>() <= structs::RELATION_DESC_SIZE);
        assert!(
            structs::SSET_AFTER_SETS + size_of::<*const BamSystemSet>()
                <= structs::SCHEDULE_SET_DESC_SIZE
        );
        assert!(structs::LINFO_FIELD_COUNT + size_of::<usize>() <= structs::LAYOUT_INFO_SIZE);
    }
}
