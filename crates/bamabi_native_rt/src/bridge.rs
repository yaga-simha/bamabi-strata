//! Unified static/dynamic ECS registration bridge (`SharedBridgeAppExt`) for Tier 3 native
//! plugins and `static-console` (`dlopen`-free) builds.

use crate::net::StrataNetPacket;
use bamabi_sys::{AbiPod, ComponentUuid, ModComponent};
use bevy_app::App;
use bevy_ecs::component::Component;
use bevy_ecs::event::{EntityEvent, Event};
use bevy_ecs::message::Message;
use bevy_ecs::prelude::Resource;
use std::collections::BTreeMap;
use thiserror::Error;

#[cfg(feature = "shared-bridge")]
use bamabi_host::{ComponentOptions, ModAppExt};

/// Opaque registration receipt returned by [`SharedBridgeAppExt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StrataBridgeHandle {
    /// Deterministic 128-bit component/type UUID shared across static and dynamic modules.
    pub uuid: ComponentUuid,
    /// Optional 1-based ABI handle assigned when `shared-bridge` (`bamabi_host`) is active.
    pub abi_component_raw: Option<u32>,
}

/// Static registration record stored inside [`StrataBridgeCatalog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrataBridgeEntry {
    /// Canonical `"namespace::Type"` name.
    pub canonical_name: &'static str,
    /// Deterministic 128-bit `ComponentUuid`.
    pub uuid: ComponentUuid,
    /// 64-bit FNV-1a structural schema fingerprint.
    pub schema_fingerprint: u64,
    /// Optional 1-based `BamComponent` raw index when registered into `ModRegistry`.
    pub abi_component_raw: Option<u32>,
}

/// Resource tracking all Strata types registered on an [`App`] (active in both `shared-bridge` and
/// `static-console` profiles).
#[derive(Resource, Default, Debug, Clone)]
pub struct StrataBridgeCatalog {
    entries: BTreeMap<[u8; 16], StrataBridgeEntry>,
}

impl StrataBridgeCatalog {
    /// Looks up a registered Strata type by its deterministic [`ComponentUuid`].
    #[inline]
    pub fn get_by_uuid(&self, uuid: &ComponentUuid) -> Option<&StrataBridgeEntry> {
        self.entries.get(uuid.as_bytes())
    }

    /// Returns the number of registered Strata bridge types.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no Strata types have been registered yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn record(&mut self, entry: StrataBridgeEntry) {
        self.entries.insert(*entry.uuid.as_bytes(), entry);
    }
}

/// Error returned when registering a static Strata schema onto a Bevy [`App`].
#[derive(Debug, Error)]
pub enum StrataBridgeError {
    /// Registration collided with an incompatible schema already registered in `ModRegistry`.
    #[error("shared-bridge registration collision for `{canonical_name}`: {reason}")]
    Collision {
        /// Canonical name of the conflicting component or resource.
        canonical_name: &'static str,
        /// Underlying collision explanation.
        reason: String,
    },
}

/// Component registration options for [`SharedBridgeAppExt::register_strata_component`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StrataComponentOptions {
    /// Register component with Bevy `SparseSet` storage (`@sparse`).
    pub sparse_set: bool,
    /// Enable Bevy `0.20` per-table summary tick acceleration (`@summary_tick`).
    pub summary_tick: bool,
    /// Mark component as immutable after spawn.
    pub immutable: bool,
}

impl StrataComponentOptions {
    /// Creates default table-stored component options.
    #[inline]
    pub const fn new() -> Self {
        Self {
            sparse_set: false,
            summary_tick: false,
            immutable: false,
        }
    }

    /// Enables `@sparse` (`SparseSet`) storage.
    #[inline]
    pub const fn sparse_set(mut self) -> Self {
        self.sparse_set = true;
        self
    }

    /// Enables `@summary_tick` per-table summary tick optimization.
    #[inline]
    pub const fn summary_tick(mut self) -> Self {
        self.summary_tick = true;
        self
    }

    /// Marks the component as immutable.
    #[inline]
    pub const fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }
}

/// Extension trait on [`App`] unifying static Tier 3 Bevy registration with `bamabi_host`'s
/// `ModRegistry` (when `shared-bridge` is enabled) or zero-`dlopen` registration (under
/// `static-console`).
pub trait SharedBridgeAppExt {
    /// Registers a Strata `component` (`T: Component + ModComponent + Default`) with options.
    fn register_strata_component<T: Component + ModComponent + Default>(
        &mut self,
        options: StrataComponentOptions,
    ) -> Result<StrataBridgeHandle, StrataBridgeError>;

    /// Registers a Strata singleton `resource` (`R: Resource + ModComponent`).
    fn register_strata_resource<R: Resource + ModComponent>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError>;

    /// Registers a Strata buffered `stream` (`M: Message + ModComponent + Default`).
    fn register_strata_stream<M: Message + ModComponent + Default>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError>;

    /// Registers a Strata POD buffered `stream` (`M: Message + ModComponent + AbiPod + Default`)
    /// supporting ABI Slots 30–32 (`msg_read_batch`, `msg_send`, `msg_write_batch`).
    fn register_strata_pod_stream<M: Message + ModComponent + AbiPod + Default>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError>;

    /// Registers the canonical POD [`StrataNetPacket`] transport message stream.
    fn register_strata_net_transport(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError>;

    /// Registers a Strata triggerable global `event` (`E: Event + ModComponent + Copy`).
    fn register_strata_event<E>(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError>
    where
        E: Event<Trigger<'static>: Default> + ModComponent + Copy;

    /// Registers a Strata entity-targeted `event` (`E: EntityEvent + Event + ModComponent + Copy`).
    fn register_strata_entity_event<E>(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError>
    where
        E: EntityEvent + Event + ModComponent + Copy,
        for<'a> E::Trigger<'a>: Default;
}

fn ensure_catalog(app: &mut App) {
    if !app.world().contains_resource::<StrataBridgeCatalog>() {
        app.insert_resource(StrataBridgeCatalog::default());
    }
}

impl SharedBridgeAppExt for App {
    fn register_strata_component<T: Component + ModComponent + Default>(
        &mut self,
        options: StrataComponentOptions,
    ) -> Result<StrataBridgeHandle, StrataBridgeError> {
        ensure_catalog(self);
        self.world_mut().register_component::<T>();

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let mut host_opts = ComponentOptions::<T>::new().with_default();
            if options.sparse_set {
                host_opts = host_opts.sparse_set();
            }
            if options.summary_tick {
                host_opts = host_opts.with_summary_tick();
            }
            if options.immutable {
                host_opts = host_opts.immutable();
            }
            let handle = self.register_mod_component::<T>(host_opts).map_err(|err| {
                StrataBridgeError::Collision {
                    canonical_name: T::CANONICAL_NAME,
                    reason: err.to_string(),
                }
            })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = {
            let _ = options;
            None
        };

        record_and_return::<T>(self, abi_component_raw)
    }

    fn register_strata_resource<R: Resource + ModComponent>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError> {
        ensure_catalog(self);
        self.world_mut().register_component::<R>();

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let handle =
                self.register_mod_resource::<R>()
                    .map_err(|err| StrataBridgeError::Collision {
                        canonical_name: R::CANONICAL_NAME,
                        reason: err.to_string(),
                    })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = None;

        record_and_return::<R>(self, abi_component_raw)
    }

    fn register_strata_stream<M: Message + ModComponent + Default>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError> {
        ensure_catalog(self);

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let handle = self.register_mod_non_pod_message::<M>().map_err(|err| {
                StrataBridgeError::Collision {
                    canonical_name: M::CANONICAL_NAME,
                    reason: err.to_string(),
                }
            })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = {
            self.add_message::<M>();
            None
        };

        record_and_return::<M>(self, abi_component_raw)
    }

    fn register_strata_pod_stream<M: Message + ModComponent + AbiPod + Default>(
        &mut self,
    ) -> Result<StrataBridgeHandle, StrataBridgeError> {
        ensure_catalog(self);

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let handle =
                self.register_mod_message::<M>()
                    .map_err(|err| StrataBridgeError::Collision {
                        canonical_name: M::CANONICAL_NAME,
                        reason: err.to_string(),
                    })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = {
            self.add_message::<M>();
            None
        };

        record_and_return::<M>(self, abi_component_raw)
    }

    fn register_strata_net_transport(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError> {
        self.register_strata_pod_stream::<StrataNetPacket>()
    }

    fn register_strata_event<E>(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError>
    where
        E: Event<Trigger<'static>: Default> + ModComponent + Copy,
    {
        ensure_catalog(self);

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let handle =
                self.register_mod_event::<E>()
                    .map_err(|err| StrataBridgeError::Collision {
                        canonical_name: E::CANONICAL_NAME,
                        reason: err.to_string(),
                    })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = None;

        record_and_return::<E>(self, abi_component_raw)
    }

    fn register_strata_entity_event<E>(&mut self) -> Result<StrataBridgeHandle, StrataBridgeError>
    where
        E: EntityEvent + Event + ModComponent + Copy,
        for<'a> E::Trigger<'a>: Default,
    {
        ensure_catalog(self);

        #[cfg(feature = "shared-bridge")]
        let abi_component_raw = {
            let handle = self.register_mod_entity_event::<E>().map_err(|err| {
                StrataBridgeError::Collision {
                    canonical_name: E::CANONICAL_NAME,
                    reason: err.to_string(),
                }
            })?;
            Some(handle.to_raw())
        };

        #[cfg(not(feature = "shared-bridge"))]
        let abi_component_raw = None;

        record_and_return::<E>(self, abi_component_raw)
    }
}

fn record_and_return<T: ModComponent>(
    app: &mut App,
    abi_component_raw: Option<u32>,
) -> Result<StrataBridgeHandle, StrataBridgeError> {
    let entry = StrataBridgeEntry {
        canonical_name: T::CANONICAL_NAME,
        uuid: T::UUID,
        schema_fingerprint: T::SCHEMA_FINGERPRINT,
        abi_component_raw,
    };
    app.world_mut()
        .resource_mut::<StrataBridgeCatalog>()
        .record(entry);
    Ok(StrataBridgeHandle {
        uuid: T::UUID,
        abi_component_raw,
    })
}
