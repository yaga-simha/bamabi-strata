use bamabi_native_rt::{
    BitSet, ChunkSliceQueryExt, Fixed32, Fixed64, GraceWindow, InlineStr, InputBuffer,
    SelectiveMutSlice, SharedBridgeAppExt, SmallVecPod, StrataBridgeCatalog,
    StrataComponentOptions, TimelineCursor,
};
use bamabi_sys::{
    BamFieldDesc, BamFieldKind, ComponentUuid, ModComponent, StrView, SymbolEntry, VTableHeader,
    fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use bevy_app::{App, Update};
use bevy_ecs::prelude::*;

#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Pos3D {
    x: f32,
    y: f32,
    z: f32,
}

#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Vel3D {
    dx: f32,
    dy: f32,
    dz: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
#[component(summary_tick)]
struct DroneHeat {
    heat: f32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DroneHeatVTable {
    header: VTableHeader,
}

static DRONE_HEAT_FIELDS: &[BamFieldDesc] = &[BamFieldDesc::new(
    BamFieldKind::F32,
    StrView::from_str("heat"),
    StrView::from_str("f32"),
    core::mem::offset_of!(DroneHeat, heat),
    core::mem::size_of::<f32>(),
    core::mem::align_of::<f32>(),
)];

static DRONE_HEAT_VTABLE: DroneHeatVTable = DroneHeatVTable {
    header: VTableHeader::new::<DroneHeatVTable, DroneHeat>(<DroneHeat as ModComponent>::UUID),
};

static DRONE_HEAT_SYMS: &[SymbolEntry] = &[];

impl ModComponent for DroneHeat {
    const CANONICAL_NAME: &'static str = "native_rt_test::DroneHeat";
    const COMPONENT_CSTR: &'static core::ffi::CStr = c"native_rt_test::DroneHeat";
    const UUID: ComponentUuid = ComponentUuid::from_parts(
        Self::CANONICAL_NAME,
        core::mem::size_of::<Self>(),
        core::mem::align_of::<Self>(),
        ComponentUuid::hash_field_schema(0, "heat", "f32", core::mem::offset_of!(Self, heat)),
    );
    const IS_ABI_POD: bool = true;
    const IS_RAW_INSERTABLE: bool = false;
    const COMPONENT_FLAGS: u32 = bamabi_sys::BAM_COMPONENT_FLAG_SUMMARY_TICK;
    const SCHEMA_FINGERPRINT: u64 = {
        let mut h = fnv1a_64_init();
        h = fnv1a_64_update_bytes(h, Self::CANONICAL_NAME.as_bytes());
        h = fnv1a_64_update_u64(h, core::mem::size_of::<Self>() as u64);
        h = fnv1a_64_update_u64(h, core::mem::align_of::<Self>() as u64);
        h = fnv1a_64_update_u64(h, Self::COMPONENT_FLAGS as u64);
        h = fnv1a_64_update_u64(h, BamFieldKind::F32.0 as u64);
        h = fnv1a_64_update_bytes(h, b"heat");
        h = fnv1a_64_update_bytes(h, b"f32");
        h = fnv1a_64_update_u64(h, core::mem::offset_of!(Self, heat) as u64);
        h = fnv1a_64_update_u64(h, core::mem::size_of::<f32>() as u64);
        h = fnv1a_64_update_u64(h, core::mem::align_of::<f32>() as u64);
        h
    };
    const BAM_FIELDS: &'static [BamFieldDesc] = DRONE_HEAT_FIELDS;
    type VTable = DroneHeatVTable;

    fn vtable() -> &'static Self::VTable {
        &DRONE_HEAT_VTABLE
    }

    fn symbols() -> &'static [SymbolEntry] {
        DRONE_HEAT_SYMS
    }
}

#[test]
fn dense_chunk_slice_iter_and_par_iter_update_100k_entities() {
    let mut world = World::new();
    let batch: Vec<(Pos3D, Vel3D)> = (0..100_000)
        .map(|i| {
            (
                Pos3D {
                    x: i as f32,
                    y: 0.0,
                    z: 0.0,
                },
                Vel3D {
                    dx: 1.0,
                    dy: 2.0,
                    dz: 0.5,
                },
            )
        })
        .collect();
    world.spawn_batch(batch);

    fn integrate_par(mut q: Query<(&mut Pos3D, &Vel3D)>) {
        q.strata_contiguous_par_iter_mut()
            .expect("dense query")
            .for_each(|(mut pos_cm, vel_ref)| {
                let pos = pos_cm.bypass_change_detection();
                let vel = vel_ref;
                for (p, v) in pos.iter_mut().zip(vel.iter()) {
                    p.x += v.dx;
                    p.y += v.dy;
                    p.z += v.dz;
                }
            });
    }

    let mut schedule = bevy_ecs::schedule::Schedule::default();
    schedule.add_systems(integrate_par);
    schedule.run(&mut world);

    let mut check_q = world.query::<&Pos3D>();
    let count = check_q.iter(&world).count();
    assert_eq!(count, 100_000);
    assert!(check_q.iter(&world).all(|p| (p.y - 2.0).abs() < 1e-6));
}

#[derive(Resource, Default)]
struct MutateTarget(Option<usize>);

#[derive(Resource, Default)]
struct ChangedObserved(Vec<Entity>);

#[test]
fn selective_mut_slice_tracks_only_mutated_rows() {
    let mut app = App::new();
    app.insert_resource(MutateTarget(Some(5)));
    app.insert_resource(ChangedObserved::default());

    let mut spawned = Vec::new();
    for i in 0..32 {
        spawned.push(app.world_mut().spawn(DroneHeat { heat: i as f32 }).id());
    }

    fn selective_clamp(mut q: Query<&mut DroneHeat>, target: Res<MutateTarget>) {
        for cm in q.strata_contiguous_iter_mut().expect("dense") {
            let mut slice = SelectiveMutSlice::from_contiguous_mut(cm);
            if let Some(idx) = target.0 {
                slice.update_if(idx, |h| {
                    h.heat = 999.0;
                    true
                });
                if idx + 1 < slice.len() {
                    slice.update_if(idx + 1, |h| {
                        h.heat = 998.0;
                        true
                    });
                }
            }
            let _ = slice.flush_dirty_runs();
        }
    }

    fn record_changed(q: Query<Entity, Changed<DroneHeat>>, mut out: ResMut<ChangedObserved>) {
        out.0.clear();
        out.0.extend(q.iter());
    }

    app.add_systems(Update, (selective_clamp, record_changed).chain());

    // Frame 0: initial spawn sets Added/Changed on all 32 entities, then selective_clamp runs.
    app.update();
    // Frame 1: change MutateTarget to None -> 0 rows mutated -> 0 Changed entities!
    app.world_mut().resource_mut::<MutateTarget>().0 = None;
    app.update();
    assert!(
        app.world().resource::<ChangedObserved>().0.is_empty(),
        "untouched table should report 0 Changed entities"
    );

    // Frame 2: mutate only indices 5 and 6 -> exactly 2 Changed entities!
    app.world_mut().resource_mut::<MutateTarget>().0 = Some(5);
    app.update();
    let changed = &app.world().resource::<ChangedObserved>().0;
    assert_eq!(changed.len(), 2);
}

#[test]
fn shared_bridge_registers_uuid_across_profiles() {
    let mut app = App::new();
    let receipt = app
        .register_strata_component::<DroneHeat>(StrataComponentOptions::new().summary_tick())
        .expect("register component");

    assert_eq!(receipt.uuid, <DroneHeat as ModComponent>::UUID);
    let catalog = app.world().resource::<StrataBridgeCatalog>();
    let entry = catalog.get_by_uuid(&receipt.uuid).expect("catalog entry");
    assert_eq!(entry.canonical_name, "native_rt_test::DroneHeat");
    assert_eq!(
        entry.schema_fingerprint,
        <DroneHeat as ModComponent>::SCHEMA_FINGERPRINT
    );

    #[cfg(feature = "shared-bridge")]
    {
        let mod_reg = app.world().resource::<bamabi_host::ModRegistry>();
        let reg_comp = mod_reg
            .get_by_uuid(&receipt.uuid)
            .expect("ModRegistry resolves static ComponentUuid");
        assert_eq!(reg_comp.name.as_ref(), "native_rt_test::DroneHeat");
        assert_eq!(
            reg_comp.schema_fingerprint,
            <DroneHeat as ModComponent>::SCHEMA_FINGERPRINT
        );
    }
}

#[test]
fn gameplay_primitives_preserve_abi_pod_layouts_and_semantics() {
    let mut grace = GraceWindow::new();
    assert!(!grace.is_active());
    grace.arm(0.095);
    assert!(grace.is_active());
    grace.tick(0.050);
    assert!(grace.is_active());
    grace.tick(0.050);
    assert!(!grace.is_active());

    let mut buf = InputBuffer::<4>::new();
    buf.push(0, 0.120);
    buf.push(1, 0.080);
    assert!(buf.peek(0));
    assert!(buf.consume(0));
    assert!(!buf.consume(0));
    buf.tick(0.090);
    assert!(!buf.peek(1));

    let mut tl = TimelineCursor::start();
    tl.active_mask = 0b0101;
    assert!(tl.is_active());
    assert!(tl.in_window(0b0100));
    assert!(!tl.in_window(0b0010));
    tl.stop();
    assert!(!tl.is_active());

    let mut bits = BitSet::<2>::new();
    bits.set(42);
    assert!(bits.get(42));
    assert!(!bits.get(41));
    assert_eq!(bits.count_ones(), 1);
    bits.clear(42);
    assert_eq!(bits.count_ones(), 0);

    let s = InlineStr::<32>::from_str_trunc("DRONE-001");
    assert_eq!(s.as_str(), "DRONE-001");

    let mut sv = SmallVecPod::<f32, 4>::default();
    assert!(sv.push(1.5));
    assert!(sv.push(2.5));
    assert_eq!(sv.as_slice(), &[1.5, 2.5]);

    let a = Fixed32::from_f32(2.5);
    let b = Fixed32::from_int(3);
    assert!(((a * b).to_f32() - 7.5).abs() < 1e-3);

    let fa = Fixed64::from_f64(1.25);
    let fb = Fixed64::from_int(4);
    assert!(((fa * fb).to_f64() - 5.0).abs() < 1e-6);
}
