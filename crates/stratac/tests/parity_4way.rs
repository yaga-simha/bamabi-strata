#![forbid(unsafe_code)]

use bamabi_host::prelude::*;
use bamabi_host::{read_entity_pod_bytes, write_entity_pod_bytes};
use bamabi_native_rt::{SharedBridgeAppExt, StrataComponentOptions};
use bamabi_sys::{
    BAM_COMPONENT_FLAG_SUMMARY_TICK, BamFieldDesc, BamFieldKind, ComponentUuid, FfiBool,
    ModComponent, StrView, SymbolEntry, VTableHeader, fnv1a_64_init, fnv1a_64_update_bytes,
    fnv1a_64_update_u64,
};
use bevy_app::{App, FixedUpdate, Startup};
use bevy_ecs::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use strata_codegen::sanitize_ident;
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;
use stratac::cli::{BuildTarget, OnboardTarget, OutputFormat};
use stratac::commands::{
    cmd_build, cmd_onboard, cmd_test, sanitized_cargo, shared_temp_target_dir,
    write_local_patch_config,
};
use stratac::sim_runner::{WorldPodDigest, hash_world_pod_state};
use tempfile::TempDir;

/// Synchronizes the global `stats_alloc` window in `atomic_rollback_and_1000_tick_zero_leak_four_way_parity`
/// against concurrent `parity_4way` test threads sharing the process-wide `#[global_allocator]`.
static PARITY_ALLOC_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());

fn parity_alloc_read_guard() -> std::sync::RwLockReadGuard<'static, ()> {
    PARITY_ALLOC_GATE.read().unwrap_or_else(|e| e.into_inner())
}

const PARITY_SRC_V1: &str = r#"
module parity::sim @version(1.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, active: bool = false }

sys step_sim(p: &res SimParam) {
    uniform let dt = p.dt;
    uniform let damp = p.damping;
    for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 0.0;
            e.vel.vy = -e.vel.vy * 0.8;
            e.heat.temp += 1.25;
            e.heat.active = true;
        }
    }
}

schedule FixedUpdate { step_sim }
"#;

const PARITY_SRC_V2: &str = r#"
module parity::sim @version(2.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, active: bool = false }

sys step_sim(p: &res SimParam) {
    uniform let dt = p.dt;
    uniform let damp = p.damping;
    for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 0.0;
            e.vel.vy = -e.vel.vy * 0.75;
            e.heat.temp += 2.0;
            e.heat.active = true;
        }
    }
}

schedule FixedUpdate { step_sim }
"#;

const MIG_SRC_V1: &str = r#"
module mig::evo @version(1.0.0);

component UnitHealth {
    hp: f32 = 50.0,
}

sys spawn_units() {
    let e0 = spawn { UnitHealth { hp: 20.0 } };
    let e1 = spawn { UnitHealth { hp: 35.0 } };
    let e2 = spawn { UnitHealth { hp: 80.0 } };
    let _ = (e0, e1, e2);
}

sys step_health() {
    for e in query(h: &mut UnitHealth) {
        e.h.hp += 10.0;
    }
}

schedule Startup { spawn_units }
schedule FixedUpdate { step_health }
"#;

const MIG_SRC_V2: &str = r#"
module mig::evo @version(2.0.0);

component UnitHealthV1 {
    hp: f32 = 50.0,
}

component UnitHealth {
    hp: f32 = 50.0,
    max_hp: f32 = 100.0,
    armor: f32 = 0.0,
}

migrate UnitHealth from 1.0.0 to 2.0.0 (old: &UnitHealthV1) -> UnitHealth {
    UnitHealth {
        hp: old.hp,
        max_hp: old.hp * 2.0 + 25.0,
        armor: old.hp * 0.5,
    }
}

sys step_health() {
    for e in query(h: &mut UnitHealth) {
        e.h.hp += 1.0;
    }
}

schedule FixedUpdate { step_health }
"#;

#[repr(C)]
#[derive(Resource, Clone, Copy, Default, Debug, PartialEq)]
struct SimParam {
    dt: f32,
    damping: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Pos {
    x: f32,
    y: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Vel {
    vx: f32,
    vy: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
#[component(summary_tick)]
struct Heat {
    temp: f32,
    active: FfiBool,
    _strata_pad_0: [u8; 3],
}

macro_rules! impl_pod_mod_comp {
    (
        $ty:ident, $canon:literal, $cstr:literal, $flags:expr,
        [$(($fname:ident, $fstr:literal, $fkind:expr, $ftag:literal, $fty:ty)),* $(,)?]
    ) => {
        const _: () = {};
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub(crate) struct VTableTy {
            _header: VTableHeader,
        }
        impl ModComponent for $ty {
            const CANONICAL_NAME: &'static str = $canon;
            const COMPONENT_CSTR: &'static core::ffi::CStr = $cstr;
            const UUID: ComponentUuid = {
                let mut h = 0u64;
                $(
                    h = ComponentUuid::hash_field_schema(
                        h,
                        $fstr,
                        $ftag,
                        core::mem::offset_of!(Self, $fname),
                    );
                )*
                ComponentUuid::from_parts(
                    Self::CANONICAL_NAME,
                    core::mem::size_of::<Self>(),
                    core::mem::align_of::<Self>(),
                    h,
                )
            };
            const IS_ABI_POD: bool = true;
            const IS_RAW_INSERTABLE: bool = true;
            const COMPONENT_FLAGS: u32 = $flags;
            const SCHEMA_FINGERPRINT: u64 = {
                let mut fp = fnv1a_64_init();
                fp = fnv1a_64_update_bytes(fp, Self::CANONICAL_NAME.as_bytes());
                fp = fnv1a_64_update_u64(fp, core::mem::size_of::<Self>() as u64);
                fp = fnv1a_64_update_u64(fp, core::mem::align_of::<Self>() as u64);
                fp = fnv1a_64_update_u64(fp, Self::COMPONENT_FLAGS as u64);
                $(
                    fp = fnv1a_64_update_u64(fp, $fkind.0 as u64);
                    fp = fnv1a_64_update_bytes(fp, $fstr.as_bytes());
                    fp = fnv1a_64_update_bytes(fp, $ftag.as_bytes());
                    fp = fnv1a_64_update_u64(fp, core::mem::offset_of!(Self, $fname) as u64);
                    fp = fnv1a_64_update_u64(fp, core::mem::size_of::<$fty>() as u64);
                    fp = fnv1a_64_update_u64(fp, core::mem::align_of::<$fty>() as u64);
                )*
                fp
            };
            const BAM_FIELDS: &'static [BamFieldDesc] = &[
                $(
                    BamFieldDesc::new(
                        $fkind,
                        StrView::from_str($fstr),
                        StrView::from_str($ftag),
                        core::mem::offset_of!(Self, $fname),
                        core::mem::size_of::<$fty>(),
                        core::mem::align_of::<$fty>(),
                    ),
                )*
            ];
            type VTable = VTableTy;
            fn vtable() -> &'static Self::VTable {
                static VT: VTableTy = VTableTy {
                    _header: VTableHeader::new::<VTableTy, $ty>(<$ty as ModComponent>::UUID),
                };
                &VT
            }
            fn symbols() -> &'static [SymbolEntry] {
                &[]
            }
        }
    };
}

mod comp_impls {
    use super::*;
    mod p_param {
        use super::*;
        impl_pod_mod_comp!(
            SimParam,
            "parity::sim::SimParam",
            c"parity::sim::SimParam",
            0,
            [
                (dt, "dt", BamFieldKind::F32, "f32", f32),
                (damping, "damping", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_pos {
        use super::*;
        impl_pod_mod_comp!(
            Pos,
            "parity::sim::Pos",
            c"parity::sim::Pos",
            0,
            [
                (x, "x", BamFieldKind::F32, "f32", f32),
                (y, "y", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_vel {
        use super::*;
        impl_pod_mod_comp!(
            Vel,
            "parity::sim::Vel",
            c"parity::sim::Vel",
            0,
            [
                (vx, "vx", BamFieldKind::F32, "f32", f32),
                (vy, "vy", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_heat {
        use super::*;
        impl_pod_mod_comp!(
            Heat,
            "parity::sim::Heat",
            c"parity::sim::Heat",
            BAM_COMPONENT_FLAG_SUMMARY_TICK,
            [
                (temp, "temp", BamFieldKind::F32, "f32", f32),
                (active, "active", BamFieldKind::BOOL, "FfiBool", FfiBool),
                (
                    _strata_pad_0,
                    "_strata_pad_0",
                    BamFieldKind::NESTED,
                    "[u8;3]",
                    [u8; 3]
                ),
            ]
        );
    }
}

fn cookbooks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks")
}

fn build_target_bin(src: &Path, target: BuildTarget, out_dir: &Path) -> PathBuf {
    let (code, msg) = cmd_build(
        src,
        true,
        target,
        Some(out_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "{target:?} build failed: {msg}");
    let rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    PathBuf::from(rep["binary_path"].as_str().unwrap())
}

fn setup_shared_world() -> App {
    let mut app = App::new();
    app.init_schedule(Startup);
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    app.insert_resource(SimParam {
        dt: 0.016,
        damping: 0.995,
    });
    app.register_strata_resource::<SimParam>().unwrap();
    app.register_strata_component::<Pos>(StrataComponentOptions::new())
        .unwrap();
    app.register_strata_component::<Vel>(StrataComponentOptions::new())
        .unwrap();
    app.register_strata_component::<Heat>(StrataComponentOptions::new().summary_tick())
        .unwrap();

    for i in 0..128 {
        app.world_mut().spawn((
            Pos {
                x: (i as f32) * 0.25,
                y: ((i % 9) as f32) * 0.6 + 0.1,
            },
            Vel {
                vx: 2.0 + ((i % 5) as f32) * 0.5,
                vy: -((i % 7) as f32) * 0.4,
            },
            Heat::default(),
        ));
    }
    app
}

fn setup_dynamic_app_with_mod(bin: &Path) -> (App, ModId) {
    let mut app = App::new();
    app.init_schedule(Startup);
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    let mod_id = app.load_mod_with(bin, LoadOptions::default()).unwrap();
    app.world_mut().run_schedule(Startup);
    (app, mod_id)
}

fn find_component_handle(world: &World, name_suffix: &str) -> BamComponent {
    let reg = world.resource::<ModRegistry>();
    let snap = reg.snapshot();
    snap.entries()
        .iter()
        .find(|e| e.name.as_ref() == name_suffix || e.name.rsplit("::").next() == Some(name_suffix))
        .unwrap_or_else(|| panic!("component `{name_suffix}` missing from ModRegistry"))
        .handle
}

fn find_entities_with_handle(world: &World, handle: BamComponent) -> Vec<Entity> {
    let reg = world.resource::<ModRegistry>();
    let snap = reg.snapshot();
    let entry = snap.get_by_handle(handle).expect("registered handle");
    let mut ents = Vec::new();
    for arch in world.archetypes().iter() {
        if !arch.is_empty() && arch.contains(entry.component_id) {
            ents.extend(arch.entities().iter().map(|ae| ae.id()));
        }
    }
    ents.sort_unstable_by_key(|e| e.to_bits());
    ents
}

fn native_struct_name(mir_layouts: &[strata_sema::layout::SolvedLayout], short: &str) -> String {
    let (idx, layout) = mir_layouts
        .iter()
        .enumerate()
        .find(|(_, l)| {
            l.canonical_name == short || l.canonical_name.rsplit("::").next() == Some(short)
        })
        .unwrap_or_else(|| panic!("missing layout `{short}` in MIR"));
    format!("Strata{}_{idx}", sanitize_ident(&layout.canonical_name))
}

struct Tier3Capture {
    digests: BTreeMap<String, WorldPodDigest>,
    pod_dumps: BTreeMap<String, Vec<u8>>,
}

/// Generates a Tier-3 Bevy native plugin crate via `cmd_onboard`, compiles and runs a real
/// `#![forbid(unsafe_code)]` Bevy binary harness against `StrataNativePlugin`, and captures
/// canonical POD world digests matching [`hash_world_pod_state`].
fn run_tier3_native_harness(
    tmp_dir: &Path,
    label: &str,
    src_path: &Path,
    harness_driver_body: &str,
) -> Tier3Capture {
    let bn_dir = tmp_dir.join(format!("onboard_{label}"));
    let (code, msg) = cmd_onboard(
        src_path,
        OnboardTarget::BevyNative,
        &bn_dir,
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "cmd_onboard failed for {label}: {msg}");
    let rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    let crate_name = rep["crate_name"].as_str().unwrap().to_owned();

    let runner_dir = tmp_dir.join(format!("tier3_runner_{label}"));
    fs::create_dir_all(runner_dir.join("src")).unwrap();
    let bn_path = fs::canonicalize(&bn_dir)
        .unwrap()
        .display()
        .to_string()
        .replace('\\', "/");

    let cargo_toml = format!(
        "[package]\n\
         name = \"strata_tier3_runner_{label}\"\n\
         version = \"0.3.0\"\n\
         edition = \"2024\"\n\n\
         [dependencies]\n\
         strata_native_mod = {{ package = \"{crate_name}\", path = \"{bn_path}\" }}\n\
         bamabi_host = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-core.git\", branch = \"main\" }}\n\
         bamabi_sys = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\" }}\n\
         bevy_app = {{ version = \"0.20.1\", default-features = false, features = [\"std\"] }}\n\
         bevy_ecs = {{ version = \"0.20.1\", default-features = false, features = [\"std\", \"async_executor\"] }}\n"
    );
    fs::write(runner_dir.join("Cargo.toml"), cargo_toml).unwrap();
    write_local_patch_config(&runner_dir);

    let out_dir_escaped = runner_dir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    let main_rs = format!(
        r#"#![forbid(unsafe_code)]

use bamabi_host::prelude::*;
use bamabi_host::{{ModRegistry, RegisteredComponent, read_entity_pod_bytes}};
use bamabi_sys::{{
    BAM_STORAGE_FLAG_ENTITY_EVENT, BAM_STORAGE_FLAG_EVENT, BAM_STORAGE_FLAG_MESSAGE,
    BAM_STORAGE_FLAG_RESOURCE, fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
}};
use bevy_app::{{App, FixedUpdate, Startup}};
use bevy_ecs::prelude::*;
use std::fs;
use std::path::PathBuf;
use strata_native_mod::*;

fn is_hashable_entity_pod(entry: &RegisteredComponent) -> bool {{
    let non_entity_mask = BAM_STORAGE_FLAG_RESOURCE
        | BAM_STORAGE_FLAG_MESSAGE
        | BAM_STORAGE_FLAG_EVENT
        | BAM_STORAGE_FLAG_ENTITY_EVENT;
    entry.is_abi_pod
        && (entry.storage_flags & non_entity_mask) == 0
        && !entry.name.starts_with("bevy_ecs::")
}}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentSig {{
    name: String,
    uuid_bytes: [u8; 16],
    schema_fingerprint: u64,
    size: usize,
    align: usize,
}}

fn capture_snapshot(out_dir: &std::path::Path, tag: &str, world: &World) {{
    let mut stream = Vec::<u8>::new();
    let mut fnv = fnv1a_64_init();

    let push_bytes = |s: &mut Vec<u8>, f: &mut u64, b: &[u8]| {{
        s.extend_from_slice(b);
        *f = fnv1a_64_update_bytes(*f, b);
    }};
    let push_u64 = |s: &mut Vec<u8>, f: &mut u64, v: u64| {{
        s.extend_from_slice(&v.to_le_bytes());
        *f = fnv1a_64_update_u64(*f, v);
    }};
    let push_str = |s: &mut Vec<u8>, f: &mut u64, txt: &str| {{
        push_u64(s, f, txt.len() as u64);
        push_bytes(s, f, txt.as_bytes());
    }};

    let registry = world.resource::<ModRegistry>();
    let snap = registry.snapshot();
    let mut pod_components: Vec<&RegisteredComponent> = snap
        .entries()
        .iter()
        .filter(|e| is_hashable_entity_pod(e))
        .collect();
    pod_components.sort_by(|a, b| a.name.as_ref().cmp(b.name.as_ref()));

    struct ArchRecord<'a> {{
        sig: Vec<ComponentSig>,
        components: Vec<&'a RegisteredComponent>,
        entities: Vec<Entity>,
    }}

    let mut arch_records = Vec::new();
    for arch in world.archetypes().iter() {{
        if arch.is_empty() {{
            continue;
        }}
        let mut comps = Vec::new();
        let mut sig = Vec::new();
        for &entry in &pod_components {{
            if arch.contains(entry.component_id) {{
                comps.push(entry);
                sig.push(ComponentSig {{
                    name: entry.name.to_string(),
                    uuid_bytes: entry.uuid.bytes,
                    schema_fingerprint: entry.schema_fingerprint,
                    size: entry.size,
                    align: entry.align,
                }});
            }}
        }}
        if comps.is_empty() {{
            continue;
        }}
        let mut entities: Vec<Entity> = arch.entities().iter().map(|ae| ae.id()).collect();
        entities.sort_unstable_by_key(|e| e.to_bits());
        arch_records.push(ArchRecord {{ sig, components: comps, entities }});
    }}

    arch_records.sort_by(|a, b| {{
        a.sig
            .cmp(&b.sig)
            .then_with(|| a.entities.len().cmp(&b.entities.len()))
            .then_with(|| {{
                a.entities
                    .first()
                    .map(|e| e.to_bits())
                    .cmp(&b.entities.first().map(|e| e.to_bits()))
            }})
    }});

    push_str(&mut stream, &mut fnv, "ARCHETYPES");
    push_u64(&mut stream, &mut fnv, arch_records.len() as u64);

    let mut total_entities = 0usize;
    let mut total_bytes = 0usize;
    for rec in &arch_records {{
        total_entities += rec.entities.len();
        push_u64(&mut stream, &mut fnv, rec.sig.len() as u64);
        for s in &rec.sig {{
            push_str(&mut stream, &mut fnv, &s.name);
            push_bytes(&mut stream, &mut fnv, &s.uuid_bytes);
            push_u64(&mut stream, &mut fnv, s.schema_fingerprint);
            push_u64(&mut stream, &mut fnv, s.size as u64);
            push_u64(&mut stream, &mut fnv, s.align as u64);
        }}
        push_u64(&mut stream, &mut fnv, rec.entities.len() as u64);
        for &entry in &rec.components {{
            push_str(&mut stream, &mut fnv, &entry.name);
            for &entity in &rec.entities {{
                let bytes = read_entity_pod_bytes(world, entity, entry.handle).unwrap_or_default();
                total_bytes += bytes.len();
                push_bytes(&mut stream, &mut fnv, &bytes);
            }}
        }}
    }}

    fs::write(out_dir.join(format!("stream_{{tag}}.bin")), &stream).unwrap();
    println!(
        "SNAP {{tag}} {{fnv}} {{}} {{total_entities}} {{total_bytes}}",
        arch_records.len()
    );
}}

#[allow(dead_code)]
fn dump_comp_bytes(out_dir: &std::path::Path, tag: &str, world: &World, suffix: &str) {{
    let reg = world.resource::<ModRegistry>();
    let snap = reg.snapshot();
    let entry = snap
        .entries()
        .iter()
        .find(|e| e.name.as_ref() == suffix || e.name.rsplit("::").next() == Some(suffix))
        .expect("comp entry");
    let mut ents = Vec::new();
    for arch in world.archetypes().iter() {{
        if !arch.is_empty() && arch.contains(entry.component_id) {{
            ents.extend(arch.entities().iter().map(|ae| ae.id()));
        }}
    }}
    ents.sort_unstable_by_key(|e| e.to_bits());
    let mut out = Vec::new();
    for e in ents {{
        out.extend_from_slice(&read_entity_pod_bytes(world, e, entry.handle).unwrap());
    }}
    fs::write(out_dir.join(format!("dump_{{tag}}.bin")), &out).unwrap();
}}

fn main() {{
    let out_dir = PathBuf::from("{out_dir_escaped}");
    let mut app = App::new();
    app.init_schedule(Startup);
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    app.add_plugins(StrataNativePlugin);
    {harness_driver_body}
}}
"#
    );
    fs::write(runner_dir.join("src").join("main.rs"), main_rs).unwrap();

    let mut cmd = sanitized_cargo();
    cmd.current_dir(&runner_dir)
        .arg("run")
        .arg("--release")
        .arg("--manifest-path")
        .arg(runner_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(shared_temp_target_dir());
    let out = cmd.output().expect("run tier3 harness");
    assert!(
        out.status.success(),
        "Tier-3 harness `{label}` failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut digests = BTreeMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() == Some(&"SNAP") && parts.len() == 6 {
            let tag = parts[1].to_owned();
            let fnv1a64: u64 = parts[2].parse().unwrap();
            let archetype_count: usize = parts[3].parse().unwrap();
            let entity_count: usize = parts[4].parse().unwrap();
            let pod_bytes_hashed: usize = parts[5].parse().unwrap();
            let stream_bytes = fs::read(runner_dir.join(format!("stream_{tag}.bin"))).unwrap();
            let sha_raw = Sha256::digest(&stream_bytes);
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&sha_raw);
            assert_eq!(
                fnv1a_64_update_bytes(fnv1a_64_init(), &stream_bytes),
                fnv1a64,
                "Tier-3 stream hash mismatch for {tag}"
            );
            digests.insert(
                tag,
                WorldPodDigest {
                    sha256,
                    fnv1a64,
                    archetype_count,
                    entity_count,
                    pod_bytes_hashed,
                },
            );
        }
    }

    let mut pod_dumps = BTreeMap::new();
    for entry in fs::read_dir(&runner_dir).unwrap() {
        let p = entry.unwrap().path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str())
            && let Some(tag) = name
                .strip_prefix("dump_")
                .and_then(|s| s.strip_suffix(".bin"))
        {
            pod_dumps.insert(tag.to_owned(), fs::read(&p).unwrap());
        }
    }

    Tier3Capture { digests, pod_dumps }
}

#[test]
fn four_way_differential_parity_500_frames_plus_live_reload() {
    let _parity_rg = parity_alloc_read_guard();
    // Verify host POD UUIDs match strata_sema solved UUIDs bit-for-bit.
    let analyzed = analyze_source("parity_v1.strata", PARITY_SRC_V1);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    assert!(
        !mir.functions.is_empty() && !mir.functions[0].blocks.is_empty(),
        "parity kernel must lower non-empty MIR blocks"
    );
    for l in &mir.layouts {
        match l.canonical_name.as_str() {
            "parity::sim::Pos" => {
                assert_eq!(l.uuid_bytes, Pos::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Pos::SCHEMA_FINGERPRINT);
            }
            "parity::sim::Vel" => {
                assert_eq!(l.uuid_bytes, Vel::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Vel::SCHEMA_FINGERPRINT);
            }
            "parity::sim::Heat" => {
                assert_eq!(l.uuid_bytes, Heat::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Heat::SCHEMA_FINGERPRINT);
            }
            "parity::sim::SimParam" => {
                assert_eq!(l.uuid_bytes, SimParam::UUID.bytes);
                assert_eq!(l.schema_fingerprint, SimParam::SCHEMA_FINGERPRINT);
            }
            _ => {}
        }
    }

    let tmp = TempDir::new().unwrap();
    let src_v1 = tmp.path().join("parity_v1.strata");
    fs::write(&src_v1, PARITY_SRC_V1).unwrap();

    // Build Targets 1-3: Cranelift PIC JIT, Strict ISO C99, Safe Rust Guest
    let jit_bin = build_target_bin(&src_v1, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_v1, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_v1,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    // Build & execute Target 4: REAL generated Tier 3 `StrataNativePlugin` via `cmd_onboard`
    let sim_param_s = native_struct_name(&mir.layouts, "SimParam");
    let pos_s = native_struct_name(&mir.layouts, "Pos");
    let vel_s = native_struct_name(&mir.layouts, "Vel");
    let heat_s = native_struct_name(&mir.layouts, "Heat");
    let tier3_driver = format!(
        r#"
    app.insert_resource({sim_param_s} {{ dt: 0.016, damping: 0.995 }});
    for i in 0..128 {{
        app.world_mut().spawn((
            {pos_s} {{
                x: (i as f32) * 0.25,
                y: ((i % 9) as f32) * 0.6 + 0.1,
            }},
            {vel_s} {{
                vx: 2.0 + ((i % 5) as f32) * 0.5,
                vy: -((i % 7) as f32) * 0.4,
            }},
            {heat_s}::default(),
        ));
    }}
    app.world_mut().run_schedule(Startup);
    for frame in 0..500u32 {{
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 1 | 249 | 499) {{
            capture_snapshot(&out_dir, &format!("f{{frame}}"), app.world());
        }}
    }}
"#
    );
    let tier3 = run_tier3_native_harness(tmp.path(), "parity_sim", &src_v1, &tier3_driver);

    // Boot 3 dynamic Bevy Worlds and run 500 FixedUpdate frames!
    let mut w_jit = setup_shared_world();
    let jit_mod_id = w_jit
        .load_mod_with(&jit_bin, LoadOptions::default())
        .unwrap();

    let mut w_c99 = setup_shared_world();
    let c99_mod_id = w_c99
        .load_mod_with(&c99_bin, LoadOptions::default())
        .unwrap();

    let mut w_rg = setup_shared_world();
    let _rg_mod_id = w_rg.load_mod_with(&rg_bin, LoadOptions::default()).unwrap();

    for frame in 0..500u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 1 | 249 | 499) {
            let d_jit = hash_world_pod_state(w_jit.world());
            let d_c99 = hash_world_pod_state(w_c99.world());
            let d_rg = hash_world_pod_state(w_rg.world());
            let d_nat = tier3.digests[&format!("f{frame}")];

            assert!(d_jit.pod_bytes_hashed > 0);
            assert_eq!(
                d_jit.sha256, d_c99.sha256,
                "JIT vs C99 diverged at frame {frame}"
            );
            assert_eq!(
                d_jit.sha256, d_rg.sha256,
                "JIT vs RustGuest diverged at frame {frame}"
            );
            assert_eq!(
                d_jit.sha256, d_nat.sha256,
                "JIT vs real compiled Tier3 StrataNativePlugin diverged at frame {frame}"
            );
            assert_eq!(d_jit.fnv1a64, d_c99.fnv1a64);
            assert_eq!(d_jit.fnv1a64, d_rg.fnv1a64);
            assert_eq!(d_jit.fnv1a64, d_nat.fnv1a64);
        }
    }

    // Live v1 -> v2 dynamic reload parity across Cranelift JIT & ISO C99!
    let src_v2 = tmp.path().join("parity_v2.strata");
    fs::write(&src_v2, PARITY_SRC_V2).unwrap();

    let jit_v2_bin = build_target_bin(&src_v2, BuildTarget::Jit, &tmp.path().join("jit_v2"));
    let c99_v2_bin = build_target_bin(&src_v2, BuildTarget::C99, &tmp.path().join("c99_v2"));

    w_jit
        .reload_mod_from(jit_mod_id, &jit_v2_bin, LoadOptions::default())
        .unwrap();
    w_c99
        .reload_mod_from(c99_mod_id, &c99_v2_bin, LoadOptions::default())
        .unwrap();

    for _ in 0..25 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
    }

    let post_jit = hash_world_pod_state(w_jit.world());
    let post_c99 = hash_world_pod_state(w_c99.world());
    assert_eq!(post_jit.sha256, post_c99.sha256);
    assert_ne!(post_jit.sha256, tier3.digests["f499"].sha256);
}

#[test]
fn v1_to_v2_struct_layout_migration_slot_67_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let tmp = TempDir::new().unwrap();
    let src_v1 = tmp.path().join("mig_v1.strata");
    let src_v2 = tmp.path().join("mig_v2.strata");
    fs::write(&src_v1, MIG_SRC_V1).unwrap();
    fs::write(&src_v2, MIG_SRC_V2).unwrap();

    let targets = [
        ("jit", BuildTarget::Jit),
        ("c99", BuildTarget::C99),
        ("rust_guest", BuildTarget::RustGuest),
    ];

    let mut post_mig_bytes_by_target: Vec<(&str, Vec<(f32, Vec<u8>)>)> = Vec::new();
    let mut post_step_bytes_by_target: Vec<(&str, Vec<(f32, Vec<u8>)>)> = Vec::new();

    for (label, target) in targets {
        let bin_v1 = build_target_bin(&src_v1, target, &tmp.path().join(format!("{label}_v1")));
        let bin_v2 = build_target_bin(&src_v2, target, &tmp.path().join(format!("{label}_v2")));

        let (mut app, mod_id) = setup_dynamic_app_with_mod(&bin_v1);
        for _ in 0..3 {
            app.world_mut().run_schedule(FixedUpdate);
        }

        let handle_v1 = find_component_handle(app.world(), "UnitHealth");
        let entities = find_entities_with_handle(app.world(), handle_v1);
        assert_eq!(entities.len(), 3, "{label}: expected 3 spawned entities");

        let mut pre_mig_by_ent: Vec<(Entity, f32)> = Vec::new();
        for &ent in &entities {
            let bytes = read_entity_pod_bytes(app.world(), ent, handle_v1).unwrap();
            assert_eq!(bytes.len(), 4, "{label}: v1 UnitHealth must be 4 bytes");
            let hp = f32::from_le_bytes(bytes.try_into().unwrap());
            pre_mig_by_ent.push((ent, hp));
        }
        let mut sorted_hps: Vec<f32> = pre_mig_by_ent.iter().map(|&(_, hp)| hp).collect();
        sorted_hps.sort_by(f32::total_cmp);
        assert_eq!(
            sorted_hps,
            vec![50.0_f32, 65.0_f32, 110.0_f32],
            "{label}: v1 stepped hps mismatch"
        );

        // Trigger live v1 -> v2 schema evolution via ABI 0.3.0 Slot 67 `migrate_component_column`!
        let _new_id = app
            .reload_mod_from(mod_id, &bin_v2, LoadOptions::default())
            .unwrap_or_else(|e| panic!("{label} reload_mod_from v1->v2 migration failed: {e}"));

        let handle_v2 = find_component_handle(app.world(), "UnitHealth");
        let mut migrated_rows: Vec<(f32, Vec<u8>)> = Vec::new();
        for &(ent, old_hp) in &pre_mig_by_ent {
            let bytes = read_entity_pod_bytes(app.world(), ent, handle_v2).unwrap();
            assert_eq!(
                bytes.len(),
                12,
                "{label}: migrated UnitHealth must be 12 bytes"
            );
            let hp = f32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let max_hp = f32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let armor = f32::from_le_bytes(bytes[8..12].try_into().unwrap());
            assert_eq!(hp, old_hp, "{label}: old hp field not preserved");
            assert_eq!(
                max_hp,
                old_hp * 2.0 + 25.0,
                "{label}: migrated max_hp mismatch"
            );
            assert_eq!(armor, old_hp * 0.5, "{label}: migrated armor mismatch");
            migrated_rows.push((old_hp, bytes));
        }
        migrated_rows.sort_by(|a, b| a.0.total_cmp(&b.0));
        post_mig_bytes_by_target.push((label, migrated_rows));

        // Step v2 for 2 frames and verify post-migration system execution & parity.
        for _ in 0..2 {
            app.world_mut().run_schedule(FixedUpdate);
        }
        let mut stepped_rows: Vec<(f32, Vec<u8>)> = Vec::new();
        for &(ent, old_hp) in &pre_mig_by_ent {
            let bytes = read_entity_pod_bytes(app.world(), ent, handle_v2).unwrap();
            let hp = f32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let max_hp = f32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let armor = f32::from_le_bytes(bytes[8..12].try_into().unwrap());
            assert_eq!(hp, old_hp + 2.0, "{label}: v2 stepped hp mismatch");
            assert_eq!(max_hp, old_hp * 2.0 + 25.0);
            assert_eq!(armor, old_hp * 0.5);
            stepped_rows.push((old_hp, bytes));
        }
        stepped_rows.sort_by(|a, b| a.0.total_cmp(&b.0));
        post_step_bytes_by_target.push((label, stepped_rows));
    }

    let (_, ref ref_mig) = post_mig_bytes_by_target[0];
    for (label, rows) in &post_mig_bytes_by_target[1..] {
        assert_eq!(rows, ref_mig, "migrated POD bytes diverged for `{label}`");
    }
    let (_, ref ref_step) = post_step_bytes_by_target[0];
    for (label, rows) in &post_step_bytes_by_target[1..] {
        assert_eq!(
            rows, ref_step,
            "post-migration stepped POD bytes diverged for `{label}`"
        );
    }
}

#[test]
fn cookbook_01_rain_swarm_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let tmp = TempDir::new().unwrap();
    let src_path = cookbooks_dir().join("01_rain_swarm.strata");

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    for frame in 0..120u32 {
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 59 | 119) {
            capture_snapshot(&out_dir, &format!("f{frame}"), app.world());
        }
    }
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "rain_swarm", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    let init_jit = hash_world_pod_state(w_jit.world());
    let init_c99 = hash_world_pod_state(w_c99.world());
    let init_rg = hash_world_pod_state(w_rg.world());
    let init_nat = tier3.digests["init"];

    assert_eq!(init_jit.entity_count, 2000);
    assert!(init_jit.pod_bytes_hashed > 0);
    assert_eq!(init_jit.sha256, init_c99.sha256, "init JIT vs C99");
    assert_eq!(init_jit.sha256, init_rg.sha256, "init JIT vs RustGuest");
    assert_eq!(init_jit.sha256, init_nat.sha256, "init JIT vs Tier3");

    for frame in 0..120u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 59 | 119) {
            let d_jit = hash_world_pod_state(w_jit.world());
            let d_c99 = hash_world_pod_state(w_c99.world());
            let d_rg = hash_world_pod_state(w_rg.world());
            let d_nat = tier3.digests[&format!("f{frame}")];

            assert_eq!(d_jit.entity_count, 2000);
            assert_eq!(d_jit.sha256, d_c99.sha256, "frame {frame}: JIT vs C99");
            assert_eq!(d_jit.sha256, d_rg.sha256, "frame {frame}: JIT vs RustGuest");
            assert_eq!(d_jit.sha256, d_nat.sha256, "frame {frame}: JIT vs Tier3");
            assert_eq!(d_jit.fnv1a64, d_nat.fnv1a64);
        }
    }

    let final_jit = hash_world_pod_state(w_jit.world());
    assert_ne!(
        final_jit.sha256, init_jit.sha256,
        "raindrops must mutate during 120 FixedUpdate frames"
    );
}

#[test]
fn cookbook_03_metroidvania_core_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let tmp = TempDir::new().unwrap();
    let src_path = cookbooks_dir().join("03_metroidvania_core.strata");
    let src_text = fs::read_to_string(&src_path).unwrap();
    let analyzed = analyze_source("03_metroidvania_core.strata", &src_text);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let kb_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("KinematicBody"))
        .expect("KinematicBody layout");
    let grounded_off = kb_layout
        .fields
        .iter()
        .find(|f| f.name == "grounded")
        .expect("grounded field")
        .offset;
    let coyote_off = kb_layout
        .fields
        .iter()
        .find(|f| f.name == "coyote")
        .expect("coyote field")
        .offset;
    let kb_struct = native_struct_name(&mir.layouts, "KinematicBody");

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = format!(
        r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());

    for _ in 0..4 {{
        app.world_mut().run_schedule(FixedUpdate);
    }}
    capture_snapshot(&out_dir, "idle", app.world());

    {{
        let mut q = app.world_mut().query::<&mut {kb_struct}>();
        for mut kb in q.iter_mut(app.world_mut()) {{
            kb.grounded = FfiBool::TRUE;
        }}
    }}
    for _ in 0..2 {{
        app.world_mut().run_schedule(FixedUpdate);
    }}
    capture_snapshot(&out_dir, "armed", app.world());
    dump_comp_bytes(&out_dir, "armed_kb", app.world(), "KinematicBody");

    {{
        let mut q = app.world_mut().query::<&mut {kb_struct}>();
        for mut kb in q.iter_mut(app.world_mut()) {{
            kb.grounded = FfiBool::FALSE;
        }}
    }}
    for _ in 0..6 {{
        app.world_mut().run_schedule(FixedUpdate);
    }}
    capture_snapshot(&out_dir, "coyote_decay", app.world());
    dump_comp_bytes(&out_dir, "decay_kb", app.world(), "KinematicBody");
"#
    );
    let tier3 = run_tier3_native_harness(tmp.path(), "metroidvania", &src_path, &tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    let assert_4way = |tag: &str, a: &App, b: &App, c: &App| {
        let da = hash_world_pod_state(a.world());
        let db = hash_world_pod_state(b.world());
        let dc = hash_world_pod_state(c.world());
        let dn = tier3.digests[tag];
        assert!(da.pod_bytes_hashed > 0, "{tag}: empty POD state");
        assert_eq!(da.sha256, db.sha256, "{tag}: JIT vs C99");
        assert_eq!(da.sha256, dc.sha256, "{tag}: JIT vs RustGuest");
        assert_eq!(da.sha256, dn.sha256, "{tag}: JIT vs Tier3");
        assert_eq!(da.fnv1a64, dn.fnv1a64, "{tag}: fnv1a64 mismatch");
        da
    };

    let init_d = assert_4way("init", &w_jit, &w_c99, &w_rg);

    for _ in 0..4 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);
    }
    assert_4way("idle", &w_jit, &w_c99, &w_rg);

    let set_grounded = |app: &mut App, val: bool| {
        let kb_h = find_component_handle(app.world(), "KinematicBody");
        let ents = find_entities_with_handle(app.world(), kb_h);
        assert_eq!(ents.len(), 1, "expected single PlayerHero entity");
        let mut bytes = read_entity_pod_bytes(app.world(), ents[0], kb_h).unwrap();
        bytes[grounded_off] = u8::from(val);
        write_entity_pod_bytes(app.world_mut(), ents[0], kb_h, &bytes).unwrap();
    };
    let read_coyote = |app: &App| -> (Vec<u8>, f32) {
        let kb_h = find_component_handle(app.world(), "KinematicBody");
        let ents = find_entities_with_handle(app.world(), kb_h);
        let bytes = read_entity_pod_bytes(app.world(), ents[0], kb_h).unwrap();
        let rem = f32::from_le_bytes(bytes[coyote_off..coyote_off + 4].try_into().unwrap());
        (bytes, rem)
    };

    set_grounded(&mut w_jit, true);
    set_grounded(&mut w_c99, true);
    set_grounded(&mut w_rg, true);
    for _ in 0..2 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);
    }
    let armed_d = assert_4way("armed", &w_jit, &w_c99, &w_rg);
    assert_ne!(
        armed_d.sha256, init_d.sha256,
        "grounded=true must mutate KinematicBody"
    );

    let (armed_jit_kb, armed_coyote) = read_coyote(&w_jit);
    assert!(
        armed_coyote > 0.08,
        "expected armed coyote GraceWindow > 0.08s, got {armed_coyote}"
    );
    assert_eq!(armed_jit_kb, read_coyote(&w_c99).0);
    assert_eq!(armed_jit_kb, read_coyote(&w_rg).0);
    assert_eq!(armed_jit_kb, tier3.pod_dumps["armed_kb"]);

    set_grounded(&mut w_jit, false);
    set_grounded(&mut w_c99, false);
    set_grounded(&mut w_rg, false);
    for _ in 0..6 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);
    }
    assert_4way("coyote_decay", &w_jit, &w_c99, &w_rg);
    let (decay_jit_kb, decay_coyote) = read_coyote(&w_jit);
    assert!(
        decay_coyote > 0.0 && decay_coyote < armed_coyote,
        "expected coyote timer decay from {armed_coyote}, got {decay_coyote}"
    );
    assert_eq!(decay_jit_kb, read_coyote(&w_c99).0);
    assert_eq!(decay_jit_kb, read_coyote(&w_rg).0);
    assert_eq!(decay_jit_kb, tier3.pod_dumps["decay_kb"]);
}

fn assert_four_way_snapshot(
    tag: &str,
    w_jit: &App,
    w_c99: &App,
    w_rg: &App,
    tier3: &Tier3Capture,
) -> WorldPodDigest {
    let d_jit = hash_world_pod_state(w_jit.world());
    let d_c99 = hash_world_pod_state(w_c99.world());
    let d_rg = hash_world_pod_state(w_rg.world());
    let d_nat = tier3.digests[tag];

    assert!(d_jit.pod_bytes_hashed > 0, "{tag}: empty POD state");
    assert_eq!(
        d_jit.sha256, d_c99.sha256,
        "{tag}: JIT vs C99 (jit={d_jit:?}, c99={d_c99:?})"
    );
    assert_eq!(
        d_jit.sha256, d_rg.sha256,
        "{tag}: JIT vs RustGuest (jit={d_jit:?}, rg={d_rg:?})"
    );
    assert_eq!(
        d_jit.sha256, d_nat.sha256,
        "{tag}: JIT vs Tier3 (jit={d_jit:?}, nat={d_nat:?})"
    );
    assert_eq!(d_jit.fnv1a64, d_c99.fnv1a64, "{tag}: fnv1a64 JIT vs C99");
    assert_eq!(
        d_jit.fnv1a64, d_rg.fnv1a64,
        "{tag}: fnv1a64 JIT vs RustGuest"
    );
    assert_eq!(d_jit.fnv1a64, d_nat.fnv1a64, "{tag}: fnv1a64 JIT vs Tier3");
    assert_eq!(d_jit.entity_count, d_nat.entity_count);
    d_jit
}

fn read_single_comp_bytes_by_u32_id(
    world: &World,
    comp_name: &str,
    id_offset: usize,
    target_id: u32,
) -> Vec<u8> {
    let h = find_component_handle(world, comp_name);
    for ent in find_entities_with_handle(world, h) {
        let bytes = read_entity_pod_bytes(world, ent, h).unwrap();
        let id = u32::from_le_bytes(bytes[id_offset..id_offset + 4].try_into().unwrap());
        if id == target_id {
            return bytes;
        }
    }
    panic!("missing {comp_name} with id={target_id}");
}

fn find_entity_by_u32_id(
    world: &World,
    comp_name: &str,
    id_offset: usize,
    target_id: u32,
) -> Entity {
    let h = find_component_handle(world, comp_name);
    for ent in find_entities_with_handle(world, h) {
        let bytes = read_entity_pod_bytes(world, ent, h).unwrap();
        let id = u32::from_le_bytes(bytes[id_offset..id_offset + 4].try_into().unwrap());
        if id == target_id {
            return ent;
        }
    }
    panic!("missing entity for {comp_name} id={target_id}");
}

#[test]
fn atomic_rollback_and_1000_tick_zero_leak_four_way_parity() {
    let parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::atomic_tx @version(1.0.0);

resource Ledger {
    bank: i32 = 500,
    tx_attempts: u32 = 0,
    committed_val: f32 = 1.0,
}

component Vault @summary_tick {
    vault_id: u32 = 0,
    gold: i32 = 100,
    energy: f32 = 25.0,
    should_commit: bool = false,
    ok_ticks: u32 = 0,
}

component GhostSpawn {
    tag_val: u32 = 77,
}

object AbortVault {
    Vault { vault_id: 1, gold: 100, energy: 25.0, should_commit: false, ok_ticks: 0 },
}

object CommitVault {
    Vault { vault_id: 2, gold: 200, energy: 50.0, should_commit: true, ok_ticks: 0 },
}

sys step_atomic(led: &mut res Ledger) {
    led.tx_attempts += 1;

    for row in query(v: &mut Vault) {
        atomic {
            row.v.gold += 1;
            row.v.energy += 0.25;
            row.v.ok_ticks += 1;
            require_true(row.v.should_commit);
        }
    }

    atomic {
        let _ghost = spawn { GhostSpawn { tag_val: 99 } };
        led.bank -= 123;
        led.committed_val += 999.0;
        require_true(false);
    }

    led.bank += 1;
}

schedule FixedUpdate { step_atomic }

sim_test "atomic_1000_tick_zero_steady_alloc_and_zero_leak" {
    step_fixed(1000);
    assert(res<Ledger>().bank == 1500);
    assert(res<Ledger>().tx_attempts == 1000);
    assert(res<Ledger>().committed_val == 1.0);
}
"#;
    let analyzed = analyze_source("parity_atomic.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let vault_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("Vault"))
        .expect("Vault layout");
    let off_id = vault_layout
        .fields
        .iter()
        .find(|f| f.name == "vault_id")
        .unwrap()
        .offset;
    let off_gold = vault_layout
        .fields
        .iter()
        .find(|f| f.name == "gold")
        .unwrap()
        .offset;
    let off_energy = vault_layout
        .fields
        .iter()
        .find(|f| f.name == "energy")
        .unwrap()
        .offset;
    let off_ok_ticks = vault_layout
        .fields
        .iter()
        .find(|f| f.name == "ok_ticks")
        .unwrap()
        .offset;

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_atomic.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let ledger_s = native_struct_name(&mir.layouts, "Ledger");
    let tier3_driver = format!(
        r#"
    app.world_mut().run_schedule(Startup);
    let init_world_ents = app.world().entities().len();
    capture_snapshot(&out_dir, "init", app.world());
    for frame in 0..1000u32 {{
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 499 | 999) {{
            capture_snapshot(&out_dir, &format!("f{{frame}}"), app.world());
        }}
    }}
    let led = app.world().resource::<{ledger_s}>();
    assert_eq!(led.bank, 1500, "Tier3 rolled-back bank must equal 1500");
    assert_eq!(led.tx_attempts, 1000);
    assert_eq!(led.committed_val, 1.0, "Tier3 rolled-back committed_val must stay 1.0");
    assert_eq!(
        app.world().entities().len(),
        init_world_ents,
        "Tier3 entity count must remain invariant across 1000 ticks"
    );
    dump_comp_bytes(&out_dir, "vaults", app.world(), "Vault");
"#
    );
    let tier3 = run_tier3_native_harness(tmp.path(), "atomic_1000", &src_path, &tier3_driver);

    let (mut w_jit, jit_id) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, c99_id) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, rg_id) = setup_dynamic_app_with_mod(&rg_bin);
    let jit_init_ents = w_jit.world().entities().len();
    let c99_init_ents = w_c99.world().entities().len();
    let rg_init_ents = w_rg.world().entities().len();

    let init_d = assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    assert_eq!(init_d.entity_count, 2);

    for frame in 0..1000u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 499 | 999) {
            let d = assert_four_way_snapshot(&format!("f{frame}"), &w_jit, &w_c99, &w_rg, &tier3);
            assert_eq!(
                d.entity_count, 2,
                "frame {frame}: rolled-back spawn leaked entities"
            );
        }
    }

    for (label, app, mid, init_ents) in [
        ("jit", &w_jit, jit_id, jit_init_ents),
        ("c99", &w_c99, c99_id, c99_init_ents),
        ("rust_guest", &w_rg, rg_id, rg_init_ents),
    ] {
        assert_eq!(
            app.world().entities().len(),
            init_ents,
            "{label}: entity leak detected after 1000 ticks"
        );
        if let Some(telem) = app.world().get_resource::<ModBudgetTelemetry>() {
            let snaps = telem.mod_snapshots(mid);
            assert!(!snaps.is_empty(), "{label}: missing telemetry snapshots");
            for s in &snaps {
                assert!(
                    s.arena_bytes_peak <= 1024,
                    "{label}: command arena leaked across 1000 ticks: peak={}B",
                    s.arena_bytes_peak
                );
            }
        }

        let abort_b = read_single_comp_bytes_by_u32_id(app.world(), "Vault", off_id, 1);
        let gold_a = i32::from_le_bytes(abort_b[off_gold..off_gold + 4].try_into().unwrap());
        let energy_a = f32::from_le_bytes(abort_b[off_energy..off_energy + 4].try_into().unwrap());
        let ticks_a =
            u32::from_le_bytes(abort_b[off_ok_ticks..off_ok_ticks + 4].try_into().unwrap());
        assert_eq!(
            gold_a, 100,
            "{label}: AbortVault.gold must roll back to 100"
        );
        assert_eq!(
            energy_a, 25.0,
            "{label}: AbortVault.energy must roll back to 25.0"
        );
        assert_eq!(
            ticks_a, 0,
            "{label}: AbortVault.ok_ticks must roll back to 0"
        );

        let commit_b = read_single_comp_bytes_by_u32_id(app.world(), "Vault", off_id, 2);
        let gold_c = i32::from_le_bytes(commit_b[off_gold..off_gold + 4].try_into().unwrap());
        let energy_c = f32::from_le_bytes(commit_b[off_energy..off_energy + 4].try_into().unwrap());
        let ticks_c =
            u32::from_le_bytes(commit_b[off_ok_ticks..off_ok_ticks + 4].try_into().unwrap());
        assert_eq!(gold_c, 1200, "{label}: CommitVault.gold mismatch");
        assert_eq!(energy_c, 300.0, "{label}: CommitVault.energy mismatch");
        assert_eq!(ticks_c, 1000, "{label}: CommitVault.ok_ticks mismatch");
    }

    // Verify 0 steady-state Rust heap allocations across 1,000 ticks via headless sim_runner.
    drop(parity_rg);
    let _parity_wg = PARITY_ALLOC_GATE.write().unwrap_or_else(|e| e.into_inner());
    let sim_res = stratac::sim_runner::run_headless_sim_tests(&mir, "parity_atomic_sim");
    assert_eq!(sim_res.len(), 1);
    assert!(
        sim_res[0].passed,
        "1000-tick atomic sim_test failed: {}",
        sim_res[0].detail
    );
    assert_eq!(sim_res[0].frames_simulated, 1000);
    assert_eq!(
        sim_res[0].steady_state_allocs, 0,
        "1000-tick atomic rollback must have 0 steady-state heap allocs"
    );
}

#[test]
fn spatial_grid_disc_and_spatial_history_segment_2pass_csr_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::spatial_csr @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
component Pos3 { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
tag Target2D;
component UnitId { unit_id: u32 = 0 }
component DiscHit { hits: u32 = 0 }
component SegNowHit { hits: u32 = 0 }
component SegPrevHit { hits: u32 = 0 }

resource SpatialSummary {
    tick: u32 = 0,
    disc_count: u32 = 0,
    seg_now_count: u32 = 0,
    seg_prev_count: u32 = 0,
    disc_id_sum: u32 = 0,
    seg_id_sum: u32 = 0,
}

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Target2D by Pos2.xy;

spatial_history Hist3D(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos3 by Pos3.xyz;

object U1HitBoth {
    Pos2 { xy: vec2(1.0, 1.0) },
    Pos3 { xyz: vec3(2.0, 0.0, 0.25) },
    Target2D,
    UnitId { unit_id: 10 },
    DiscHit {},
    SegNowHit {},
    SegPrevHit {},
}

object U2HitDiscOnly {
    Pos2 { xy: vec2(3.5, 1.0) },
    Pos3 { xyz: vec3(2.0, 0.0, 6.0) },
    Target2D,
    UnitId { unit_id: 20 },
    DiscHit {},
    SegNowHit {},
    SegPrevHit {},
}

object U3HitSegOnly {
    Pos2 { xy: vec2(22.0, 22.0) },
    Pos3 { xyz: vec3(8.0, 0.0, 0.2) },
    Target2D,
    UnitId { unit_id: 40 },
    DiscHit {},
    SegNowHit {},
    SegPrevHit {},
}

object U4Mover {
    Pos2 { xy: vec2(0.0, 0.0) },
    Pos3 { xyz: vec3(5.0, 0.0, 0.1) },
    Target2D,
    UnitId { unit_id: 80 },
    DiscHit {},
    SegNowHit {},
    SegPrevHit {},
}

object U5Untagged {
    Pos2 { xy: vec2(1.0, 1.0) },
    Pos3 { xyz: vec3(2.0, 0.0, 6.0) },
    UnitId { unit_id: 99 },
    DiscHit {},
    SegNowHit {},
    SegPrevHit {},
}

sys move_u4() {
    for row in query(u: &UnitId, p3: &mut? Pos3) {
        if row.u.unit_id == 80 {
            row.p3.xyz.z += 5.0;
        }
    }
}

sys scan_disc(g: &res Grid2D, out: &mut res SpatialSummary) {
    out.tick += 1;

    let mut dc: u32 = 0;
    let mut dsum: u32 = 0;
    for hit in g.query_disc(vec2(1.0, 1.0), 4.0_m) {
        dc += 1;
        if let Some(u) = query_one(id: &UnitId, dh: &mut DiscHit).on(hit.id) {
            u.dh.hits += 1;
            dsum += u.id.unit_id;
        }
    }
    out.disc_count = dc;
    out.disc_id_sum = dsum;
}

sys scan_seg_now(h: &res Hist3D, out: &mut res SpatialSummary) {
    let mut sc0: u32 = 0;
    let mut ssum: u32 = 0;
    for hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0)) {
        sc0 += 1;
        if let Some(u) = query_one(id: &UnitId, sh: &mut SegNowHit).on(hit.id) {
            u.sh.hits += 1;
            ssum += u.id.unit_id;
        }
    }
    out.seg_now_count = sc0;
    out.seg_id_sum = ssum;
}

sys scan_seg_prev(h: &res Hist3D, out: &mut res SpatialSummary) {
    let mut sc1: u32 = 0;
    if out.tick >= 2 {
        for hit in h.query_segment_at(1, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0)) {
            sc1 += 1;
            if let Some(u) = query_one(id: &UnitId, ph: &mut SegPrevHit).on(hit.id) {
                u.ph.hits += 1;
            }
        }
    }
    out.seg_prev_count = sc1;
}

schedule FixedUpdate {
    seq SpatialSeq { scan_disc, scan_seg_now, scan_seg_prev, move_u4 }
}
"#;
    let analyzed = analyze_source("parity_spatial.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let uid_off = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("UnitId"))
        .unwrap()
        .fields
        .iter()
        .find(|f| f.name == "unit_id")
        .unwrap()
        .offset;
    let hit_off = |comp: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with(comp))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == "hits")
            .unwrap()
            .offset
    };
    let off_dh = hit_off("DiscHit");
    let off_s0 = hit_off("SegNowHit");
    let off_s1 = hit_off("SegPrevHit");

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_spatial.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let summary_s = native_struct_name(&mir.layouts, "SpatialSummary");
    let tier3_driver = format!(
        r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "t1", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "t2", app.world());
    let s = app.world().resource::<{summary_s}>();
    assert_eq!(s.disc_count, 3, "disc must hit U1, U2, U4");
    assert_eq!(s.disc_id_sum, 110, "disc id sum 10+20+80");
    assert_eq!(s.seg_now_count, 2, "tick 2 seg_now must hit U1, U3 (U4 moved to z=5.1)");
    assert_eq!(s.seg_id_sum, 50, "seg_now id sum 10+40");
    assert_eq!(s.seg_prev_count, 3, "tick 2 seg_prev(1) must hit U1, U3, U4");
"#
    );
    let tier3 = run_tier3_native_harness(tmp.path(), "spatial_csr", &src_path, &tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    let init_d = assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);
    let t1_d = assert_four_way_snapshot("t1", &w_jit, &w_c99, &w_rg, &tier3);
    assert_ne!(t1_d.sha256, init_d.sha256);

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);
    let t2_d = assert_four_way_snapshot("t2", &w_jit, &w_c99, &w_rg, &tier3);
    assert_ne!(t2_d.sha256, t1_d.sha256);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let dh_h = find_component_handle(app.world(), "DiscHit");
        let s0_h = find_component_handle(app.world(), "SegNowHit");
        let s1_h = find_component_handle(app.world(), "SegPrevHit");
        let check_u = |uid: u32, exp_d: u32, exp_s0: u32, exp_s1: u32| {
            let ent = find_entity_by_u32_id(app.world(), "UnitId", uid_off, uid);
            let bd = read_entity_pod_bytes(app.world(), ent, dh_h).unwrap();
            let bs0 = read_entity_pod_bytes(app.world(), ent, s0_h).unwrap();
            let bs1 = read_entity_pod_bytes(app.world(), ent, s1_h).unwrap();
            let dh = u32::from_le_bytes(bd[off_dh..off_dh + 4].try_into().unwrap());
            let s0 = u32::from_le_bytes(bs0[off_s0..off_s0 + 4].try_into().unwrap());
            let s1 = u32::from_le_bytes(bs1[off_s1..off_s1 + 4].try_into().unwrap());
            assert_eq!(
                (dh, s0, s1),
                (exp_d, exp_s0, exp_s1),
                "{label}: Unit({uid}) hit counts mismatch"
            );
        };
        check_u(10, 2, 2, 1);
        check_u(20, 2, 0, 0);
        check_u(40, 0, 2, 1);
        check_u(80, 2, 1, 1);
        check_u(99, 0, 0, 0);
    }
}

#[test]
fn up_rel_cascade_slot_58_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::up_cascade @version(1.0.0);

component Faction {
    team: u32 = 0,
    mult: f32 = 1.0,
}

component NodeAcc {
    node_id: u32 = 0,
    total: f32 = 0.0,
    seen_team: u32 = 0,
    ticks: u32 = 0,
}

object RootOrg {
    Faction { team: 77, mult: 2.5 },
}

object MidNode {
    NodeAcc { node_id: 1, total: 10.0, seen_team: 0, ticks: 0 },
}

object LeafNode {
    NodeAcc { node_id: 2, total: 20.0, seen_team: 0, ticks: 0 },
}

object SelfOwner {
    Faction { team: 33, mult: 1.5 },
    NodeAcc { node_id: 3, total: 5.0, seen_team: 0, ticks: 0 },
}

sys cascade_step() {
    for row in query(acc: &mut NodeAcc, fac: Option<&Faction>).up<ChildOf>() {
        let f = row.fac.unwrap();
        row.acc.total += f.mult;
        row.acc.seen_team = f.team;
        row.acc.ticks += 1;
    }
}

schedule FixedUpdate { cascade_step }
"#;
    let analyzed = analyze_source("parity_cascade.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let acc_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("NodeAcc"))
        .expect("NodeAcc layout");
    let off_nid = acc_layout
        .fields
        .iter()
        .find(|f| f.name == "node_id")
        .unwrap()
        .offset;
    let off_total = acc_layout
        .fields
        .iter()
        .find(|f| f.name == "total")
        .unwrap()
        .offset;
    let off_team = acc_layout
        .fields
        .iter()
        .find(|f| f.name == "seen_team")
        .unwrap()
        .offset;
    let off_ticks = acc_layout
        .fields
        .iter()
        .find(|f| f.name == "ticks")
        .unwrap()
        .offset;

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_cascade.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    {
        let named = app.world().resource::<StrataNamedObjects>();
        let root = named.get("RootOrg").expect("RootOrg");
        let mid = named.get("MidNode").expect("MidNode");
        let leaf = named.get("LeafNode").expect("LeafNode");
        app.world_mut().entity_mut(mid).insert(ChildOf(root));
        app.world_mut().entity_mut(leaf).insert(ChildOf(mid));
    }
    capture_snapshot(&out_dir, "init", app.world());
    for frame in 0..10u32 {
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 9) {
            capture_snapshot(&out_dir, &format!("f{frame}"), app.world());
        }
    }
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "up_cascade", &src_path, tier3_driver);

    let wire_hierarchy = |app: &mut App| {
        let fac_h = find_component_handle(app.world(), "Faction");
        let acc_h = find_component_handle(app.world(), "NodeAcc");
        let fac_ents = find_entities_with_handle(app.world(), fac_h);
        let acc_ents = find_entities_with_handle(app.world(), acc_h);
        let root = fac_ents
            .into_iter()
            .find(|e| !acc_ents.contains(e))
            .expect("RootOrg entity");
        let mid = find_entity_by_u32_id(app.world(), "NodeAcc", off_nid, 1);
        let leaf = find_entity_by_u32_id(app.world(), "NodeAcc", off_nid, 2);
        app.world_mut().entity_mut(mid).insert(ChildOf(root));
        app.world_mut().entity_mut(leaf).insert(ChildOf(mid));
    };

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);
    wire_hierarchy(&mut w_jit);
    wire_hierarchy(&mut w_c99);
    wire_hierarchy(&mut w_rg);

    let init_d = assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    for frame in 0..10u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 9) {
            let d = assert_four_way_snapshot(&format!("f{frame}"), &w_jit, &w_c99, &w_rg, &tier3);
            assert_ne!(d.sha256, init_d.sha256);
        }
    }

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let check_node = |nid: u32, exp_total: f32, exp_team: u32, exp_ticks: u32| {
            let b = read_single_comp_bytes_by_u32_id(app.world(), "NodeAcc", off_nid, nid);
            let total = f32::from_le_bytes(b[off_total..off_total + 4].try_into().unwrap());
            let team = u32::from_le_bytes(b[off_team..off_team + 4].try_into().unwrap());
            let ticks = u32::from_le_bytes(b[off_ticks..off_ticks + 4].try_into().unwrap());
            assert_eq!(
                (total, team, ticks),
                (exp_total, exp_team, exp_ticks),
                "{label}: NodeAcc({nid}) cascade mismatch"
            );
        };
        check_node(1, 35.0, 77, 10);
        check_node(2, 45.0, 77, 10);
        check_node(3, 20.0, 33, 10);
    }
}

#[test]
fn fix64_div_mixed_arith_nb123_and_option_queries_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::fix64_nb_opt @version(1.0.0);

component MathBox {
    lhs: fix64 = 7.5,
    rhs: fix64 = 2.5,
    neg_lhs: fix64 = -7.5,
    zero_div: fix64 = 0.0,
    q_pos: fix64 = 0.0,
    q_neg: fix64 = 0.0,
    q_frac: fix64 = 0.0,
    q_zero: fix64 = 99.0,
    acc: fix64 = 1.25,
    mix_out: f32 = 0.0,
    iv: ivec2 = ivec2(0, 0),
    neg_i: i32 = -42,
    mat_sum: f32 = 0.0,
    arr: [fix64; 3] = [1.0, 2.0, 3.0],
}

component DefaultExtra {
    keep_v: i32 = 42,
    keep_neg: i32 = -7,
    keep_f: f32 = -1.5,
}

component OptRO {
    weight: f32 = 4.0,
}

component OptRW {
    bonus: i32 = 10,
}

component OptStat {
    stat_id: u32 = 0,
    some_ro: u32 = 0,
    none_ro: u32 = 0,
    some_rw: u32 = 0,
    none_rw: u32 = 0,
    both_ro: u32 = 0,
    both_rw: u32 = 0,
    sum_w: f32 = 0.0,
}

object HeroPartial {
    MathBox { arr: [5.0, 6.0, 7.0], iv: ivec2(-1, -2) },
    DefaultExtra {},
}

object OptBoth {
    OptStat { stat_id: 1 },
    OptRO { weight: 3.5 },
    OptRW { bonus: 10 },
}

object OptNeither {
    OptStat { stat_id: 2 },
}

object OptOnlyRW {
    OptStat { stat_id: 3 },
    OptRW { bonus: 20 },
}

object OptOnlyRO {
    OptStat { stat_id: 4 },
    OptRO { weight: 1.5 },
}

sys step_math() {
    let delta: f32 = 0.5;
    let one: fix64 = 1.0;
    let three: fix64 = 3.0;
    let mat: [[f32; 2]; 2] = [[1, 2.5], [3.5, 4]];

    for row in query(m: &mut MathBox) {
        row.m.q_pos = row.m.lhs / row.m.rhs;
        row.m.q_neg = row.m.neg_lhs / row.m.rhs;
        row.m.q_frac = one / three;
        row.m.q_zero = row.m.lhs / row.m.zero_div;
        row.m.acc += delta;
        let mixed_val: fix64 = row.m.acc + 0.25_f32;
        row.m.mix_out = (mixed_val as f32) + mat[0][1];
        row.m.mat_sum = mat[0][1] + mat[1][0];
    }
}

sys step_opt_ro() {
    for row in query(st: &mut OptStat, ro: Option<&OptRO>) {
        if row.ro.is_some() && !row.ro.is_none() {
            row.st.some_ro += 1;
            row.st.sum_w += row.ro.unwrap().weight;
        }
        if row.ro.is_none() {
            row.st.none_ro += 1;
        }
    }
}

sys step_opt_rw() {
    for row in query(st: &mut OptStat, rw: Option<&mut OptRW>) {
        if row.rw.is_some() {
            row.st.some_rw += 1;
            row.rw.unwrap().bonus += 5;
        } else {
            row.st.none_rw += 1;
        }
    }
}

sys step_opt_both() {
    for row in query(st: &mut OptStat, ro: Option<&OptRO>, rw: Option<&mut OptRW>) {
        if row.ro.is_some() {
            row.st.both_ro += 1;
            row.st.sum_w += row.ro.unwrap().weight;
        }
        if row.rw.is_some() {
            row.st.both_rw += 1;
            row.rw.unwrap().bonus += 1;
        }
    }
}

schedule FixedUpdate { step_math, step_opt_ro, step_opt_rw, step_opt_both }
"#;
    let analyzed = analyze_source("parity_fix64_nb_opt.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let field_off = |comp: &str, name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with(comp))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let mb_off = |name: &str| field_off("MathBox", name);
    let os_off = |name: &str| field_off("OptStat", name);
    let rw_off = |name: &str| field_off("OptRW", name);
    let de_off = |name: &str| field_off("DefaultExtra", name);

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_fix64_nb_opt.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    for frame in 0..5u32 {
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 4) {
            capture_snapshot(&out_dir, &format!("f{frame}"), app.world());
        }
    }
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "fix64_nb_opt", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    let init_d = assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    for frame in 0..5u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 4) {
            let d = assert_four_way_snapshot(&format!("f{frame}"), &w_jit, &w_c99, &w_rg, &tier3);
            assert_ne!(d.sha256, init_d.sha256);
        }
    }

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let mb_h = find_component_handle(app.world(), "MathBox");
        let mb_ents = find_entities_with_handle(app.world(), mb_h);
        assert_eq!(mb_ents.len(), 1);
        let b = read_entity_pod_bytes(app.world(), mb_ents[0], mb_h).unwrap();
        let read_i64 = |f: &str| -> i64 {
            let o = mb_off(f);
            i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
        };
        let read_i32 = |f: &str| -> i32 {
            let o = mb_off(f);
            i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
        };
        let read_f32 = |f: &str| -> f32 {
            let o = mb_off(f);
            f32::from_le_bytes(b[o..o + 4].try_into().unwrap())
        };
        assert_eq!(read_i64("q_pos"), 3i64 << 32, "{label}: Fix64 7.5 / 2.5");
        assert_eq!(
            read_i64("q_neg"),
            -(3i64 << 32),
            "{label}: Fix64 -7.5 / 2.5"
        );
        assert_eq!(
            read_i64("q_frac"),
            ((1i128 << 64) / (3i128 << 32)) as i64,
            "{label}: Fix64 1/3"
        );
        assert_eq!(read_i64("q_zero"), 0, "{label}: Fix64 / 0 must yield 0");
        // acc starts at 1.25 and adds 0.5_f32 for 5 frames => 3.75 (0x3_c000_0000)
        assert_eq!(
            read_i64("acc"),
            (15i64 << 30),
            "{label}: fix64 += f32 accumulation mismatch"
        );
        assert_eq!(read_f32("mat_sum"), 6.0, "{label}: NB-2 mat_sum");
        assert_eq!(read_f32("mix_out"), 6.5, "{label}: mixed common_ty output");
        assert_eq!(read_i32("neg_i"), -42, "{label}: NB-1 negative default");
        let iv_o = mb_off("iv");
        let iv_x = i32::from_le_bytes(b[iv_o..iv_o + 4].try_into().unwrap());
        let iv_y = i32::from_le_bytes(b[iv_o + 4..iv_o + 8].try_into().unwrap());
        assert_eq!((iv_x, iv_y), (-1, -2), "{label}: NB-1 ivec2(-1, -2)");

        let de_h = find_component_handle(app.world(), "DefaultExtra");
        let de_ents = find_entities_with_handle(app.world(), de_h);
        assert_eq!(de_ents.len(), 1);
        let deb = read_entity_pod_bytes(app.world(), de_ents[0], de_h).unwrap();
        let kv = i32::from_le_bytes(
            deb[de_off("keep_v")..de_off("keep_v") + 4]
                .try_into()
                .unwrap(),
        );
        let kn = i32::from_le_bytes(
            deb[de_off("keep_neg")..de_off("keep_neg") + 4]
                .try_into()
                .unwrap(),
        );
        let kf = f32::from_le_bytes(
            deb[de_off("keep_f")..de_off("keep_f") + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!((kv, kn, kf), (42, -7, -1.5), "{label}: NB-3 DefaultExtra");

        let sid_o = os_off("stat_id");
        let check_opt = |sid: u32,
                         exp_sro: u32,
                         exp_nro: u32,
                         exp_srw: u32,
                         exp_nrw: u32,
                         exp_bro: u32,
                         exp_brw: u32,
                         exp_w: f32| {
            let ob = read_single_comp_bytes_by_u32_id(app.world(), "OptStat", sid_o, sid);
            let sro = u32::from_le_bytes(
                ob[os_off("some_ro")..os_off("some_ro") + 4]
                    .try_into()
                    .unwrap(),
            );
            let nro = u32::from_le_bytes(
                ob[os_off("none_ro")..os_off("none_ro") + 4]
                    .try_into()
                    .unwrap(),
            );
            let srw = u32::from_le_bytes(
                ob[os_off("some_rw")..os_off("some_rw") + 4]
                    .try_into()
                    .unwrap(),
            );
            let nrw = u32::from_le_bytes(
                ob[os_off("none_rw")..os_off("none_rw") + 4]
                    .try_into()
                    .unwrap(),
            );
            let bro = u32::from_le_bytes(
                ob[os_off("both_ro")..os_off("both_ro") + 4]
                    .try_into()
                    .unwrap(),
            );
            let brw = u32::from_le_bytes(
                ob[os_off("both_rw")..os_off("both_rw") + 4]
                    .try_into()
                    .unwrap(),
            );
            let sw =
                f32::from_le_bytes(ob[os_off("sum_w")..os_off("sum_w") + 4].try_into().unwrap());
            assert_eq!(
                (sro, nro, srw, nrw, bro, brw, sw),
                (exp_sro, exp_nro, exp_srw, exp_nrw, exp_bro, exp_brw, exp_w),
                "{label}: OptStat({sid})"
            );
        };
        check_opt(1, 5, 0, 5, 0, 5, 5, 35.0);
        check_opt(2, 0, 5, 0, 5, 0, 0, 0.0);
        check_opt(3, 0, 5, 5, 0, 0, 5, 0.0);
        check_opt(4, 5, 0, 0, 5, 5, 0, 15.0);

        let rw_h = find_component_handle(app.world(), "OptRW");
        for (sid, exp_bonus) in [(1u32, 40i32), (3u32, 50i32)] {
            let ent = find_entity_by_u32_id(app.world(), "OptStat", sid_o, sid);
            let rb = read_entity_pod_bytes(app.world(), ent, rw_h).unwrap();
            let bonus =
                i32::from_le_bytes(rb[rw_off("bonus")..rw_off("bonus") + 4].try_into().unwrap());
            assert_eq!(bonus, exp_bonus, "{label}: OptRW bonus for {sid}");
        }
    }
}

#[test]
fn option_combined_ro_and_rw_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::opt_both @version(1.0.0);

component OptRO {
    weight: f32 = 4.0,
}

component OptRW {
    bonus: i32 = 10,
}

component OptStat {
    stat_id: u32 = 0,
    both_ro: u32 = 0,
    both_rw: u32 = 0,
    neither: u32 = 0,
    sum_w: f32 = 0.0,
}

object OptBoth {
    OptStat { stat_id: 1 },
    OptRO { weight: 3.5 },
    OptRW { bonus: 10 },
}

object OptNeither {
    OptStat { stat_id: 2 },
}

object OptOnlyRW {
    OptStat { stat_id: 3 },
    OptRW { bonus: 20 },
}

object OptOnlyRO {
    OptStat { stat_id: 4 },
    OptRO { weight: 1.5 },
}

sys step_opt_both() {
    for row in query(st: &mut OptStat, ro: Option<&OptRO>, rw: Option<&mut OptRW>) {
        if row.ro.is_some() {
            row.st.both_ro += 1;
            row.st.sum_w += row.ro.unwrap().weight;
        }
        if row.rw.is_some() {
            row.st.both_rw += 1;
            row.rw.unwrap().bonus += 5;
        }
        if row.ro.is_none() && row.rw.is_none() {
            row.st.neither += 1;
        }
    }
}

schedule FixedUpdate { step_opt_both }
"#;
    let analyzed = analyze_source("parity_opt_both.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let field_off = |comp: &str, name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with(comp))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let os_off = |name: &str| field_off("OptStat", name);
    let rw_off = |name: &str| field_off("OptRW", name);

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_opt_both.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    for frame in 0..5u32 {
        app.world_mut().run_schedule(FixedUpdate);
        if matches!(frame, 0 | 4) {
            capture_snapshot(&out_dir, &format!("f{frame}"), app.world());
        }
    }
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "opt_both", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    let init_d = assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    for frame in 0..5u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 4) {
            let d = assert_four_way_snapshot(&format!("f{frame}"), &w_jit, &w_c99, &w_rg, &tier3);
            assert_ne!(d.sha256, init_d.sha256);
        }
    }

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let sid_o = os_off("stat_id");
        let check_opt = |sid: u32, exp_bro: u32, exp_brw: u32, exp_none: u32, exp_w: f32| {
            let ob = read_single_comp_bytes_by_u32_id(app.world(), "OptStat", sid_o, sid);
            let bro = u32::from_le_bytes(
                ob[os_off("both_ro")..os_off("both_ro") + 4]
                    .try_into()
                    .unwrap(),
            );
            let brw = u32::from_le_bytes(
                ob[os_off("both_rw")..os_off("both_rw") + 4]
                    .try_into()
                    .unwrap(),
            );
            let ne = u32::from_le_bytes(
                ob[os_off("neither")..os_off("neither") + 4]
                    .try_into()
                    .unwrap(),
            );
            let sw =
                f32::from_le_bytes(ob[os_off("sum_w")..os_off("sum_w") + 4].try_into().unwrap());
            assert_eq!(
                (bro, brw, ne, sw),
                (exp_bro, exp_brw, exp_none, exp_w),
                "{label}: OptStat({sid})"
            );
        };
        check_opt(1, 5, 5, 0, 17.5);
        check_opt(2, 0, 0, 5, 0.0);
        check_opt(3, 0, 5, 0, 0.0);
        check_opt(4, 5, 0, 0, 7.5);

        let rw_h = find_component_handle(app.world(), "OptRW");
        for (sid, exp_bonus) in [(1u32, 35i32), (3u32, 45i32)] {
            let ent = find_entity_by_u32_id(app.world(), "OptStat", sid_o, sid);
            let rb = read_entity_pod_bytes(app.world(), ent, rw_h).unwrap();
            let bonus =
                i32::from_le_bytes(rb[rw_off("bonus")..rw_off("bonus") + 4].try_into().unwrap());
            assert_eq!(bonus, exp_bonus, "{label}: OptRW bonus for {sid}");
        }
    }
}

#[test]
fn param_set_task_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::pset_task @version(1.0.0);

component Actor {
    actor_id: u32 = 0,
    alive: bool = true,
    hp: f32 = 100.0,
}

tag TagA;

task ProcessOrder(target: Ref<Actor>)
    on (a: &Actor)
{
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            if t.tgt.alive {
                t.tgt.hp -= 10.0;
            }
        }
    }
    yield_tick;
    let _done: bool = true;
}

task DelayedStrike(target: Ref<Actor>)
    on (a: &Actor)
{
    yield_tick;
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            if t.tgt.alive {
                t.tgt.hp -= 5.0;
            }
        }
    }
}

sys setup() {
    let tgt = spawn { Actor { actor_id: 1, alive: true, hp: 100.0 }, TagA {} };
    let runner = spawn { Actor { actor_id: 2, alive: true, hp: 50.0 } };
    let passive = spawn { Actor { actor_id: 3, alive: false, hp: 20.0 } };
    insert(runner, ProcessOrder::start(tgt));
    insert(runner, DelayedStrike::start(tgt));
    let _ = passive;
}

sys disjoint_steps() {
    for r in query(a: &mut Actor).with<TagA>() {
        r.a.hp += 1.0;
    }
    for r in query(a: &mut Actor).without<TagA>() {
        r.a.hp += 2.0;
    }
}

schedule Startup { setup }
schedule FixedUpdate {
    seq Step { ProcessOrder, DelayedStrike, disjoint_steps }
}

sim_test "param_set_process_order_and_disjoint_queries" {
    step_fixed(1);
    let mut hp1: f32 = 0.0;
    let mut hp2: f32 = 0.0;
    let mut hp3: f32 = 0.0;
    for r in query(a: &Actor) {
        if r.a.actor_id == 1 {
            hp1 = r.a.hp;
        }
        if r.a.actor_id == 2 {
            hp2 = r.a.hp;
        }
        if r.a.actor_id == 3 {
            hp3 = r.a.hp;
        }
    }
    assert(hp1 == 91.0);
    assert(hp2 == 52.0);
    assert(hp3 == 22.0);

    step_fixed(2);
    for r in query(a: &Actor) {
        if r.a.actor_id == 1 {
            hp1 = r.a.hp;
        }
        if r.a.actor_id == 2 {
            hp2 = r.a.hp;
        }
        if r.a.actor_id == 3 {
            hp3 = r.a.hp;
        }
    }
    assert(hp1 == 88.0);
    assert(hp2 == 56.0);
    assert(hp3 == 26.0);
}
"#;
    let analyzed = analyze_source("parity_pset_task.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let actor_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("Actor"))
        .expect("Actor layout");
    let off_id = actor_layout
        .fields
        .iter()
        .find(|f| f.name == "actor_id")
        .unwrap()
        .offset;
    let off_alive = actor_layout
        .fields
        .iter()
        .find(|f| f.name == "alive")
        .unwrap()
        .offset;
    let off_hp = actor_layout
        .fields
        .iter()
        .find(|f| f.name == "hp")
        .unwrap()
        .offset;

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_pset_task.strata");
    fs::write(&src_path, src).unwrap();

    // Verify `stratac test` passes with exit 0 and zero ACCESS_CONFLICT.
    let (test_code, test_out) = cmd_test(&src_path, OutputFormat::Text);
    assert_eq!(test_code, 0, "stratac test failed:\n{test_out}");
    assert!(
        !test_out.contains("ACCESS_CONFLICT"),
        "unexpected ACCESS_CONFLICT in stratac test output:\n{test_out}"
    );
    assert!(
        test_out.contains("PASS"),
        "expected PASS in stratac test output:\n{test_out}"
    );

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    dump_comp_bytes(&out_dir, "init_actor", app.world(), "Actor");
    for frame in 0..3u32 {
        app.world_mut().run_schedule(FixedUpdate);
        capture_snapshot(&out_dir, &format!("f{frame}"), app.world());
        dump_comp_bytes(&out_dir, &format!("f{frame}_actor"), app.world(), "Actor");
    }
    dump_comp_bytes(&out_dir, "actors_final", app.world(), "Actor");
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "pset_task", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    // On `init` and `f0`, active `TaskState` components store opaque host `Entity` bits
    // (`Ref<Actor>`), which match identically across all 3 dynamic ModHost worlds
    // (JIT == C99 == RustGuest), while Tier 3 native registration allocates 1 extra internal
    // Bevy world entity (`EntityRow` offset by 1). Verify 3-way full WorldPodDigest + 4-way
    // `Actor` POD parity on `init`/`f0`, and full 4-way WorldPodDigest parity once tasks finish
    // on `f1`/`f2`.
    let assert_three_way_dyn = |tag: &str, wj: &App, wc: &App, wr: &App| -> WorldPodDigest {
        let d_jit = hash_world_pod_state(wj.world());
        let d_c99 = hash_world_pod_state(wc.world());
        let d_rg = hash_world_pod_state(wr.world());
        assert!(d_jit.pod_bytes_hashed > 0, "{tag}: empty POD state");
        assert_eq!(d_jit.sha256, d_c99.sha256, "{tag}: JIT vs C99");
        assert_eq!(d_jit.sha256, d_rg.sha256, "{tag}: JIT vs RustGuest");
        assert_eq!(d_jit.fnv1a64, d_c99.fnv1a64, "{tag}: fnv1a64 JIT vs C99");
        assert_eq!(
            d_jit.fnv1a64, d_rg.fnv1a64,
            "{tag}: fnv1a64 JIT vs RustGuest"
        );
        assert_eq!(d_jit.entity_count, 3);
        assert_eq!(tier3.digests[tag].entity_count, 3);
        d_jit
    };

    let init_d = assert_three_way_dyn("init", &w_jit, &w_c99, &w_rg);

    let check_actors = |tag: &str, wj: &App, wc: &App, wr: &App, exp: [(u32, bool, f32); 3]| {
        for (label, app) in [("jit", wj), ("c99", wc), ("rust_guest", wr)] {
            for (aid, exp_alive, exp_hp) in exp {
                let b = read_single_comp_bytes_by_u32_id(app.world(), "Actor", off_id, aid);
                let alive = b[off_alive] != 0;
                let hp = f32::from_le_bytes(b[off_hp..off_hp + 4].try_into().unwrap());
                assert_eq!(
                    (alive, hp),
                    (exp_alive, exp_hp),
                    "{tag} {label}: Actor({aid}) mismatch"
                );
            }
        }
        let actor_h = find_component_handle(wj.world(), "Actor");
        let mut jit_actor_bytes = Vec::new();
        for ent in find_entities_with_handle(wj.world(), actor_h) {
            jit_actor_bytes
                .extend_from_slice(&read_entity_pod_bytes(wj.world(), ent, actor_h).unwrap());
        }
        assert_eq!(
            jit_actor_bytes,
            tier3.pod_dumps[&format!("{tag}_actor")],
            "{tag}: Tier 3 Actor POD bytes must match JIT/C99/RustGuest bit-for-bit"
        );
    };

    check_actors(
        "init",
        &w_jit,
        &w_c99,
        &w_rg,
        [(1, true, 100.0), (2, true, 50.0), (3, false, 20.0)],
    );

    let expected_by_frame = [
        [(1, true, 91.0), (2, true, 52.0), (3, false, 22.0)],
        [(1, true, 87.0), (2, true, 54.0), (3, false, 24.0)],
        [(1, true, 88.0), (2, true, 56.0), (3, false, 26.0)],
    ];

    let mut prev_sha = init_d.sha256;
    for (frame, exp) in expected_by_frame.into_iter().enumerate() {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);

        let tag = format!("f{frame}");
        let d = if frame == 0 {
            assert_three_way_dyn(&tag, &w_jit, &w_c99, &w_rg)
        } else {
            assert_four_way_snapshot(&tag, &w_jit, &w_c99, &w_rg, &tier3)
        };
        assert_ne!(d.sha256, prev_sha, "frame {frame}: state must advance");
        prev_sha = d.sha256;
        check_actors(&tag, &w_jit, &w_c99, &w_rg, exp);
    }

    // Also verify Tier 3 raw Actor POD dump matches dynamic backends bit-for-bit.
    let actor_h = find_component_handle(w_jit.world(), "Actor");
    let mut jit_actor_bytes = Vec::new();
    for ent in find_entities_with_handle(w_jit.world(), actor_h) {
        jit_actor_bytes
            .extend_from_slice(&read_entity_pod_bytes(w_jit.world(), ent, actor_h).unwrap());
    }
    assert_eq!(
        jit_actor_bytes, tier3.pod_dumps["actors_final"],
        "Tier 3 final Actor POD bytes must match JIT/C99/RustGuest bit-for-bit"
    );
}

#[test]
fn nb123_object_struct_ivec_runtime_precision_and_fix64_variants_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::nb123_fix64 @version(1.0.0);

enum Kind { Alpha = 0, Beta = 1 }

struct Pair {
    a: i32,
    b: u32,
}

struct Inner {
    x: i32 = -7,
    y: u32 = 3000000001,
    pts: [ivec2; 2] = [ivec2(16777217, -16777219), ivec2(1, 2)],
}

struct Outer {
    pad: i32 = 9,
    inner: Inner = Inner { x: -7, y: 3000000001, pts: [ivec2(16777217, -16777219), ivec2(1, 2)] },
}

const C_INNER: Inner = Inner { x: 1, y: 3000000001, pts: [ivec2(16777217, -16777219), ivec2(1, 2)] };

component Payload {
    id: u32 = 1,
    one: Pair = Pair { a: 0, b: 0 },
    pairs: [Pair; 2] = [Pair { a: 0, b: 0 }, Pair { a: 0, b: 0 }],
    pts: [ivec2; 2] = [ivec2(0, 0), ivec2(0, 0)],
    kind: Kind = Kind::Alpha,
    kinds: [Kind; 2] = [Kind::Alpha, Kind::Beta],
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0, 0),
    acc: fix64 = 1.0,
    out_local: fix64 = 0.0,
    outer: Outer = Outer { pad: 9, inner: Inner { x: -7, y: 3000000001, pts: [ivec2(16777217, -16777219), ivec2(1, 2)] } },
    mat_pair: [[Pair; 2]; 2] = [[Pair { a: -1, b: 3000000001 }, Pair { a: 2, b: 3 }], [Pair { a: 4, b: 5 }, Pair { a: 6, b: 7 }]],
    cast_i32: i32 = 0,
    cast_fix: fix64 = 0.0,
    iv_bin: ivec2 = ivec2(0, 0),
    uv_cast: uvec2 = uvec2(0, 0),
    c_in: Inner = Inner { x: 0, y: 0, pts: [ivec2(0, 0), ivec2(0, 0)] },
    out_y: u32 = 0,
    out_pt0: ivec2 = ivec2(0, 0),
    out_mat_b: u32 = 0,
}

object ObjOverride {
    Payload {
        id: 1,
        one: Pair { a: 30000001, b: 3000000001 },
        pairs: [Pair { a: -7, b: 9 }, Pair { a: 11, b: 13 }],
        pts: [ivec2(30000003, -30000005), ivec2(42, -99)],
        kind: Kind::Beta,
        kinds: [Kind::Beta, Kind::Alpha],
        cast_i32: 3.9_f32 as i32,
        cast_fix: 3.9_f32 as i32,
        iv_bin: ivec2(-2147483647 - 1, 2147483647),
        uv_cast: uvec2((-1_i32) as u32, (-(-5)) as u32),
        c_in: C_INNER,
    },
}

fn make_iv3(x: i32, y: i32, z: i32) -> ivec3 {
    return ivec3(x, y, z);
}

sys step_payload() {
    for r in query(p: &mut Payload) {
        r.p.iv = ivec2(30000001, -30000007);
        r.p.iv3 = make_iv3(30000011, -30000013, 30000017);
        r.p.uv = uvec2(3000000001, 4000000003);
        r.p.acc += 0.5_f32;
        let delta: fix64 = 0.25;
        let mut lx: fix64 = 2.5;
        lx += delta;
        r.p.out_local = lx;
        r.p.out_y = r.p.outer.inner.y;
        r.p.out_pt0 = r.p.outer.inner.pts[0];
        r.p.out_mat_b = r.p.mat_pair[0][0].b;
    }
}

schedule FixedUpdate { step_payload }
"#;
    let analyzed = analyze_source("parity_nb123.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let p_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("Payload"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_nb123.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "f0", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "nb123_fix64", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b = read_single_comp_bytes_by_u32_id(app.world(), "Payload", p_off("id"), 1);
        let one_a = i32::from_le_bytes(b[p_off("one")..p_off("one") + 4].try_into().unwrap());
        let one_b = u32::from_le_bytes(b[p_off("one") + 4..p_off("one") + 8].try_into().unwrap());
        let pt0_x = i32::from_le_bytes(b[p_off("pts")..p_off("pts") + 4].try_into().unwrap());
        let pt0_y = i32::from_le_bytes(b[p_off("pts") + 4..p_off("pts") + 8].try_into().unwrap());
        let kind = b[p_off("kind")];
        let kinds0 = b[p_off("kinds")];
        let kinds1 = b[p_off("kinds") + 1];
        let cast_i32 = i32::from_le_bytes(
            b[p_off("cast_i32")..p_off("cast_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let cast_fix = i64::from_le_bytes(
            b[p_off("cast_fix")..p_off("cast_fix") + 8]
                .try_into()
                .unwrap(),
        );
        let ivb0 = i32::from_le_bytes(b[p_off("iv_bin")..p_off("iv_bin") + 4].try_into().unwrap());
        let ivb1 = i32::from_le_bytes(
            b[p_off("iv_bin") + 4..p_off("iv_bin") + 8]
                .try_into()
                .unwrap(),
        );
        let uvc0 = u32::from_le_bytes(
            b[p_off("uv_cast")..p_off("uv_cast") + 4]
                .try_into()
                .unwrap(),
        );
        let uvc1 = u32::from_le_bytes(
            b[p_off("uv_cast") + 4..p_off("uv_cast") + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            (one_a, one_b, pt0_x, pt0_y, kind, kinds0, kinds1),
            (30000001, 3000000001, 30000003, -30000005, 1, 1, 0),
            "{label}: init object overrides mismatch"
        );
        assert_eq!(
            (cast_i32, cast_fix, ivb0, ivb1, uvc0, uvc1),
            (3, 3i64 << 32, i32::MIN, i32::MAX, u32::MAX, 5),
            "{label}: init cast/ivec/uvec object overrides mismatch"
        );
    }

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);
    assert_four_way_snapshot("f0", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b = read_single_comp_bytes_by_u32_id(app.world(), "Payload", p_off("id"), 1);
        let iv_x = i32::from_le_bytes(b[p_off("iv")..p_off("iv") + 4].try_into().unwrap());
        let iv_y = i32::from_le_bytes(b[p_off("iv") + 4..p_off("iv") + 8].try_into().unwrap());
        let iv3_x = i32::from_le_bytes(b[p_off("iv3")..p_off("iv3") + 4].try_into().unwrap());
        let iv3_y = i32::from_le_bytes(b[p_off("iv3") + 4..p_off("iv3") + 8].try_into().unwrap());
        let iv3_z = i32::from_le_bytes(b[p_off("iv3") + 8..p_off("iv3") + 12].try_into().unwrap());
        let uv_x = u32::from_le_bytes(b[p_off("uv")..p_off("uv") + 4].try_into().unwrap());
        let uv_y = u32::from_le_bytes(b[p_off("uv") + 4..p_off("uv") + 8].try_into().unwrap());
        let acc_raw = i64::from_le_bytes(b[p_off("acc")..p_off("acc") + 8].try_into().unwrap());
        let local_raw = i64::from_le_bytes(
            b[p_off("out_local")..p_off("out_local") + 8]
                .try_into()
                .unwrap(),
        );
        let out_y = u32::from_le_bytes(b[p_off("out_y")..p_off("out_y") + 4].try_into().unwrap());
        let out_pt0_x = i32::from_le_bytes(
            b[p_off("out_pt0")..p_off("out_pt0") + 4]
                .try_into()
                .unwrap(),
        );
        let out_pt0_y = i32::from_le_bytes(
            b[p_off("out_pt0") + 4..p_off("out_pt0") + 8]
                .try_into()
                .unwrap(),
        );
        let out_mat_b = u32::from_le_bytes(
            b[p_off("out_mat_b")..p_off("out_mat_b") + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            (iv_x, iv_y, iv3_x, iv3_y, iv3_z, uv_x, uv_y),
            (
                30000001, -30000007, 30000011, -30000013, 30000017, 3000000001, 4000000003
            ),
            "{label}: runtime ivec/uvec >2^24 precision mismatch"
        );
        assert_eq!(
            (acc_raw, local_raw),
            (3i64 << 31, 11i64 << 30),
            "{label}: fix64 += f32/local delta mismatch"
        );
        assert_eq!(
            (out_y, out_pt0_x, out_pt0_y, out_mat_b),
            (3000000001, 16777217, -16777219, 3000000001),
            "{label}: nested struct non-zero-offset read mismatch"
        );
    }
}

#[test]
fn option_zst_sparse_if_let_match_expect_and_single_term_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::opt_matrix @version(1.0.0);

tag TagZ;

@sparse
component Sp {
    bonus: i32 = 0,
}

component Shield {
    hp: f32 = 10.0,
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component Out {
    id: u32 = 0,
    tag_hits: i32 = 0,
    tag_misses: i32 = 0,
    sp_sum: i32 = 0,
    iflet_sum: f32 = 0.0,
    match_sum: f32 = 0.0,
    rev_match_sum: i32 = 0,
    rev_wild_sum: i32 = 0,
}

resource SingleRes {
    some_cnt: i32 = 0,
    none_cnt: i32 = 0,
    expect_hp: f32 = 0.0,
    unwrap_hp: f32 = 0.0,
    iflet_hp: f32 = 0.0,
    match_hp: f32 = 0.0,
    oc_pad: i32 = 0,
    oc_hp: f32 = 0.0,
    oc_changed: i32 = 0,
}

component ResSnap {
    id: u32 = 99,
    some_cnt: i32 = 0,
    none_cnt: i32 = 0,
    expect_hp: f32 = 0.0,
    unwrap_hp: f32 = 0.0,
    iflet_hp: f32 = 0.0,
    match_hp: f32 = 0.0,
    oc_pad: i32 = 0,
    oc_hp: f32 = 0.0,
    oc_changed: i32 = 0,
}

object Obj1 {
    Out { id: 1 },
    TagZ {},
    Sp { bonus: 10 },
    Shield { hp: 12.0 },
    OtherComp { pad: 123, hp: 55.0 },
}

object Obj2 {
    Out { id: 2 },
    TagZ {},
}

object Obj3 {
    Out { id: 3 },
    Sp { bonus: 20 },
}

object Obj4 {
    Out { id: 4 },
    Shield { hp: 8.0 },
}

object ObjSnap {
    ResSnap { id: 99 },
}

sys check_tag_and_sparse() {
    for row in query(o: &mut Out, tg: Option<&TagZ>, sp: Option<&mut Sp>) {
        if let Some(_) = row.tg {
            row.o.tag_hits += 1;
        } else {
            row.o.tag_misses += 1;
        }
        match row.sp {
            Some(s) => {
                s.bonus += 5;
                row.o.sp_sum += s.bonus;
            },
            None => {
                row.o.sp_sum -= 1;
            },
        }
    }
}

sys check_iflet_and_match() {
    for row in query(o: &mut Out, sh: Option<&Shield>, oc: Option<&mut OtherComp>) {
        if let Some(x) = row.sh {
            row.o.iflet_sum += x.hp;
        }
        match row.sh {
            Some(x) => { row.o.match_sum += x.hp * 2.0; },
            None => { row.o.match_sum += 1.0; },
        }
        if row.oc.is_some() {
            let op = row.oc.expect("oc present");
            op.hp += 1.0;
        }
        match row.oc {
            None => { row.o.rev_match_sum -= 2; },
            Some(x) => { row.o.rev_match_sum += x.pad; },
        }
        match row.oc {
            None => { row.o.rev_wild_sum -= 3; },
            _ => { row.o.rev_wild_sum += 7; },
        }
    }
}

sys check_oc_changed(sr: &mut res SingleRes) {
    for r in query(oc: &OtherComp).changed<OtherComp>() {
        sr.oc_changed += 1;
        sr.oc_pad = r.oc.pad;
        sr.oc_hp = r.oc.hp;
    }
}

sys check_single_term(sr: &mut res SingleRes) {
    for sh in query(sh: Option<&mut Shield>).with<Out>() {
        if sh.is_some() && !sh.is_none() {
            sr.some_cnt += 1;
            sr.unwrap_hp += sh.unwrap().hp;
            let p = sh.expect("shield present");
            p.hp += 3.0;
            sr.expect_hp += p.hp;
        }
        if sh.is_none() {
            sr.none_cnt += 1;
        }
        if let Some(x) = sh {
            sr.iflet_hp += x.hp;
        }
        match sh {
            Some(x) => { sr.match_hp += x.hp + 1.0; },
            None => { sr.match_hp += 100.0; },
        }
    }
}

sys flush_snap(sr: &res SingleRes) {
    for r in query(s: &mut ResSnap) {
        r.s.some_cnt = sr.some_cnt;
        r.s.none_cnt = sr.none_cnt;
        r.s.expect_hp = sr.expect_hp;
        r.s.unwrap_hp = sr.unwrap_hp;
        r.s.iflet_hp = sr.iflet_hp;
        r.s.match_hp = sr.match_hp;
        r.s.oc_pad = sr.oc_pad;
        r.s.oc_hp = sr.oc_hp;
        r.s.oc_changed = sr.oc_changed;
    }
}

schedule FixedUpdate {
    seq OrderedAll {
        check_tag_and_sparse,
        check_iflet_and_match,
        check_oc_changed,
        check_single_term,
        flush_snap,
    }
}
"#;
    let analyzed = analyze_source("parity_opt_matrix.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let out_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("Out"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let rs_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("ResSnap"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_opt_matrix.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "f0", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "opt_matrix", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let chk_out = |id: u32,
                       exp_th: i32,
                       exp_tm: i32,
                       exp_sp: i32,
                       exp_il: f32,
                       exp_ms: f32,
                       exp_rms: i32,
                       exp_rws: i32| {
            let b = read_single_comp_bytes_by_u32_id(app.world(), "Out", out_off("id"), id);
            let th = i32::from_le_bytes(
                b[out_off("tag_hits")..out_off("tag_hits") + 4]
                    .try_into()
                    .unwrap(),
            );
            let tm = i32::from_le_bytes(
                b[out_off("tag_misses")..out_off("tag_misses") + 4]
                    .try_into()
                    .unwrap(),
            );
            let sp = i32::from_le_bytes(
                b[out_off("sp_sum")..out_off("sp_sum") + 4]
                    .try_into()
                    .unwrap(),
            );
            let il = f32::from_le_bytes(
                b[out_off("iflet_sum")..out_off("iflet_sum") + 4]
                    .try_into()
                    .unwrap(),
            );
            let ms = f32::from_le_bytes(
                b[out_off("match_sum")..out_off("match_sum") + 4]
                    .try_into()
                    .unwrap(),
            );
            let rms = i32::from_le_bytes(
                b[out_off("rev_match_sum")..out_off("rev_match_sum") + 4]
                    .try_into()
                    .unwrap(),
            );
            let rws = i32::from_le_bytes(
                b[out_off("rev_wild_sum")..out_off("rev_wild_sum") + 4]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(
                (th, tm, sp, il, ms, rms, rws),
                (exp_th, exp_tm, exp_sp, exp_il, exp_ms, exp_rms, exp_rws),
                "{label}: Out({id}) mismatch"
            );
        };
        chk_out(1, 1, 0, 15, 12.0, 24.0, 123, 7);
        chk_out(2, 1, 0, -1, 0.0, 1.0, -2, -3);
        chk_out(3, 0, 1, 25, 0.0, 1.0, -2, -3);
        chk_out(4, 0, 1, -1, 8.0, 16.0, -2, -3);

        let sh_h = find_component_handle(app.world(), "Shield");
        let sh_hp1 = {
            let mut v = Vec::new();
            for ent in find_entities_with_handle(app.world(), sh_h) {
                let sb = read_entity_pod_bytes(app.world(), ent, sh_h).unwrap();
                v.push(f32::from_le_bytes(sb[0..4].try_into().unwrap()));
            }
            v
        };

        let rb = read_single_comp_bytes_by_u32_id(app.world(), "ResSnap", rs_off("id"), 99);
        let sc = i32::from_le_bytes(
            rb[rs_off("some_cnt")..rs_off("some_cnt") + 4]
                .try_into()
                .unwrap(),
        );
        let nc = i32::from_le_bytes(
            rb[rs_off("none_cnt")..rs_off("none_cnt") + 4]
                .try_into()
                .unwrap(),
        );
        let ehp = f32::from_le_bytes(
            rb[rs_off("expect_hp")..rs_off("expect_hp") + 4]
                .try_into()
                .unwrap(),
        );
        let uhp = f32::from_le_bytes(
            rb[rs_off("unwrap_hp")..rs_off("unwrap_hp") + 4]
                .try_into()
                .unwrap(),
        );
        let ihp = f32::from_le_bytes(
            rb[rs_off("iflet_hp")..rs_off("iflet_hp") + 4]
                .try_into()
                .unwrap(),
        );
        let mhp = f32::from_le_bytes(
            rb[rs_off("match_hp")..rs_off("match_hp") + 4]
                .try_into()
                .unwrap(),
        );
        let oc_pad = i32::from_le_bytes(
            rb[rs_off("oc_pad")..rs_off("oc_pad") + 4]
                .try_into()
                .unwrap(),
        );
        let oc_hp =
            f32::from_le_bytes(rb[rs_off("oc_hp")..rs_off("oc_hp") + 4].try_into().unwrap());
        let oc_changed = i32::from_le_bytes(
            rb[rs_off("oc_changed")..rs_off("oc_changed") + 4]
                .try_into()
                .unwrap(),
        );
        /* Entities with Out: Obj1(Shield 12), Obj2(none), Obj3(none), Obj4(Shield 8) -> some=2, none=2;
        unwrap=20, expect=(15+11)=26, iflet=26, match=(16+12)+2*100=228 */
        assert_eq!(
            (sc, nc, uhp, ehp, ihp, mhp),
            (2, 2, 20.0, 26.0, 26.0, 228.0),
            "{label}: SingleRes snapshot mismatch (shield_hps={sh_hp1:?})"
        );
        assert_eq!(
            (oc_changed, oc_pad, oc_hp),
            (1, 123, 56.0),
            "{label}: let-bound expect() non-offset-0 mutation + Changed<OtherComp> mismatch"
        );
    }
    assert_four_way_snapshot("f0", &w_jit, &w_c99, &w_rg, &tier3);
}

#[test]
fn step2_iter3_all_seven_fixes_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::step2_iter3 @version(1.0.0);

tag TagA;
tag TagB;

enum Kind16 {
    Low = 1,
    High = 60000,
}

@repr(u16)
enum Explicit16 {
    Zero = 0,
    One = 1,
}

struct WithInlineStr {
    label: InlineStr<16> = "init",
    k: Kind16 = Kind16::High,
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component BoxAll {
    id: u32 = 0,
    uv_one: uvec2 = uvec2::ZERO,
    uv_x: uvec2 = uvec2::ZERO,
    uv_y: uvec2 = uvec2::ZERO,
    iv_x: ivec2 = ivec2::ZERO,
    iv_y: ivec2 = ivec2::ZERO,
    iv3_x: ivec3 = ivec3::ZERO,
    iv3_y: ivec3 = ivec3::ZERO,
    iv3_z: ivec3 = ivec3::ZERO,
    v2_x: vec2 = vec2::ZERO,
    v3_up: vec3 = vec3::ZERO,
    v4_w: vec4 = vec4::ZERO,
    neg_i32: i32 = 0,
    neg_u32: u32 = 99,
    neg_u64: u64 = 99,
    k16: Kind16 = Kind16::Low,
    arr16: [Kind16; 2] = [Kind16::Low, Kind16::Low],
    e16: Explicit16 = Explicit16::Zero,
    w: WithInlineStr = WithInlineStr { label: "init", k: Kind16::High },
    shadow_iflet: i32 = 0,
    acc_out: i32 = 0,
    oc_changed: i32 = 0,
}

object ObjA {
    BoxAll {
        id: 1,
        uv_one: uvec2::ONE,
        uv_x: uvec2::X,
        uv_y: uvec2::Y,
        iv_x: ivec2::X,
        iv_y: ivec2::Y,
        iv3_x: ivec3::X,
        iv3_y: ivec3::Y,
        iv3_z: ivec3::Z,
        v2_x: vec2::X,
        v3_up: vec3::UP,
        v4_w: vec4::W,
        neg_i32: (-3.9_f32) as i32,
        neg_u32: (-3.9_f32) as u32,
        neg_u64: (-3.9_f32) as u64,
        k16: Kind16::High,
        arr16: [Kind16::High, Kind16::Low],
        e16: Explicit16::One,
    },
    TagA {},
    OtherComp { pad: 123, hp: 55.0 },
}

object ObjB {
    BoxAll { id: 2 },
    TagB {},
    OtherComp { pad: 123, hp: 70.0 },
}

object ObjNone {
    BoxAll { id: 3 },
}

sys step_iflet() {
    for row in query(b: &mut BoxAll, oc: Option<&mut OtherComp>) {
        let x: i32 = 999;
        let mut acc: i32 = 10;
        if let Some(x) = row.oc {
            let x2 = x;
            x2.hp += 1.0;
        }
        if true {
            let y: i32 = 77;
            acc += y;
        }
        row.b.shadow_iflet = x;
        row.b.acc_out = acc;
    }
}

sys step_single_oc_a() {
    for oc in query(oc: Option<&mut OtherComp>).with<TagA>() {
        if oc.is_some() {
            let op = oc.expect("single oc");
            let op2 = op;
            op2.hp += 3.0;
        }
    }
}

sys step_single_oc_b() {
    for row in query(oc: Option<&mut OtherComp>).with<TagB>() {
        if row.oc.is_some() {
            let op = row.oc.expect("row single oc");
            let op2 = op;
            op2.hp += 4.0;
        }
    }
}

sys count_changed() {
    let mut cnt: i32 = 0;
    for r in query(oc: &OtherComp).changed<OtherComp>() {
        let _ = r.oc.pad;
        cnt += 1;
    }
    for r in query(b: &mut BoxAll) {
        r.b.oc_changed = cnt;
    }
}

schedule FixedUpdate {
    seq OrderedAll {
        step_iflet,
        step_single_oc_a,
        step_single_oc_b,
        count_changed,
    }
}
"#;
    let analyzed = analyze_source("parity_iter3.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let b_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("BoxAll"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter3.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "f0", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter3", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);
    assert_four_way_snapshot("f0", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b1 = read_single_comp_bytes_by_u32_id(app.world(), "BoxAll", b_off("id"), 1);
        let uo0 = u32::from_le_bytes(b1[b_off("uv_one")..b_off("uv_one") + 4].try_into().unwrap());
        let uo1 = u32::from_le_bytes(
            b1[b_off("uv_one") + 4..b_off("uv_one") + 8]
                .try_into()
                .unwrap(),
        );
        let ni = i32::from_le_bytes(
            b1[b_off("neg_i32")..b_off("neg_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let nu = u32::from_le_bytes(
            b1[b_off("neg_u32")..b_off("neg_u32") + 4]
                .try_into()
                .unwrap(),
        );
        let nu64 = u64::from_le_bytes(
            b1[b_off("neg_u64")..b_off("neg_u64") + 8]
                .try_into()
                .unwrap(),
        );
        let k16 = u16::from_le_bytes(b1[b_off("k16")..b_off("k16") + 2].try_into().unwrap());
        let a16_0 = u16::from_le_bytes(b1[b_off("arr16")..b_off("arr16") + 2].try_into().unwrap());
        let a16_1 = u16::from_le_bytes(
            b1[b_off("arr16") + 2..b_off("arr16") + 4]
                .try_into()
                .unwrap(),
        );
        let w_len = u32::from_le_bytes(b1[b_off("w")..b_off("w") + 4].try_into().unwrap());
        let sh = i32::from_le_bytes(
            b1[b_off("shadow_iflet")..b_off("shadow_iflet") + 4]
                .try_into()
                .unwrap(),
        );
        let acc = i32::from_le_bytes(
            b1[b_off("acc_out")..b_off("acc_out") + 4]
                .try_into()
                .unwrap(),
        );
        let chg = i32::from_le_bytes(
            b1[b_off("oc_changed")..b_off("oc_changed") + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            (uo0, uo1, ni, nu, nu64),
            (1, 1, -3, 0, 0),
            "{label}: vec/cast mismatch"
        );
        assert_eq!(
            (k16, a16_0, a16_1, w_len),
            (60000, 60000, 1, 4),
            "{label}: enum16/inlinestr mismatch"
        );
        assert_eq!(
            &b1[b_off("w") + 4..b_off("w") + 8],
            b"init",
            "{label}: InlineStr bytes mismatch"
        );
        assert_eq!(
            (sh, acc, chg),
            (999, 87, 2),
            "{label}: shadow_iflet/acc/oc_changed mismatch"
        );
    }
}

#[test]
fn step2_iter4_all_four_bugs_and_float_sat_four_way_parity() {
    let src = r#"module test::parity_iter4 @version(1.0.0);

enum NegAuto {
    Neg = -5,
    Zero = 0,
    Pos = 5,
}

@repr(i32)
enum NegExplicit {
    MinNeg = -300,
    BigPos = 70000,
}

component BoxAll {
    id: u32 = 0,
    neg_a: NegAuto = NegAuto::Neg,
    neg_e: NegExplicit = NegExplicit::MinNeg,
    arr_neg: [NegAuto; 2] = [NegAuto::Neg, NegAuto::Pos],
    ov_f64_u64: u64 = 0,
    ov_huge_i8: i8 = 0,
    ov_nhuge_i8: i8 = 0,
    ov_huge_u8: u8 = 0,
    rt_huge_i8: i8 = 0,
    rt_nhuge_i8: i8 = 0,
    rt_huge_i32: i32 = 0,
    rt_nhuge_i32: i32 = 0,
    rt_huge_i64: i64 = 0,
    rt_nhuge_i64: i64 = 0,
    rt_nan_i32: i32 = 77,
    rt_nan_i64: i64 = 88,
    row_alias_sum: i32 = 0,
    f_big32: f32 = 1e20_f32,
    f_nbig32: f32 = -1e20_f32,
    f_big64: f64 = 1e25_f64,
    f_nbig64: f64 = -1e25_f64,
    f_zero: f32 = 0.0_f32,
}

component Wallet1 {
    id: u32 = 0,
    coins: i32 = 100,
}

component Wallet2 {
    id: u32 = 0,
    coins: i32 = 200,
}

component MissingComp {
    id: u32 = 0,
}

object ObjBox {
    BoxAll {
        id: 1,
        neg_a: NegAuto::Pos,
        neg_e: NegExplicit::MinNeg,
        arr_neg: [NegAuto::Pos, NegAuto::Neg],
        ov_f64_u64: (1000000000000001.0_f64) as u64,
        ov_huge_i8: (1e20_f32) as i8,
        ov_nhuge_i8: (-1e20_f32) as i8,
        ov_huge_u8: (300.0_f32) as u8,
    },
}

object ObjW1 { Wallet1 { id: 10, coins: 100 } }
object ObjW2 { Wallet2 { id: 20, coins: 200 } }
object ObjNoWallet { MissingComp { id: 30 } }

sys step_row_and_q1_a() {
    for row in query(b: &mut BoxAll) {
        let row2 = row;
        let row3 = row2;
        row3.b.row_alias_sum += 10;
        row3.b.rt_huge_i8 = (row3.b.f_big32) as i8;
        row3.b.rt_nhuge_i8 = (row3.b.f_nbig32) as i8;
        row3.b.rt_huge_i32 = (row3.b.f_big32) as i32;
        row3.b.rt_nhuge_i32 = (row3.b.f_nbig32) as i32;
        row3.b.rt_huge_i64 = (row3.b.f_big64) as i64;
        row3.b.rt_nhuge_i64 = (row3.b.f_nbig64) as i64;
        let nan32: f32 = row3.b.f_zero / row3.b.f_zero;
        let nan64: f64 = (nan32) as f64;
        row3.b.rt_nan_i32 = (nan32) as i32;
        row3.b.rt_nan_i64 = (nan64) as i64;
    }
    if let Some(wrow) = query_one(w: &mut Wallet1).on(ObjW1) {
        let wrow2 = wrow;
        wrow2.w.coins += 10;
    }
    let r2 = query_one(w: &mut Wallet2).on(ObjW2).expect("w2");
    r2.w.coins += 7;
}

sys step_row_and_q1_b() {
    let r1 = query_one(w: &mut Wallet1).on(ObjW1).unwrap();
    let r1b = r1;
    r1b.w.coins += 5;
    match query_one(w: &mut Wallet2).on(ObjW2) {
        Some(mr) => { mr.w.coins += 3; },
        None => {},
    }
}

sys step_absent_unwrap() {
    let rm = query_one(w: &mut Wallet1).on(ObjNoWallet).unwrap();
    rm.w.coins += 999;
}

schedule FixedUpdate {
    seq OrderedAll {
        step_row_and_q1_a,
        step_row_and_q1_b,
        step_absent_unwrap,
    }
}
"#;
    let analyzed = analyze_source("parity_iter4.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let b_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("BoxAll"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let w1_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("Wallet1"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let w2_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("Wallet2"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter4.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "f0", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter4", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    w_jit.world_mut().run_schedule(FixedUpdate);
    w_c99.world_mut().run_schedule(FixedUpdate);
    w_rg.world_mut().run_schedule(FixedUpdate);
    assert_four_way_snapshot("f0", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b1 = read_single_comp_bytes_by_u32_id(app.world(), "BoxAll", b_off("id"), 1);
        let neg_a = i32::from_le_bytes(b1[b_off("neg_a")..b_off("neg_a") + 4].try_into().unwrap());
        let neg_e = i32::from_le_bytes(b1[b_off("neg_e")..b_off("neg_e") + 4].try_into().unwrap());
        let arr0 = i32::from_le_bytes(
            b1[b_off("arr_neg")..b_off("arr_neg") + 4]
                .try_into()
                .unwrap(),
        );
        let arr1 = i32::from_le_bytes(
            b1[b_off("arr_neg") + 4..b_off("arr_neg") + 8]
                .try_into()
                .unwrap(),
        );
        let ov_f64_u64 = u64::from_le_bytes(
            b1[b_off("ov_f64_u64")..b_off("ov_f64_u64") + 8]
                .try_into()
                .unwrap(),
        );
        let ov_hi8 = b1[b_off("ov_huge_i8")] as i8;
        let ov_nhi8 = b1[b_off("ov_nhuge_i8")] as i8;
        let ov_hu8 = b1[b_off("ov_huge_u8")];
        let rt_hi8 = b1[b_off("rt_huge_i8")] as i8;
        let rt_nhi8 = b1[b_off("rt_nhuge_i8")] as i8;
        let rt_hi32 = i32::from_le_bytes(
            b1[b_off("rt_huge_i32")..b_off("rt_huge_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let rt_nhi32 = i32::from_le_bytes(
            b1[b_off("rt_nhuge_i32")..b_off("rt_nhuge_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let rt_hi64 = i64::from_le_bytes(
            b1[b_off("rt_huge_i64")..b_off("rt_huge_i64") + 8]
                .try_into()
                .unwrap(),
        );
        let rt_nhi64 = i64::from_le_bytes(
            b1[b_off("rt_nhuge_i64")..b_off("rt_nhuge_i64") + 8]
                .try_into()
                .unwrap(),
        );
        let rt_nan32 = i32::from_le_bytes(
            b1[b_off("rt_nan_i32")..b_off("rt_nan_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let rt_nan64 = i64::from_le_bytes(
            b1[b_off("rt_nan_i64")..b_off("rt_nan_i64") + 8]
                .try_into()
                .unwrap(),
        );
        let alias_sum = i32::from_le_bytes(
            b1[b_off("row_alias_sum")..b_off("row_alias_sum") + 4]
                .try_into()
                .unwrap(),
        );

        let w1 = read_single_comp_bytes_by_u32_id(app.world(), "Wallet1", w1_off("id"), 10);
        let w1_coins =
            i32::from_le_bytes(w1[w1_off("coins")..w1_off("coins") + 4].try_into().unwrap());
        let w2 = read_single_comp_bytes_by_u32_id(app.world(), "Wallet2", w2_off("id"), 20);
        let w2_coins =
            i32::from_le_bytes(w2[w2_off("coins")..w2_off("coins") + 4].try_into().unwrap());

        assert_eq!(
            (neg_a, neg_e, arr0, arr1),
            (5, -300, 5, -5),
            "{label}: negative enum mismatch"
        );
        assert_eq!(
            (ov_f64_u64, ov_hi8, ov_nhi8, ov_hu8),
            (1_000_000_000_000_001, 127, -128, 255),
            "{label}: object f64/narrow cast mismatch"
        );
        assert_eq!(
            (
                rt_hi8, rt_nhi8, rt_hi32, rt_nhi32, rt_hi64, rt_nhi64, rt_nan32, rt_nan64
            ),
            (127, -128, i32::MAX, i32::MIN, i64::MAX, i64::MIN, 0, 0),
            "{label}: runtime signed float saturation mismatch"
        );
        assert_eq!(
            (alias_sum, w1_coins, w2_coins),
            (10, 115, 210),
            "{label}: row alias / query_one unwrap/expect mismatch"
        );
    }
}

#[test]
fn step2_iter5_non_finite_object_override_casts_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::step2_iter5 @version(1.0.0);

component CastRes {
    id: u32 = 1,
    ov_nan_i8: i8 = 11,
    ov_nan_i16: i16 = 22,
    ov_nan_i32: i32 = 33,
    ov_nan_i64: i64 = 44,
    ov_inf_i32: i32 = 55,
    ov_ninf_i8: i8 = 66,
    ov_inf_u8: u8 = 77,
    ov_ninf_u64: u64 = 88,
}

object ObjCast {
    CastRes {
        id: 1,
        ov_nan_i8: (0.0_f32 / 0.0_f32) as i8,
        ov_nan_i16: (0.0_f32 / 0.0_f32) as i16,
        ov_nan_i32: (0.0_f32 / 0.0_f32) as i32,
        ov_nan_i64: (0.0_f32 / 0.0_f32) as i64,
        ov_inf_i32: (1.0_f32 / 0.0_f32) as i32,
        ov_ninf_i8: (-1.0_f32 / 0.0_f32) as i8,
        ov_inf_u8: (1.0_f32 / 0.0_f32) as u8,
        ov_ninf_u64: (-1.0_f64 / 0.0_f64) as u64,
    },
}

sys noop_tick() {}
schedule FixedUpdate { noop_tick }
"#;
    let analyzed = analyze_source("parity_iter5.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let cr_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("CastRes"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter5.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter5", &src_path, tier3_driver);

    let (w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let bytes = read_single_comp_bytes_by_u32_id(app.world(), "CastRes", cr_off("id"), 1);
        let nan_i8 = bytes[cr_off("ov_nan_i8")] as i8;
        let nan_i16 = i16::from_le_bytes(
            bytes[cr_off("ov_nan_i16")..cr_off("ov_nan_i16") + 2]
                .try_into()
                .unwrap(),
        );
        let nan_i32 = i32::from_le_bytes(
            bytes[cr_off("ov_nan_i32")..cr_off("ov_nan_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let nan_i64 = i64::from_le_bytes(
            bytes[cr_off("ov_nan_i64")..cr_off("ov_nan_i64") + 8]
                .try_into()
                .unwrap(),
        );
        let inf_i32 = i32::from_le_bytes(
            bytes[cr_off("ov_inf_i32")..cr_off("ov_inf_i32") + 4]
                .try_into()
                .unwrap(),
        );
        let ninf_i8 = bytes[cr_off("ov_ninf_i8")] as i8;
        let inf_u8 = bytes[cr_off("ov_inf_u8")];
        let ninf_u64 = u64::from_le_bytes(
            bytes[cr_off("ov_ninf_u64")..cr_off("ov_ninf_u64") + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            (
                nan_i8, nan_i16, nan_i32, nan_i64, inf_i32, ninf_i8, inf_u8, ninf_u64
            ),
            (0, 0, 0, 0, i32::MAX, i8::MIN, u8::MAX, 0),
            "{label}: non-finite float-to-int object override mismatch"
        );
    }
}

#[test]
fn step2_iter6_non_finite_fix_ivec_nested_and_local_struct_write_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::step2_iter6 @version(1.0.0);

struct DeepS {
    y: i32 = 4,
}

struct InnerS {
    si: i32 = 11,
    sf: fix32 = 2.0,
    deep: DeepS = DeepS { y: 4 },
}

component CastRes {
    id: u32 = 1,
    nan_fx32: fix32 = 3.0,
    inf_fx32: fix32 = 4.0,
    ninf_fx32: fix32 = 5.0,
    nan_fx64: fix64 = 6.0,
    inf_fx64: fix64 = 7.0,
    ninf_fx64: fix64 = 8.0,
    chained_fx: i32 = 9,
    iv: ivec2 = ivec2(1, 2),
    iv3: ivec3 = ivec3(1, 2, 3),
    uv: uvec2 = uvec2(4, 5),
    nested: InnerS = InnerS { si: 11, sf: 2.0, deep: DeepS { y: 4 } },
    rt_inf_fx32: fix32 = 9.0,
    rt_ninf_fx64: fix64 = 9.0,
    last_si: i32 = 0,
    last_dy: i32 = 0,
}

object ObjCast {
    CastRes {
        id: 1,
        nan_fx32: (0.0_f32 / 0.0_f32) as fix32,
        inf_fx32: (1.0_f32 / 0.0_f32) as fix32,
        ninf_fx32: (-1.0_f32 / 0.0_f32) as fix32,
        nan_fx64: (0.0_f64 / 0.0_f64) as fix64,
        inf_fx64: (1.0_f64 / 0.0_f64) as fix64,
        ninf_fx64: (-1.0_f64 / 0.0_f64) as fix64,
        chained_fx: ((0.0_f32 / 0.0_f32) as fix32) as i32,
        iv: ivec2((0.0_f32 / 0.0_f32) as i32, (1.0_f32 / 0.0_f32) as i32),
        iv3: ivec3((0.0_f32 / 0.0_f32) as i32, (1.0_f32 / 0.0_f32) as i32, (-1.0_f32 / 0.0_f32) as i32),
        uv: uvec2((1.0_f32 / 0.0_f32) as u32, (-1.0_f32 / 0.0_f32) as u32),
        nested: InnerS {
            si: (0.0_f32 / 0.0_f32) as i32,
            sf: (1.0_f32 / 0.0_f32) as fix32,
            deep: DeepS { y: 4 },
        },
    },
}

@node_pure fn mk_inf_f32(z: f32) -> f32 { 1.0_f32 / z }
@node_pure fn mk_ninf_f64(z: f64) -> f64 { -1.0_f64 / z }

sys step_all() {
    let r = query_one(c: &mut CastRes).on(ObjCast).unwrap();
    let mut sv = r.c.nested;
    sv.si = 77;
    sv.deep.y = 88;
    r.c.last_si = sv.si;
    r.c.last_dy = sv.deep.y;
    r.c.rt_inf_fx32 = mk_inf_f32(0.0_f32) as fix32;
    r.c.rt_ninf_fx64 = mk_ninf_f64(0.0_f64) as fix64;
}

schedule FixedUpdate { step_all }
"#;
    let analyzed = analyze_source("parity_iter6.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let cr_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("CastRes"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter6.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter6", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let bytes = read_single_comp_bytes_by_u32_id(app.world(), "CastRes", cr_off("id"), 1);
        let read_i32 = |off: usize| i32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let read_u32 = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let read_i64 = |off: usize| i64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());

        assert_eq!(read_i32(cr_off("nan_fx32")), 0, "{label} nan_fx32");
        assert_eq!(read_i32(cr_off("inf_fx32")), 0, "{label} inf_fx32");
        assert_eq!(read_i32(cr_off("ninf_fx32")), 0, "{label} ninf_fx32");
        assert_eq!(read_i64(cr_off("nan_fx64")), 0, "{label} nan_fx64");
        assert_eq!(read_i64(cr_off("inf_fx64")), 0, "{label} inf_fx64");
        assert_eq!(read_i64(cr_off("ninf_fx64")), 0, "{label} ninf_fx64");
        assert_eq!(read_i32(cr_off("chained_fx")), 0, "{label} chained_fx");
        assert_eq!(read_i32(cr_off("iv")), 0, "{label} iv.x");
        assert_eq!(read_i32(cr_off("iv") + 4), i32::MAX, "{label} iv.y");
        assert_eq!(read_i32(cr_off("iv3")), 0, "{label} iv3.x");
        assert_eq!(read_i32(cr_off("iv3") + 4), i32::MAX, "{label} iv3.y");
        assert_eq!(read_i32(cr_off("iv3") + 8), i32::MIN, "{label} iv3.z");
        assert_eq!(read_u32(cr_off("uv")), u32::MAX, "{label} uv.x");
        assert_eq!(read_u32(cr_off("uv") + 4), 0, "{label} uv.y");
        assert_eq!(read_i32(cr_off("nested")), 0, "{label} nested.si");
        assert_eq!(read_i32(cr_off("nested") + 4), 0, "{label} nested.sf");
        assert_eq!(read_i32(cr_off("rt_inf_fx32")), 0, "{label} rt_inf_fx32");
        assert_eq!(read_i64(cr_off("rt_ninf_fx64")), 0, "{label} rt_ninf_fx64");
        assert_eq!(read_i32(cr_off("last_si")), 77, "{label} last_si");
        assert_eq!(read_i32(cr_off("last_dy")), 88, "{label} last_dy");
    }
}

#[test]
fn step2_iter7_four_backend_parity_opt_row_loop_scope_nested_ctors_and_fix_trunc() {
    let src = r#"
module test::parity_iter7 @version(1.0.0);

enum BitKind { A = 0, C = 2 }

struct Leaf {
    d: meters = meters(1.0),
    wait_ms: ms = ms(10.0),
    va: vec3a = vec3a(0.0, 0.0, 0.0),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    col: rgba = rgba(0.0, 0.0, 0.0, 1.0),
    mask: u64 = 0,
}

struct Container {
    leaves: [Leaf; 2] = [Leaf {}, Leaf {}],
    const_sat_i32: i32 = 0,
    const_neg_i64: i64 = 0,
    const_zero_i32: i32 = 9,
}

component MainPod {
    id: u32 = 1,
    val: i32 = 10,
    box_cfg: Container = Container {},
    rt_pos_fx32: i32 = 0,
    rt_neg_fx32: i32 = 0,
    rt_zero_fx32: i32 = 9,
    rt_sat_fx32: i32 = 0,
    rt_neg_fx64: i64 = 0,
    rt_sat_fx64: i64 = 0,
    rt_u32_fx32: u32 = 0,
    rt_nan_fx32_i32: i32 = 9,
    opt_if_let: i32 = 0,
    opt_match: i32 = 0,
    opt_else: i32 = 0,
    opt_unwrap: i32 = 0,
    opt_expect: i32 = 0,
    opt_oc_hp: i32 = 0,
    opt_none_flags: u32 = 0,
    loop_s_d_pos: i32 = 0,
    fsm_ticks: i32 = 0,
    task_ticks: i32 = 0,
}

component OptExtra { hp: i32 = 55 }
component OtherOnly { tag_val: i32 = 1 }

event PulseEvt { inc: i32 }

object ObjMain {
    MainPod {
        id: 1,
        val: 42,
        box_cfg: Container {
            leaves: [
                Leaf {
                    d: meters(7.5),
                    wait_ms: ms(125.0),
                    va: vec3a(1.0, 2.0, 3.0),
                    q: quat(0.0, 1.0, 0.0, 0.0),
                    col: rgba(0.25, 0.5, 0.75, 1.0),
                    mask: bits(BitKind::A, BitKind::C),
                },
                Leaf {
                    d: meters(9.0),
                    wait_ms: ms(250.0),
                    va: Vec3a(4.0, 5.0, 6.0),
                    q: Quat(0.0, 0.0, 1.0, 0.0),
                    col: Rgba(1.0, 1.0, 0.5, 1.0),
                    mask: bits(BitKind::C),
                },
            ],
            const_sat_i32: (100000.0_f32 as fix32) as i32,
            const_neg_i64: (-2.75_f64 as fix64) as i64,
            const_zero_i32: (-0.25_f32 as fix32) as i32,
        },
    },
    OptExtra { hp: 77 },
}

object ObjAbsent {
    OtherOnly { tag_val: 9 },
}

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

sys step_all() {
    let opt_r = query_one(m: &mut MainPod, oc: Option<&OptExtra>).on(ObjMain);
    let opt2 = opt_r;

    if let Some(r1) = opt2 {
        r1.m.opt_if_let = r1.m.val;
        if r1.oc.is_some() {
            r1.m.opt_oc_hp = r1.oc.unwrap().hp;
        }
    }

    match opt2 {
        Some(rm) => { rm.m.opt_match = rm.m.val; }
        None => {}
    }

    let Some(re) = opt2 else { return; };
    re.m.opt_else = re.m.val;

    let ru = opt2.unwrap();
    ru.m.opt_unwrap = ru.m.val;

    let rex = Some(ru).expect("present");
    rex.m.opt_expect = rex.m.val;

    let opt_miss = query_one(o: &OtherOnly).on(ObjMain);
    let mut miss_flags: u32 = 0;
    if opt_miss.is_none() { miss_flags += 1; }
    if opt2.is_some() { miss_flags += 2; }
    ru.m.opt_none_flags = miss_flags;

    // Canonical (fix32/fix64 as int) truncating toward zero + float->fix saturation
    ru.m.rt_pos_fx32 = (id_f32(2.75_f32) as fix32) as i32;
    ru.m.rt_neg_fx32 = (id_f32(-2.75_f32) as fix32) as i32;
    ru.m.rt_zero_fx32 = (id_f32(-0.25_f32) as fix32) as i32;
    ru.m.rt_sat_fx32 = (id_f32(100000.0_f32) as fix32) as i32;
    ru.m.rt_neg_fx64 = (id_f64(-2.75_f64) as fix64) as i64;
    ru.m.rt_sat_fx64 = (id_f64(1.0e12_f64) as fix64) as i64;
    ru.m.rt_u32_fx32 = (id_f32(42.75_f32) as fix32) as u32;
    ru.m.rt_nan_fx32_i32 = ((0.0_f32 / id_f32(0.0_f32)) as fix32) as i32;

    // Start FSM and Task on ObjMain on first tick so tick 2 executes their bodies across all 4 backends.
    insert @if_new(ru.entity, PodFsm::start());
    insert @if_new(ru.entity, PodTask::start());

    // Loop-local `s_d_pos` shadowing outer `s_d_pos` must preserve outer value after loop exit
    let s_d_pos: i32 = 100;
    for s_d_pos in query(s_d_pos: &OtherOnly.tag_val) {
        let _inner = s_d_pos;
    }
    ru.m.loop_s_d_pos = s_d_pos + ru.m.val;
}

obs on_pulse(trg: &Trigger<PulseEvt>) {
    let opt_p = query_one(m: &mut MainPod).on(ObjMain);
    if let Some(rp) = opt_p {
        rp.m.val += trg.payload.inc;
    }
}

fsm PodFsm @require(MainPod) {
    initial Active;
    state Active {
        on_tick {
            let opt_f = query_one(m: &mut MainPod).on(ObjMain);
            if let Some(rf) = opt_f {
                rf.m.fsm_ticks += 1;
            }
        }
        to Active when false;
    }
}

task PodTask() on (m: &mut MainPod) {
    let opt_t = query_one(ex: &OptExtra).on(ObjMain);
    if opt_t.is_some() {
        m.task_ticks += 1;
    }
    yield_tick;
}

schedule FixedUpdate {
    seq Frame {
        step_all,
        PodFsm,
        PodTask,
    }
}

sim_test "iter7_sim_match_expect_and_optional_term" {
    step_fixed(2);
    let q_ok = query_one(m: &MainPod, oc: Option<&OptExtra>).on(ObjMain);
    let hit_m = match q_ok {
        Some(r) => {
            if r.oc.is_some() { r.oc.unwrap().hp } else { 0 }
        }
        None => -1,
    };
    assert(hit_m == 77);
    let exp = q_ok.expect("ObjMain present");
    assert(exp.m.opt_unwrap == 42);
    assert(exp.m.opt_oc_hp == 77);
    assert(exp.m.loop_s_d_pos == 142);
    assert(exp.m.rt_sat_fx32 == 32767);
    assert(exp.m.rt_neg_fx64 == -2);
    assert(exp.m.rt_zero_fx32 == 0);
}
"#;
    let analyzed = analyze_source("parity_iter7.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let mp_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("MainPod"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter7.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick2", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter7", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick2", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let bytes = read_single_comp_bytes_by_u32_id(app.world(), "MainPod", mp_off("id"), 1);
        let read_i32 = |off: usize| i32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let read_u32 = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let read_i64 = |off: usize| i64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());

        assert_eq!(read_i32(mp_off("rt_pos_fx32")), 2, "{label} rt_pos_fx32");
        assert_eq!(read_i32(mp_off("rt_neg_fx32")), -2, "{label} rt_neg_fx32");
        assert_eq!(read_i32(mp_off("rt_zero_fx32")), 0, "{label} rt_zero_fx32");
        assert_eq!(
            read_i32(mp_off("rt_sat_fx32")),
            32767,
            "{label} rt_sat_fx32"
        );
        assert_eq!(read_i64(mp_off("rt_neg_fx64")), -2, "{label} rt_neg_fx64");
        assert_eq!(
            read_i64(mp_off("rt_sat_fx64")),
            i64::MAX / 4_294_967_296,
            "{label} rt_sat_fx64"
        );
        assert_eq!(read_u32(mp_off("rt_u32_fx32")), 42, "{label} rt_u32_fx32");
        assert_eq!(
            read_i32(mp_off("rt_nan_fx32_i32")),
            0,
            "{label} rt_nan_fx32_i32"
        );
        assert_eq!(read_i32(mp_off("opt_if_let")), 42, "{label} opt_if_let");
        assert_eq!(read_i32(mp_off("opt_match")), 42, "{label} opt_match");
        assert_eq!(read_i32(mp_off("opt_else")), 42, "{label} opt_else");
        assert_eq!(read_i32(mp_off("opt_unwrap")), 42, "{label} opt_unwrap");
        assert_eq!(read_i32(mp_off("opt_expect")), 42, "{label} opt_expect");
        assert_eq!(read_i32(mp_off("opt_oc_hp")), 77, "{label} opt_oc_hp");
        assert_eq!(
            read_u32(mp_off("opt_none_flags")),
            3,
            "{label} opt_none_flags"
        );
        assert_eq!(
            read_i32(mp_off("loop_s_d_pos")),
            142,
            "{label} loop_s_d_pos"
        );
        assert_eq!(read_i32(mp_off("fsm_ticks")), 2, "{label} fsm_ticks");
        // Single-shot task with trailing `yield_tick;` executes tick 1, suspends, and completes on tick 2 (GF-04).
        assert_eq!(read_i32(mp_off("task_ticks")), 1, "{label} task_ticks");
    }

    let _parity_wg = PARITY_ALLOC_GATE.write().unwrap_or_else(|e| e.into_inner());
    let sim_res = stratac::sim_runner::run_headless_sim_tests(&mir, "parity_iter7_sim");
    assert_eq!(sim_res.len(), 1);
    assert!(
        sim_res[0].passed,
        "iter7 sim_test failed: {}",
        sim_res[0].detail
    );
}

#[test]
fn step2_iter8_native_observers_and_all_fixes_four_way_parity() {
    let src = r#"
module test::parity_iter8 @version(1.0.0);

enum BitKind { A = 0, C = 2, Hi = 70 }

struct Sub {
    x: i32 = 3,
    fx: fix32 = 1.5,
}
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };
const C_ARR: [fix32; 2] = [1.5, 2.5];
const C_FX: fix32 = (1.5_f32 + 0.5_f32) as fix32;

component Marker;
component RoTarget { val: i32 = 100 }
component RwTarget { val: i32 = 10 }
component HelperComp { val: i32 = 5 }

component Iter8Pod {
    id: u32 = 1,
    ro_seen: i32 = 0,
    ro_copy_mut: i32 = 0,
    rw_copy: i32 = 0,
    tup_n: i32 = 0,
    tup_alias_val: i32 = 0,
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    va_arr: [vec3a; 2] = [vec3a(1.0, 0.0, 0.0), Vec3a(0.0, 1.0, 0.0)],
    bs64: BitSet<64> = bits(BitKind::A, BitKind::C),
    bs128: BitSet<128> = bits(0, 70),
    rt_arr32: [fix32; 2] = [0.0, 0.0],
    rt_arr64: [fix64; 2] = [0.0, 0.0],
    sub: Sub = C_SUB,
    c_arr: [fix32; 2] = C_ARR,
    c_fx: fix32 = C_FX,
    u_neg8: u8 = (-1) as u8,
    u_neg64: u64 = (-1) as u64,
    global_hits: i32 = 0,
    ping_hits: i32 = 0,
    target_hits: i32 = 0,
    chain_hits: i32 = 0,
    obs_cmd_hits: i32 = 0,
    tick_count: i32 = 0,
}

component ObsChildSpawned {
    tag_val: i32 = 0,
}

event GlobalEvt { delta: i32 }
event PingEvt { entity: Ref<Entity>, amt: i32 }
event TargetEvt { entity: Ref<Entity>, bonus: i32 }
event ChainA { step: i32 }
event ChainB { step: i32 }

object ObjIter8Main {
    Iter8Pod {
        id: 1,
        bs128: bits(2, 75),
        va: Vec3a(2.0, 4.0, 6.0),
    },
    RoTarget { val: 33 },
    RwTarget { val: 11 },
    HelperComp { val: 8 },
    Marker,
}

object ObjIter8Unmarked {
    Iter8Pod {
        id: 2,
    },
}

fn touch_helper(h: &mut HelperComp, inc: i32) {
    h.val += inc;
}

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

sys step_iter8() {
    // 1. Projected SingleTermPtr read vs write isolation
    let mut seen_ro: i32 = 0;
    let mut cp_ro: i32 = 0;
    for x in query(x: &RoTarget.val) {
        seen_ro += x;
        let mut hp = x;
        hp = 99;
        cp_ro = hp;
    }
    let mut cp_rw: i32 = 0;
    for mut v in query(v: &mut RwTarget.val) {
        let mut copy_v = v;
        copy_v = 99;
        cp_rw = copy_v;
        v = 42;
    }

    // 2. Tuple destructuring with RowAlias + helper &mut Comp + runtime arrays + vec3a + bits
    let opt_main = query_one(m: &mut Iter8Pod, h: &mut HelperComp).on(ObjIter8Main);
    if let Some(q1) = opt_main {
        let (mut r2, s_row) = (10, q1);
        r2 += 5;
        s_row.m.ro_seen = seen_ro;
        s_row.m.ro_copy_mut = cp_ro;
        s_row.m.rw_copy = cp_rw;
        s_row.m.tup_n = r2;
        touch_helper(s_row.h, r2);
        s_row.m.tup_alias_val = s_row.h.val;
        s_row.m.rt_arr32 = [id_f32(1.25_f32), id_f32(-0.5_f32)];
        s_row.m.rt_arr64 = [id_f64(-2.75_f64), id_f64(1.5_f64)];
        s_row.m.bs64 = bits(1, 62);
        s_row.m.bs128 = bits(1, 70);
        s_row.m.va = Vec3a(7.0, 8.0, 9.0);
        s_row.m.va_arr = [vec3a(3.0, 4.0, 5.0), Vec3a(6.0, 7.0, 8.0)];
        s_row.m.tick_count += 1;

        if s_row.m.tick_count == 1 {
            trigger(GlobalEvt { delta: 10 });
            trigger(PingEvt { entity: s_row.entity, amt: 15 });
            trigger(TargetEvt { entity: s_row.entity, bonus: 21 });
            trigger(ChainA { step: 7 });
        }
    }
}

sys step_trigger_unmarked() {
    let opt_unm = query_one(m: &mut Iter8Pod).on(ObjIter8Unmarked);
    if let Some(qu) = opt_unm {
        if qu.m.tick_count == 0 {
            qu.m.tick_count += 1;
            // TargetEvt on ObjIter8Unmarked MUST NOT fire on_target_marked (lacks Marker)!
            trigger(TargetEvt { entity: qu.entity, bonus: 100 });
        }
    }
}

obs on_global(trg: &Trigger<GlobalEvt>) {
    let opt_m = query_one(m: &mut Iter8Pod).on(ObjIter8Main);
    if let Some(r) = opt_m {
        r.m.global_hits += trg.payload.delta;
    }
}

obs on_ping(trg: &Trigger<PingEvt>) {
    let opt_t = query_one(m: &mut Iter8Pod).on(trg.target);
    if let Some(r) = opt_t {
        r.m.ping_hits += trg.payload.amt;
    }
}

obs on_target_marked(trg: &Trigger<TargetEvt, Marker>) {
    let opt_t = query_one(m: &mut Iter8Pod).on(trg.target);
    if let Some(r) = opt_t {
        r.m.target_hits += trg.payload.bonus;
    }
}

obs on_chain_a(trg: &Trigger<ChainA>) {
    trigger(ChainB { step: trg.payload.step + 3 });
}

obs on_chain_b(trg: &Trigger<ChainB>) {
    let opt_m = query_one(m: &mut Iter8Pod).on(ObjIter8Main);
    if let Some(r) = opt_m {
        r.m.chain_hits += trg.payload.step;
        r.m.obs_cmd_hits += 1;
        spawn { ObsChildSpawned { tag_val: trg.payload.step * 2 } };
    }
}

schedule FixedUpdate {
    seq Frame {
        step_iter8,
        step_trigger_unmarked,
    }
}

sim_test "iter8_sim_observers_and_fixes" {
    step_fixed(1);
    let q_ok = query_one(m: &Iter8Pod, ro: &RoTarget, rw: &RwTarget, h: &HelperComp).on(ObjIter8Main);
    assert_eq(Some(q_ok.unwrap()), q_ok);
    assert_ne(None, q_ok);
    assert_ne(Option::None, q_ok);
    let r = q_ok.unwrap();
    assert_eq(r.ro.val, 33);
    assert_eq(r.m.ro_seen, 33);
    assert_eq(r.m.ro_copy_mut, 99);
    assert_eq(r.rw.val, 42);
    assert_eq(r.m.rw_copy, 99);
    assert_eq(r.m.tup_n, 15);
    assert_eq(r.h.val, 23);
    assert_eq(r.m.global_hits, 10);
    assert_eq(r.m.ping_hits, 15);
    assert_eq(r.m.target_hits, 21);
    assert_eq(r.m.chain_hits, 10);
    assert_eq(r.m.obs_cmd_hits, 1);

    let mut sim_seen: i32 = 0;
    for x in query(x: &RoTarget.val) {
        sim_seen += x;
        let mut hp = x;
        hp = 99;
    }
    assert_eq(sim_seen, 33);
    let q_ro_after = query_one(ro: &RoTarget).on(ObjIter8Main).unwrap();
    assert_eq(q_ro_after.ro.val, 33);

    let q_unm = query_one(m: &Iter8Pod).on(ObjIter8Unmarked).unwrap();
    assert_eq(q_unm.m.target_hits, 0);
}
"#;
    let analyzed = analyze_source("parity_iter8.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let mp_off = |name: &str| {
        mir.layouts
            .iter()
            .find(|l| l.canonical_name.ends_with("Iter8Pod"))
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter8.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick2", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter8", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick2", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let bytes1 = read_single_comp_bytes_by_u32_id(app.world(), "Iter8Pod", mp_off("id"), 1);
        let bytes2 = read_single_comp_bytes_by_u32_id(app.world(), "Iter8Pod", mp_off("id"), 2);
        let read_i32 =
            |b: &[u8], off: usize| i32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        let read_u64 =
            |b: &[u8], off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());

        assert_eq!(read_i32(&bytes1, mp_off("ro_seen")), 33, "{label} ro_seen");
        assert_eq!(
            read_i32(&bytes1, mp_off("ro_copy_mut")),
            99,
            "{label} ro_copy_mut"
        );
        assert_eq!(read_i32(&bytes1, mp_off("rw_copy")), 99, "{label} rw_copy");
        assert_eq!(read_i32(&bytes1, mp_off("tup_n")), 15, "{label} tup_n");
        assert_eq!(
            read_i32(&bytes1, mp_off("tup_alias_val")),
            38,
            "{label} tup_alias_val"
        );
        assert_eq!(
            read_i32(&bytes1, mp_off("global_hits")),
            10,
            "{label} global_hits"
        );
        assert_eq!(
            read_i32(&bytes1, mp_off("ping_hits")),
            15,
            "{label} ping_hits"
        );
        assert_eq!(
            read_i32(&bytes1, mp_off("target_hits")),
            21,
            "{label} target_hits"
        );
        assert_eq!(
            read_i32(&bytes1, mp_off("chain_hits")),
            10,
            "{label} chain_hits"
        );
        assert_eq!(
            read_i32(&bytes1, mp_off("obs_cmd_hits")),
            1,
            "{label} obs_cmd_hits"
        );
        assert_eq!(
            read_u64(&bytes1, mp_off("u_neg64")),
            u64::MAX,
            "{label} u_neg64"
        );
        assert_eq!(
            read_i32(&bytes2, mp_off("target_hits")),
            0,
            "{label} negative TargetEvt watched_components"
        );
    }

    let _parity_wg = PARITY_ALLOC_GATE.write().unwrap_or_else(|e| e.into_inner());
    let sim_res = stratac::sim_runner::run_headless_sim_tests(&mir, "parity_iter8_sim");
    assert_eq!(sim_res.len(), 1);
    assert!(
        sim_res[0].passed,
        "iter8 sim_test failed: {}",
        sim_res[0].detail
    );
}

#[test]
fn step2_iter9_bits_const_u64_nested_struct_and_bitset_arrays_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::step2_iter9_bits @version(1.0.0);

enum BitKind {
    A = 0,
    B = 1,
    C = 2,
}

struct BsBox {
    s_bs64: BitSet<64> = bits(BitKind::A, BitKind::C),
    s_bs128: BitSet<128> = bits(1, 33, 70),
    s_u64: u64 = 0,
}

struct BsU64 {
    mask: u64 = 0,
}

const C_MASK: BsU64 = BsU64 { mask: bits(BitKind::A, BitKind::C) };

component BitsIter9Pod {
    id: u32 = 0,
    ov_nested: BsBox = BsBox {},
    def_mask: BsU64 = C_MASK,
    rt_mask: BsU64 = BsU64 {},
    arr64: [BitSet<64>; 2] = [bits(0), bits(1)],
    arr128: [BitSet<128>; 2] = [bits(0, 65), bits(1, 90)],
}

object ObjDefaults {
    BitsIter9Pod { id: 1 },
}

object ObjOverrides {
    BitsIter9Pod {
        id: 2,
        ov_nested: BsBox {
            s_bs64: bits(BitKind::A, BitKind::B),
            s_bs128: bits(1, 33, 70),
            s_u64: bits(BitKind::B, BitKind::C),
        },
        arr64: [bits(BitKind::B, 35), bits(BitKind::C, 63)],
        arr128: [bits(1, 33, 70), bits(2, 75, 127)],
    },
}

sys step_bits() {
    for row in query(p: &mut BitsIter9Pod) {
        row.p.rt_mask = C_MASK;
    }
}

schedule FixedUpdate { step_bits }
"#;
    let analyzed = analyze_source("parity_iter9_bits.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let pod_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("BitsIter9Pod"))
        .unwrap();
    let box_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("BsBox"))
        .unwrap();
    let pod_off = |name: &str| {
        pod_layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let box_off = |name: &str| {
        box_layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter9_bits.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
"#;
    let tier3 = run_tier3_native_harness(tmp.path(), "step2_iter9_bits", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);

    let read_u64 = |b: &[u8], off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
    let read_u32 = |b: &[u8], off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b1 = read_single_comp_bytes_by_u32_id(app.world(), "BitsIter9Pod", pod_off("id"), 1);
        let b2 = read_single_comp_bytes_by_u32_id(app.world(), "BitsIter9Pod", pod_off("id"), 2);

        // Component defaults + C_MASK runtime & default
        assert_eq!(
            read_u64(&b1, pod_off("def_mask")),
            5,
            "{label} id=1 def_mask"
        );
        assert_eq!(read_u64(&b1, pod_off("rt_mask")), 5, "{label} id=1 rt_mask");
        let a64_1 = pod_off("arr64");
        assert_eq!(read_u64(&b1, a64_1), 1u64, "{label} id=1 arr64[0]");
        assert_eq!(read_u64(&b1, a64_1 + 8), 2u64, "{label} id=1 arr64[1]");
        let a128_1 = pod_off("arr128");
        assert_eq!(read_u32(&b1, a128_1), 1u32, "{label} id=1 arr128[0].w0");
        assert_eq!(read_u32(&b1, a128_1 + 8), 2u32, "{label} id=1 arr128[0].w2");
        assert_eq!(
            read_u32(&b1, a128_1 + 16),
            2u32,
            "{label} id=1 arr128[1].w0"
        );
        assert_eq!(
            read_u32(&b1, a128_1 + 24),
            1u32 << 26,
            "{label} id=1 arr128[1].w2"
        );

        // Nested StructLit object override (bits 1, 33, 70) + C_MASK + [BitSet<N>; 2] overrides
        let n_off = pod_off("ov_nested");
        assert_eq!(
            read_u64(&b2, n_off + box_off("s_bs64")),
            3,
            "{label} id=2 s_bs64"
        );
        let bs128_off = n_off + box_off("s_bs128");
        assert_eq!(
            read_u32(&b2, bs128_off),
            1u32 << 1,
            "{label} id=2 s_bs128.w0"
        );
        assert_eq!(
            read_u32(&b2, bs128_off + 4),
            1u32 << 1,
            "{label} id=2 s_bs128.w1"
        );
        assert_eq!(
            read_u32(&b2, bs128_off + 8),
            1u32 << 6,
            "{label} id=2 s_bs128.w2 (bit 70)"
        );
        assert_eq!(
            read_u32(&b2, bs128_off + 12),
            0u32,
            "{label} id=2 s_bs128.w3"
        );
        assert_eq!(
            read_u64(&b2, n_off + box_off("s_u64")),
            6,
            "{label} id=2 s_u64"
        );
        assert_eq!(
            read_u64(&b2, pod_off("def_mask")),
            5,
            "{label} id=2 def_mask"
        );
        assert_eq!(read_u64(&b2, pod_off("rt_mask")), 5, "{label} id=2 rt_mask");

        let a64_2 = pod_off("arr64");
        assert_eq!(
            read_u64(&b2, a64_2),
            (1u64 << 1) | (1u64 << 35),
            "{label} id=2 arr64[0]"
        );
        assert_eq!(
            read_u64(&b2, a64_2 + 8),
            (1u64 << 2) | (1u64 << 63),
            "{label} id=2 arr64[1]"
        );

        let a128_2 = pod_off("arr128");
        assert_eq!(
            read_u32(&b2, a128_2),
            1u32 << 1,
            "{label} id=2 arr128[0].w0"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 4),
            1u32 << 1,
            "{label} id=2 arr128[0].w1"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 8),
            1u32 << 6,
            "{label} id=2 arr128[0].w2"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 12),
            0u32,
            "{label} id=2 arr128[0].w3"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 16),
            1u32 << 2,
            "{label} id=2 arr128[1].w0"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 20),
            0u32,
            "{label} id=2 arr128[1].w1"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 24),
            1u32 << 11,
            "{label} id=2 arr128[1].w2"
        );
        assert_eq!(
            read_u32(&b2, a128_2 + 28),
            1u32 << 31,
            "{label} id=2 arr128[1].w3"
        );
    }
}

#[test]
fn step2_iter10_nested_bitset_arrays_and_smallvec_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::step2_iter10_arr_gen @version(1.0.0);

component Iter10Pod {
    id: u32 = 0,
    arr64: [BitSet<64>; 2] = [bits(0), bits(1)],
    arr128: [BitSet<128>; 2] = [bits(0, 65), bits(1, 90)],
    mat_f: [[f32; 3]; 2] = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]],
    mat128: [[BitSet<128>; 2]; 2] = [[bits(1, 70), bits(2, 90)], [bits(3, 100), bits(4, 127)]],
    sv_arr: SmallVec<[f32; 3], 2>,
    sv_bs64: SmallVec<BitSet<64>, 2>,
    sum_f: f32 = 0.0,
}

object ObjDefaults {
    Iter10Pod { id: 1 },
}

object ObjOverrides {
    Iter10Pod {
        id: 2,
        arr64: [bits(2, 35), bits(3, 63)],
        arr128: [bits(1, 70), bits(2, 127)],
        mat_f: [[10.0, 20.0, 30.0], [40.0, 50.0, 60.0]],
        mat128: [[bits(5, 72), bits(6, 95)], [bits(7, 105), bits(8, 126)]],
    },
}

sys step_iter10() {
    for row in query(p: &mut Iter10Pod) {
        row.p.id += 10;
        row.p.sum_f = row.p.mat_f[0][1] + row.p.mat_f[1][2];
    }
}

schedule FixedUpdate { step_iter10 }
"#;
    let analyzed = analyze_source("parity_iter10_arr_gen.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let pod_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("Iter10Pod"))
        .unwrap();
    let pod_field = |name: &str| {
        pod_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
    };
    let pod_off = |name: &str| pod_field(name).offset;

    // Exact layout size checks (regression guard against CST int misextraction)
    assert_eq!(pod_field("arr64").size, 16);
    assert_eq!(pod_field("arr128").size, 32);
    assert_eq!(pod_field("mat_f").size, 24);
    assert_eq!(pod_field("mat128").size, 64);
    assert_eq!(pod_field("sv_arr").size, 32);
    assert_eq!(pod_field("sv_bs64").size, 24);
    assert_eq!(pod_layout.size, 200);

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("parity_iter10_arr_gen.strata");
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );

    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
"#;
    let tier3 =
        run_tier3_native_harness(tmp.path(), "step2_iter10_arr_gen", &src_path, tier3_driver);

    let (mut w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (mut w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (mut w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);

    let read_u32 = |b: &[u8], off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
    let read_f32 = |b: &[u8], off: usize| f32::from_le_bytes(b[off..off + 4].try_into().unwrap());

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b1 = read_single_comp_bytes_by_u32_id(app.world(), "Iter10Pod", pod_off("id"), 11);
        let b2 = read_single_comp_bytes_by_u32_id(app.world(), "Iter10Pod", pod_off("id"), 12);

        assert_eq!(read_f32(&b1, pod_off("sum_f")), 8.0, "{label} id=11 sum_f");
        assert_eq!(read_f32(&b2, pod_off("sum_f")), 80.0, "{label} id=12 sum_f");

        let m1 = pod_off("mat128");
        assert_eq!(
            read_u32(&b1, m1),
            1u32 << 1,
            "{label} id=11 mat128[0][0].w0"
        );
        assert_eq!(
            read_u32(&b1, m1 + 8),
            1u32 << 6,
            "{label} id=11 mat128[0][0].w2 (bit 70)"
        );
        assert_eq!(
            read_u32(&b1, m1 + 48),
            1u32 << 4,
            "{label} id=11 mat128[1][1].w0"
        );
        assert_eq!(
            read_u32(&b1, m1 + 60),
            1u32 << 31,
            "{label} id=11 mat128[1][1].w3 (bit 127)"
        );

        assert_eq!(
            read_u32(&b2, m1),
            1u32 << 5,
            "{label} id=12 mat128[0][0].w0"
        );
        assert_eq!(
            read_u32(&b2, m1 + 8),
            1u32 << 8,
            "{label} id=12 mat128[0][0].w2 (bit 72)"
        );
        assert_eq!(
            read_u32(&b2, m1 + 48),
            1u32 << 8,
            "{label} id=12 mat128[1][1].w0"
        );
        assert_eq!(
            read_u32(&b2, m1 + 60),
            1u32 << 30,
            "{label} id=12 mat128[1][1].w3 (bit 126)"
        );
    }
}

/// Shared 4-way parity harness that compiles a `.strata` source module for JIT, C99, RustGuest,
/// and Tier-3 BevyNative, runs the provided Tier-3 driver, and sets up the 3 dynamic host apps.
fn setup_four_way_apps(
    label: &str,
    src: &str,
    tier3_driver: &str,
) -> (TempDir, strata_mir::MirModule, App, App, App, Tier3Capture) {
    let analyzed = analyze_source(format!("{label}.strata"), src);
    assert!(
        analyzed.ok(),
        "{label} sema failed: {:?}",
        analyzed.diagnostics
    );
    let mir = lower_to_mir(&analyzed);
    strata_mir::verify_mir(&mir).unwrap_or_else(|e| panic!("{label} verify_mir failed: {e:?}"));

    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join(format!("{label}.strata"));
    fs::write(&src_path, src).unwrap();

    let jit_bin = build_target_bin(&src_path, BuildTarget::Jit, &tmp.path().join("jit"));
    let c99_bin = build_target_bin(&src_path, BuildTarget::C99, &tmp.path().join("c99"));
    let rg_bin = build_target_bin(
        &src_path,
        BuildTarget::RustGuest,
        &tmp.path().join("rust_guest"),
    );
    let tier3 = run_tier3_native_harness(tmp.path(), label, &src_path, tier3_driver);

    let (w_jit, _) = setup_dynamic_app_with_mod(&jit_bin);
    let (w_c99, _) = setup_dynamic_app_with_mod(&c99_bin);
    let (w_rg, _) = setup_dynamic_app_with_mod(&rg_bin);
    (tmp, mir, w_jit, w_c99, w_rg, tier3)
}

#[test]
fn wave3_math_tables_collections_and_layouts_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src = r#"
module parity::wave3_math_coll @version(1.0.0);

enum Biome {
    Abyss = -2,
    Surface = 0,
    Sky = 5,
}

struct SubCfg {
    tag_id: i32,
    gain: f32,
}

struct ItemSlot {
    hp: i32 = 10,
    label: InlineStr<16> = "init",
}

struct NestBox {
    src_str: InlineStr<16> = "hello",
    copied: InlineStr<16> = "",
    bs: [BitSet<128>; 2] = [bits(3), bits(4)],
}

table CfgByBiome by Biome {
    off: vec2,
    sub: SubCfg,
    mask: BitSet<128>,
} = {
    Abyss => { off: vec2(-2.0, 4.0), sub: SubCfg { tag_id: -9, gain: 0.25 }, mask: bits(0, 127) },
    Surface => { off: vec2(0.0, 0.0), sub: SubCfg { tag_id: 0, gain: 1.0 }, mask: bits(1) },
    Sky => { off: vec2(3.0, 5.0), sub: SubCfg { tag_id: 7, gain: 2.5 }, mask: bits(64) },
};

component FxRow {
    fx32: fix32 = 12.0,
    fx64: fix64 = 1000.0,
    flag: bool = true,
}

component MathCollPod {
    id: u32 = 1,
    q_res: quat = quat(0.0, 0.0, 0.0, 1.0),
    v3_rot: vec3 = vec3(0.0, 0.0, 0.0),
    abs_i32_min: i32 = 0,
    abs_i64_min: i64 = 0,
    abs_fx32: fix32 = 0.0,
    abs_fx64: fix64 = 0.0,
    prod_fx32: fix32 = 0.0,
    prod_fx64: fix64 = 0.0,
    red_cnt: u32 = 0,
    red_any: bool = false,
    red_all: bool = false,
    tbl_tag: i32 = 0,
    tbl_off_x: f32 = 0.0,
    tbl_has_127: bool = false,
    arr128: [BitSet<128>; 2] = [bits(1), bits(1, 90)],
    bs_has_70: bool = false,
    bs_has_1: bool = false,
    mat2: [[i32; 2]; 2] = [[1, 2], [3, 4]],
    cube3: [[[i32; 2]; 2]; 2] = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]],
    items: [ItemSlot; 2] = [ItemSlot { hp: 10, label: "a" }, ItemSlot { hp: 20, label: "b" }],
    str_arr: [InlineStr<16>; 2] = ["alpha", "beta"],
    nest: NestBox = NestBox {},
    sv: SmallVec<i32, 4> = [11, 22],
    sv_len: u32 = 0,
    sv_sum: i32 = 0,
}

object Fx1 { FxRow { fx32: 12.0, fx64: 1000.0, flag: true } }
object Fx2 { FxRow { fx32: 12.0, fx64: 1000.0, flag: true } }
object Fx3 { FxRow { fx32: 12.0, fx64: 1000.0, flag: false } }
object Fx4 { FxRow { fx32: 12.0, fx64: 1.0, flag: true } }

object MainMathColl {
    MathCollPod { id: 1 },
}

fn id_i32(v: i32) -> i32 { v }
fn id_i64(v: i64) -> i64 { v }
fn id_fx32(v: fix32) -> fix32 { v }
fn id_fx64(v: fix64) -> fix64 { v }

sys step_math_coll() {
    let (p32, p64, cnt, has_any, every_flag) = for r in query(x: &FxRow) reduce (
        p32: prod(1.0, r.x.fx32),
        p64: prod(1.0, r.x.fx64),
        cnt: count(r.x.flag),
        has_any: any(r.x.flag),
        every_flag: all(r.x.flag)
    );
    let qz = quat(0.0, 0.0, 0.70710677, 0.70710677);
    let qid = quat(0.0, 0.0, 0.0, 1.0);
    let t_row = CfgByBiome[Biome::Abyss];

    for row in query(m: &mut MathCollPod) {
        let mut q = qz * qid;
        q *= qid;
        row.m.q_res = q;
        row.m.v3_rot = q * vec3(1.0, 0.0, 0.0);

        row.m.abs_i32_min = abs(id_i32(-2147483647 - 1));
        row.m.abs_i64_min = abs(id_i64(-9223372036854775808));
        row.m.abs_fx32 = abs(id_fx32(-3.25));
        row.m.abs_fx64 = abs(id_fx64(-5.5));

        row.m.prod_fx32 = p32;
        row.m.prod_fx64 = p64;
        row.m.red_cnt = cnt;
        row.m.red_any = has_any;
        row.m.red_all = every_flag;

        row.m.tbl_tag = t_row.sub.tag_id;
        row.m.tbl_off_x = t_row.off.x;
        row.m.tbl_has_127 = t_row.mask.has(127);

        row.m.arr128[1].set(70);
        row.m.arr128[1].clear(1);
        row.m.bs_has_70 = row.m.arr128[1].has(70);
        row.m.bs_has_1 = row.m.arr128[1].has(1);

        row.m.mat2[1][0] = 77;
        row.m.cube3[1][0][1] = 88;
        row.m.items[1].hp += 25;
        row.m.items[0].label = "hero";
        row.m.str_arr[1] = "omega";
        row.m.nest.copied = row.m.nest.src_str;
        row.m.nest.bs[0].set(126);

        row.m.sv.push(33);
        row.m.sv_len = row.m.sv.len();
        row.m.sv_sum = row.m.sv[0] + row.m.sv[1] + row.m.sv[2];
    }
}

schedule FixedUpdate { step_math_coll }
"#;
    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
"#;
    let (_tmp, mir, mut w_jit, mut w_c99, mut w_rg, tier3) =
        setup_four_way_apps("wave3_math_coll", src, tier3_driver);
    let pod_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("MathCollPod"))
        .unwrap();
    let off = |name: &str| {
        pod_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b = read_single_comp_bytes_by_u32_id(app.world(), "MathCollPod", off("id"), 1);
        let r_i32 = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r_u32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r_i64 = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let r_f32 = |o: usize| f32::from_le_bytes(b[o..o + 4].try_into().unwrap());

        assert!(
            (r_f32(off("v3_rot")) - 0.0).abs() < 1e-4,
            "{label} v3_rot.x"
        );
        assert!(
            (r_f32(off("v3_rot") + 4) - 1.0).abs() < 1e-4,
            "{label} v3_rot.y"
        );
        assert_eq!(r_i32(off("abs_i32_min")), i32::MIN, "{label} abs_i32_min");
        assert_eq!(r_i64(off("abs_i64_min")), i64::MIN, "{label} abs_i64_min");
        assert_eq!(
            r_i32(off("abs_fx32")),
            (3.25_f32 * 65536.0) as i32,
            "{label} abs_fx32"
        );
        assert_eq!(
            r_i64(off("abs_fx64")),
            (5.5_f64 * 4_294_967_296.0) as i64,
            "{label} abs_fx64"
        );
        assert_eq!(
            r_i32(off("prod_fx32")),
            20736_i32 * 65536,
            "{label} prod_fx32"
        );
        assert_eq!(
            r_i64(off("prod_fx64")),
            1_000_000_000_i64 * 4_294_967_296,
            "{label} prod_fx64"
        );
        assert_eq!(r_u32(off("red_cnt")), 3, "{label} red_cnt");
        assert_eq!(b[off("red_any")], 1, "{label} red_any");
        assert_eq!(b[off("red_all")], 0, "{label} red_all");
        assert_eq!(r_i32(off("tbl_tag")), -9, "{label} tbl_tag");
        assert_eq!(r_f32(off("tbl_off_x")), -2.0, "{label} tbl_off_x");
        assert_eq!(b[off("tbl_has_127")], 1, "{label} tbl_has_127");
        assert_eq!(b[off("bs_has_70")], 1, "{label} bs_has_70");
        assert_eq!(b[off("bs_has_1")], 0, "{label} bs_has_1");
        assert_eq!(r_i32(off("mat2") + 2 * 4), 77, "{label} mat2[1][0]");
        assert_eq!(r_i32(off("cube3") + 5 * 4), 88, "{label} cube3[1][0][1]");
        assert_eq!(r_u32(off("sv_len")), 3, "{label} sv_len");
        assert_eq!(r_i32(off("sv_sum")), 66, "{label} sv_sum");
    }
}

#[test]
fn wave3_ecs_flow_fsm_task_timeline_atomic_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let mut src = String::from(
        r#"
module parity::wave3_ecs_flow @version(1.0.0);

resource SimClock { dt: sec = 0.016_s }

component SelBox { id: u32 = 0, val: i32 = 0 }
component RetBox { id: u32 = 0, val: i32 = 0 }
component BornComp { tag_id: u32 = 0 }
component RelParent { pval: i32 = 0 }
component RelChild { cval: i32 = 0, got_prop: i32 = 0 }
component TxBox { id: u32 = 1, hp: f32 = 10.0, arr: [i32; 2] = [1, 2], flags: BitSet<32> = bits(1) }
component TxRoll { id: u32 = 2, hp: f32 = 10.0 }
component FlowOut {
    id: u32 = 1,
    sel_changed: u32 = 0,
    ret_changed: u32 = 0,
    added_seen: u32 = 0,
    childof_sum: i32 = 0,
    squad_sum: i32 = 0,
    prop_sum: i32 = 0,
    tl_fired: u32 = 0,
    tl_w31_active: bool = false,
    task_if_val: i32 = 0,
    task_race_ticks: i32 = 0,
    fsm_local_val: i32 = 0,
}

relation ChildOf;
relation Squad { power: u32 }
event PulseEvt { inc: i32 }

object Sel1 { SelBox { id: 1, val: 0 } }
object Sel2 { SelBox { id: 2, val: 0 } }
object Sel3 { SelBox { id: 3, val: 0 } }
object Ret1 { RetBox { id: 1, val: 0 } }
object Ret2 { RetBox { id: 2, val: 0 } }

object RootNode { RelParent { pval: 100 }, RelChild { cval: 1, got_prop: 0 } }
object ChildNode { RelChild { cval: 20, got_prop: 0 } }
object SquadChild { RelChild { cval: 30, got_prop: 0 } }

object ActorNode { FlowOut { id: 1 }, TxBox { id: 1 }, TxRoll { id: 2 } }

obs on_pulse(trg: &Trigger<PulseEvt>) {
    if let Some(rc) = query_one(c: &mut RelChild).on(trg.entity) {
        rc.c.got_prop += trg.payload.inc;
    }
}

@sparse
timeline WinTl @rate(60_hz) @duration(10_f) {
"#,
    );
    for w in 0..32 {
        let start = if w == 31 { 1 } else { 0 };
        src.push_str(&format!("    window w{w} = {start}_f .. 10_f;\n"));
    }
    src.push_str(
        r#"    at 2_f => {
        for o in query(flow_out: &mut FlowOut) {
            o.flow_out.tl_fired += 1_u32;
        }
    }
}

fsm PersistFsm @require(FlowOut) {
    initial Boot;
    state Boot {
        to Active when true;
    }
    state Active {
        local_cnt: i32 = 0,
        on_enter {
            local_cnt = 10;
            for o in query(flow_out: &mut FlowOut) {
                o.flow_out.fsm_local_val = local_cnt;
            }
        }
        on_tick {
            local_cnt += 1;
            for o in query(flow_out: &mut FlowOut) {
                o.flow_out.fsm_local_val = local_cnt;
            }
        }
        to Active when false;
    }
}

@sparse
task BranchRaceTask(flag: bool)
    on (flow_out: &mut FlowOut)
    using (clk: &res SimClock)
{
    if flag {
        flow_out.task_if_val += 1;
        yield_tick;
        flow_out.task_if_val += 10;
    }
    race {
        branch {
            wait 0.020_s;
        }
        branch {
            loop {
                flow_out.task_race_ticks += 1;
                yield_tick;
            }
        }
    }
    flow_out.task_if_val += 100;
}

sys init_links() {
    let root = query_one(p: &RelParent).on(RootNode).unwrap().id;
    let c_ent = query_one(c: &RelChild).on(ChildNode).unwrap().id;
    let s_ent = query_one(c: &RelChild).on(SquadChild).unwrap().id;
    insert_relation<ChildOf>(c_ent, root);
    insert_relation<Squad>(s_ent, root, Squad { power: 5 });
    let _b = spawn { BornComp { tag_id: 1 } };
    let act = query_one(flow_out: &FlowOut).on(ActorNode).unwrap().id;
    insert(act, PersistFsm::start());
    insert(act, WinTl::start());
    insert(act, BranchRaceTask::start(true));
}

sys mutate_selective_and_spawn() {
    for row in query(s: &mut? SelBox) {
        if row.s.id == 1_u32 {
            row.s.val += 10;
        } else if row.s.id == 2_u32 {
            break;
        }
    }
    for row in query(r: &mut? RetBox) {
        row.r.val += 20;
        return;
    }
}

sys count_sel_and_added() {
    let mut sc: u32 = 0;
    for _s in query(s: &SelBox).changed<SelBox>() {
        sc += 1;
    }
    let mut rc: u32 = 0;
    for _r in query(r: &RetBox).changed<RetBox>() {
        rc += 1;
    }
    let mut ac: u32 = 0;
    for _b in query(b: &BornComp).added<BornComp>() {
        ac += 1;
    }
    let mut c_sum: i32 = 0;
    for u1 in query(c: &RelChild, p: Option<&RelParent>).up<ChildOf>() {
        if let Some(par) = u1.p {
            c_sum += u1.c.cval + par.pval;
        }
    }
    let mut s_sum: i32 = 0;
    for u2 in query(c: &RelChild, p: Option<&RelParent>).up<Squad>() {
        if let Some(par) = u2.p {
            s_sum += u2.c.cval + par.pval;
        }
    }
    let mut tl_w31: bool = false;
    for row in query(tl: &WinTl) {
        tl_w31 = row.tl.in(w31);
    }
    for o in query(f: &mut FlowOut) {
        o.f.sel_changed = sc;
        o.f.ret_changed = rc;
        o.f.added_seen += ac;
        o.f.childof_sum = c_sum;
        o.f.squad_sum = s_sum;
        o.f.tl_w31_active = tl_w31;
    }
}

sys run_prop_and_atomic() {
    let c_ent = query_one(c: &RelChild).on(ChildNode).unwrap().id;
    trigger(c_ent, PulseEvt { inc: 7 }, propagate: true);

    let mut psum: i32 = 0;
    for row in query(c: &RelChild) {
        psum += row.c.got_prop;
    }
    for o in query(f: &mut FlowOut) {
        o.f.prop_sum = psum;
    }

    for row in query(tx: &mut TxBox) {
        atomic {
            row.tx.hp = 30.0;
            row.tx.arr[0] = 300;
            row.tx.flags.set(5);
            atomic {
                row.tx.hp = 99.0;
                row.tx.arr[0] = 999;
                row.tx.flags.set(9);
                require_true(false);
            }
            require_true(true);
        }
    }
    for row in query(tr: &mut TxRoll) {
        atomic {
            row.tr.hp = 77.0;
            require_true(false);
        }
    }
}

schedule Startup { init_links }
schedule FixedUpdate {
    seq Frame {
        mutate_selective_and_spawn,
        count_sel_and_added,
        run_prop_and_atomic,
        WinTl,
        PersistFsm,
        BranchRaceTask,
    }
}
"#,
    );
    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick2", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick4", app.world());
    for (tag, suf) in [
        ("tick4_fo", "FlowOut"),
        ("tick4_rc", "RelChild"),
        ("tick4_rp", "RelParent"),
        ("tick4_sb", "SelBox"),
        ("tick4_rb", "RetBox"),
        ("tick4_bc", "BornComp"),
        ("tick4_tb", "TxBox"),
        ("tick4_tr", "TxRoll"),
    ] {
        dump_comp_bytes(&out_dir, tag, app.world(), suf);
    }
"#;
    let (_tmp, mir, mut w_jit, mut w_c99, mut w_rg, tier3) =
        setup_four_way_apps("wave3_ecs_flow", &src, tier3_driver);
    let flow_out_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("FlowOut"))
        .unwrap();
    let flow_out_off = |name: &str| {
        flow_out_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };
    let tx_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("TxBox"))
        .unwrap();
    let tx_off = |name: &str| {
        tx_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };
    let tr_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("TxRoll"))
        .unwrap();
    let tr_off = |name: &str| {
        tr_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };

    // `__strata_rel_parent_Squad.parent` stores opaque host `Entity` bits, which match identically
    // across JIT/C99/RustGuest while Tier-3 native allocates entities at a fixed offset. Verify
    // full 3-way `WorldPodDigest` + Tier-3 structural parity on every stage, plus bit-for-bit
    // 4-way POD byte parity across all non-Entity state components at `tick4`.
    let assert_flow_stage = |tag: &str, wj: &App, wc: &App, wr: &App| {
        let dj = hash_world_pod_state(wj.world());
        let dc = hash_world_pod_state(wc.world());
        let dr = hash_world_pod_state(wr.world());
        let dn = tier3.digests[tag];
        assert!(dj.pod_bytes_hashed > 0, "{tag}: empty POD state");
        assert_eq!(dj.sha256, dc.sha256, "{tag}: JIT vs C99");
        assert_eq!(dj.sha256, dr.sha256, "{tag}: JIT vs RustGuest");
        assert_eq!(dj.fnv1a64, dc.fnv1a64, "{tag}: fnv1a64 JIT vs C99");
        assert_eq!(dj.fnv1a64, dr.fnv1a64, "{tag}: fnv1a64 JIT vs RustGuest");
        assert_eq!(
            (dj.archetype_count, dj.entity_count, dj.pod_bytes_hashed),
            (dn.archetype_count, dn.entity_count, dn.pod_bytes_hashed),
            "{tag}: Tier-3 structural/POD size mismatch"
        );
    };

    assert_flow_stage("init", &w_jit, &w_c99, &w_rg);
    for tag in ["tick1", "tick2"] {
        for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
            w.world_mut().run_schedule(FixedUpdate);
        }
        assert_flow_stage(tag, &w_jit, &w_c99, &w_rg);
    }
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_flow_stage("tick4", &w_jit, &w_c99, &w_rg);

    for (dump_key, comp_name) in [
        ("tick4_fo", "FlowOut"),
        ("tick4_rc", "RelChild"),
        ("tick4_rp", "RelParent"),
        ("tick4_sb", "SelBox"),
        ("tick4_rb", "RetBox"),
        ("tick4_bc", "BornComp"),
        ("tick4_tb", "TxBox"),
        ("tick4_tr", "TxRoll"),
    ] {
        let h = find_component_handle(w_jit.world(), comp_name);
        let mut ents = find_entities_with_handle(w_jit.world(), h);
        ents.sort_unstable_by_key(|e| e.to_bits());
        let mut jit_bytes = Vec::new();
        for ent in ents {
            jit_bytes.extend_from_slice(&read_entity_pod_bytes(w_jit.world(), ent, h).unwrap());
        }
        assert_eq!(
            jit_bytes, tier3.pod_dumps[dump_key],
            "tick4: Tier-3 `{comp_name}` POD bytes must match JIT/C99/RustGuest bit-for-bit"
        );
    }

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let fb = read_single_comp_bytes_by_u32_id(app.world(), "FlowOut", flow_out_off("id"), 1);
        let r_u32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r_i32 = |b: &[u8], o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r_f32 = |b: &[u8], o: usize| f32::from_le_bytes(b[o..o + 4].try_into().unwrap());

        assert_eq!(
            r_u32(&fb, flow_out_off("sel_changed")),
            1,
            "{label} sel_changed"
        );
        assert_eq!(
            r_u32(&fb, flow_out_off("ret_changed")),
            1,
            "{label} ret_changed"
        );
        assert_eq!(
            r_u32(&fb, flow_out_off("added_seen")),
            1,
            "{label} added_seen"
        );
        assert_eq!(
            r_i32(&fb, flow_out_off("childof_sum")),
            221,
            "{label} childof_sum"
        );
        assert_eq!(
            r_i32(&fb, flow_out_off("squad_sum")),
            231,
            "{label} squad_sum"
        );
        // `trigger(..., propagate: true)` flushes via `Commands` after `run_prop_and_atomic` returns,
        // so tick 4 observes the 3 prior flushes (`3 * 2 * 7 = 42`) before the 4th flush brings
        // `RelChild.got_prop` across ChildNode + RootNode to 56.
        assert_eq!(r_i32(&fb, flow_out_off("prop_sum")), 42, "{label} prop_sum");
        assert!(
            r_u32(&fb, flow_out_off("tl_fired")) >= 1,
            "{label} tl_fired"
        );
        assert_eq!(
            fb[flow_out_off("tl_w31_active")],
            1,
            "{label} tl_w31_active"
        );
        assert_eq!(
            r_i32(&fb, flow_out_off("task_if_val")),
            111,
            "{label} task_if_val"
        );
        assert_eq!(
            r_i32(&fb, flow_out_off("task_race_ticks")),
            2,
            "{label} task_race_ticks"
        );
        assert_eq!(
            r_i32(&fb, flow_out_off("fsm_local_val")),
            13,
            "{label} fsm_local_val"
        );

        let tb = read_single_comp_bytes_by_u32_id(app.world(), "TxBox", tx_off("id"), 1);
        assert_eq!(
            r_f32(&tb, tx_off("hp")),
            30.0,
            "{label} nested atomic outer hp"
        );
        assert_eq!(
            r_i32(&tb, tx_off("arr")),
            300,
            "{label} nested atomic outer arr[0]"
        );
        let flags = r_u32(&tb, tx_off("flags"));
        assert_ne!(flags & (1u32 << 5), 0, "{label} outer bit 5 must stay set");
        assert_eq!(
            flags & (1u32 << 9),
            0,
            "{label} inner rolled-back bit 9 must stay clear"
        );

        let rb = read_single_comp_bytes_by_u32_id(app.world(), "TxRoll", tr_off("id"), 2);
        assert_eq!(
            r_f32(&rb, tr_off("hp")),
            10.0,
            "{label} rolled-back TxRoll hp"
        );
    }
}

#[test]
fn wave3_spatial_schedules_and_migrate_four_way_parity() {
    let _parity_rg = parity_alloc_read_guard();
    let src_v1 = r#"
module parity::wave3_spat_sched @version(1.0.0);

component MigBox { x: i32 = 30 }
sys init_mig() { let _ = spawn { MigBox { x: 30 } }; }
schedule Startup { init_mig }
"#;
    let src_v2 = r#"
module parity::wave3_spat_sched @version(2.0.0);

struct NestV2 {
    scale: i32 = 7,
    bs: BitSet<128> = bits(2, 70),
}

component MigBoxV1 { x: i32 = 0 }
component MigBox {
    x: i32 = 0,
    flag: bool = true,
    m3: mat3 = mat3::IDENTITY,
    nest: NestV2 = NestV2 {},
}

migrate MigBox from 1.0.0 to 2.0.0 (old: &MigBoxV1) -> MigBox {
    MigBox {
        x: old.x + 5,
        flag: true,
        m3: mat3::IDENTITY,
        nest: NestV2 {},
    }
}

component Pos3 { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
tag SpatTag;

spatial_grid GridXZ(
    cell_size: 4.0_m,
    bounds: vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
    plane_axes: [0, 2],
    capacity: 16,
) over SpatTag by Pos3.xyz;

spatial_history HistXZ(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
    plane_axes: [0, 2],
    capacity: 16,
) over SpatTag by Pos3.xyz;

component SpatOut {
    id: u32 = 1,
    xz_hits: u32 = 0,
    seg_wide_hits: u32 = 0,
    seg_narrow_hits: u32 = 0,
    seg_oob_hits: u32 = 0,
    sched_trace: i32 = 0,
    never_ran: bool = false,
}

object UnitNearZ { Pos3 { xyz: vec3(2.0, 50.0, 2.0) }, SpatTag }
object UnitMoveZ { Pos3 { xyz: vec3(2.0, -30.0, 12.0) }, SpatTag }
object ProbeEnt { SpatOut { id: 1 } }

sys move_z_in_range() {
    for p in query(pos: &mut Pos3) {
        if p.pos.xyz.z > 10.0 {
            p.pos.xyz.z = 2.0;
        }
    }
}

sys scan_xz_and_hist(g: &res GridXZ, h: &res HistXZ) {
    let mut xz: u32 = 0;
    for _u in g.query_disc(vec2(2.0, 2.0), 1.5_m) {
        xz += 1;
    }
    let mut sw: u32 = 0;
    for _w in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 0.0), 2.5_m) {
        sw += 1;
    }
    let mut sn: u32 = 0;
    for _n in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 0.0), 0.5_m) {
        sn += 1;
    }
    let mut soob: u32 = 0;
    for _o in h.query_segment_at(999, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 0.0), 5.0_m) {
        soob += 1;
    }
    for row in query(so: &mut SpatOut) {
        row.so.xz_hits = xz;
        row.so.seg_wide_hits = sw;
        row.so.seg_narrow_hits = sn;
        row.so.seg_oob_hits = soob;
    }
}

sys step_a() {
    for row in query(so: &mut SpatOut) {
        row.so.sched_trace = 1;
    }
}

sys step_b() {
    for row in query(so: &mut SpatOut) {
        row.so.sched_trace = row.so.sched_trace * 10 + 2;
    }
}

sys blocked_sys() {
    for row in query(so: &mut SpatOut) {
        row.so.never_ran = true;
    }
}

schedule FixedUpdate {
    move_z_in_range before(scan_xz_and_hist)
    scan_xz_and_hist
    set GroupA before(GroupB) { step_a }
    set GroupB after(GroupA) { step_b }
}

schedule FixedUpdate run_if(false) {
    blocked_sys
}
"#;

    // 1. 4-way differential parity on v2 spatial XZ, non-seq rebuild, radius/OOB, before/after, run_if(false)
    let tier3_driver = r#"
    app.world_mut().run_schedule(Startup);
    capture_snapshot(&out_dir, "init", app.world());
    app.world_mut().run_schedule(FixedUpdate);
    capture_snapshot(&out_dir, "tick1", app.world());
"#;
    let (tmp, mir, mut w_jit, mut w_c99, mut w_rg, tier3) =
        setup_four_way_apps("wave3_spat_sched", src_v2, tier3_driver);
    let so_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("SpatOut"))
        .unwrap();
    let so_off = |name: &str| {
        so_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };

    assert_four_way_snapshot("init", &w_jit, &w_c99, &w_rg, &tier3);
    for w in [&mut w_jit, &mut w_c99, &mut w_rg] {
        w.world_mut().run_schedule(FixedUpdate);
    }
    assert_four_way_snapshot("tick1", &w_jit, &w_c99, &w_rg, &tier3);

    for (label, app) in [("jit", &w_jit), ("c99", &w_c99), ("rust_guest", &w_rg)] {
        let b = read_single_comp_bytes_by_u32_id(app.world(), "SpatOut", so_off("id"), 1);
        let r_u32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r_i32 = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        assert_eq!(r_u32(so_off("xz_hits")), 2, "{label} xz_hits");
        assert_eq!(r_u32(so_off("seg_wide_hits")), 2, "{label} seg_wide_hits");
        assert_eq!(
            r_u32(so_off("seg_narrow_hits")),
            0,
            "{label} seg_narrow_hits"
        );
        assert_eq!(r_u32(so_off("seg_oob_hits")), 0, "{label} seg_oob_hits");
        assert_eq!(r_i32(so_off("sched_trace")), 12, "{label} sched_trace");
        assert_eq!(b[so_off("never_ran")], 0, "{label} run_if(false) never_ran");
    }

    // 2. Live Slot-67 v1 -> v2 migration with mat3 + nested BitSet<128> across JIT, C99, RustGuest
    let v1_path = tmp.path().join("mig_adv_v1.strata");
    let v2_path = tmp.path().join("mig_adv_v2.strata");
    fs::write(&v1_path, src_v1).unwrap();
    fs::write(&v2_path, src_v2).unwrap();

    let mb_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("MigBox"))
        .unwrap();
    let mb_off = |name: &str| {
        mb_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap()
            .offset
    };

    let mut mig_bytes = Vec::new();
    for (label, target) in [
        ("jit", BuildTarget::Jit),
        ("c99", BuildTarget::C99),
        ("rust_guest", BuildTarget::RustGuest),
    ] {
        let bin_v1 = build_target_bin(&v1_path, target, &tmp.path().join(format!("{label}_mv1")));
        let bin_v2 = build_target_bin(&v2_path, target, &tmp.path().join(format!("{label}_mv2")));
        let (mut app, mod_id) = setup_dynamic_app_with_mod(&bin_v1);
        let h_v1 = find_component_handle(app.world(), "MigBox");
        let ents = find_entities_with_handle(app.world(), h_v1);
        assert_eq!(ents.len(), 1, "{label} v1 MigBox entity");
        let ent = ents[0];

        app.reload_mod_from(mod_id, &bin_v2, LoadOptions::default())
            .unwrap_or_else(|e| panic!("{label} Slot-67 migrate failed: {e}"));
        let h_v2 = find_component_handle(app.world(), "MigBox");
        let bytes = read_entity_pod_bytes(app.world(), ent, h_v2).unwrap();
        let x = i32::from_le_bytes(bytes[mb_off("x")..mb_off("x") + 4].try_into().unwrap());
        assert_eq!(x, 35, "{label} migrated x");
        assert_eq!(bytes[mb_off("flag")], 1, "{label} migrated flag");
        let m0 = f32::from_le_bytes(bytes[mb_off("m3")..mb_off("m3") + 4].try_into().unwrap());
        let m4 = f32::from_le_bytes(
            bytes[mb_off("m3") + 16..mb_off("m3") + 20]
                .try_into()
                .unwrap(),
        );
        assert!(
            (m0 - 1.0).abs() < 1e-5 && (m4 - 1.0).abs() < 1e-5,
            "{label} mat3::IDENTITY"
        );
        mig_bytes.push((label, bytes));
    }
    for (label, bytes) in &mig_bytes[1..] {
        assert_eq!(
            bytes, &mig_bytes[0].1,
            "migrated MigBox bytes diverged for `{label}`"
        );
    }
}
