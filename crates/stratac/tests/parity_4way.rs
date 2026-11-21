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
    cmd_build, cmd_onboard, sanitized_cargo, shared_temp_target_dir, write_local_patch_config,
};
use stratac::sim_runner::{WorldPodDigest, hash_world_pod_state};
use tempfile::TempDir;

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
    entry.is_abi_pod && (entry.storage_flags & non_entity_mask) == 0
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
