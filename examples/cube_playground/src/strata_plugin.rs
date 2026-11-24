//! Generic, zero-game-knowledge, shape-agnostic Bevy [`Plugin`] bridging a single
//! `.strata` script to the full Bevy `0.20.1` engine + `bamabi` companion bridges,
//! `FixedUpdate`, live Zed hot-reloading, and `"BAMT"` telemetry.

use bamabi::prelude::{
    ModPreset3dPlugin, ModPresetUiPlugin, ModReflectPlugin, ModRenderRecoveryPlugin,
    ModSaveGamePlugin, ModSubAppPlugin, ModTelemetryPlugin, ModWeslMaterialPlugin,
};
use bamabi_host::prelude::*;
use bamabi_host::{
    BamFieldDescriptor, BamFieldPodKind, RegisteredComponent, inspect_component_bam_fields,
    read_entity_pod_bytes,
};
use bamabi_sys::SystemTelemetryDigest64;
use bevy::asset::RenderAssetUsages;
use bevy::mesh::{Indices, PrimitiveTopology};
use bevy::prelude::*;
use bevy::remote::RemotePlugin;
use bevy::render::RenderApp;
use notify_debouncer_full::notify::event::{
    AccessKind, AccessMode, CreateKind, ModifyKind, RenameMode,
};
use notify_debouncer_full::notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{
    DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache, new_debouncer,
};
use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use strata_codegen::module_stem;
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{lower_to_mir, verify_mir};
use strata_sema::db::Setter;
use strata_sema::{SemaDb, Severity, SourceFile};
use tempfile::TempDir;

const DEFAULT_TELEMETRY_PORT: u16 = 15703;

/// Generic Bevy plugin onboarding full Bevy + `bamabi` bridges and compiling,
/// loading, hot-reloading, and syncing a `.strata` script.
pub(crate) struct StrataPlugin {
    script_path: PathBuf,
    watch: bool,
    headless: bool,
    telemetry_port: u16,
}

impl StrataPlugin {
    /// Creates a windowed [`StrataPlugin`] onboarding all internal Bevy crates
    /// and watching `script_path` for live hot-reloads on save.
    pub(crate) fn watch(script_path: PathBuf) -> Self {
        Self {
            script_path,
            watch: true,
            headless: false,
            telemetry_port: DEFAULT_TELEMETRY_PORT,
        }
    }

    /// Creates a headless [`StrataPlugin`] without windowing, file watching, or TCP
    /// telemetry (for deterministic integration tests).
    #[cfg(test)]
    pub(crate) fn headless(script_path: PathBuf) -> Self {
        Self {
            script_path,
            watch: false,
            headless: true,
            telemetry_port: 0,
        }
    }

    /// Resolves the default `game.strata` path from CWD or crate manifest directory.
    pub(crate) fn default_script_path() -> PathBuf {
        for candidate in [
            PathBuf::from("game.strata"),
            PathBuf::from("examples/cube_playground/game.strata"),
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/game.strata")),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/game.strata"))
    }
}

impl Plugin for StrataPlugin {
    fn build(&self, app: &mut App) {
        // 1. Core `bamabi` host + full 3D/UI/Asset/State/Picking/Audio/BSN bridges MUST
        //    install `ModAssetPlugin` before Bevy's `AssetPlugin` builds `AssetServer`.
        if !app.is_plugin_added::<AbiModPlugin>() {
            app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        }
        if !app.is_plugin_added::<ModPreset3dPlugin>() {
            app.add_plugins(ModPreset3dPlugin);
        }
        if !app.is_plugin_added::<ModPresetUiPlugin>() {
            app.add_plugins(ModPresetUiPlugin);
        }

        // 2. Full Bevy internal crate onboarding (windowed `DefaultPlugins` vs headless test shell).
        if self.headless {
            app.add_plugins((
                MinimalPlugins,
                bevy::asset::AssetPlugin::default(),
                bevy::input::InputPlugin,
            ));
            app.init_asset::<Mesh>();
            app.init_asset::<StandardMaterial>();
            app.init_asset::<Shader>();
            app.init_asset::<AudioSource>();
            app.insert_resource(RemSize(16.0));
        } else {
            // `ModPreset3dPlugin` already registers `StatesPlugin`.
            app.add_plugins(
                DefaultPlugins
                    .set(WindowPlugin {
                        primary_window: Some(Window {
                            title: format!("Strata — {}", self.script_path.display()),
                            ..default()
                        }),
                        ..default()
                    })
                    .disable::<bevy::state::app::StatesPlugin>(),
            );
        }

        // 3. Post-engine `bamabi` companion plugins: reflection/BRP, save/load, telemetry,
        //    WESL materials, and `RenderApp` extraction + device-loss recovery when rendering.
        app.add_plugins((
            RemotePlugin::default(),
            ModReflectPlugin,
            ModSaveGamePlugin::new(),
            ModTelemetryPlugin::new(),
            ModWeslMaterialPlugin,
        ));
        if app.get_sub_app(RenderApp).is_some() {
            app.add_plugins((
                ModSubAppPlugin::<RenderApp>::default(),
                ModRenderRecoveryPlugin::default(),
            ));
        }

        let sink_tx = TelemetryBroadcaster::bind(self.telemetry_port);
        app.add_plugins(ModTelemetrySinkPlugin::new().with_sink(move |digests| {
            sink_tx.broadcast(digests);
        }));
        ensure_child_of_registered(app.world_mut());

        // 4. Initial Salsa + Cranelift JIT compilation of the `.strata` script.
        let mut compiler = match StrataCompiler::new() {
            Ok(c) => c,
            Err(err) => {
                eprintln!("[Strata] {err}");
                return;
            }
        };

        let mut last_source = String::new();
        let mut active_mod = None;
        let mut last_error = None;

        match fs::read_to_string(&self.script_path) {
            Ok(source) => {
                last_source = source.clone();
                match compiler.compile_source(&self.script_path, &source) {
                    Ok(art) => {
                        match app.load_mod_with(
                            &art.dylib_path,
                            LoadOptions::new().with_shadow_copy(true),
                        ) {
                            Ok(id) => {
                                active_mod = Some(id);
                                println!(
                                    "[Strata] Loaded {} from {} in {:.1} ms ({id:?})",
                                    art.module_path,
                                    self.script_path.display(),
                                    art.compile_ms
                                );
                            }
                            Err(err) => {
                                let msg = format!("bamabi_host failed loading mod: {err}");
                                eprintln!("[Strata] {msg}");
                                last_error = Some(msg);
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("[Strata] Initial compile error:\n{err}");
                        last_error = Some(err);
                    }
                }
            }
            Err(err) => {
                let msg = format!("failed reading `{}`: {err}", self.script_path.display());
                eprintln!("[Strata] {msg}");
                last_error = Some(msg);
            }
        }

        let watcher = if self.watch {
            match ScriptWatcher::new(&self.script_path) {
                Ok(w) => Some(w),
                Err(err) => {
                    eprintln!("[Strata] Watcher disabled: {err}");
                    None
                }
            }
        } else {
            None
        };

        app.insert_resource(StrataRuntimeState {
            script_path: self.script_path.clone(),
            active_mod,
            last_source,
            reload_count: 0,
            last_error,
            inner: Mutex::new(StrataSyncInner { compiler, watcher }),
        });

        app.add_systems(ModLifecycleFlush, poll_strata_hot_reload);
        app.add_systems(
            PostUpdate,
            sync_strata_to_bevy_3d.before(TransformSystems::Propagate),
        );
    }
}

#[derive(Resource)]
struct StrataRuntimeState {
    script_path: PathBuf,
    active_mod: Option<ModId>,
    last_source: String,
    reload_count: u64,
    last_error: Option<String>,
    inner: Mutex<StrataSyncInner>,
}

struct StrataSyncInner {
    compiler: StrataCompiler,
    watcher: Option<ScriptWatcher>,
}

#[derive(Component, Clone, Copy, PartialEq, Eq)]
struct SyncedMeshKey {
    revision: u32,
    vertex_count: u32,
    index_count: u32,
    content_hash: u64,
}

#[derive(Clone)]
struct TelemetryBroadcaster {
    state: Option<Arc<Mutex<TelemetryTcpState>>>,
}

struct TelemetryTcpState {
    listener: TcpListener,
    clients: Vec<TcpStream>,
}

impl TelemetryBroadcaster {
    fn bind(port: u16) -> Self {
        if port == 0 {
            return Self { state: None };
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let Ok(listener) = TcpListener::bind(addr) else {
            return Self { state: None };
        };
        if listener.set_nonblocking(true).is_err() {
            return Self { state: None };
        }
        Self {
            state: Some(Arc::new(Mutex::new(TelemetryTcpState {
                listener,
                clients: Vec::new(),
            }))),
        }
    }

    fn broadcast(&self, digests: &[SystemTelemetryDigest64]) {
        if digests.is_empty() {
            return;
        }
        let Some(ref arc) = self.state else {
            return;
        };
        let Ok(mut guard) = arc.lock() else {
            return;
        };
        while let Ok((stream, _)) = guard.listener.accept() {
            if stream.set_nonblocking(true).is_ok() {
                guard.clients.push(stream);
            }
        }
        if guard.clients.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(digests.len() * 64);
        for d in digests {
            bytes.extend_from_slice(&d.to_le_bytes());
        }
        guard
            .clients
            .retain_mut(|stream| match stream.write_all(&bytes) {
                Ok(()) => true,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(_) => false,
            });
    }
}

struct CompiledArtifact {
    dylib_path: PathBuf,
    module_path: String,
    compile_ms: f64,
}

struct StrataCompiler {
    db: SemaDb,
    sfile: Option<SourceFile>,
    build_dir: TempDir,
    build_seq: u64,
}

impl StrataCompiler {
    fn new() -> Result<Self, String> {
        let build_dir = TempDir::new().map_err(|e| format!("failed creating JIT temp dir: {e}"))?;
        Ok(Self {
            db: SemaDb::default(),
            sfile: None,
            build_dir,
            build_seq: 0,
        })
    }

    fn compile_source(
        &mut self,
        display_path: &Path,
        source: &str,
    ) -> Result<CompiledArtifact, String> {
        let t0 = Instant::now();
        let path_str = display_path.to_string_lossy().into_owned();
        let sfile = match self.sfile {
            Some(existing) => {
                if *existing.path(&self.db) != path_str {
                    existing.set_path(&mut self.db).to(path_str);
                }
                existing.set_text(&mut self.db).to(source.to_owned());
                existing
            }
            None => {
                let created = SourceFile::new(&self.db, path_str, source.to_owned());
                self.sfile = Some(created);
                created
            }
        };

        let analyzed = self.db.analyze_file(sfile);
        if !analyzed.ok() {
            let mut lines = Vec::new();
            for diag in analyzed
                .diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Error)
            {
                lines.push(format!(
                    "{}:{}:{}: [{}] {}",
                    diag.span.file, diag.span.line, diag.span.col, diag.code, diag.message
                ));
            }
            return Err(if lines.is_empty() {
                "Strata semantic check failed".to_owned()
            } else {
                lines.join("\n")
            });
        }

        let mir = lower_to_mir(&analyzed);
        if let Err(errs) = verify_mir(&mir) {
            let detail = errs
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!("MIR verification failed:\n{detail}"));
        }

        self.build_seq = self.build_seq.saturating_add(1);
        let gen_dir = self
            .build_dir
            .path()
            .join(format!("gen_{}", self.build_seq));
        let stem = module_stem(&mir.module_path);
        let art = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir: gen_dir,
                module_stem: stem,
                opt_level: JitOptLevel::FastCompile,
            },
        )
        .map_err(|e| format!("Cranelift JIT build failed: {e}"))?;

        Ok(CompiledArtifact {
            dylib_path: art.dylib_path,
            module_path: mir.module_path,
            compile_ms: t0.elapsed().as_secs_f64() * 1000.0,
        })
    }
}

struct ScriptWatcher {
    _debouncer: Debouncer<notify_debouncer_full::notify::RecommendedWatcher, RecommendedCache>,
    rx: Receiver<DebounceEventResult>,
    target_name: std::ffi::OsString,
    target_canonical: PathBuf,
}

impl ScriptWatcher {
    fn new(script_path: &Path) -> Result<Self, String> {
        let abs = fs::canonicalize(script_path).unwrap_or_else(|_| script_path.to_path_buf());
        let watch_dir = abs
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let target_name = abs
            .file_name()
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("script path `{}` has no filename", script_path.display()))?;

        let (tx, rx) = mpsc::channel::<DebounceEventResult>();
        let mut debouncer = new_debouncer(Duration::from_millis(60), None, tx)
            .map_err(|e| format!("failed initializing file watcher: {e}"))?;
        debouncer
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| format!("failed watching `{}`: {e}", watch_dir.display()))?;

        Ok(Self {
            _debouncer: debouncer,
            rx,
            target_name,
            target_canonical: abs,
        })
    }

    fn poll_changed(&self) -> bool {
        let mut changed = false;
        while let Ok(res) = self.rx.try_recv() {
            if let Ok(events) = res {
                for ev in &events {
                    if is_relevant_watch_event(ev)
                        && ev.paths.iter().any(|p| self.matches_target(p))
                    {
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    fn matches_target(&self, path: &Path) -> bool {
        if path.file_name() == Some(self.target_name.as_os_str()) {
            return true;
        }
        fs::canonicalize(path)
            .map(|canon| canon == self.target_canonical)
            .unwrap_or(false)
    }
}

fn is_relevant_watch_event(ev: &DebouncedEvent) -> bool {
    matches!(
        ev.kind,
        EventKind::Create(CreateKind::File | CreateKind::Any)
            | EventKind::Modify(
                ModifyKind::Data(_)
                    | ModifyKind::Name(RenameMode::To | RenameMode::Both | RenameMode::Any)
                    | ModifyKind::Any
            )
            | EventKind::Access(AccessKind::Close(AccessMode::Write))
    )
}

fn ensure_child_of_registered(world: &mut World) {
    let child_of_id = world.register_component::<ChildOf>();
    let is_immutable = world
        .components()
        .get_info(child_of_id)
        .is_some_and(|info| !info.mutable());
    if let Some(mut reg) = world.get_resource_mut::<ModRegistry>()
        && reg.get_by_name(bamabi_sys::BAM_CHILD_OF_NAME).is_none()
    {
        let _ = reg.register_hierarchy(child_of_id, is_immutable);
    }
}

fn poll_strata_hot_reload(world: &mut World) {
    let should_check = world
        .get_resource::<StrataRuntimeState>()
        .and_then(|rt| {
            let guard = rt.inner.lock().ok()?;
            Some(
                guard
                    .watcher
                    .as_ref()
                    .is_some_and(ScriptWatcher::poll_changed),
            )
        })
        .unwrap_or(false);
    if should_check {
        reload_strata_from_disk(world);
    }
}

fn reload_strata_from_disk(world: &mut World) -> bool {
    let Some((script_path, last_source, old_id)) =
        world.get_resource::<StrataRuntimeState>().map(|rt| {
            (
                rt.script_path.clone(),
                rt.last_source.clone(),
                rt.active_mod,
            )
        })
    else {
        return false;
    };

    let Ok(source) = fs::read_to_string(&script_path) else {
        return false;
    };
    if source == last_source {
        return false;
    }

    let compile_res = world.get_resource::<StrataRuntimeState>().and_then(|rt| {
        rt.inner
            .lock()
            .ok()
            .map(|mut g| g.compiler.compile_source(&script_path, &source))
    });

    let Some(compile_res) = compile_res else {
        return false;
    };

    let art = match compile_res {
        Ok(a) => a,
        Err(err) => {
            eprintln!("[Strata] Compile error (keeping previous scene live):\n{err}");
            if let Some(mut rt) = world.get_resource_mut::<StrataRuntimeState>() {
                rt.last_source = source;
                rt.last_error = Some(err);
            }
            return false;
        }
    };

    if let Some(prev_id) = old_id
        && let Err(err) = world.unload_mod(prev_id)
    {
        eprintln!("[Strata] Unload error ({prev_id:?}): {err}");
        if let Some(mut rt) = world.get_resource_mut::<StrataRuntimeState>() {
            rt.last_error = Some(err.to_string());
        }
        return false;
    }

    match world.load_mod_with(&art.dylib_path, LoadOptions::new().with_shadow_copy(true)) {
        Ok(new_id) => {
            if let Some(mut rt) = world.get_resource_mut::<StrataRuntimeState>() {
                rt.active_mod = Some(new_id);
                rt.last_source = source;
                rt.reload_count = rt.reload_count.saturating_add(1);
                rt.last_error = None;
                println!(
                    "[Strata] Hot-reloaded {} (#{}) in {:.1} ms",
                    art.module_path, rt.reload_count, art.compile_ms
                );
            }
            true
        }
        Err(err) => {
            eprintln!(
                "[Strata] Reload failed ({err}); if you modified component fields, restart the app"
            );
            if let Some(mut rt) = world.get_resource_mut::<StrataRuntimeState>() {
                rt.active_mod = None;
                rt.last_source = source;
                rt.last_error = Some(err.to_string());
            }
            false
        }
    }
}

struct ReflectedComp {
    entry: RegisteredComponent,
    fields: Vec<BamFieldDescriptor>,
}

fn find_comp(
    world: &World,
    entries: &[RegisteredComponent],
    aliases: &[&str],
) -> Option<ReflectedComp> {
    for &alias in aliases {
        for entry in entries {
            let short = entry
                .name
                .rsplit("::")
                .next()
                .unwrap_or(entry.name.as_ref());
            if short.eq_ignore_ascii_case(alias) {
                let fields = inspect_component_bam_fields(world, entry.handle)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                return Some(ReflectedComp {
                    entry: entry.clone(),
                    fields,
                });
            }
        }
    }
    None
}

fn sync_strata_to_bevy_3d(world: &mut World) {
    let Some(snap) = world
        .get_resource::<ModRegistry>()
        .map(ModRegistry::snapshot)
    else {
        return;
    };
    let entries: Vec<RegisteredComponent> = snap
        .entries()
        .iter()
        .filter(|e| {
            e.is_abi_pod
                && !e.is_resource()
                && !e.is_message()
                && !e.is_event()
                && !e.is_entity_event()
                && !e.name.starts_with("bevy_ecs::")
        })
        .cloned()
        .collect();

    let pos_c = find_comp(world, &entries, &["Position", "Pos", "Pos3D"]);
    let rot_c = find_comp(world, &entries, &["Rotation", "Rot", "Rot3D"]);
    let scale_c = find_comp(world, &entries, &["Scale", "Scale3D"]);
    let xf_c = find_comp(world, &entries, &["Transform"]);
    let mesh_c = find_comp(world, &entries, &["Mesh"]);
    let mat_c = find_comp(world, &entries, &["Material", "Color", "ColorRgba"]);
    let cam_c = find_comp(world, &entries, &["Camera"]);
    let pt_light_c = find_comp(world, &entries, &["PointLight"]);
    let dir_light_c = find_comp(world, &entries, &["DirectionalLight"]);

    let tracked_ids: Vec<_> = [
        &pos_c,
        &rot_c,
        &scale_c,
        &xf_c,
        &mesh_c,
        &mat_c,
        &cam_c,
        &pt_light_c,
        &dir_light_c,
    ]
    .into_iter()
    .flatten()
    .map(|c| c.entry.component_id)
    .collect();

    if tracked_ids.is_empty() {
        return;
    }

    let mut entities = Vec::new();
    let mut seen = HashSet::new();
    for arch in world.archetypes().iter() {
        if arch.is_empty() || !tracked_ids.iter().any(|id| arch.contains(*id)) {
            continue;
        }
        for ae in arch.entities() {
            let ent = ae.id();
            if seen.insert(ent.to_bits()) {
                entities.push(ent);
            }
        }
    }

    for ent in entities {
        let mut translation = Vec3::ZERO;
        let mut rotation = Quat::IDENTITY;
        let mut scale = Vec3::ONE;

        if let Some(ref xf) = xf_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, xf.entry.handle)
        {
            (translation, rotation, scale) = extract_transform(&xf.fields, &bytes);
        }
        if let Some(ref pc) = pos_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, pc.entry.handle)
        {
            translation = extract_vec3(&pc.fields, &bytes, Vec3::ZERO);
        }
        if let Some(ref rc) = rot_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, rc.entry.handle)
        {
            rotation = extract_rotation(&rc.fields, &bytes);
        }
        if let Some(ref sc) = scale_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, sc.entry.handle)
        {
            scale = extract_scale(&sc.fields, &bytes);
        }

        let mut transform = Transform {
            translation: sanitize_vec3(translation, Vec3::ZERO),
            rotation: sanitize_quat(rotation),
            scale: sanitize_vec3(scale, Vec3::ONE),
        };

        if let Some(ref cc) = cam_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, cc.entry.handle)
        {
            let (look_at, fov_deg, clear_color) = extract_camera(&cc.fields, &bytes);
            transform = transform.looking_at(look_at, Vec3::Y);
            let clear = Color::srgba(
                clear_color[0],
                clear_color[1],
                clear_color[2],
                clear_color[3],
            );
            let proj = Projection::Perspective(PerspectiveProjection {
                fov: fov_deg.clamp(5.0, 150.0).to_radians(),
                ..default()
            });
            if let Ok(mut e) = world.get_entity_mut(ent) {
                if e.contains::<Camera3d>() {
                    if let Some(mut cam) = e.get_mut::<Camera>() {
                        cam.clear_color = ClearColorConfig::Custom(clear);
                    }
                    if let Some(mut p) = e.get_mut::<Projection>() {
                        *p = proj;
                    }
                } else {
                    e.insert((
                        Camera3d::default(),
                        Camera {
                            clear_color: ClearColorConfig::Custom(clear),
                            ..default()
                        },
                        proj,
                    ));
                }
            }
        }

        if let Some(ref lc) = pt_light_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, lc.entry.handle)
        {
            let (col, intensity, shadows) = extract_point_light(&lc.fields, &bytes);
            let color = Color::srgba(col[0], col[1], col[2], col[3]);
            if let Ok(mut e) = world.get_entity_mut(ent) {
                if let Some(mut light) = e.get_mut::<PointLight>() {
                    light.color = color;
                    light.intensity = intensity;
                    light.shadow_maps_enabled = shadows;
                } else {
                    e.insert(PointLight {
                        color,
                        intensity,
                        shadow_maps_enabled: shadows,
                        ..default()
                    });
                }
            }
        }

        if let Some(ref dlc) = dir_light_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, dlc.entry.handle)
        {
            let (col, illuminance, shadows) = extract_dir_light(&dlc.fields, &bytes);
            let color = Color::srgba(col[0], col[1], col[2], col[3]);
            if let Ok(mut e) = world.get_entity_mut(ent) {
                if let Some(mut light) = e.get_mut::<DirectionalLight>() {
                    light.color = color;
                    light.illuminance = illuminance;
                    light.shadow_maps_enabled = shadows;
                } else {
                    e.insert(DirectionalLight {
                        color,
                        illuminance,
                        shadow_maps_enabled: shadows,
                        ..default()
                    });
                }
            }
        }

        if let Some(ref mc) = mesh_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, mc.entry.handle)
            && let Some(key) = extract_mesh_key(&mc.fields, &bytes)
        {
            let existing_key = world
                .get_entity(ent)
                .ok()
                .and_then(|e| e.get::<SyncedMeshKey>().copied());
            let existing_handle = world
                .get_entity(ent)
                .ok()
                .and_then(|e| e.get::<Mesh3d>().map(|m| m.0.clone()));
            let needs_upload = existing_key != Some(key) || existing_handle.is_none();

            if needs_upload
                && let Some(mesh) = extract_procedural_mesh(&mc.fields, &bytes, key)
                && let Some(mut meshes) = world.get_resource_mut::<Assets<Mesh>>()
            {
                if let Some(handle) = existing_handle {
                    if let Some(mut asset) = meshes.get_mut(&handle) {
                        *asset = mesh;
                    } else {
                        let new_handle = meshes.add(mesh);
                        if let Ok(mut e) = world.get_entity_mut(ent) {
                            e.insert(Mesh3d(new_handle));
                        }
                    }
                    if let Ok(mut e) = world.get_entity_mut(ent) {
                        e.insert(key);
                    }
                } else {
                    let handle = meshes.add(mesh);
                    if let Ok(mut e) = world.get_entity_mut(ent) {
                        e.insert((Mesh3d(handle), key));
                    }
                }
            }
        }

        if let Some(ref mat_comp) = mat_c
            && let Ok(bytes) = read_entity_pod_bytes(world, ent, mat_comp.entry.handle)
        {
            let mat = extract_standard_material(&mat_comp.fields, &bytes);
            let existing_handle = world.get_entity(ent).ok().and_then(|e| {
                e.get::<MeshMaterial3d<StandardMaterial>>()
                    .map(|m| m.0.clone())
            });
            if let Some(mut materials) = world.get_resource_mut::<Assets<StandardMaterial>>() {
                if let Some(handle) = existing_handle {
                    if let Some(mut asset) = materials.get_mut(&handle) {
                        *asset = mat;
                    }
                } else {
                    let handle = materials.add(mat);
                    if let Ok(mut e) = world.get_entity_mut(ent) {
                        e.insert(MeshMaterial3d(handle));
                    }
                }
            }
        }

        if let Ok(mut e) = world.get_entity_mut(ent) {
            if let Some(mut tf) = e.get_mut::<Transform>() {
                *tf = transform;
            } else {
                e.insert(transform);
            }
        }
    }
}

fn non_padding(fields: &[BamFieldDescriptor]) -> impl Iterator<Item = &BamFieldDescriptor> {
    fields
        .iter()
        .filter(|f| !f.name.starts_with("_strata_pad_"))
}

fn read_u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = bytes.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_f32_at(bytes: &[u8], off: usize) -> Option<f32> {
    let end = off.checked_add(4)?;
    let s = bytes.get(off..end)?;
    let v = f32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    Some(if v.is_finite() { v } else { 0.0 })
}

fn read_vec2_at(bytes: &[u8], off: usize) -> Option<[f32; 2]> {
    Some([read_f32_at(bytes, off)?, read_f32_at(bytes, off + 4)?])
}

fn read_vec3_at(bytes: &[u8], off: usize) -> Option<[f32; 3]> {
    Some([
        read_f32_at(bytes, off)?,
        read_f32_at(bytes, off + 4)?,
        read_f32_at(bytes, off + 8)?,
    ])
}

fn read_vec4_at(bytes: &[u8], off: usize) -> Option<[f32; 4]> {
    Some([
        read_f32_at(bytes, off)?,
        read_f32_at(bytes, off + 4)?,
        read_f32_at(bytes, off + 8)?,
        read_f32_at(bytes, off + 12)?,
    ])
}

fn read_bool_at(bytes: &[u8], off: usize) -> Option<bool> {
    bytes.get(off).map(|&b| b != 0)
}

fn fnv1a_step(mut hash: u64, slice: &[u8]) -> u64 {
    for &b in slice {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn extract_mesh_key(fields: &[BamFieldDescriptor], bytes: &[u8]) -> Option<SyncedMeshKey> {
    let mut vertex_count = 0_u32;
    let mut index_count = 0_u32;
    let mut revision = 0_u32;
    let mut pos_slice: Option<&BamFieldDescriptor> = None;
    let mut norm_slice: Option<&BamFieldDescriptor> = None;
    let mut uv_slice: Option<&BamFieldDescriptor> = None;
    let mut idx_slice: Option<&BamFieldDescriptor> = None;

    for f in non_padding(fields) {
        match f.name.as_str() {
            "vertex_count" => {
                if let Some(v) = read_u32_at(bytes, f.offset) {
                    vertex_count = v;
                }
            }
            "index_count" | "indices_len" => {
                if let Some(v) = read_u32_at(bytes, f.offset) {
                    index_count = v;
                }
            }
            "revision" | "version" => {
                if let Some(v) = read_u32_at(bytes, f.offset) {
                    revision = v;
                }
            }
            "positions" | "vertices" => pos_slice = Some(f),
            "normals" => norm_slice = Some(f),
            "uvs" | "uv0" => uv_slice = Some(f),
            "indices" | "triangles" => idx_slice = Some(f),
            _ => {}
        }
    }

    let pf = pos_slice?;
    let max_verts = pf.size / 12;
    let vcount = (vertex_count as usize).min(max_verts);
    let icount = idx_slice
        .map(|f| (index_count as usize).min(f.size / 4))
        .unwrap_or(0);
    if vcount < 3 || icount < 3 {
        return None;
    }

    let mut hash = 0xCBF2_9CE4_8422_2325_u64;
    if let Some(end) = pf.offset.checked_add(vcount.saturating_mul(12))
        && let Some(sl) = bytes.get(pf.offset..end)
    {
        hash = fnv1a_step(hash, sl);
    }
    if let Some(nf) = norm_slice
        && vcount <= nf.size / 12
        && let Some(end) = nf.offset.checked_add(vcount.saturating_mul(12))
        && let Some(sl) = bytes.get(nf.offset..end)
    {
        hash = fnv1a_step(hash, sl);
    }
    if let Some(uf) = uv_slice
        && vcount <= uf.size / 8
        && let Some(end) = uf.offset.checked_add(vcount.saturating_mul(8))
        && let Some(sl) = bytes.get(uf.offset..end)
    {
        hash = fnv1a_step(hash, sl);
    }
    if let Some(ixf) = idx_slice
        && let Some(end) = ixf.offset.checked_add(icount.saturating_mul(4))
        && let Some(sl) = bytes.get(ixf.offset..end)
    {
        hash = fnv1a_step(hash, sl);
    }

    Some(SyncedMeshKey {
        revision,
        vertex_count: vcount as u32,
        index_count: icount as u32,
        content_hash: hash,
    })
}

fn extract_procedural_mesh(
    fields: &[BamFieldDescriptor],
    bytes: &[u8],
    key: SyncedMeshKey,
) -> Option<Mesh> {
    let mut pos_field: Option<&BamFieldDescriptor> = None;
    let mut norm_field: Option<&BamFieldDescriptor> = None;
    let mut uv_field: Option<&BamFieldDescriptor> = None;
    let mut idx_field: Option<&BamFieldDescriptor> = None;

    for f in non_padding(fields) {
        match f.name.as_str() {
            "positions" | "vertices" => pos_field = Some(f),
            "normals" => norm_field = Some(f),
            "uvs" | "uv0" => uv_field = Some(f),
            "indices" | "triangles" => idx_field = Some(f),
            _ => {}
        }
    }

    let pf = pos_field?;
    let ixf = idx_field?;
    let vcount = (key.vertex_count as usize).min(pf.size / 12);
    let icount = (key.index_count as usize).min(ixf.size / 4);
    if vcount < 3 || icount < 3 {
        return None;
    }

    let mut positions = Vec::with_capacity(vcount);
    for i in 0..vcount {
        let off = pf.offset.checked_add(i.checked_mul(12)?)?;
        positions.push(read_vec3_at(bytes, off)?);
    }

    let mut normals_opt = None;
    if let Some(nf) = norm_field
        && vcount <= nf.size / 12
    {
        let mut norms = Vec::with_capacity(vcount);
        let mut ok = true;
        for i in 0..vcount {
            if let Some(off) = nf.offset.checked_add(i.checked_mul(12)?)
                && let Some(n) = read_vec3_at(bytes, off)
            {
                norms.push(n);
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            normals_opt = Some(norms);
        }
    }

    let mut uvs_opt = None;
    if let Some(uf) = uv_field
        && vcount <= uf.size / 8
    {
        let mut uvs = Vec::with_capacity(vcount);
        let mut ok = true;
        for i in 0..vcount {
            if let Some(off) = uf.offset.checked_add(i.checked_mul(8)?)
                && let Some(uv) = read_vec2_at(bytes, off)
            {
                uvs.push(uv);
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            uvs_opt = Some(uvs);
        }
    }

    let tri_count = (icount / 3) * 3;
    if tri_count < 3 {
        return None;
    }
    let max_idx = (vcount - 1) as u32;
    let mut indices = Vec::with_capacity(tri_count);
    for i in 0..tri_count {
        let off = ixf.offset.checked_add(i.checked_mul(4)?)?;
        let raw_idx = read_u32_at(bytes, off)?;
        indices.push(raw_idx.min(max_idx));
    }

    let mut mesh = Mesh::new(
        PrimitiveTopology::TriangleList,
        RenderAssetUsages::default(),
    );
    mesh.insert_attribute(Mesh::ATTRIBUTE_POSITION, positions);
    if let Some(uvs) = uvs_opt {
        mesh.insert_attribute(Mesh::ATTRIBUTE_UV_0, uvs);
    }
    mesh.insert_indices(Indices::U32(indices));
    if let Some(norms) = normals_opt {
        mesh.insert_attribute(Mesh::ATTRIBUTE_NORMAL, norms);
    } else {
        mesh.compute_flat_normals();
    }

    Some(mesh)
}

fn extract_vec3(fields: &[BamFieldDescriptor], bytes: &[u8], fallback: Vec3) -> Vec3 {
    if let Some(f) = non_padding(fields).find(|f| f.pod_kind == Some(BamFieldPodKind::Vec3))
        && let Some(v) = read_vec3_at(bytes, f.offset)
    {
        return Vec3::from_array(v);
    }
    fallback
}

fn extract_rotation(fields: &[BamFieldDescriptor], bytes: &[u8]) -> Quat {
    if let Some(f) = non_padding(fields).find(|f| f.pod_kind == Some(BamFieldPodKind::Vec4))
        && let Some(v) = read_vec4_at(bytes, f.offset)
    {
        return sanitize_quat(Quat::from_xyzw(v[0], v[1], v[2], v[3]));
    }
    if let Some(f) = non_padding(fields).find(|f| f.pod_kind == Some(BamFieldPodKind::Vec3))
        && let Some(e) = read_vec3_at(bytes, f.offset)
    {
        return Quat::from_euler(EulerRot::YXZ, e[1], e[0], e[2]);
    }
    Quat::IDENTITY
}

fn extract_scale(fields: &[BamFieldDescriptor], bytes: &[u8]) -> Vec3 {
    if let Some(f) = non_padding(fields).find(|f| f.pod_kind == Some(BamFieldPodKind::Vec3))
        && let Some(v) = read_vec3_at(bytes, f.offset)
    {
        return Vec3::from_array(v);
    }
    if let Some(f) = non_padding(fields).find(|f| f.pod_kind == Some(BamFieldPodKind::F32))
        && let Some(s) = read_f32_at(bytes, f.offset)
    {
        return Vec3::splat(s);
    }
    Vec3::ONE
}

fn extract_transform(fields: &[BamFieldDescriptor], bytes: &[u8]) -> (Vec3, Quat, Vec3) {
    let mut pos = Vec3::ZERO;
    let mut rot = Quat::IDENTITY;
    let mut scale = Vec3::ONE;
    for f in non_padding(fields) {
        match f.name.as_str() {
            "pos" | "position" | "translation" | "xyz"
                if f.pod_kind == Some(BamFieldPodKind::Vec3) =>
            {
                if let Some(v) = read_vec3_at(bytes, f.offset) {
                    pos = Vec3::from_array(v);
                }
            }
            "rot" | "rotation" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    rot = Quat::from_xyzw(v[0], v[1], v[2], v[3]);
                }
            }
            "rot" | "rotation" | "euler" if f.pod_kind == Some(BamFieldPodKind::Vec3) => {
                if let Some(e) = read_vec3_at(bytes, f.offset) {
                    rot = Quat::from_euler(EulerRot::YXZ, e[1], e[0], e[2]);
                }
            }
            "scale" if f.pod_kind == Some(BamFieldPodKind::Vec3) => {
                if let Some(v) = read_vec3_at(bytes, f.offset) {
                    scale = Vec3::from_array(v);
                }
            }
            _ => {}
        }
    }
    (pos, rot, scale)
}

fn extract_standard_material(fields: &[BamFieldDescriptor], bytes: &[u8]) -> StandardMaterial {
    let mut base_color = [1.0_f32, 1.0, 1.0, 1.0];
    let mut metallic = 0.0_f32;
    let mut roughness = 0.5_f32;
    let mut emissive = [0.0_f32, 0.0, 0.0, 1.0];

    for f in non_padding(fields) {
        match f.name.as_str() {
            "base_color" | "color" | "rgba" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    base_color = v;
                }
            }
            "metallic" if f.pod_kind == Some(BamFieldPodKind::F32) => {
                if let Some(v) = read_f32_at(bytes, f.offset) {
                    metallic = v.clamp(0.0, 1.0);
                }
            }
            "roughness" | "perceptual_roughness" if f.pod_kind == Some(BamFieldPodKind::F32) => {
                if let Some(v) = read_f32_at(bytes, f.offset) {
                    roughness = v.clamp(0.04, 1.0);
                }
            }
            "emissive" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    emissive = v;
                }
            }
            _ => {}
        }
    }

    StandardMaterial {
        base_color: Color::srgba(base_color[0], base_color[1], base_color[2], base_color[3]),
        metallic,
        perceptual_roughness: roughness,
        emissive: LinearRgba::rgb(emissive[0], emissive[1], emissive[2]),
        ..default()
    }
}

fn extract_camera(fields: &[BamFieldDescriptor], bytes: &[u8]) -> (Vec3, f32, [f32; 4]) {
    let mut look_at = Vec3::ZERO;
    let mut fov_deg = 45.0_f32;
    let mut clear_color = [0.04_f32, 0.05, 0.08, 1.0];
    for f in non_padding(fields) {
        match f.name.as_str() {
            "look_at" | "target" if f.pod_kind == Some(BamFieldPodKind::Vec3) => {
                if let Some(v) = read_vec3_at(bytes, f.offset) {
                    look_at = Vec3::from_array(v);
                }
            }
            "fov_deg" | "fov" if f.pod_kind == Some(BamFieldPodKind::F32) => {
                if let Some(v) = read_f32_at(bytes, f.offset) {
                    fov_deg = v;
                }
            }
            "clear_color" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    clear_color = v;
                }
            }
            _ => {}
        }
    }
    (sanitize_vec3(look_at, Vec3::ZERO), fov_deg, clear_color)
}

fn extract_point_light(fields: &[BamFieldDescriptor], bytes: &[u8]) -> ([f32; 4], f32, bool) {
    let mut color = [1.0_f32; 4];
    let mut intensity = 1_500_000.0_f32;
    let mut shadows = true;
    for f in non_padding(fields) {
        match f.name.as_str() {
            "color" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    color = v;
                }
            }
            "intensity" if f.pod_kind == Some(BamFieldPodKind::F32) => {
                if let Some(v) = read_f32_at(bytes, f.offset) {
                    intensity = v.max(0.0);
                }
            }
            "shadows" | "shadows_enabled" if f.pod_kind == Some(BamFieldPodKind::Bool) => {
                if let Some(b) = read_bool_at(bytes, f.offset) {
                    shadows = b;
                }
            }
            _ => {}
        }
    }
    (color, intensity, shadows)
}

fn extract_dir_light(fields: &[BamFieldDescriptor], bytes: &[u8]) -> ([f32; 4], f32, bool) {
    let mut color = [1.0_f32; 4];
    let mut illuminance = 10_000.0_f32;
    let mut shadows = true;
    for f in non_padding(fields) {
        match f.name.as_str() {
            "color" if f.pod_kind == Some(BamFieldPodKind::Vec4) => {
                if let Some(v) = read_vec4_at(bytes, f.offset) {
                    color = v;
                }
            }
            "illuminance" if f.pod_kind == Some(BamFieldPodKind::F32) => {
                if let Some(v) = read_f32_at(bytes, f.offset) {
                    illuminance = v.max(0.0);
                }
            }
            "shadows" | "shadows_enabled" if f.pod_kind == Some(BamFieldPodKind::Bool) => {
                if let Some(b) = read_bool_at(bytes, f.offset) {
                    shadows = b;
                }
            }
            _ => {}
        }
    }
    (color, illuminance, shadows)
}

fn sanitize_vec3(v: Vec3, fallback: Vec3) -> Vec3 {
    Vec3::new(
        if v.x.is_finite() { v.x } else { fallback.x },
        if v.y.is_finite() { v.y } else { fallback.y },
        if v.z.is_finite() { v.z } else { fallback.z },
    )
}

fn sanitize_quat(q: Quat) -> Quat {
    if q.is_finite() && q.length_squared() > 1e-6 {
        q.normalize()
    } else {
        Quat::IDENTITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strata_plugin_drives_bevy_3d_scene_and_hot_reloads() {
        let dir = TempDir::new().expect("create tempdir");
        let script = dir.path().join("game.strata");
        let default_src = fs::read_to_string(StrataPlugin::default_script_path())
            .expect("read default game.strata");
        fs::write(&script, &default_src).expect("write temp game.strata");

        let mut app = App::new();
        app.insert_resource(Time::<Fixed>::from_hz(60.0));
        app.add_plugins(StrataPlugin::headless(script.clone()));
        app.finish();
        app.cleanup();
        app.update();

        assert_eq!(
            app.world_mut()
                .query::<&Camera3d>()
                .iter(app.world())
                .count(),
            1,
            "game.strata must spawn 1 Camera3d"
        );
        assert_eq!(
            app.world_mut()
                .query::<&PointLight>()
                .iter(app.world())
                .count(),
            2,
            "game.strata must spawn 2 PointLights"
        );
        assert_eq!(
            app.world_mut()
                .query::<(&Mesh3d, &MeshMaterial3d<StandardMaterial>)>()
                .iter(app.world())
                .count(),
            2,
            "game.strata must spawn floor + hero cube procedural meshes"
        );

        let mut counts: Vec<(usize, usize)> = {
            let mut q = app.world_mut().query::<&Mesh3d>();
            let meshes = app.world().resource::<Assets<Mesh>>();
            q.iter(app.world())
                .map(|m3d| {
                    let mesh = meshes.get(&m3d.0).expect("uploaded procedural Mesh");
                    let idx_len = mesh.indices().map(|i| i.len()).unwrap_or(0);
                    (mesh.count_vertices(), idx_len)
                })
                .collect()
        };
        counts.sort_unstable();
        assert_eq!(
            counts,
            vec![(4, 6), (24, 36)],
            "Strata must procedurally construct a 4-vertex/6-index floor and 24-vertex/36-index cube"
        );

        let initial_tfs: Vec<Transform> = app
            .world_mut()
            .query_filtered::<&Transform, With<Mesh3d>>()
            .iter(app.world())
            .copied()
            .collect();
        let initial_hero_tf = initial_tfs
            .iter()
            .find(|t| t.translation.y > 0.5)
            .copied()
            .expect("hero cube transform");

        for _ in 0..60 {
            app.world_mut().run_schedule(FixedUpdate);
        }
        app.update();

        let stepped_tfs: Vec<Transform> = app
            .world_mut()
            .query_filtered::<&Transform, With<Mesh3d>>()
            .iter(app.world())
            .copied()
            .collect();
        let stepped_hero_tf = stepped_tfs
            .iter()
            .find(|t| t.translation.y > 0.5)
            .copied()
            .expect("stepped hero cube transform");

        assert!(
            (stepped_hero_tf.translation - initial_hero_tf.translation).length() > 0.05,
            "cube position must update over 60 FixedUpdate steps"
        );
        assert!(
            stepped_hero_tf
                .rotation
                .angle_between(initial_hero_tf.rotation)
                > 0.5,
            "cube rotation must advance over 60 FixedUpdate steps"
        );
        assert!(
            (stepped_hero_tf.scale - initial_hero_tf.scale).length() > 0.01,
            "cube scale must pulse over 60 FixedUpdate steps"
        );

        // Hot-reload with an edited `.strata` script building a single procedural triangle/quad mesh.
        let edited_src = r#"module demo::cube @version(1.0.0);

resource Clock { dt : sec = 16.6667_ms, elapsed : f32 = 0.0 }

component Position { xyz : vec3 = vec3::ZERO }
component Rotation { euler : vec3 = vec3::ZERO }
component Scale { xyz : vec3 = vec3::ONE }
component Mesh {
    positions : [vec3; 24],
    normals : [vec3; 24],
    uvs : [vec2; 24],
    indices : [u32; 36],
    vertex_count : u32 = 0,
    index_count : u32 = 0,
    revision : u32 = 0,
}
component Material {
    base_color : rgba = rgba(1.0, 1.0, 1.0, 1.0),
    metallic : f32 = 0.0,
    roughness : f32 = 0.5,
    emissive : rgba = rgba(0.0, 0.0, 0.0, 1.0),
}
component Camera {
    look_at : vec3 = vec3::ZERO,
    fov_deg : f32 = 45.0,
    clear_color : rgba = rgba(0.04, 0.05, 0.08, 1.0),
}
component Cube;

fn build_pyramid_4tri(m : &mut Mesh, half : f32, height : f32) {
    m.positions[0_u32] = vec3(-half, 0.0, half);
    m.positions[1_u32] = vec3(half, 0.0, half);
    m.positions[2_u32] = vec3(half, 0.0, -half);
    m.positions[3_u32] = vec3(-half, 0.0, -half);
    m.positions[4_u32] = vec3(0.0, height, 0.0);

    for i in 0_u32..5_u32 {
        m.normals[i] = vec3(0.0, 1.0, 0.0);
        m.uvs[i] = vec2(0.5, 0.5);
    }

    // 4 side faces = 12 indices
    m.indices[0_u32] = 0_u32; m.indices[1_u32] = 1_u32; m.indices[2_u32] = 4_u32;
    m.indices[3_u32] = 1_u32; m.indices[4_u32] = 2_u32; m.indices[5_u32] = 4_u32;
    m.indices[6_u32] = 2_u32; m.indices[7_u32] = 3_u32; m.indices[8_u32] = 4_u32;
    m.indices[9_u32] = 3_u32; m.indices[10_u32] = 0_u32; m.indices[11_u32] = 4_u32;

    m.vertex_count = 5_u32;
    m.index_count = 12_u32;
    m.revision += 1_u32;
}

sys spawn_scene() effects(spawns : [Camera, Mesh, Material, Position, Rotation, Scale, Cube]) {
    spawn {
        Camera { look_at : vec3::ZERO, fov_deg : 45.0, clear_color : rgba(0.04, 0.05, 0.08, 1.0) },
        Position { xyz : vec3(3.0, 3.0, 4.0) },
    };
    spawn {
        Cube { },
        Mesh { },
        Material {
            base_color : rgba(0.95, 0.25, 0.15, 1.0),
            metallic : 0.90,
            roughness : 0.12,
            emissive : rgba(0.2, 0.05, 0.0, 1.0),
        },
        Position { xyz : vec3(2.5, 2.0, -1.0) },
        Rotation { euler : vec3::ZERO },
        Scale { xyz : vec3(1.8, 1.8, 1.8) },
    };
}

sys build_pyr() effects(writes : [Mesh], reads : [Cube]) {
    for c in query(m : &mut? Mesh).with<Cube>() {
        if c.m.revision == 0_u32 {
            build_pyramid_4tri(c.m, 0.75, 1.25);
        }
    }
}

sys update_cube(clk : &mut res Clock) effects(writes : [Clock], reads : [Cube]) {
    clk.elapsed += clk.dt.as_secs();
}

schedule Startup { spawn_scene }
schedule Update { build_pyr }
schedule FixedUpdate { update_cube }
"#;
        fs::write(&script, edited_src).expect("write edited game.strata");
        assert!(reload_strata_from_disk(app.world_mut()));
        app.update();

        assert_eq!(
            app.world_mut().query::<&Mesh3d>().iter(app.world()).count(),
            1,
            "reload must despawn old ModScoped entities cleanly"
        );
        let (tf, key, mesh_h, mat_h) = app
            .world_mut()
            .query::<(
                &Transform,
                &SyncedMeshKey,
                &Mesh3d,
                &MeshMaterial3d<StandardMaterial>,
            )>()
            .single(app.world())
            .expect("reloaded entity");
        assert_eq!(key.vertex_count, 5);
        assert_eq!(key.index_count, 12);
        let reloaded_mesh = app
            .world()
            .resource::<Assets<Mesh>>()
            .get(&mesh_h.0)
            .expect("reloaded procedural Mesh");
        assert_eq!(reloaded_mesh.count_vertices(), 5);
        assert_eq!(reloaded_mesh.indices().map(|i| i.len()), Some(12));
        assert!((tf.translation - Vec3::new(2.5, 2.0, -1.0)).length() < 0.01);
        assert!((tf.scale - Vec3::splat(1.8)).length() < 0.01);

        let mat = app
            .world()
            .resource::<Assets<StandardMaterial>>()
            .get(&mat_h.0)
            .expect("reloaded StandardMaterial");
        assert!((mat.metallic - 0.90).abs() < 0.01);
        assert!((mat.perceptual_roughness - 0.12).abs() < 0.01);

        // Broken syntax must keep existing Bevy scene intact without panicking.
        fs::write(&script, "module broken; sys bad( { }").expect("write broken script");
        assert!(!reload_strata_from_disk(app.world_mut()));
        app.update();
        assert_eq!(
            app.world_mut().query::<&Mesh3d>().iter(app.world()).count(),
            1
        );
        assert!(
            app.world()
                .resource::<StrataRuntimeState>()
                .last_error
                .is_some()
        );
    }
}
