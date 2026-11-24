# Strata 3D Cube Playground (`examples/cube_playground`)

An ultra-lean Bevy `0.20.1` + `StrataPlugin` playground where **the entire 3D scene, procedural cube/floor geometry, PBR material, and 60 Hz simulation live inside [`game.strata`](./game.strata)**.

- **~25-line [`main.rs`](./src/main.rs):** Sets `Time::<Fixed>::from_hz(60.0)` and mounts `StrataPlugin::watch(script)`.
- **100% Strata-built geometry & 60 Hz simulation:** [`game.strata`](./game.strata) defines a raw `component Mesh` (`positions`, `normals`, `uvs`, `indices`, `vertex_count`, `index_count`, `revision`) and procedurally constructs the **6-face / 24-vertex / 36-index cube** (`build_cube_mesh`) and **4-vertex / 6-index floor quad** (`build_plane_mesh`) using pure Strata functions alongside `Camera`, `PointLight`s, `Material`, and `update_cube` at 60 Hz.
- **Shape-agnostic [`strata_plugin.rs`](./src/strata_plugin.rs):** Onboards full Bevy `0.20.1` (`DefaultPlugins` + `RemotePlugin`) and `bamabi` bridges (`ModPreset3dPlugin`, `ModPresetUiPlugin`, `ModReflectPlugin`, `ModSaveGamePlugin`, `ModTelemetryPlugin`, `ModWeslMaterialPlugin`, `ModSubAppPlugin::<RenderApp>`, `ModRenderRecoveryPlugin`), compiles `.strata` via Salsa + `strata_jit`, watches for Zed saves in `ModLifecycleFlush`, streams `"BAMT"` telemetry, and uploads raw vertex/index buffers to `Assets<Mesh>` with **zero knowledge of cubes, spheres, or planes**.

---

## 1. Launch into the Default Scene

From the `strata` repository root:

```bash
cargo run --manifest-path examples/cube_playground/Cargo.toml --release
```

Or from inside `examples/cube_playground/`:

```bash
cargo run --release
```

---

## 2. Edit Live in Zed

1. Open `examples/cube_playground/` in Zed (`zed examples/cube_playground`).
   - One-time setup if needed: `cargo install --path crates/stratac` and `cargo install --path crates/strata_lsp`, then **`zed: install dev extension`** -> `strata/editors/zed`.
2. Launch **`Launch Default Scene (Live Hot-Reload)`** from Zed's tasks (`Cmd+Shift+P` -> `task: spawn`) or a terminal.
3. Open [`game.strata`](./game.strata), edit anything below, and press **`Cmd+S`**:
   - **Procedural geometry:** edit `CUBE_HALF_EXTENTS`, `FLOOR_HALF_EXTENT`, `build_cube_mesh`, or `push_quad` to deform vertices, normals, UVs, or winding live.
   - **Position / orbit:** tweak `BASE_POSITION`, `ORBIT_RADIUS`, `BOB_AMPLITUDE`.
   - **Rotation / scale:** tweak `SPIN_SPEED`, `BASE_SCALE`, `PULSE_AMPLITUDE`.
   - **PBR Material:** tweak `COLOR_A`, `COLOR_B`, `METALLIC`, `ROUGHNESS`, `EMISSIVE_STRENGTH`.
   - **Camera / lights:** move the `Camera` or `PointLight` positions or change `fov_deg`, `clear_color`, or `intensity`.

---

## 3. Why Dropping Any Anonymous `.strata` File Without Glue Is Not Yet Possible

Today, `strata` provides the compiler/JIT stack and `bamabi` provides the C-ABI runtime + subsystem bridges, but a zero-glue "drop in any anonymous `.strata` script and run" experience requires upstream pieces that do not exist yet:

1. **No cross-namespace / `extern component` binding in `strata_sema`:** Every `component Foo` inside `module a::b` is namespaced as `a::b::Foo`, so a `.strata` file cannot bind directly to `bamabi_bridges`'s canonical Bevy component names (e.g., `bevy_transform::components::transform::Transform`, `bamabi::camera_light::FfiPointLight`).
2. **No `MappedWireVTable` (non-POD bridged component) access in `strata_jit`:** `StdTypesBridgePlugin` registers `Transform`, `Visibility`, `Time<*>`, and input types via VTable bridges, whereas `strata_jit` queries raw SoA POD columns.
3. **No C-ABI `Mesh3d` / `StandardMaterial` component bridge in `bamabi`:** `bamabi_bridges` bridges transforms, cameras, lights, audio, picking, UI, BSN, and states, while `bamabi_render` exposes host Rust APIs rather than C-ABI components for procedural `Mesh3d` buffers or `StandardMaterial`.
4. **No first-party `strata` standard library (`std::bevy::*`) or published `strata_bevy` plugin crate yet:** Until Strata ships canonical Bevy stdlib declarations alongside an official `strata_bevy` runtime plugin crate, the host plugin still needs ~150 lines of generic `ModRegistry` POD reflection to mirror `Camera` / `PointLight` / `Mesh` / `Material` onto Bevy types.
5. **Live schema edits without a `migrate` block:** Adding/removing/reordering fields on an already-registered component alters its `ComponentUuid`, causing `bamabi_host` to return `TYPE_MISMATCH` unless a `migrate` block is provided or the app restarts.
