# Strata Language Specification (Strata v2.0 / `bamabi-strata` v0.3.0)

> **Target Runtime & ABI:** Bevy `0.20.1` (`bevy_ecs`, `bevy_app`) · `bamabi-wire` ABI `0.3.0` (`0x0003_0000`, `73` `BamHostApi` slots) · Rust Edition `2024` (MSRV `1.95`).

**Strata** (`.strata`) is a statically typed, zero-allocation, data-parallel Entity-Component-System (ECS) gameplay language. From a single `.strata` source file, the compiler suite (`stratac`) targets four execution backends with verified bit-exact parity:

1. **Tier 1a — Cranelift PIC JIT (`--target jit`):** In-process relocatable shared libraries (`.dylib`/`.so`/`.dll`) for sub-35 ms hot reloads (`stratac watch`).
2. **Tier 1b — Strict ISO C99 (`--target c99`):** Standalone `-std=c99 -Werror` modules against `bamabi.h`.
3. **Tier 2 — Safe Rust Guest (`--target rust-guest`):** `#![forbid(unsafe_code)]`, zero-Bevy `bamabi_guest` `.cdylib` crates packaged into Ed25519-signed `.bampack` bundles.
4. **Tier 3 — Native Bevy `0.20.1` (`stratac onboard --target bevy-native`):** Static `#![forbid(unsafe_code)]` Bevy `0.20.1` `Plugin` crates backed by `bamabi_native_rt` (with `--static-console` stripping dynamic loading completely).

---

## 1. Quick Mental Model & Core Design Philosophy

If you already know a bit of Rust or Bevy, think of Strata as **Bevy's ECS distilled into a dedicated gameplay DSL**: instead of writing derive macros, system traits, query filters, SIMD chunk loops, state-machine boilerplate, and rollback/networking glue by hand, you declare *what your data looks like* and *who owns what*, and the compiler proves safety and emits optimal Bevy / C-ABI code.

### The 6 Design Pillars

| Pillar | What Problem It Solves | How Strata Solves It |
|---|---|---|
| **1. Zero-Allocation `AbiPod` Data Model** | Heap types (`Vec`, `String`, `Box`) and implicit C struct padding cause dangling pointers across FFI, uninitialized-byte UB, and layout drift between compilers. | All ECS state uses plain-old-data `#[repr(C)]` types with zero-heap inline primitives (`InlineStr<N>`, `SmallVec<T, N>`, `BitSet<N>`, `GraceWindow`, `InputBuffer<A, N>`) and compiler-inserted `_strata_pad_N` fields. |
| **2. Compile-Time Soundness** | Game bugs often stem from swapped units (`ms` vs `sec`, `deg` vs `rad`), aliasing borrows, or client code accidentally mutating server-only state. | SI `UnitDim` type algebra catches unit mix-ups at compile time (`0` runtime cost); **Theorem 0.1** (`FilteredAccessSet`) proves query disjointness statically; **Unified Provenance `@authority`** blocks client writes to `@authority(server)` state (`E0501`). |
| **3. Cache-Line & Tick Sympathy** | Bloated components thrash CPU caches, and naive `&mut T` queries dirty Bevy change ticks on every entity even inside untouched `if` branches. | `@soa` splits hot per-frame fields from cold metadata; `?T` (`?&T` / `?&mut T`) hoists presence checks to the archetype chunk boundary; `&mut? T` coalesces dirty row spans so unchanged chunks keep Bevy `summary_tick` skipping intact. |
| **4. First-Class Gameplay Without Heap Coroutines** | Attack frame windows, coyote time, dash coroutines, NPC state machines, and spatial queries normally need fragile timer structs and heap-allocated futures. | `timeline`, `fsm`, stackless `task` (`wait`, `race`, `abort_if`), 2-pass CSR `spatial_grid`/`spatial_history`, and single-entity `atomic`/`on_rollback` transactions compile into flat POD components and deterministic systems. |
| **5. 4-Way Bit-Exact Determinism** | FMA contraction differences, platform `libm`, and unordered parallel loops desynchronize lockstep simulations and replays. | `@deterministic` disables FMA contraction (`#pragma STDC FP_CONTRACT OFF`), selects deterministic math intrinsics, locks reduction/CSR order, and pairs with `fix32` (Q16.16) / `fix64` (Q32.32) fixed-point scalars. |
| **6. Native Graduation & Built-In Sim Testing** | Testing Bevy gameplay or packet-loss multiplayer normally requires heavy test harnesses; graduating scripts to native code often means rewriting from scratch. | `sim_test` and multi-world `net_sim_test` run headlessly inside `stratac test`, and `stratac onboard --target bevy-native --static-console` graduates the exact module into a native Bevy `0.20.1` `Plugin`. |

### Side-by-Side: Strata vs. Bevy `0.20.1`

Below is a **complete, compilable** Strata module (tested with `stratac check`) alongside the equivalent Bevy `0.20.1` Rust code that Strata generates:

```strata
module quickstart::regen @version(1.0.0);

resource SimClock { dt: sec = 16.6667_ms }

@summary_tick
component Vitals { hp: f32 = 100.0, max_hp: f32 = 100.0 }

@par(chunk = 1024)
sys regen_wounded(clk: &res SimClock) effects(writes: [Vitals]) {
    uniform let heal = 5.0 * clk.dt.as_secs();
    for v in query(hp: &mut? Vitals.hp, max_hp: &Vitals.max_hp) {
        if v.hp < v.max_hp {
            v.hp = min(v.max_hp, v.hp + heal);
        }
    }
}

schedule FixedUpdate { regen_wounded }
```

In Bevy `0.20.1` (with `bamabi_native_rt`), the compiler expands those 18 lines into:

```rust
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Resource)]
pub struct SimClock { pub dt: f32 }

#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Component)]
#[component(summary_tick)] // enables Bevy 0.20 chunk summary tick skipping
pub struct Vitals { pub hp: f32, pub max_hp: f32 }

pub fn strata_sys_regen_wounded(
    clk: Res<SimClock>,
    mut q: Query<(&mut Vitals,)>, // split into contiguous column slices at runtime
) {
    let heal = 5.0_f32 * clk.dt;
    // `ChunkSliceQueryExt` + `SelectiveMutSlice` (backed by `DirtyRunCoalescer`):
    // runs across parallel chunks without marking clean entities as `Changed<Vitals>`
    if let Ok(par_it) = q.strata_contiguous_par_iter_mut() {
        par_it.for_each(|(raw_v,)| {
            let mut sel = SelectiveMutSlice::from_contiguous_mut(raw_v);
            for row in 0..sel.len() {
                if sel.as_slice()[row].hp < sel.as_slice()[row].max_hp {
                    let next_hp = sel.as_slice()[row].max_hp.min(sel.as_slice()[row].hp + heal);
                    sel.as_mut_untracked()[row].hp = next_hp;
                    sel.mark_dirty_row(row);
                }
            }
            let _ = sel.flush_dirty_runs(); // also flushes on Drop
        });
    }
}

pub struct StrataNativePlugin;
impl Plugin for StrataNativePlugin {
    fn build(&self, app: &mut App) {
        let _ = app.register_strata_resource::<SimClock>();
        let _ = app.register_strata_component::<Vitals>(
            StrataComponentOptions::default().summary_tick(),
        );
        app.init_resource::<SimClock>()
           .add_systems(FixedUpdate, strata_sys_regen_wounded);
    }
}
```

---

## 2. Master Glossary & Strata <-> Bevy `0.20.1` Rosetta Stone

Every language construct, keyword, attribute, and type in Strata maps directly to a concrete concept in Bevy `0.20.1` and/or `bamabi_native_rt`.

### 2.1 Top-Level Declarations & Verification Directives

| Construct | Plain-English Meaning | Why It Exists (Philosophy) | Bevy `0.20.1` / Runtime Construct |
|---|---|---|---|
| `module a::b` | Namespaces all generated components, UUIDs, and plugin registration. | Prevents UUID and symbol collisions when multiple mods load into one host `App`. | `pub struct StrataNativePlugin; impl Plugin` + canonical `"a::b::Item"` IDs |
| `use path` / `use p::{a, b}` / `use p as x` | Imports external/sibling symbol paths in syntax. | Allows modular path aliases without pulling in wildcard ambiguity (`use p::*` is unsupported). | Rust `use` path resolution |
| `const NAME: T = expr;` | Compile-time constant scalar, unit, vector, or aggregate. | Eliminates magic numbers while preserving SI unit checking in expressions. | Rust `pub const NAME: T = ...;` |
| `struct Name { ... }` | `#[repr(C)]` plain-old-data helper aggregate. | Shares structured payloads inside components, RPCs, and local variables across C99/Rust/JIT. | `#[repr(C, align(N))] #[derive(Clone, Copy)] struct Name` |
| `enum Name { A = 0, B = 1 }` | Compact C-ABI integer enum (`u8`/`u16`/`u32`/`i32`). | Gives readable state/action keys that pack tightly into components and `table` lookups. | `#[repr(u8 \| u16 \| u32 \| i32)] enum Name` |
| `component Name { ... }` | ECS data attached per entity (dense table or `@sparse`, or `@soa` split). | Separates data schema from logic; auto-solves alignment and `ComponentUuid`. | `#[repr(C)] #[derive(Component)]` + `ModComponent` |
| `tag A, B;` | Zero-byte marker component with no fields. | Filters archetypes (`With<A>`, `Without<B>`) at zero memory cost per entity. | Zero-sized `#[derive(Component)] struct StrataTag_A;` |
| `resource Name { ... }` | Global singleton data shared across systems (`{ ... }` required). | Holds clocks, match rules, and input state without spawning dummy entities. | `#[derive(Resource, Default)] struct Name` + `app.init_resource` |
| `event Name { ... }` / `event Name;` | Immediate fire-and-observe notification (global or entity-targeted; `;` only on marker form). | Triggers instant reactive handlers (`obs`) without polling every entity each tick. | `#[derive(Event)]` or `#[derive(EntityEvent)]` (`#[event_target]`) |
| `stream Name { ... }` / `stream Name;` | Buffered frame-to-frame message channel (`;` only on marker form). | Decouples producers and consumers across ticks with zero per-entity observer overhead. | `#[derive(Message)]` + `add_message::<M>()` (`Messages<M>`) |
| `rpc Name { ... }` / `rpc Name;` | Typed network message sent between client and server (`;` only on marker form). | Guarantees direction, channel, reliability, and bit-packed quantization on the wire. | `StrataNetPacket` (`PACKET_KIND_RPC`) dispatched to `obs(&Trigger<Rpc>)` |
| `relation Name [flags] { ... }` | Typed entity-to-entity graph edge (plus built-in `ChildOf`). | Models squads, equipment, and hierarchies with automatic exclusivity/cycle/cleanup rules. | `ChildOf` (`bevy_ecs::hierarchy::ChildOf`) or `StrataRelation_*` `Resource` + 8 B parent link |
| `table Name by Enum { ... } = { ... };` | Compile-time lookup table keyed exhaustively by an `enum`. | Replaces error-prone `match` boilerplate with O(1) indexed design data (`E0106` if missing variant). | Static `const` lookup array indexed by `enum_val as usize` |
| `curve Name(In -> Out) = [...];` | Piecewise-linear curve with strictly increasing x-points (`E0107`). | Expresses damage falloff, scaling, or easing declaratively (`Name.sample(x)`). | Static control-point array + piecewise-linear interpolation helper |
| `spatial_grid Name(...) over C by F;` | Deterministic 2D uniform spatial hash grid over `C` by position `F`. | Eliminates `O(N*M)` nested query loops (`W0401`) via O(1) cell disc queries. | 2-pass counting-sort CSR `Resource` rebuilt before earliest reader |
| `spatial_history Name(...) over C by F;` | Ring buffer of `frames` historical CSR grids for lag compensation. | Lets authoritative servers trace bullets/hits back in time (`query_segment_at`). | `frames`-deep CSR ring buffer `Resource` with `populated_frames` guard |
| `object Name { Comp { ... }, ... }` | Pre-placed singleton entity spawned automatically at startup. | Gives tests and gameplay a named entity handle (`query_one(...).on(Name)`) with zero manual setup. | `StrataNamedObjects` `Resource` + `Startup` spawner before user systems |
| `timeline Name @rate(...) @duration(...) { ... }` | Frame-indexed window & cue component (`window`, `at`). | Replaces brittle frame counters for hitboxes, i-frames, parry windows, and cancels. | 16 B `@sparse` `TimelineCursor` `Component` + frame-advance system |
| `task Name(...) on (...) using (...) { ... }` | Stackless zero-allocation multi-tick coroutine (`wait`, `race`, `abort_if`). | Writes multi-frame dashes, revives, and channels linearly without heap `Future`s. | `TaskState` POD `Component` (`__pc`, `__timer`, live vars) + step system |
| `fsm Name(...) { initial S; state S { ... } }` | Priority-ordered finite state machine per entity. | Encodes AI routines and modal states with explicit `on_enter`/`on_tick`/`on_exit` hooks. | 4 B+ POD `FsmState` `Component` (`__state`, `__flags`, state locals) + tick system |
| `sys name(...) effects(...) { ... }` | ECS system running on a schedule. | Units of parallel execution verified by Theorem 0.1 and `effects(...)`. | Bevy `System` (`Query`, `Res`, `ResMut`, `Commands`, `MessageReader`/`MessageWriter`) |
| `obs name(trg: &Trigger<E[, T]>, ...) { ... }` | Reactive observer fired immediately on `trigger(...)` or incoming `rpc`. | Reacts cleanly to damage, posture breaks, or RPCs without scanning all entities. | `fn(on: On<Ev>, ...)` registered via `app.add_observer(...)` |
| `fn name(...) -> T { ... }` | Pure or helper function callable from systems, observers, tasks, or FSMs. | Shares math/logic; `@node_pure fn` exposes pure nodes to Visual Graph IR (`E0601`). | Rust `pub fn` (queries forbidden inside `fn`, `E0204`) |
| `migrate Comp from V1 to V2 (old: &Old) -> Comp` | Upgrades serialized/hot-reloaded components across schema versions. | Keeps `@persist` saves and live reloads valid when component fields change. | `BamRowMigrateFn` (Slot 67) / generated `pub fn strata_mig_*` |
| `schedule Phase { ... }` | Places systems, tasks, FSMs, and timelines into execution phases. | Controls deterministic ordering (`seq`/`par`/`set`/`before`/`after`) and `run_if`. | `Startup`/`PreUpdate`/`Update`/`FixedUpdate`/`PostUpdate`/`Last` + `SystemSet` |
| `assert_layout(Comp, size == N, ...);` | Compile-time assertion on solved `#[repr(C)]` size, align, and padding. | Catches accidental ABI bloat or padding breaks at compile time (`E0105`). | Compile-time check against `SolvedLayout` (`strata_sema`) |
| `assert_par(sys_a, sys_b);` | Compile-time assertion that listed systems have zero Theorem 0.1 conflicts. | Locks in parallel scalability guarantees (`E0202` if a future edit adds an alias). | Compile-time check on `ConcurrencyGraph` (`strata_sema`) |
| `sim_test "name" { ... }` | Headless single-world deterministic simulation test. | Verifies gameplay invariants and zero steady-state heap allocations (`stratac test`). | Headless `bamabi_host` `App` (`SingleThreadedExecutor`) JIT test harness |
| `net_sim_test "name"(...) { ... }` | Multi-world virtual network test with latency, jitter, packet loss, and seed. | Proves multiplayer replication, RPCs, and quantization converge deterministically. | Multi-world server + client Bevy worlds over deterministic PRNG ARQ channel |
| `zone`, `prefab`, `aspect`, `hash_index` | **Parser-reserved CST keywords** (parsed by `parser.rs`, not yet lowered by `strata_sema`). | Reserved grammar slots for future zone streaming, prefabs, query aspects, and hash indices. | N/A (not emitted by `strata_codegen` yet; avoid in runnable modules) |

### 2.2 Attributes (`@...`)

| Attribute | Valid Targets | Arguments | Plain-English Meaning & Philosophy | Bevy `0.20.1` / Compiler Effect |
|---|---|---|---|---|
| `@version(x.y.z)` | `module` | SemVer (`1.0.0`) | Declares module ABI/schema version for manifests and migrations. | `mod.toml` version metadata |
| `@deterministic` | `module` | None | Locks module to strict bit-exact execution across all 4 backends. | Disables FMA (`allow_fma = false`), forces deterministic libm & ordered reductions |
| `@soa` | `component` | None | Splits fields into `hot { ... }` and `cold <name> { ... }` cache strata. | Hot -> `Comp` `Component`; each cold block -> `Comp__<name>` `Component` |
| `@sparse` | `component`, `task`, `timeline` | None | Uses sparse-set storage for frequently added/removed state. | `#[component(storage = "SparseSet")]` (`BAM_COMPONENT_FLAG_SPARSE_SET`) |
| `@summary_tick` | `component`, `task` | None | Enables chunk-level tick summaries (cannot combine with `@sparse`, `E0110`). | `#[component(summary_tick)]` (`BAM_COMPONENT_FLAG_SUMMARY_TICK`) |
| `@require(A, B)` | `component` (parsed inline on `component`/`fsm`/`event`/`resource`/`object`) | Component paths | Auto-attaches prerequisite components whenever the owner `component` is spawned (`strata_sema` lowers `required_components` on `component`; `graph_ir` reads on `component`/`timeline`/`fsm`). | `#[require(A, B)]` + transitive `effects(spawns)` coverage |
| `@no_pad` | `component` (including `@soa` `hot` strata) | None | Forbids compiler-inserted `_strata_pad_*` bytes (`E0104` on `component` / `@soa` `hot` strata; `struct` checks `InlineStr<N>` `N % 4 != 0` only). | Zero-padding check in `solve_pod_layout` |
| `@persist` | `component`, `resource`, `object`, `fsm` | None | Preserves state across zone unloads (`despawn_all`) and live mod reloads. | Host persistence flags (Slots 38/56) |
| `@persistent` | `spawn` expression | None | Spawns an individual entity marked persistent (`spawn @persistent { ... };`). | Persistent entity spawn (Slot 38) |
| `@if_new` | `insert` expression | None | Attaches a component/task/fsm/timeline only if not already present on entity. | Conditional insert (`insert_if_new` semantics) |
| `@rollback` | `component`, `resource` | None | Parsed AST/LSP marker attribute (used in cookbook 06); snapshot metadata wiring is not yet emitted by `strata_sema`/`strata_mir`/`strata_codegen`. | AST/LSP marker (reserved; no codegen metadata emitted yet) |
| `@par(...)` | `sys`, `obs` | `chunk = N` and/or `read_only` | Opts system into chunk-parallel execution (`@par(read_only)` forbids `&mut`). | `QueryContiguousParIter::for_each` / `par_for_each_chunk_readonly` (Slot 59) |
| `@rate(N_hz)` | `timeline` | Frequency `UnitLit` (`60_hz`) | Sets timeline tick rate in Hertz (default `60_hz`). | `TimelineAdvance` frame rate normalization |
| `@duration(N_f)` | `timeline` | Frame `UnitLit` (`24_f`) | Sets total timeline duration in frames (default `60_f`); bounds `window` checks. | Max frame count in `TimelineAdvance` (`E0108` if window exceeds) |
| `@priority(N)` | `fsm` `to` transition | Integer (`@priority(10)`) | Breaks ties when multiple state transitions are true on the same tick. | Transitions sorted by descending priority before lowering |
| `@repr(T)` | `enum` | `u8`, `u16`, `u32`, `i32` | Overrides auto-selected C-ABI discriminant integer size/signedness. | Rust `#[repr(u8 \| u16 \| u32 \| i32)]` |
| `@node_pure` | `fn` | None | Marks a pure math/helper function with zero ECS access (`E0601` if impure). | Emitted as `GraphNodeKind::NodePureFn` in Visual Graph IR |
| `@node_group("...")` | Graph items, `sys`, `rpc` | Non-empty string (`"A/B"` or `name = "A/B"`) | Groups items visually in Graph IR without affecting ABI fingerprints (`E0602`). | `group` metadata in `.strata.graph.json` |
| `@authority(role)` | `component`, `resource`, `sys`, `rpc` | `server`, `client`, `predicted`, `shared` | Assigns network ownership; prevents client mutation of server state (`E0501`). | Role-split MIR filtering + unified provenance abstract interpreter |
| `@predicted` | `component`, `sys` | None | Shorthand for `@authority(predicted)`; cannot mix with `@authority(server)` (`E0504`). | `FLAG_IS_PREDICTED` + client-predicted replication/system role |
| `@net(...)` | `component`, `resource` | `reliable\|unreliable`, `rate = NHz` or `interval = N`, `channel = 0..=255` | Configures automatic delta replication (`rate` and `interval` mutually exclusive, `E0502`). | `StrataNetPacket` RX/TX systems (`Messages<StrataNetPacket>`) |
| `@net_rpc(...)` | `rpc`, `sys` | `direction = client_to_server\|server_to_client\|bidirectional`, `reliable\|unreliable`, `channel = 0..=255` | Configures RPC wire routing (`direction` required, `E0502`). | `PACKET_KIND_RPC` header + direction validation |
| `@quantize(...)` | `component`, `struct`/`resource`/`rpc` field | `min = f, max = f, bits = 1..=32`, optional `step = f` | Bit-packs floats/vectors cleanly into minimal network bits (`E0503`). | `quantize_scalar_f64` / `dequantize_scalar_f64` + `pack_bits_le` |

### 2.3 Keywords Index (48 Hard + 47 Contextual + Special Identifiers)

* **48 Hard Keywords** (reserved everywhere except after `.` where `in`/`match` are allowed):
  `module`, `use`, `as`, `const`, `struct`, `enum`, `component`, `tag`, `resource`, `event`, `stream`, `relation`, `table`, `curve`, `spatial_grid`, `spatial_history`, `hash_index`, `aspect`, `prefab`, `object`, `timeline`, `task`, `fsm`, `sys`, `obs`, `fn`, `migrate`, `schedule`, `assert_layout`, `assert_par`, `sim_test`, `net_sim_test`, `let`, `mut`, `if`, `else`, `for`, `in`, `while`, `loop`, `match`, `return`, `break`, `continue`, `true`, `false`, `self`, `Self`.
* **47 Contextual Keywords** (recognized by the parser in specific syntactic positions; legal as field/variable names elsewhere):
  `zone`, `rpc`, `by`, `over`, `key`, `cache`, `where`, `hot`, `cold`, `require`, `window`, `at`, `on`, `using`, `initial`, `state`, `on_enter`, `on_tick`, `on_exit`, `to`, `when`, `effects`, `from`, `run_if`, `before`, `after`, `seq`, `seq_weak`, `par`, `set`, `res`, `stream_in`, `uniform`, `reduce`, `abort_if`, `race`, `branch`, `wait`, `wait_until`, `yield_tick`, `atomic`, `on_rollback`, `spawn`, `spawn_batch`, `despawn_all`, `insert`, `remove`.
* **Special Parser-Recognized Identifiers:** `_` (wildcard pattern), `query` and `query_one` (switch call arguments into query projection term mode when followed by `(`).

---

## 3. Lexical Rules, Types, `AbiPod` Layout & SI Units

### 3.1 Lexical Rules & Operators

* **Whitespace & Comments:** `[ \t\r\n]+` whitespace, `//...` line comments (`///` and `//!` also lex as regular `LineComment`s), and `/* ... */` block comments supporting **arbitrary nesting depth**.
* **Identifiers:** `[a-zA-Z_][a-zA-Z0-9_]*`.
* **Integer Literals (`IntLit`):** Decimal (`42`, `1_000_u32`), hexadecimal (`0xFF_u8`), binary (`0b1010_u32`), and octal (`0o755_u32`) — prefixes `0x`, `0b`, `0o` must be lowercase, and underscores must precede digits. Optional suffixes **must** start with `_`: `_u8`, `_u16`, `_u32`, `_u64`, `_i8`, `_i16`, `_i32`, `_i64`, `_f32`, `_f64`. Unsuffixed integer literals default to `i32` (or `i64` if `> u32::MAX`).
* **Float Literals (`FloatLit`):** Require at least one digit after `.` (`1.0`, `3.14_f64`) or an exponent (`1e-3`, `2.5e4_f32`). Writing `1.` without a trailing digit is invalid; this lets `0..10_m` lex cleanly as `IntLit("0")`, `DotDot`, `UnitLit("10_m")`. Optional suffixes: `_f32`, `_f64`. Unsuffixed floats default to `f32`.
* **Unit Literals (`UnitLit`):** `<int-or-float-mantissa>_?<suffix>` using the **13 exact suffixes**: `sec`, `s`, `ms`, `hz`, `Hz`, `frames`, `f`, `rad`, `deg`, `meters`, `m`, `mps`, `mps2`. The `_` before the suffix is optional (`50ms` and `50_ms` are identical). Negative unit values like `-9.81_mps2` lex as unary `-` followed by `UnitLit`.
* **Strings & Chars:** `"..."` allows multiline text and unescapes `\"`, `\\`, `\n`, `\r`, `\t`, `\0`, `\'`. `'a'` / `'\n'` (`CharLit`) allows a single character or single `\c` escape (no `\xHH` or `\u{...}`) and **types as `u8`** (ASCII/byte literal, never Rust 4-byte `char`).
* **Punctuation (49 tokens):** `..=`, `..`, `::`, `=>`, `->`, `<=`, `>=`, `==`, `!=`, `&&`, `||`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, `>>=`, `<<`, `>>`, `{`, `}`, `(`, `)`, `[`, `]`, `;`, `,`, `.`, `:`, `=`, `<`, `>`, `+`, `-`, `*`, `/`, `%`, `!`, `&`, `|`, `^`, `~`, `@`, `?` (`#` is reserved by the lexer and unused by the parser).

#### Exact Pratt Operator Precedence (Lowest to Highest)

| Tier | Operators | Associativity | Notes |
|---|---|---|---|
| 1 | `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `\|=`, `^=`, `<<=`, `>>=` | Right | Assignment / compound assignment statements |
| 2 | `..`, `..=` | Left | Half-open and inclusive ranges (`0..10`, `0..=N`) |
| 3 | `\|\|` | Left | Short-circuit logical OR |
| 4 | `&&` | Left | Short-circuit logical AND |
| 5 | `==`, `!=`, `<`, `<=`, `>`, `>=` | Left | Comparisons |
| 6 | `\|` | Left | Bitwise OR |
| 7 | `^` | Left | Bitwise XOR |
| 8 | `&` | Left | Bitwise AND |
| 9 | `<<`, `>>` | Left | Bit shifts |
| 10 | `+`, `-` | Left | Addition / subtraction |
| 11 | `*`, `/`, `%` | Left | Multiplication / division / remainder |
| 12 | `as Type` | Left | Explicit scalar/fixed-point cast |
| 13 | `-`, `!`, `~`, `&`, `&mut` | Right (Prefix) | Unary neg, logical not, bitwise not (`~` or `!` on ints), borrow |
| 14 | `.field`, `.method()`, `()`, `<T>()`, `[i]`, `S { ... }`, `?` | Left (Postfix) | Highest binding power (`-x.y()` parses as `-(x.y())`) |

### 3.2 Complete Type System

#### A. Primitive & Fixed-Point Scalars (`AbiPod`)

| Strata Type | Size / Align | Wire Tag (`BamFieldKind`) | Notes & Default Literal Rule |
|---|---|---|---|
| `u8`, `i8` | 1 B / 1 B | `u8` (`U8`), `i8` (`I8`) | Char literals (`'a'`) type as `u8` |
| `u16`, `i16` | 2 B / 2 B | `u16` (`U16`), `i16` (`I16`) | |
| `u32`, `i32` | 4 B / 4 B | `u32` (`U32`), `i32` (`I32`) | Default unsuffixed `IntLit` is `i32` (or `i64` if `> u32::MAX`) |
| `u64`, `i64` | 8 B / 8 B | `u64` (`U64`), `i64` (`I64`) | Replacement for banned `usize`/`isize` |
| `f32`, `f64` | 4 B / 4 B, 8 B / 8 B | `f32` (`F32`), `f64` (`F64`) | Default unsuffixed `FloatLit` is `f32` |
| `fix32` | 4 B / 4 B | `i32` (`I32`) | Signed Q16.16 fixed-point (`scale = 2^16 = 65536`) |
| `fix64` | 8 B / 8 B | `i64` (`I64`) | Signed Q32.32 fixed-point (`scale = 2^32`) |
| `bool` | 1 B / 1 B | `FfiBool` (`BOOL`) | C-ABI 1-byte boolean (`0` or `1`) |
| `sym` | 4 B / 4 B | `u32` (`U32`) | Interned symbol ID |
| `()` | 0 B / 1 B | `()` (`NESTED`) | Unit type |
| `sec`, `ms`, `hz`, `frames`, `rad`, `deg`, `meters`, `mps`, `mps2` | 4 B / 4 B | `f32` (`F32`) | SI unit scalars (erase to `f32` in ABI and runtime) |

#### B. Vectors, Matrices & Colors (`AbiPod`)

Lowercase type names have PascalCase constructor/alias equivalents (`vec2`/`Vec2`, `vec3`/`Vec3`, `vec3a`/`Vec3a`, `vec4`/`Vec4`, `ivec2`/`IVec2`, `ivec3`/`IVec3`, `uvec2`/`UVec2`, `quat`/`Quat`, `rgba`/`Rgba`; `Quat` and `Rgba8` are predeclared unless shadowed by a user type):

* **`vec2` (8 B / 4 B, `[f32; 2]`):** Constants `vec2::ZERO`, `ONE`, `X`, `Y`. Swizzles `.x`/`.y` (1–4 lanes -> `f32`/`vec2`/`vec3`/`vec4`).
* **`vec3` (12 B / 4 B, `[f32; 3]`), `vec3a` (16 B / 4 B, `[f32; 4]`):** Constants `vec3::ZERO`, `ONE`, `X`, `Y`, `UP`, `Z`. Swizzles `.x`/`.y`/`.z` (1–4 lanes).
* **`vec4` (16 B / 4 B, `[f32; 4]`), `quat` / `Quat` (16 B / 4 B, `[f32; 4]`):** Constants `vec4::ZERO`, `ONE`, `X`, `Y`, `Z`, `W`. Swizzles `.x`/`.y`/`.z`/`.w` (1–4 lanes).
* **`ivec2` (8 B / 4 B, `[i32; 2]`), `ivec3` (12 B / 4 B, `[i32; 3]`), `uvec2` (8 B / 4 B, `[u32; 2]`):** Constants `::ZERO`, `::ONE`, `::X`, `::Y` (plus `ivec3::Z`). Swizzles `.x`/`.y`/`.z` returning `i32`/`u32`/`ivec*`/`uvec2`.
* **`mat3` (36 B / 4 B, `[f32; 9]`), `mat4` (64 B / 4 B, `[f32; 16]`):** Column-major rotation/transform matrices.
* **`rgba8` / `Rgba8` (4 B / 4 B, `u32`), `rgba` / `Rgba` (16 B / 4 B, `[f32; 4]`):** Packed 8-bit vs linear `f32` colors.

#### C. Handles & Zero-Heap Inline Primitives (`AbiPod`)

| Type | Size / Align | Purpose & Key API |
|---|---|---|
| `Ref<T>` (default `Ref<Entity>`), `Entity` | 8 B / 8 B | Generation-checked entity reference (`FfiEntity`). `row.id` and `id: Entity` resolve to `Ref<Entity>`. |
| `Asset<T>` (default `Asset<Untyped>`) | 32 B / 8 B | Generation-checked asset handle (`FfiAssetHandle`). |
| `[T; N]` | `stride(T) * N` / `align(T)` | Fixed-size inline array (`N` supports integer const arithmetic/shifts). |
| `(T1, T2, ...)` | C-aligned + tail-padded | Fixed tuple (`row` multi-value / helper return). |
| `InlineStr<N>` | `4 + align_up(N, 4)` / 4 B | Inline UTF-8 string (`len: u32` + bytes). **`N` must be a multiple of 4 (`E0104`)**; init directly from `"text"`. |
| `SmallVec<T, N>` | `8 + stride(T) * N` / `max(align(T), 4)` | Fixed-capacity inline vector (`len: u32`, `_pad: u32`, `[T; N]`); init from `[a, b]` (`E0111` if len > `N`). |
| `BitSet<BITS>` (default `32`) | `max(1, ceil(BITS/32)) * 4` / 4 B | Fixed bitmask (`bits(0, 2)` constructor). Methods: `.set(i)`, `.clear(i)`, `.get(i) -> bool`, `.count_ones() -> u32`, `bs[i] -> bool`. |
| `InputBuffer<Action, CAP>` (defaults `u16, 4`) | `CAP * 8` / 4 B | Buffered action ring buffer (`action_id: u16, _pad: u16, remaining_sec: f32`). Methods: `.push(a, win)`, `.peek(a) -> bool`, `.consume(a) -> bool`, `.tick(dt)`, `.clear()`. |
| `GraceWindow` | 4 B / 4 B | Coyote/grace countdown (`remaining_sec: f32`). Methods: `.arm(dur)`, `.tick(dt)`, `.is_active() -> bool`, `.clear()`. |

#### D. Non-ABI Control Types & Banned Wire Types

* **Valid in code/queries/params, invalid as stored `component`/`resource`/`struct`/`event`/`stream`/`rpc` fields (`E0103`):**
  `Option<T>` (`Some(x)` / `None`; methods `.is_some()`, `.is_none()`, `.unwrap()`, `.expect()`, `.unwrap_or(d)`, `.unwrap_or_else(...)`, `.or(...)`, `.and(...)`, `.as_ref()`, `.as_mut()`, `.take()`, `.filter(...)`), `Result<T, E>`, borrows (`&T`, `&mut T`, `&mut? T`, `?&T`, `?&mut T`, `&res R`, `&mut res R`), `&Trigger<E[, Target]>`, `stream_in<S>`, `QueryRow`, and structural `Record` literals.
* **Banned Wire Types (`E0103` with fix-its):** `usize`/`isize`/`u128`/`i128` (use `u64`/`i64`), `String`/`str` (use `InlineStr<N>`), `Vec`/`Box` (use `SmallVec<T, N>`), and `char` (use `u32` or `u8` byte chars).

### 3.3 Bidirectional Inference & Explicit Casting

* **Top-Down Propagation:** Expected types propagate from `let pat: T = e`, `const C: T = e`, field defaults `f: T = e`, struct/component initializers, `Assign` RHS, array/tuple elements, `if`/`match` branches, and function arguments/returns.
* **Numeric Widening Ladder:** `f64 > UnitScalar > fix64 > fix32 > f32 > u64 > i64 > u32 > i32 > u16 > i16 > u8 > i8`. Binary arithmetic/comparisons widen narrower operands automatically via `HirExpr::Cast`, **except** a non-negative `i32` literal (`0`, `1`, `42`) adapts directly to a typed integer operand (`u8..u64`, `i8..i64`).
* **Explicit `expr as Type`:** Required when narrowing, converting floats to ints, or bridging `fix32`/`fix64` (`f32 as fix32` scales by `65536.0`; `fix64 as i64` divides by `2^32`). Float-to-unsigned casts emit saturating/safe conversion helpers.

### 3.4 `AbiPod` Layout Solver, `@no_pad` & Deterministic Wire Identity

Because Strata's 4 backends share raw component buffers across the 73-slot C ABI (`bamabi_sys`), implicit C struct padding cannot be trusted (uninitialized padding bytes cause UB in Rust `Pod` casts and break cross-compiler hashes).

1. **`solve_pod_layout`:** Walks fields in declaration order. Whenever alignment requires a gap before a field or at the struct tail, the solver inserts explicit zero-initialized `_strata_pad_N: [u8; K]` fields so `size == sum(field.size)` with **zero implicit padding**.
2. **`@no_pad` & `assert_layout`:** Attach `@no_pad` to a `component` (or `@soa` `hot` stratum) to reject any layout needing padding (`E0104_PADDING_HAZARD`, e.g., pack largest-alignment fields first). `InlineStr<N>` always enforces `N % 4 == 0` (`E0104`) on both `component` and `struct`. Verify layouts with `assert_layout(Comp, size == 16, align == 4, padding == 0);` (`==`, `!=`, `<`, `<=`, `>`, `>=` supported; `E0105` on mismatch).
3. **Wire Identity:** `ComponentUuid` (SipHash-2-4-128 rendered `8-4-4-4-12`) and `SCHEMA_FINGERPRINT` (64-bit FNV-1a) hash canonical name, size, align, flags (`SPARSE_SET | SUMMARY_TICK`), and every field including `_strata_pad_*`, matching `bamabi_macros` bit-for-bit. Visual metadata (`@node_group`) and `sys`/`fn`/`sim_test` bodies do **not** affect schema fingerprints.

### 3.5 SI Dimensional Unit Algebra (`UnitDim`)

* **Why It Exists:** Mixing up milliseconds vs. seconds or degrees vs. radians causes silent physics bugs. Strata encodes a 4-exponent dimensional vector `UnitDim { sec: i8, meters: i8, rad: i8, frames: i8 }` in the type checker and erases every unit type to `f32` (4 B) at codegen.
* **Normalization & Constructors:** Literals normalize to SI base `f64` at compile time (`ms` multiplies by `0.001`; `deg` multiplies by `π / 180.0`; all others scale by `1.0`). You can also construct unit values from plain floats via `sec(x)`, `ms(x)`, `meters(x)`, `mps(x)`, `mps2(x)`, `hz(x)`, `rad(x)`, `deg(x)`, `frames(x)`.
* **Conversions & Dimensional Arithmetic:** Call `.raw()` (or `.as_secs()` / `.as_millis()` on time units) to extract a plain `f32`. Multiplying/dividing unit values adds/subtracts exponents (`meters / sec -> mps`, `sec * hz -> f32` when `UnitDim::NONE` cancels out). Unit dimension mismatches on `const` or field defaults emit `E0102_UNIT_MISMATCH`.

| Unit Type(s) | Exact Literal Suffixes | Exponents `(sec, m, rad, frames)` | Base Factor |
|---|---|---|---|
| `sec`, `ms` | `sec`, `s`, `ms` | `(1, 0, 0, 0)` | `1.0` (`ms`: `0.001`) |
| `hz` | `hz`, `Hz` | `(-1, 0, 0, 0)` | `1.0` |
| `frames` | `frames`, `f` | `(0, 0, 0, 1)` | `1.0` |
| `rad`, `deg` | `rad`, `deg` | `(0, 0, 1, 0)` | `1.0` (`deg`: `π/180`) |
| `meters` | `meters`, `m` | `(0, 1, 0, 0)` | `1.0` |
| `mps` | `mps` | `(-1, 1, 0, 0)` | `1.0` |
| `mps2` | `mps2` | `(-2, 1, 0, 0)` | `1.0` |

---

## 4. ECS Data Model

Each construct below shows **Syntax**, **Philosophy (Why)**, **Bevy `0.20.1` Mapping**, and a **Mini Example** (note: short syntax snippets omit `module` boilerplate; complete runnable modules appear in Sections 1 and 9).

### 4.1 Components, Tags & `@require`

* **Syntax:** `component Name @require(Dep1, Dep2) { field: Type = default, ... }` · Marker: `component Marker;` · Tags: `tag A, B;` (no trailing comma in `tag` lists). Note `@require(...)` appears **after** the component name.
* **Philosophy:** Keeps entity data flat and composable without inheritance. `@require(...)` prevents invalid half-initialized spawns (like spawning a `Raindrop` without a `Pos3D`) by auto-attaching dependencies with their defaults.
* **Bevy `0.20.1` Mapping:** `#[repr(C)] #[derive(Clone, Copy, Component)] #[require(Dep1, Dep2)] struct Name`; `tag` lowers to zero-sized `struct StrataTag_*`.

```strata
component Pos2D { xy: vec2 = vec2::ZERO }
component Hero @require(Pos2D) { hp: f32 = 100.0 }
tag Alive, PlayerControlled;
```

### 4.2 `@soa` Hot/Cold Splitting & `@no_pad`

* **Syntax:** `@soa @summary_tick component Name { hot { ... } cold <stratum> { ... } }`
* **Philosophy:** Dense table queries iterate every column touched. When a component exceeds a 64 B cache line (`W0404`), moving rare fields (serial numbers, logs, caps) into `cold <stratum>` packs hot per-tick scalars tightly into 16 B–64 B cache lines while keeping user syntax natural (`Comp.hp` for single fields, `Comp::caps` for a whole cold stratum).
* **Bevy `0.20.1` Mapping:** `hot` compiles to `mod::Comp` (`SchemaItemKind::SoaHot`); each `cold <s_name>` compiles to companion component `mod::Comp__<s_name>` (`SchemaItemKind::SoaCold`) with `mod::Comp` prepended to its `#[require(...)]`. When spawning an entity or `object` that uses a cold stratum, include `Comp::<s_name> { ... }` alongside `Comp { ... }`.

```strata
@soa @summary_tick @no_pad
component DroneHull {
    hot { hp: f32 = 100.0, heat: f32 = 0.0 }
    cold meta { serial: InlineStr<16> }
}
```

### 4.3 Sparse-Set (`@sparse`) vs. `@summary_tick`

* **Syntax:** `@sparse component Stunned { rem: sec = 1.0_s }` vs. `@summary_tick component Health { hp: f32 = 100.0 }`
* **Philosophy:** Adding/removing dense table components moves all entity fields across archetypes. `@sparse` keeps transient buffs, `timeline`s, and `task`s in O(1) side tables without archetype moves. Conversely, `@summary_tick` opts dense components into Bevy `0.20.1` chunk-level tick summaries so `Changed<T>` skips entire unchanged tables. Combining `@sparse` and `@summary_tick` is illegal (`E0110`).
* **Bevy `0.20.1` Mapping:** `@sparse` -> `#[component(storage = "SparseSet")]`; `@summary_tick` -> `#[component(summary_tick)]`.

```strata
@sparse component Stunned { remaining: sec = 1.5_s }
@summary_tick component Armor { value: f32 = 25.0 }
```

### 4.4 Resources (`resource`)

* **Syntax:** `resource Clock { dt: sec = 16.6667_ms }` (`{ ... }` is mandatory; there is no `;` marker form).
* **Philosophy:** Centralizes world-wide singletons (clocks, input snapshots, scoreboards) with compile-time borrow tracking (`&res R` vs `&mut res R` or `res<R>()` / `res_mut<R>()`).
* **Bevy `0.20.1` Mapping:** `#[derive(Resource, Default)]` registered via `app.init_resource::<R>()`, injected as `Res<R>` / `ResMut<R>`.

```strata
@persist
resource MatchState { wave: u32 = 1, paused: bool = false }
```

### 4.5 Named Entities (`object`) & Persistence (`@persist`, `@persistent`)

* **Syntax:** `[@persist] object Hero { CompA { x: 1.0 }, CompB {} }` and `spawn @persistent { CompA {} };`.
* **Philosophy:** Gives singletons like `PlayerHero` or `ArenaBoss` a deterministic handle (`query_one(...).on(Hero)`) spawned before user `Startup` systems. `@persist` / `@persistent` marks progression entities/components/resources so room transitions (`despawn_all<With<Transient>>()`) and mod reloads preserve them via `bamabi_host` Slots 38/56.
* **Bevy `0.20.1` Mapping:** `StrataNamedObjects` `Resource` initialized by `strata_init_named_objects` in `Startup` strictly before user systems.

```strata
@persist component SaveFlags { unlocked: BitSet<32> }
@persist object CampaignSave { SaveFlags {} }
```

### 4.6 Streams (`stream`, `stream_in<S>`, `emit`) vs. Events & Observers (`event`, `obs`, `trigger`)

* **Syntax:**
  * Buffered stream: `stream HitLog { dmg: f32 }` -> `emit(HitLog { dmg: 12.0 });` -> `sys read_hits(h: stream_in<HitLog>) { let x = h.dmg; }`
  * Immediate observer event: `event Strike { target: Ref<Health>, dmg: f32 }` -> `trigger(e, Strike { target: e, dmg: 20.0 });` -> `obs on_strike(trg: &Trigger<Strike, Health>) { ... }` (add `propagate: true` to bubble up `ChildOf` ancestors).
* **Philosophy:** Streams batch high-volume notifications across a frame boundary with zero per-entity observer dispatch cost. Events + observers deliver immediate, targeted reactions (`trg.payload`, `trg.target`) without scanning unrelated entities. Note: `stream_in<S>` binds the latest message in the stream directly as `&S` (use `h.dmg`, not `for m in h`).
* **Bevy `0.20.1` Mapping:** `stream` -> `#[derive(Message)]` + `MessageWriter<M>` / `MessageReader<M>` (or `ParallelCommands::command_scope` inside `@par`). Global `event` -> `#[derive(Event)]`; entity `event` -> `#[derive(EntityEvent)]` (`#[event_target]`); `obs` -> `fn(on: On<Ev>, ...)` via `app.add_observer(...)` (ancestors walked via `Query<&ChildOf>` up to guard `< 256` when `propagate: true`).

```strata
stream TelemetryPing { seq_no: u32 }
event DamageTaken { dmg: f32 }

obs on_damage(trg: &Trigger<DamageTaken, Armor>) {
    if let Some(a) = query_one(arm: &mut Armor).on(trg.target) {
        a.arm.value = max(0.0, a.arm.value - trg.payload.dmg);
    }
}
```

### 4.7 Relations, Hierarchy & Upward Cascades (`relation`, `ChildOf`, `.up<R>()`)

* **Syntax:** `relation InSquad [exclusive, cleanup_remove];` · `relation Affinity [symmetric] { points: i16 = 0 }` · Built-in `ChildOf`.
  * Graph ops: `insert_relation<R>(child, parent[, R { ... }]);` and `remove_relation<R>(child, parent);`.
  * Upward cascade query: `for row in query(a: &mut Node, p: &ParentVal).up<ChildOf>() { ... }`.
  * Flags: `exclusive`, `symmetric`, `acyclic`, `cascade_despawn` (`cascade_delete` alias), `cleanup_remove`.
* **Philosophy:** Models parent-child transforms, inventory ownership, and symmetric social graphs safely without raw pointer spaghetti, while Slot 58 `IterUpCascade` handles ancestor lookups with built-in cycle protection (Brent's cycle detection).
* **Bevy `0.20.1` Mapping:** `ChildOf` maps to native `bevy_ecs::hierarchy::ChildOf` (`Query<&ChildOf>`); custom relations compile to `StrataRelation_<Name>` `Resource` (`Vec<(Entity, Entity, Payload)>`) + 8 B `__strata_rel_parent_<Name>` `Component` for `.up<R>()` cascades.

```strata
relation EquippedOn [exclusive, cascade_despawn] { slot: u8 }
```

### 4.8 Static Data (`table`, `curve`) & Schema Evolution (`migrate`)

* **Syntax:**
  * `table CropSpec by CropKind { cost: u32 } = { Turnip => { cost: 20 }, ... };` (indexed via `CropSpec[kind]`)
  * `curve Falloff(meters -> f32) = [(0.0_m, 34.0), (100.0_m, 14.0)];` (evaluated via `Falloff.sample(dist)`)
  * `migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health { Health { hp: old.hp as f32 } }`
* **Philosophy:** `table` forces every enum variant to have design data (`E0106`), `curve` guarantees monotonic control points (`E0107`), and `migrate` provides deterministic in-place upgrades (`BamRowMigrateFn` Slot 67) across `@persist` reloads.
* **Bevy `0.20.1` Mapping:** `table`/`curve` lower to immutable static data helpers; `migrate` lowers to `pub fn strata_mig_*` (native) / Slot 67 callback (JIT/guest). *(Note: `zone`, `prefab`, `aspect`, and `hash_index` exist in `parser.rs` as reserved syntax declarations and are not lowered in `strata_sema` yet.)*

---

## 5. Systems, Queries, Schedules & Concurrency

### 5.1 Systems, Queries, Filters & Row Loops

```strata
sys update_enemies(clk: &res Clock) effects(writes: [Vel], reads: [Pos, Entity]) {
    uniform let dt = clk.dt.as_secs();
    for row in query(id: Entity, v: &mut Vel, p: &Pos.xy)
        .with<Active>()
        .without<Stunned>()
        .changed<Pos>()
        .where(p.y > 0.0)
    {
        row.v.dxy += vec2(0.0, -9.81 * dt);
    }
}
```

* **Query Shorthands & Accessors:**
  * `query(pos: &Pos3D)` binds `row.pos`; `query(&Pos3D)` defaults the field name to `row.Pos3D`.
  * Project individual fields (`&mut Pos3D.xyz`) or `@soa` cold strata (`&CombatantBody::caps`).
  * `row.id` (always available, or explicit `e: Entity`) has type `Ref<Entity>`.
  * Point lookups: `query_one(...).on(entity_or_object)` returns `Option<QueryRow>` (chain `.unwrap()` if guaranteed present). Count matches with `query(...).count() -> u32`.
  * Multi-world test helpers: `server_query(...)` and `client_query(cid, ...)` inside `net_sim_test`.
* **Query Filters -> Bevy `0.20.1`:** `.with<T>()` (`With<T>`), `.without<T>()` (`Without<T>`), `.changed()` / `.changed<T>()` (`Changed<T>`), `.added()` / `.added<T>()` (`Added<T>`), `.allow<T>()` / `.has<T>()` (access/presence hints), `.where(pred)` (row filter), `.on(target)` (single entity), `.up<R>()` (ancestor cascade).
* **Entity Commands Inside Systems:** `spawn { C1 {}, C2 };`, `spawn @persistent { ... };`, `spawn_batch(N) |i| { { C1 {}, C2 } };` (Slot 39 SoA bulk spawn; `W0403` warns if calling `spawn` inside a loop), `despawn(e);`, `despawn_all<With<Tag>>();` (Slot 40 bulk despawn), `insert(e, Comp {});`, `insert @if_new(e, Comp {});`, `remove<Comp>(e);`.
* **`uniform let`:** Marks loop-invariant values loaded once outside chunk loops (`clk.dt.as_secs()`) so inner SIMD/chunk loops stay scalar-free.

### 5.2 `?T` Chunk Splitting (`?&T` / `?&mut T` / `Option<&T>`)

* **Exact Syntax Warning:** The compiler optimization pass is called `?T` chunk splitting (`optional_split.rs`), **but bare `?T` is a syntax error in `.strata` source!** Always write **`?&T`** or **`?&mut T`** (or `Option<&T>` / `Option<&mut T>`) in `query(...)` / `query_one(...)` terms, and `Option<T>` for optional local values.
* **Philosophy & Runtime Behavior:** Checking `Option<&T>` per entity inside a tight loop causes branch misprediction on every row. `optional_split.rs` emits `OptionalChunkIsPresent` at the **chunk header** and clones the loop into two branch-free paths: a *present* path where the column pointer is proven non-null, and an *absent* path where optional blocks are skipped entirely.
* **Bevy `0.20.1` Mapping:** `Query<(..., Option<&'static T>, Option<&'static mut U>)>` inspected per archetype chunk via `ChunkSliceQueryExt`.

### 5.3 `&mut? T` Selective Tick Coalescing

* **Syntax:** `query(hp: &mut? Health.hp)` or `query(sh: Option<&mut? Shield>)` (also `?&mut` for optional mutable; note `&mut?` puts `?` *after* `mut`, whereas `?&mut` puts `?` *before* `&`).
* **Philosophy & Runtime Behavior:** Normal `&mut T` marks every entity in every visited chunk as changed in Bevy—even if an `if` guard prevented any actual write (`W0402`). `&mut? T` lowers via `tick_coalesce.rs` to untracked slice writes (`IterColWriteUntracked`, Slot 14) paired with register-held run tracking (`DirtyRunInit`/`DirtyRunRecordRow`) that flushes contiguous dirty row spans (`IterMarkChangedRange`, Slot 15) only when a row was actually modified—and **never** marks rolled-back rows dirty inside `atomic` transactions.
* **Bevy `0.20.1` Mapping:** `SelectiveMutSlice::from_contiguous_mut` (`ContiguousMut::bypass_change_detection_split`) + `SelectiveMutSlice::mark_dirty_row(row)` (via `DirtyRunCoalescer::mark_row`) -> `ContiguousComponentTicksMut::slice(start..end).mark_all_as_changed()`. (Sparse/row-iter fallback uses `bypass_change_detection()` + conditional `.set_changed()`.)

### 5.4 Conflicting Queries & Automatic `ParamSet`

* **Philosophy:** Rust/Bevy forbids two `Query` parameters in one system from holding aliasing mutable/shared borrows at the same time. When a `task` header `on (...)` coexists with `.on(target)` `query_one` lookups, or `.up<R>()` cascades overlap a query without `With`/`Without` disjointness, manually juggling `ParamSet` indices is tedious and error-prone.
* **Compiler Rule:** `strata_sema` rejects truly illegal intra-query or unguarded inter-query aliases (`E0201`), while permitting safe sequential patterns (`task` `on (...)` + `.on(target)`, or `.up<R>()` cascades). `strata_codegen` packs *only* those conflicting queries into Bevy `ParamSet<(...)>` (`q_set.p0()`, `q_set.p1()`, or snapshot-plus-writeback when loops overlap) and leaves disjoint queries as direct `Query` parameters.

### 5.5 Schedules, Sets, Ordering & `run_if`

* **Phases (Mapping 1-to-1 to Bevy `0.20.1` Schedules):** `Startup`, `PreUpdate`, `Update`, `FixedUpdate` *(default if a system isn't placed elsewhere)*, `PostUpdate`, `Last`. Note: when any `Resource` has a `dt` field, Strata automatically synthesizes `strata_timer_tick` in `FixedUpdate` before user systems to tick `GraceWindow` and `InputBuffer` fields.
* **Containers & Modifiers:**
  * `seq Group { A, B }` -> `SystemSet` with `.chain()` (strict ordering + sync points if commands exist).
  * `seq_weak Group { A, B }` -> `.chain_weak()` (orders only if neither system is skipped).
  * `par Group { A, B }` -> unordered parallel `SystemSet`.
  * `set Leaf { A, B }` -> logical `SystemSet` grouping.
  * `before(Target)` / `after(Target)` -> `.before(Target)` / `.after(Target)`.
  * `run_if(cond)` -> `.run_if(strata_run_if_*)` (works on `schedule` or `ScheduleNode`).

### 5.6 Theorem 0.1 Parallelism & Declared Effects

* **Theorem 0.1 (`FilteredAccessSet`, Kani `PO-S7`):** Two queries `A` and `B` are provably archetype-disjoint if `!A.with.is_disjoint(&B.without) || !B.with.is_disjoint(&A.without)` (for example, `query(...).with<Hero>()` and `query(...).without<Hero>()`). Note that `.changed<T>()` and `.added<T>()` are runtime tick filters and do **not** prove disjointness! `@soa` strata (`Body::hot` vs `Body::caps`) are also disjoint.
* **Hard ABI Caps (`E0203`):** At most `32` terms+filters per query (`bamabi_sys::MAX_TERMS_PER_QUERY`) and at most `16` queries per system (`bamabi_sys::MAX_QUERIES_PER_SYSTEM`).
* **`@par` & Parallel Reductions:** `@par(chunk = 1024)` enables chunk-parallel execution (`QueryContiguousParIter::for_each`). `@par(read_only, chunk = 2048)` unlocks `par_for_each_chunk_readonly` (Slot 59) for `for row in query(...) reduce (acc: op(init, expr))` reductions supporting 7 operators (`sum`, `prod`, `min`, `max`, `count`, `any`, `all` — including 1-argument `count()`, `any(cond)`, `all(cond)`) without arena locks (`E0202` if `@par(read_only)` borrows `&mut`). Lock in parallelism guarantees with `assert_par(sys_a, sys_b);`.
* **Declared `effects(...)` Clauses:** Optional on `sys` / `obs`; when present, the compiler verifies every direct and transitive helper/workflow access (`E0204`):
  * Exact 6 effect keys: `reads: [...]`, `writes: [...]`, `spawns: [...]`, `despawns: [...]`, `triggers: [...]`, `emits: [...]` (wildcard `*` allowed; `writes` implies `reads`, and `spawns` transitively covers `@require(...)` components).

---

## 6. Control Flow, Functions & First-Class Gameplay Constructs

### 6.1 Control Flow, Functions & Math Builtins

* **Statements & Expressions:** `let x = 1;`, `let Some(v) = opt else { return; };`, `uniform let`, `if cond { ... } else { ... }`, `if let Pat = expr { ... }`, `match expr { Pat if guard => body, _ => fallback }`, `for i in 0..N { ... }`, `for i in 0..=N { ... }`, `while cond { ... }`, `loop { ... }`, `break [val];`, `continue;`, `return [val];`. Struct literals are forbidden in `if`/`while`/`match`/`for`/`abort_if` headers (`ExprNoStruct`) so `if flag { ... }` is never ambiguous; wrap `(S { x: 1 })` in parentheses if needed.
* **Functions (`fn` & `@node_pure`):** Plain `fn` cannot execute `query`/`query_one`/spatial queries (`E0204`), though helper `fn`s can access `res`/`res_mut` and call entity commands (transitively checked against calling system's `effects` and `@authority`). `@node_pure fn` forbids all ECS/resource/mutable access (`E0601`).
* **Builtin Math & Vector Functions:** `length`, `length_sq`, `distance`, `distance_sq`, `dot`, `cross`, `normalize`, `min`, `max`, `clamp`, `abs`, `floor`, `ceil`, `round`, `sqrt`, `sqr`, `signum`, `remap`, `sin`, `cos`, `tan`, `atan2`, `pow`, `exp`, `ln`, `lerp` (note: `mix` only lowers as a `lerp` alias in `rust_guest`; prefer `lerp` across all 4 backends).

### 6.2 Finite State Machines (`fsm`)

* **Philosophy:** Turns multi-state AI or lifecycle logic into a 4 B+ POD component (`__state: u16, __flags: u16` + per-state locals) with deterministic priority-ordered transitions—no `Box<dyn State>` traits.
* **Syntax & Bevy Mapping:** Declare states (`initial StateA { ... };`, `state StateA { local_var: f32 = 0.0; on_enter { ... } on_tick { ... } on_exit { ... } to StateB { ... } when cond @priority(5); }`), attach with `insert(e, MyFsm::start());`, and place `MyFsm` in a `schedule`. Compiles to a POD `Component` + tick `System`.

### 6.3 Frame-Accurate Timelines (`timeline`)

* **Philosophy:** Expresses combat startup/active/recovery/i-frame windows and frame cues without fragile manual frame floats.
* **Syntax & Bevy Mapping:** Always sparse (`@sparse`), with `@rate(60_hz)` and `@duration(28_f)`. Define `window name = start_f..end_f;` (`E0108` if out of bounds) and `at frame_f => trigger(self, Ev { ... });`. Query active windows via `tl.in(window_name)`. Attach with `insert @if_new(e, MyTimeline::start());` and schedule `MyTimeline`. Compiles to a 16 B `@sparse` `TimelineCursor` `Component`.

### 6.4 Stackless Zero-Alloc Coroutines (`task`)

* **Philosophy:** Linear multi-tick gameplay actions (dashes, revives, channeling) without heap allocations or async runtimes.
* **Syntax & Rules:** `@sparse task Dash(speed: mps) on (vel: &mut Vel.dxy) using (clk: &res Clock) { abort_if ... { ... } race { branch { wait 140.0_ms; } branch { wait_until cond; } } yield_tick; }`. Start with `insert(e, Dash::start(20.0_mps));` and schedule `Dash`. Every parameter or `let` binding live across a suspension (`wait`, `wait_until`, `yield_tick`, `race`) **must** be `AbiPod` (`E0302_NON_POD_ACROSS_WAIT`). Compiles to a POD `TaskState` `Component` (`__pc: u8`, `_strata_pad_0: [u8; 3]`, `__timer: f32`, live locals) + step `System`.

### 6.5 Spatial CSR Grids (`spatial_grid` & `spatial_history`)

* **Philosophy:** Prevents `O(N^2)` entity checks (`W0401`) using lock-free Compressed Sparse Row (CSR) spatial grids rebuilt deterministically in 2 counting-sort passes (`SpatialCsrBegin` -> `Count` -> `PrefixSum` -> `Scatter`). `spatial_csr.rs` automatically schedules the rebuild strictly before the earliest reader system.
* **Syntax:**
  * `spatial_grid Grid(cell_size: 4.0_m, bounds: vec2(-128.0_m, -128.0_m)..vec2(128.0_m, 128.0_m), capacity: 512) over Enemy by Pos.xy [cache (HitCapsule)];`
  * `spatial_history Hist(frames: 16, cell_size: 16.0_m, bounds: ..., capacity: 128) over Player by Pos3D.xyz;`
  * Query in systems/observers (`g: &res Grid`) via `for hit in g.query_disc(center, radius) { hit.id ... }` or `h.query_segment_at(rewind_tick, p0, p1[, radius])`.

### 6.6 Single-Entity Transactions (`atomic` / `on_rollback`)

* **Philosophy:** Multi-step mutations (like spending coins + spawning placed furniture) often fail halfway when a check fails. `atomic { ... } on_rollback { ... }` records pre-image undo slots (`CmdCheckpoint`) before mutating a single entity or resource; if `require_true(cond);` fails, `CmdRollback` restores pre-images in reverse order, discards deferred commands (`__tx_cmds`), suppresses `&mut?` tick dirtying, and runs `on_rollback { ... }`. Multi-entity loops spanning `atomic` are rejected at MIR verification.

### 6.7 Deterministic Execution (`@deterministic` & `fix32`/`fix64`)

* **Philosophy:** Guarantees identical simulation hashes across Cranelift JIT, ISO C99, Safe Rust Guest, and Bevy Native.
* **Mechanism:** `@deterministic` on `module` sets `allow_fma = false` (C99 emits `#pragma STDC FP_CONTRACT OFF`), selects deterministic libm intrinsics, and locks parallel reduction/CSR ordering. Use `fix32` (Q16.16) and `fix64` (Q32.32) for exact platform-independent integer-backed fractional physics.

### 6.8 Networking, Quantization & Unified Provenance (`@authority`)

* **Wire Packet (`StrataNetPacket`):** Fixed `184`-byte `#[repr(C)]` packet (`"STNP"`, `128 B` payload) sent over `Messages<StrataNetPacket>` (ABI Slots 30–32) with handshake validation of `module_net_fingerprint` and per-item `SCHEMA_FINGERPRINT`. RX systems run before `FixedUpdate` user systems; TX systems run after.
* **Replication & RPCs:**
  * `@net(reliable|unreliable, rate = 20Hz | interval = 3, channel = 0..=255)` on `component`/`resource`.
  * `@net_rpc(direction = client_to_server | server_to_client | bidirectional, reliability = reliable | unreliable, channel = 0..=255)` on `rpc` (or `sys`). Incoming RPCs dispatch to `obs on_rpc(trg: &Trigger<MyRpc>)`.
  * `@quantize(min = -256.0, max = 256.0, bits = 16[, step = 0.01])` on numeric/vector components or fields (`E0503` if `min >= max` or `bits` outside `1..=32`).
* **Unified Provenance (`@authority` & `E0501`):**
  * Non-server callables (`@authority(client)`, `@predicted`, `@authority(shared)`) are checked by an abstract interpreter tracking `AuthoritySet` (`SERVER`, `CLIENT`) and `PlaceOrigin` (`TempValue` vs `EcsPlace`).
  * **Why Copy-vs-Borrow Soundness matters:** Client HUDs and prediction code *can* safely copy plain scalar values (`f32`, `u32`, `bool`, `UnitScalar`, `enum`) out of `@authority(server)` components/resources into `let` bindings—those decay to `TempValue`. Holding a borrow (`&T`, `&mut T`, `QueryRow`), mutating/spawning/despawning server state, calling `server_res<R>()`, or calling a helper/observer/`task`/`fsm` that mutates server state preserves server provenance and fails compilation with `E0501_AUTHORITY_VIOLATION`.

---

## 7. Testing, Visual Graph IR, `stratac` CLI & Novice Pitfalls

### 7.1 Simulation & Network Testing (`sim_test` & `net_sim_test`)

* **`sim_test "name" { ... }`:** Compiles via `strata_jit` into a headless `bamabi_host` `App` (`SingleThreadedExecutor`) and measures and reports `steady_allocs` (`steady_state_allocs`) across post-warmup `FixedUpdate` steps (reporting the allocation count without failing on non-zero allocations; the separate parity harness in `sim_runner.rs` uses `hash_world_pod_state` -> `WorldPodDigest` with SHA-256 + FNV-1a).
  * Helpers: `step_fixed(n)`, `res<R>()`, `res_mut<R>()`, `query(...)`, `query_one(...).on(obj_or_id)`, `assert(cond)`, `assert_eq(a, b)`, `assert_ne(a, b)`.
* **`net_sim_test "name"(latency: 40ms, jitter: 10ms, loss: 0.05, seed: 42, clients: 2) { ... }`:** Splits MIR by `@authority(server|client)`, compiles separate server and client JIT `.dylib`s, and steps virtual Bevy worlds over a deterministic PRNG ARQ channel (`E0505` on negative times or `loss` outside `0.0..=1.0`).
  * Helpers: `clients(n)` (statement fallback if omitted from header), `spawn_client(cid)`, `send_rpc(cid, Rpc { ... })`, `step_net(ticks)`, `server_step(ticks)`, `client_step(cid, ticks)`, `server_spawn(...)`, `client_spawn(cid, ...)`, `server_query(...)`, `client_query(cid, ...)`, `server_res<R>()`, `client_res<R>(cid)`, `assert_converged()` (0 args: all clients, default tolerance), `assert_converged(client_id)` (1 arg), `assert_converged(client_id, tolerance)` (2 args).

### 7.2 Visual Graph IR & Live Tooling (`graph_ir.rs` & `strata-lsp`)

* **Visual Graph IR (`GRAPH_IR_VERSION = "1.0"`):** Lossless CST <-> JSON projection over 8 node kinds (`component`, `@node_pure fn`, `timeline`, `fsm`, `task`, `table`, `curve`, `schedule`) organized by `@node_group("Group/Sub")` and stored in `.strata.graph.json` layout sidecars without altering schema fingerprints.
* **`strata-lsp`:** Salsa-backed incremental diagnostics, ABI layout hover cards (`#[repr(C)]` size/offsets/UUIDs/SI units), canonical `stratafmt`, `strata/graphTelemetry` endpoints decoding 64 B `"BAMT"` (`SystemTelemetryDigest64`) IPC frames, and BRP `bam/component_schemas` ingestion.

### 7.3 `stratac` CLI Workflow

All inspection/build/graph commands support `--format text|json`. Exit codes: `0` (`EXIT_OK`), `1` (`EXIT_COMPILE_ERROR`), `2` (`EXIT_SIM_TEST_FAILED`), `3` (`EXIT_PARITY_OR_ASSERT_FAILED`).

| Command | Purpose |
|---|---|
| `stratac check <FILE>` | Parse, type/layout/Theorem 0.1/authority check, lower & verify MIR. |
| `stratac fmt <FILE> [--check]` | Format with `stratafmt` (`--check` exits `3` on diff). |
| `stratac layout <FILE>` | Inspect solved sizes, alignments, `_strata_pad_*`, `ComponentUuid`, `SCHEMA_FINGERPRINT`. |
| `stratac explain-par <FILE>` | Report `@par` vectorization eligibility and conflict blockers. |
| `stratac test <FILE>` | Run all headless `sim_test` and `net_sim_test` cases. |
| `stratac build <FILE> [--release] [--target jit\|c99\|rust-guest] [--out <DIR>] [--bampack] [--sign] [--key <PATH> \| --ephemeral-key]` | Build mod `.dylib`/`.cdylib` + `mod.toml` (+ optional Ed25519 `.sig` / `.bampack`; `--sign`/`--bampack` require `--key` or `--ephemeral-key`). |
| `stratac watch <FILE> [--sign] [--key <PATH> \| --ephemeral-key] [--once]` | Incremental Salsa hot-reload loop + sub-ms `.schedule_delta.json` (`ModScheduleSetRewirePass`) when only schedule topology changes. |
| `stratac onboard <FILE> [--target bevy-native] --out <DIR> [--static-console] [--check]` | Generate a standalone `#![forbid(unsafe_code)]` Bevy `0.20.1` `Plugin` crate (`--static-console` eliminates `dlopen`). |
| `stratac graph export <FILE>` / `apply <FILE> <PATCH>` | Export Graph IR JSON or validate+apply a Graph IR patch cleanly. |

### 7.4 Top Novice Syntax Pitfalls & Compiler Error Guide

**Syntax & `grammar.js` Traps to Avoid:**
1. **`?T` vs `?&T` vs `Option<T>`:** Bare `?T` is a syntax error! Use `?&T` / `?&mut T` (or `Option<&T>` / `Option<&mut T>`) in queries, and `Option<T>` for optional values.
2. **`&mut? T` vs `?&mut T`:** `&mut? T` is *selective tick coalescing* (non-optional); `?&mut T` is an *optional* mutable component.
3. **Numeric & Float Syntax:** Write `1.0` (never `1.`). Always put `_` before scalar type suffixes (`42_u32`, `10.0_f32`; `10f32` lexes as `10f` + `32`).
4. **No `::<>` Turbofish:** Write `remove<Tag>(e)` and `res<Clock>()`, never `remove::<Tag>(e)`.
5. **Semicolons on Contextual Commands:** `spawn { ... };`, `spawn_batch(n) |i| { ... };`, `insert(...);`, `remove<T>(...);`, and `despawn_all<With<T>>();` all end with `;`. `tag A, B;` forbids a trailing comma before `;`.
6. **`@require(...)` Placement:** Goes *after* the item name (`component Hero @require(Pos) { ... }`), not before `component`.
7. **Features in `grammar.js` NOT Accepted by `parser.rs`:** Do not write `pub`, `type` aliases, `unit` decls, `use a::*`, `[T]` unsized slices, `meters / sec` type expressions, `[val; N]` array repeat literals, `while let`, `Foo { x, .. }` struct patterns, `A | B` or-patterns, general `|x| expr` closures, unary `*` deref, `resource Foo;` marker form, or bare tuple enum variants `Foo(u32)` (sema requires unit enums).

**Compiler Diagnostic Reference:**

| Code | Meaning | How to Fix |
|---|---|---|
| `E0001` / `E0002` | Lexer invalid token / Parser syntax error | Check semicolons, `1.0` floats, `_` numeric suffixes, or `?T` -> `?&T`/`Option<T>`. |
| `E0101` | Unknown type name | Verify spelling or declare the `struct`/`enum`/`component` first. |
| `E0102` | SI unit dimension mismatch on `const` or field default | Match unit suffix to declared type (`_s`/`_ms` for `sec`, `_m` for `meters`). |
| `E0103` | Non-`AbiPod` / banned wire type (`String`, `Vec`, `usize`, `&T`, `Option`, `char`) or non-const `const`/`object` init | Use `InlineStr<N>`, `SmallVec<T, N>`, `u64`/`i64`, `u32`/`u8`, and constant initializers. |
| `E0104` | `InlineStr<N>` with `N % 4 != 0`, or padding gap under `@no_pad` | Make `N` divisible by 4, or reorder fields largest-alignment-first / remove `@no_pad`. |
| `E0105` | `assert_layout` failed | Adjust field order/types or update `assert_layout` expectation (`stratac layout`). |
| `E0106` | `table ... by Enum` omitted an enum variant | Add rows for every enum variant. |
| `E0107` | `curve` x-coordinates not strictly increasing | Sort control points with strictly greater x values left-to-right. |
| `E0108` | `timeline` `window` invalid (`start >= end` or `end > @duration`) | Fix window frame bounds or increase `@duration(...)`. |
| `E0109` | `fsm` `initial` or `to` references undeclared `state` | Declare the target `state` block inside the `fsm`. |
| `E0110` | Combined `@sparse` and `@summary_tick` | Remove one attribute (sparse storage has no dense chunk tick summaries). |
| `E0111` | Array/`SmallVec` length mismatch or ragged nested array | Match `[T; N]` element count or increase `SmallVec<T, N>` capacity. |
| `E0201` | Aliasing mutable/shared borrows (`query` or `&mut res`) | Project disjoint fields (`&mut Body.hp, &mut Body.stamina`), make queries `.with<T>()`/`.without<T>()` disjoint, or avoid double `res_mut`. |
| `E0202` | `assert_par` conflict or `@par(read_only)` mutates data | Disjoint archetypes via `With`/`Without` or `@soa`; remove `&mut`/`&mut?` under `@par(read_only)`. |
| `E0203` | Query cap exceeded (`> 32` terms+filters or `> 16` queries in one system) | Split into `@soa` strata, structs, or smaller systems. |
| `E0204` | `effects(...)` missing accessed item, or plain `fn` runs a `query` | Add missing entry to `effects(...)`; move `query(...)` calls into `sys`/`obs`/`task`. |
| `E0301` | Unresolved field, query term, or `assert_par` system | Check row alias (`for r in query(p: &Pos)` uses `r.p.x`, not `p.p.x`). |
| `E0302` | Non-`AbiPod` local or param live across `wait`/`race`/`yield_tick` | Store only `AbiPod` scalars/structs/handles across suspension points. |
| `E0303` | Duplicate declaration (e.g., duplicate `rpc`) | Rename or remove duplicate item. |
| `E0501` | Non-server callable (`client`/`predicted`/`shared`) mutates/borrows/spawns `@authority(server)` state or calls `server_res` | Move mutation to `@authority(server)` `sys`/`obs`, or copy scalars to local `let` values for read-only UI. |
| `E0502`..`E0505` | Invalid `@net`/`@net_rpc`, `@quantize`, `@authority`/`@predicted`, or `net_sim_test` param | Verify `rate` vs `interval`, `direction`, `min < max` & `bits in 1..=32`, don't mix `@predicted` + `@authority(server)`, keep `loss in 0.0..=1.0`. |
| `E0601` / `E0602` | `@node_pure` performs ECS/mutable work, or bad `@node_group` | Remove queries/mutations from `@node_pure fn`; pass non-empty string to `@node_group("...")`. |
| `E0900` | MIR structural verification failed | Check `atomic` loops or unsupported MIR control flow. |
| `W0401`..`W0404` | Performance lints (quadratic nested query, `&mut` inside `if`, `spawn` in loop, component `> 64 B`) | Use `spatial_grid`, `&mut?`, `spawn_batch`, and `@soa` respectively. |

---

## 8. Complete Formal EBNF Grammar

Exact grammar derived 1-to-1 from `crates/strata_syntax/src/{lexer.rs,parser.rs}`:
* `IdentOrCtx` = `Ident | ContextualKw | self | Self`
* `MemberIdent` = `IdentOrCtx | in | match`
* `ExprNoStruct` = `Expr` parsed with `allow_struct_lit = false` (prevents `if flag { ... }` from parsing `flag { ... }` as a struct literal).

```ebnf
SourceFile      ::= ItemDecl*

(* --- Attributes, SemVer, Paths & Generics --- *)
Attribute       ::= '@' IdentOrCtx AttrArgList?
AttrArgList     ::= '(' (AttrArg (',' AttrArg)* ','?)? ')'
AttrArg         ::= SemVer | Ident '=' Expr | Expr
SemVer          ::= FloatLit '.' IntLit | IntLit '.' IntLit '.' IntLit
RequireClause   ::= '@' 'require' '(' (RequireItem (',' RequireItem)* ','?)? ')'
RequireItem     ::= Path ('=' Expr)?
InlineMods      ::= (RequireClause | Attribute)*

Path            ::= IdentOrCtx ('::' IdentOrCtx)*        (* stops before ::{ *)
FieldPath       ::= IdentOrCtx (('::' | '.') IdentOrCtx)*
GenericParams   ::= '<' (GenericParam (',' GenericParam)* ','?)? '>'
GenericParam    ::= IdentOrCtx (':' Type)?
GenericArgs     ::= '<' ((Type | IntLit | UnitLit | FloatLit) ','?)* '>'
                    (* nested '>>' splits automatically into '>' + '>' *)

(* --- Top-Level Items --- *)
ItemDecl        ::= Attribute* (
                      ModuleDecl | ImportDecl | ConstDecl | StructDecl | EnumDecl
                    | ComponentDecl | TagDecl | ResourceDecl | EventDecl | StreamDecl
                    | RpcDecl | RelationDecl | TableDecl | CurveDecl
                    | SpatialGridDecl | SpatialHistoryDecl | HashIndexDecl | AspectDecl
                    | PrefabDecl | ObjectDecl | ZoneDecl | TimelineDecl | TaskDecl
                    | FsmDecl | SysDecl | ObsDecl | FnDecl | MigrateDecl | ScheduleDecl
                    | AssertLayoutDecl | AssertParDecl | SimTestDecl | NetSimTestDecl
                    )

ModuleDecl      ::= 'module' Path Attribute* ';'
ImportDecl      ::= 'use' Path ('::' ImportList | 'as' IdentOrCtx)? ';'
ImportList      ::= '{' (IdentOrCtx (',' IdentOrCtx)* ','?)? '}'
ConstDecl       ::= 'const' IdentOrCtx ':' Type '=' Expr ';'
StructDecl      ::= 'struct' IdentOrCtx GenericParams? Attribute* FieldDeclBraced
EnumDecl        ::= 'enum' IdentOrCtx Attribute* '{' (VariantDecl (',' VariantDecl)* ','?)? '}'
VariantDecl     ::= IdentOrCtx ( '(' (FieldDecl (',' FieldDecl)* ','?)? ')' | FieldDeclBraced | '=' Expr )?

ComponentDecl   ::= 'component' IdentOrCtx InlineMods (';' | '{' ComponentBodyItem* '}')
ComponentBodyItem ::= StratumBlock | FieldDecl (',' | ';')?
StratumBlock    ::= ('hot' | 'cold' IdentOrCtx) FieldDeclBraced

TagDecl         ::= 'tag' IdentOrCtx (',' IdentOrCtx)* ';'
ResourceDecl    ::= 'resource' IdentOrCtx InlineMods FieldDeclBraced
EventDecl       ::= 'event' IdentOrCtx InlineMods (';' | FieldDeclBraced)
StreamDecl      ::= 'stream' IdentOrCtx InlineMods (';' | FieldDeclBraced)
RpcDecl         ::= 'rpc' IdentOrCtx InlineMods (';' | FieldDeclBraced)
RelationDecl    ::= 'relation' IdentOrCtx RelFlags? InlineMods (';' | FieldDeclBraced ';'?)
RelFlags        ::= '[' (IdentOrCtx (',' IdentOrCtx)* ','?)? ']'

TableDecl       ::= 'table' IdentOrCtx 'by' Path FieldDeclBraced '=' '{' (TableRow (',' TableRow)* ','?)? '}' ';'
TableRow        ::= IdentOrCtx '=>' '{' FieldInitList '}'
CurveDecl       ::= 'curve' IdentOrCtx '(' Type '->' Type ')' '=' '[' (CurvePoint (',' CurvePoint)* ','?)? ']' ';'
CurvePoint      ::= '(' Expr ',' Expr ')'

SpatialGridDecl    ::= 'spatial_grid' IdentOrCtx '(' FieldInitList ')' 'over' Path 'by' FieldPath ('cache' '(' ProjTermList ')')? ';'
SpatialHistoryDecl ::= 'spatial_history' IdentOrCtx '(' FieldInitList ')' 'over' Path 'by' FieldPath ('cache' '(' ProjTermList ')')? ';'
HashIndexDecl      ::= 'hash_index' IdentOrCtx '(' FieldInitList ')' 'over'? Path 'by'? 'key'? '(' FieldPath ')' ('cache' '(' ProjTermList ')')? ';'

AspectDecl      ::= 'aspect' IdentOrCtx '(' ProjTermList ')' FilterChain* ('where' Expr)? ';'
FilterChain     ::= '.' IdentOrCtx GenericArgs? ArgList?
PrefabDecl      ::= 'prefab' IdentOrCtx InlineMods '{' CompInitList '}'
ObjectDecl      ::= 'object' IdentOrCtx InlineMods '{' CompInitList '}'
ZoneDecl        ::= 'zone' IdentOrCtx InlineMods FieldDeclBraced

TimelineDecl    ::= 'timeline' IdentOrCtx InlineMods '{' (TimelineWindow | TimelineAt)* '}'
TimelineWindow  ::= 'window' IdentOrCtx '=' Expr ';'
TimelineAt      ::= 'at' Expr '=>' StmtInBlock

TaskDecl        ::= 'task' IdentOrCtx ParamList ('on' '(' ProjTermList ')')? FilterChain* ('using' SysParamList)? Block
FsmDecl         ::= 'fsm' IdentOrCtx SysParamList? InlineMods '{' (FsmInitial | StateDecl)* '}'
FsmInitial      ::= 'initial' IdentOrCtx RecordLit? ';'
StateDecl       ::= 'state' IdentOrCtx '{' StateMember* '}'
StateMember     ::= ('on_enter' | 'on_tick' | 'on_exit') Block | TransitionDecl | FieldDecl (',' | ';')?
TransitionDecl  ::= 'to' IdentOrCtx RecordLit? 'when'? Expr Attribute* ';'

SysDecl         ::= 'sys' IdentOrCtx SysParamList EffectsClause? Block
ObsDecl         ::= 'obs' IdentOrCtx SysParamList EffectsClause? Block
EffectsClause   ::= 'effects' '(' (EffectEntry (',' EffectEntry)* ','?)? ')'
EffectEntry     ::= IdentOrCtx ':' '[' (Path (',' Path)* ','?)? ']'

FnDecl          ::= 'fn' IdentOrCtx GenericParams? ParamList ('->' Type)? Block
MigrateDecl     ::= 'migrate' Path 'from'? SemVer 'to'? SemVer '(' IdentOrCtx ':' Type ')' '->' Path Block

ScheduleDecl    ::= 'schedule' Path ScheduleMod* '{' ScheduleNode* '}'
ScheduleMod     ::= 'run_if' '(' Expr ')' | 'before' '(' Path ')' | 'after' '(' Path ')'
ScheduleNode    ::= ('seq' | 'seq_weak' | 'par' | 'set') IdentOrCtx ScheduleMod* '{' ScheduleNode* '}'
                  | Path ScheduleMod* (',' | ';')?

AssertLayoutDecl ::= 'assert_layout' '(' Path (',' Expr?)* ')' ';'
AssertParDecl   ::= 'assert_par' '(' (Path (',' Path)* ','?)? ')' ';'
SimTestDecl     ::= 'sim_test' StringLit Block
NetSimTestDecl  ::= 'net_sim_test' StringLit NetSimParamList? Block
NetSimParamList ::= '(' (NetSimParam (',' NetSimParam)* ','?)? ')'
NetSimParam     ::= IdentOrCtx ':' Expr

(* --- Fields, Params, Initializers & Projections --- *)
FieldDeclBraced ::= '{' (FieldDecl (',' | ';')?)* '}'
FieldDecl       ::= Attribute* IdentOrCtx ':' Type ('=' Expr)?
FieldInitList   ::= (FieldInit (',' FieldInit)* ','?)?
FieldInit       ::= IdentOrCtx (':' Expr)?
CompInitList    ::= (CompInit (',' CompInit)* ','?)?
CompInit        ::= Path ('{' FieldInitList '}')?
ParamList       ::= '(' (Param (',' Param)* ','?)? ')'
Param           ::= IdentOrCtx ':' Type ('=' Expr)?
SysParamList    ::= '(' (SysParam (',' SysParam)* ','?)? ')'
SysParam        ::= IdentOrCtx ':' Type
ProjTermList    ::= (ProjTerm (',' ProjTerm)* ','?)?
ProjTerm        ::= (Ident ':')? Type

(* --- Types --- *)
Type            ::= PtrTermType | RefType | ArrayType | TupleType | TypeRef
PtrTermType     ::= '?' '&' 'mut'? Type
RefType         ::= '&' 'mut'? '?'? 'res'? Type
ArrayType       ::= '[' Type ';' Expr ']'
TupleType       ::= '(' (Type (',' Type)* ','?)? ')'
TypeRef         ::= ('stream_in' | Path) ('.' IdentOrCtx)* GenericArgs?
                    (* 'stream_in' recognized only at top-level Type *)

(* --- Patterns --- *)
Pattern         ::= TuplePattern | '_' | LiteralPat | TupleStructPat | PathPat
LiteralPat      ::= '-'? (IntLit | FloatLit | UnitLit) | StringLit | CharLit | 'true' | 'false'
TuplePattern    ::= '(' (Pattern (',' Pattern)* ','?)? ')'
TupleStructPat  ::= 'mut'? Path '(' (Pattern (',' Pattern)* ','?)? ')'
PathPat         ::= 'mut'? Path

(* --- Blocks & Statements --- *)
Block           ::= '{' StmtInBlock* '}'
StmtInBlock     ::= UniformLetStmt | LetStmt | ReturnStmt | BreakStmt | ContinueStmt
                  | AbortIfStmt | RaceStmt | WaitStmt | WaitUntilStmt | YieldTickStmt
                  | AtomicStmt | WhileStmt | LoopStmt | ExprOrTailStmt
UniformLetStmt  ::= 'uniform' 'let' Pattern (':' Type)? '=' Expr ';'
LetStmt         ::= 'let' Pattern (':' Type)? '=' Expr ('else' Block)? ';'
ReturnStmt      ::= 'return' Expr? ';'
BreakStmt       ::= 'break' Expr? ';'
ContinueStmt    ::= 'continue' ';'
AbortIfStmt     ::= 'abort_if' ExprNoStruct Block
RaceStmt        ::= 'race' '{' ('branch' Block)* '}'     (* when nth(1) == '{' *)
WaitStmt        ::= 'wait' Expr ';'                      (* when nth(1) not in {'(', '.', ':'} *)
WaitUntilStmt   ::= 'wait_until' Expr ';'                (* when nth(1) not in {'(', '.', ':'} *)
YieldTickStmt   ::= 'yield_tick' ';'                     (* when nth(1) == ';' *)
AtomicStmt      ::= 'atomic' Block ('on_rollback' Block)? (* when nth(1) == '{' *)
WhileStmt       ::= 'while' ExprNoStruct Block
LoopStmt        ::= 'loop' Block
ExprOrTailStmt  ::= Expr (';' | (* if starts with if/for/match/{ and not tail before '}' *))

(* --- Expressions (Pratt Precedence in Section 3.1) --- *)
PrimaryOrAtom   ::= ('-' | '!' | '~' | '&') 'mut'? Expr(bp=25)
                  | IntLit | FloatLit | UnitLit | StringLit | CharLit | 'true' | 'false'
                  | '(' ')' | '(' Expr ')' | '(' Expr ',' (Expr (',' Expr)* ','?)? ')'
                  | '[' (Expr (',' Expr)* ','?)? ']'
                  | IfExpr | MatchExpr | ForExpr
                  | RecordLit                            (* '{' Ident ':' ... *)
                  | BundleLit                            (* '{' Path ('{' | ',') ... *)
                  | Block
                  | 'spawn' Attribute* '{' CompInitList '}'          (* nth(1) in {'{', '@'} *)
                  | 'spawn_batch' ArgList '|' Pattern '|' Block      (* nth(1) == '(' *)
                  | 'despawn_all' GenericArgs ArgList                (* nth(1) == '<' *)
                  | 'insert' ('@' IdentOrCtx)* ArgList               (* nth(1) in {'@', '('} *)
                  | 'remove' GenericArgs ArgList                     (* nth(1) == '<' *)
                  | Path
RecordLit       ::= '{' FieldInitList '}'
BundleLit       ::= '{' CompInitList '}'
IfExpr          ::= 'if' ('let' Pattern '=' ExprNoStruct | ExprNoStruct) Block ('else' (IfExpr | Block))?
MatchExpr       ::= 'match' ExprNoStruct '{' (Pattern ('if' ExprNoStruct)? '=>' Expr ','?)* '}'
ForExpr         ::= 'for' Pattern 'in' ExprNoStruct (ReduceClause | Block)
ReduceClause    ::= 'reduce' '(' (ReduceEntry (',' ReduceEntry)* ','?)? ')'
ReduceEntry     ::= IdentOrCtx ':' Expr
ArgList         ::= '(' (Arg (',' Arg)* ','?)? ')'
Arg             ::= Ident ':' Expr | Expr

PostfixOp       ::= '.' MemberIdent (GenericArgs ArgList | ArgList)?   (* GenericArgs requires '(' *)
                  | '(' ProjTermList ')'                               (* ONLY when callee is "query" | "query_one" *)
                  | ArgList
                  | GenericArgs ArgList                                (* requires '(' *)
                  | '[' Expr ']'
                  | '{' FieldInitList '}'                              (* only if allow_struct_lit *)
                  | '?'
```

---

## 9. Progressive Example Blueprints & Cookbook Index

All three blueprints below compile with `stratac check` and pass `stratac test`.

### Blueprint 1 (Novice): Arena Wave Spawner

Demonstrates `const` with SI units, `resource`, `component` + `@require`, `tag`, `spawn_batch`, `&mut? T` tick coalescing, `despawn_all`, `FixedUpdate` `seq`/`set` schedules, and `sim_test`.

```strata
module blueprints::arena_wave @version(1.0.0);

const ARENA_SPEED: mps = 10.0_mps;

resource SimClock { dt: sec = 16.6667_ms }
resource WaveCtrl { spawn_requested: bool = true, clear_requested: bool = false, alive: u32 = 0 }

component Pos2D { xy: vec2 = vec2::ZERO }
component Projectile @require(Pos2D) { ttl: sec = 1.0_s }
tag WaveMob;

sys manage_wave(ctrl: &mut res WaveCtrl) effects(writes: [WaveCtrl], spawns: [Projectile, WaveMob], despawns: [WaveMob]) {
    if ctrl.clear_requested {
        ctrl.clear_requested = false;
        despawn_all<With<WaveMob>>();
        ctrl.alive = 0_u32;
        return;
    }
    if ctrl.spawn_requested {
        ctrl.spawn_requested = false;
        spawn_batch(25) |i| {
            let x = (i as f32) * 1.5;
            {
                Projectile { ttl: 0.5_s },
                Pos2D { xy: vec2(x, 0.0) },
                WaveMob,
            }
        };
    }
}

@par(chunk = 256)
sys advance_projectiles(clk: &res SimClock) effects(writes: [Pos2D, Projectile], despawns: [Projectile]) {
    uniform let dt = clk.dt;
    uniform let step_x = ARENA_SPEED.raw() * dt.as_secs();
    for p in query(pos: &mut? Pos2D.xy, proj: &mut? Projectile) {
        p.pos.x += step_x;
        p.proj.ttl -= dt;
        if p.proj.ttl <= 0.0_s {
            despawn(p.id);
        }
    }
}

@par(read_only, chunk = 256)
sys tally_alive(ctrl: &mut res WaveCtrl) {
    let total = for _m in query(t: &WaveMob)
    reduce (cnt: sum(0_u32, 1_u32));
    ctrl.alive = total;
}

schedule FixedUpdate {
    seq ArenaTick {
        set Spawning { manage_wave }
        set Motion { advance_projectiles }
        set Tally { tally_alive }
    }
}

sim_test "wave_spawns_moves_and_clears" {
    step_fixed(1);
    assert_eq(res<WaveCtrl>().alive, 25_u32);
    step_fixed(10);
    let min_x = query(p: &Pos2D.xy).count();
    assert_eq(min_x, 25_u32);
    res_mut<WaveCtrl>().clear_requested = true;
    step_fixed(1);
    assert_eq(res<WaveCtrl>().alive, 0_u32);
}
```

### Blueprint 2 (Intermediate): Boss Encounter (`@soa`, `table`, `curve`, `timeline`, `fsm`, `task`, `spatial_grid`, `atomic`, `assert_par`)

Demonstrates cache-friendly `@soa` + `assert_layout`, `table`/`curve`, `@sparse timeline`, `fsm`, stackless `task`, `spatial_grid`, `atomic`/`on_rollback`, `assert_par` disjointness, `obs`, and `sim_test`.

```strata
module blueprints::boss_encounter @version(1.0.0);

enum Stance { Calm = 0, Enraged = 1 }

table StanceStats by Stance { dmg: f32, speed: f32 } = {
    Calm    => { dmg: 15.0, speed: 4.0 },
    Enraged => { dmg: 35.0, speed: 8.0 },
};

curve RageScale(f32 -> f32) = [
    (0.0,   1.0),
    (50.0,  1.5),
    (100.0, 2.0),
];

resource SimClock { dt: sec = 16.6667_ms }
resource ArenaCtrl { engage: bool = false, try_spend: bool = false, hits: u32 = 0, rollbacks: u32 = 0 }

component Pos2D { xy: vec2 = vec2::ZERO }
component Raider @require(Pos2D) { hp: f32 = 120.0 }
tag HeroUnit, MinionUnit;

@soa @summary_tick
component BossStats @require(Pos2D) {
    hot { hp: f32 = 500.0, rage: f32 = 0.0, stance: Stance = Stance::Calm }
    cold tuning { armor: f32 = 8.0, mana: u32 = 100 }
}

assert_layout(BossStats::hot, size == 12, align == 4);

event SlamWave { origin: vec2, radius: meters, base_dmg: f32 }
event SpendMana { cost: u32 }

spatial_grid RaiderGrid(
    cell_size: 4.0_m,
    bounds:    vec2(-64.0_m, -64.0_m)..vec2(64.0_m, 64.0_m),
    capacity:  128,
) over Raider by Pos2D.xy;

@sparse
timeline SlamTimeline @rate(60_hz) @duration(10_f) {
    window windup = 0_f..4_f;
    window active = 4_f..8_f;
    at 4_f => trigger(self, SlamWave { origin: vec2(0.0, 0.0), radius: 6.0_m, base_dmg: 25.0 });
}

fsm BossFsm(ctrl: &res ArenaCtrl) @require(BossStats) {
    initial Calm;
    state Calm {
        to Enraged when ctrl.engage;
    }
    state Enraged {
        on_tick {
            let _dt = ctrl.engage;
        }
        to Calm when !ctrl.engage;
    }
}

@sparse
task DashLunge(step_x: f32) on (pos: &mut Pos2D.xy, hp: &BossStats.hp) using (clk: &res SimClock) {
    abort_if hp <= 0.0 { }
    race {
        branch {
            loop {
                pos.x += step_x * clk.dt.as_secs();
                yield_tick;
            }
        }
        branch {
            wait 80.0_ms;
        }
    }
}

object Boss {
    Pos2D { xy: vec2(0.0, 0.0) },
    BossStats { hp: 500.0, rage: 25.0, stance: Stance::Calm },
    BossStats::tuning { armor: 8.0, mana: 100 },
}
object Hero {
    Pos2D { xy: vec2(2.0, 0.0) },
    Raider { hp: 120.0 },
    HeroUnit,
}

sys drive_boss(ctrl: &mut res ArenaCtrl) {
    if ctrl.try_spend {
        ctrl.try_spend = false;
        trigger(SpendMana { cost: 500_u32 });
    }
    if !ctrl.engage { return; }
    if let Some(b) = query_one(st: &mut BossStats).on(Boss) {
        b.st.rage = min(100.0, b.st.rage + 25.0);
        if b.st.rage >= 50.0 { b.st.stance = Stance::Enraged; }
        insert @if_new(b.id, BossFsm::start());
        insert @if_new(b.id, SlamTimeline::start());
        insert @if_new(b.id, DashLunge::start(StanceStats[b.st.stance].speed));
    }
}

// Theorem 0.1 disjoint pair verified statically via assert_par
sys heal_heroes() {
    for h in query(r: &mut Raider).with<HeroUnit>().without<MinionUnit>() {
        h.r.hp = min(120.0, h.r.hp + 1.0);
    }
}
sys drain_minions() {
    for m in query(r: &mut Raider).with<MinionUnit>().without<HeroUnit>() {
        m.r.hp = max(0.0, m.r.hp - 1.0);
    }
}
assert_par(heal_heroes, drain_minions);

obs on_slam_wave(trg: &Trigger<SlamWave>, grid: &res RaiderGrid, ctrl: &mut res ArenaCtrl) {
    let ev = trg.payload;
    let mult = if let Some(b) = query_one(rage: &BossStats.rage).on(Boss) {
        RageScale.sample(b.rage)
    } else {
        1.0
    };
    for cand in grid.query_disc(ev.origin, ev.radius) {
        if let Some(r) = query_one(raider: &mut Raider).on(cand.id) {
            r.raider.hp -= ev.base_dmg * mult;
            ctrl.hits += 1_u32;
        }
    }
}

obs on_spend_mana(trg: &Trigger<SpendMana>, ctrl: &mut res ArenaCtrl) {
    let cost = trg.payload.cost;
    atomic {
        let Some(b) = query_one(t: &mut BossStats::tuning).on(Boss) else { require_true(false); };
        require_true(b.t.mana >= cost);
        b.t.mana -= cost;
    } on_rollback {
        ctrl.rollbacks += 1_u32;
    }
}

schedule FixedUpdate {
    seq BossFrame {
        par DisjointUnits { heal_heroes, drain_minions }
        set BossAI { drive_boss, BossFsm, SlamTimeline, DashLunge }
    }
}

sim_test "boss_timeline_atomic_and_spatial_hit" {
    res_mut<ArenaCtrl>().engage = true;
    step_fixed(6);
    assert(res<ArenaCtrl>().hits >= 1_u32);
    let hero_hp = query_one(r: &Raider).on(Hero).unwrap().r.hp;
    assert(hero_hp < 120.0);
    let boss_x = query_one(p: &Pos2D.xy).on(Boss).unwrap().p.x;
    assert(boss_x > 0.0);
    res_mut<ArenaCtrl>().try_spend = true;
    step_fixed(1);
    assert_eq(res<ArenaCtrl>().rollbacks, 1_u32);
    let mana = query_one(t: &BossStats::tuning).on(Boss).unwrap().t.mana;
    assert_eq(mana, 100_u32);
}
```

### Blueprint 3 (Intermediate Multiplayer): Authoritative Co-op Dash (`@deterministic`, `@authority`, `@predicted`, `@net`, `@net_rpc`, `@quantize`, `stream`, `net_sim_test`)

Demonstrates deterministic multiplayer networking: server authority (`@authority(server)`), bit-packed `@quantize` replication (`@net`), client prediction (`@predicted`), RPC dispatch to `obs`, `stream`/`stream_in`, and virtual packet-loss testing (`net_sim_test`).

```strata
module blueprints::coop_dash @version(1.0.0) @deterministic;

@authority(server)
@net(reliable, rate = 30Hz, channel = 0)
component AuthPlayer {
    @quantize(min = -256.0, max = 256.0, bits = 16)
    pos: vec2 = vec2(0.0, 0.0),
    seq: u32 = 0,
}

@predicted
component PredPlayer {
    pred_pos: vec2 = vec2(0.0, 0.0),
    last_seq: u32 = 0,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc DashCmd {
    @quantize(min = -10.0, max = 10.0, bits = 12)
    dx: f32,
    seq: u32,
}

stream DashAudit { seq: u32 }
@authority(server)
resource ServerAudit { accepted_rpcs: u32 = 0, last_seq: u32 = 0 }

object Runner {
    AuthPlayer { pos: vec2(0.0, 0.0), seq: 0 },
    PredPlayer { pred_pos: vec2(0.0, 0.0), last_seq: 0 },
}

obs on_dash_rpc(trg: &Trigger<DashCmd>, audit: &mut res ServerAudit) {
    let cmd = trg.payload;
    audit.accepted_rpcs += 1_u32;
    audit.last_seq = cmd.seq;
    if let Some(p) = query_one(auth: &mut? AuthPlayer).on(Runner) {
        p.auth.pos.x += cmd.dx;
        p.auth.seq = cmd.seq;
    }
    emit(DashAudit { seq: cmd.seq });
}

@authority(server)
sys read_dash_audit(msg: stream_in<DashAudit>, audit: &mut res ServerAudit) {
    if msg.seq > audit.last_seq {
        audit.last_seq = msg.seq;
    }
}

@predicted
sys predict_dash() {
    for p in query(pred: &mut? PredPlayer) {
        if p.pred.last_seq == 0_u32 {
            p.pred.last_seq = 1_u32;
            p.pred.pred_pos.x += 4.0;
        }
    }
}

@authority(client)
sys reconcile_dash() {
    for p in query(auth: &AuthPlayer, pred: &mut? PredPlayer) {
        if p.auth.seq > 0_u32 {
            p.pred.pred_pos = p.auth.pos;
            p.pred.last_seq = p.auth.seq;
        }
    }
}

schedule FixedUpdate {
    seq NetStep {
        read_dash_audit
        predict_dash
        reconcile_dash
    }
}

net_sim_test "dash_rpc_converges_under_loss"(latency: 25ms, jitter: 5ms, loss: 0.15, seed: 7, clients: 2) {
    send_rpc(0, DashCmd { dx: 4.0, seq: 1_u32 });
    step_net(35);
    assert_eq(server_res<ServerAudit>().accepted_rpcs, 1_u32);
    assert_converged(0, 0.05);
    assert_converged(1, 0.05);
    let cli = client_query(0, a: &AuthPlayer).on(Runner).unwrap().a;
    assert_eq(cli.seq, 1_u32);
    assert(abs(cli.pos.x - 4.0) < 0.05);
}
```

### Index of Repository Cookbooks (`fixtures/cookbooks/`)

| Cookbook | Key Features Demonstrated | Quick Verification Command |
|---|---|---|
| [`01_rain_swarm.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/01_rain_swarm.strata) | SI units, `@require`, `spawn_batch`, `@par(chunk)`, `uniform let`, `Startup`/`FixedUpdate` | `cargo run -p stratac -- check fixtures/cookbooks/01_rain_swarm.strata` |
| [`02_soa_and_ticks.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/02_soa_and_ticks.strata) | `@soa`, `@summary_tick`, `assert_layout`, `stream`/`emit`, `&mut? T`, `@par(read_only)` `reduce` | `cargo run -p stratac -- layout fixtures/cookbooks/02_soa_and_ticks.strata` |
| [`03_metroidvania_core.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/03_metroidvania_core.strata) | `GraceWindow`, `InputBuffer`, `task` (`race`/`abort_if`), `timeline`, `@persist`, `despawn_all`, `sim_test` | `cargo run -p stratac -- test fixtures/cookbooks/03_metroidvania_core.strata` |
| [`04_cozy_valley.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/04_cozy_valley.strata) | `table`, `curve`, `relation [symmetric]`, `atomic`/`on_rollback`, `@persist`, `fsm` | `cargo run -p stratac -- check fixtures/cookbooks/04_cozy_valley.strata` |
| [`05_soulslike_combat.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/05_soulslike_combat.strata) | `@soa` `CombatantBody`, multiple `timeline`s, `?&T`, `obs` cascades, bonfire `despawn_all` | `cargo run -p stratac -- explain-par fixtures/cookbooks/05_soulslike_combat.strata` |
| [`06_battle_royale_server.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/06_battle_royale_server.strata) | `@deterministic`, `@rollback`, `spatial_history`, `curve`, `&mut?`, `par reduce`, `task` (`wait_until`) | `cargo run -p stratac -- check fixtures/cookbooks/06_battle_royale_server.strata` |
| [`07_visual_boss_graph.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/07_visual_boss_graph.strata) | All 8 Graph IR node kinds, `@node_pure`, `@node_group`, `fsm` hooks, `sim_test` | `cargo run -p stratac -- test fixtures/cookbooks/07_visual_boss_graph.strata` |
| [`08_authoritative_multiplayer.strata`](file:///Users/simha/Desktop/bamabi/strata/fixtures/cookbooks/08_authoritative_multiplayer.strata) | `@authority`, `@predicted`, `@net`, `@quantize`, `@net_rpc`, `&mut?`, `sim_test`, `net_sim_test` | `cargo run -p stratac -- test fixtures/cookbooks/08_authoritative_multiplayer.strata` |
