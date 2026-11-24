# Strata for Zed (`editors/zed`)

First-class [Zed](https://zed.dev) editor support for **Strata v2.0** (`*.strata`), the zero-`unsafe` ECS gameplay compiler language in `bamabi-strata`.

## Features

- **Rich Tree-sitter Syntax Highlighting (`highlights.scm`):**
  - ECS & simulation item declarations (`module`, `use`, `component`, `tag`, `resource`, `event`, `stream`, `rpc`, `relation`, `table`, `curve`, `spatial_grid`, `spatial_history`, `hash_index`, `aspect`, `prefab`, `object`, `zone`, `timeline`, `task`, `fsm`, `sys`, `obs`, `fn`, `migrate`, `schedule`, `assert_layout`, `assert_par`, `sim_test`, `net_sim_test`).
  - Strata attributes (`@soa`, `@summary_tick`, `@par`, `@persist`, `@rollback`, `@deterministic`, `@authority`, `@predicted`, `@net`, `@quantize`, `@net_rpc`, `@require`, `@sparse`, `@node_group`, `@node_pure`, `@version`, `@rate`, `@duration`, `@if_new`, `@persistent`).
  - Borrow & query projection modifiers (`&T`, `&mut T`, `&mut? T` selective tick-coalesced borrow, `?&T` / `?&mut T` optional query terms, `&res` / `&mut res`).
  - Built-in scalar, SIMD math, fixed-capacity ABI POD, and SI physical unit types (`u8`..`u64`, `i8`..`i64`, `f32`, `f64`, `fix32`, `fix64`, `bool`, `sym`, `vec2`, `vec3`, `vec3a`, `vec4`, `ivec2`, `ivec3`, `uvec2`, `quat`, `mat3`, `mat4`, `rgba8`, `rgba`, `InlineStr`, `SmallVec`, `BitSet`, `InputBuffer`, `GraceWindow`, `Ref`, `Asset`, `Trigger`, `Option`, `Result`, `sec`, `ms`, `hz`, `frames`, `rad`, `deg`, `meters`, `mps`, `mps2`) and SI unit literals (`16.6667_ms`, `-9.81_mps2`, `60Hz`, `24_f`).
  - UpperCamelCase user types, `SCREAMING_SNAKE_CASE` constants, enum variants, function/method definitions & calls, field accesses, string escapes, nested block comments (`/* ... */`), and doc comments (`///`, `//!`).
- **Code Outline & Breadcrumbs (`outline.scm`):** Jump across modules, components (and `@soa` `hot`/`cold` strata), resources, events, streams, RPCs, relations, tables, curves, spatial indexes, objects, timelines, tasks, FSMs (and `state` blocks), systems, observers, functions, schedules, constants, and `sim_test` / `net_sim_test` suites via `Cmd+Shift+O` / `Ctrl+Shift+O`.
- **Smart Brackets, Auto-Indentation & Scope Overrides (`brackets.scm`, `indents.scm`, `overrides.scm`, `config.toml`):** Balanced `{}`, `[]`, `()`, `""`, and generic `<...>` matching (without misfiring on `<` / `>` comparison operators), block/arm/list auto-indentation, and disabled quote/bracket auto-closing inside comments and string literals.
- **Inline Runnable Gutter Buttons & Tasks (`runnables.scm`, `tasks.json`):** One-click play buttons in the editor gutter on `sim_test`, `net_sim_test`, and `module` declarations invoking `stratac test` and `stratac check`, plus command-palette task templates for `stratac layout` and `stratac explain-par`.
- **`strata-lsp` Language Server Integration (`src/lib.rs`):** Automatic stdio discovery of `strata-lsp` (via user `settings.json`, `$PATH`, or workspace `target/{release,debug}/strata-lsp`) with syntax-highlighted completion & symbol picker labels (`label_for_completion`, `label_for_symbol`), providing:
  - Incremental `salsa` diagnostics on open, change, and save.
  - Rich Markdown hover popovers (`#[repr(C)]` layout size/align/offset tables, `ComponentUuid`, `SCHEMA_FINGERPRINT`, Theorem 0.1 conflicts, live `"BAMT"` telemetry, `fn` signatures, `enum` variants, `rpc` / `fsm` / `timeline` summaries).
  - Context-aware autocompletion (`@attributes`, `.field` projections on query aliases, `::` enum variants & `@soa` strata, declared symbols, built-in types, and keywords).
  - Go-to-definition (`Cmd+Click` / `gd`), workspace symbol search (`Cmd+T`), hierarchical document symbols (`Cmd+Shift+O`), find references (`Shift+F12`), and comment-aware document highlights.
  - Inline inlay hints for solved `AbiPod` layouts and `@par` concurrency status, canonical `stratafmt` formatting, and live 64-byte `"BAMT"` telemetry CodeLens annotations.

---

## Prerequisites: Building `strata-lsp` & `stratac`

From the `bamabi-strata` repository root:

```bash
# Install both CLI and LSP binaries onto ~/.cargo/bin (recommended):
cargo install --path crates/stratac
cargo install --path crates/strata_lsp

# Or build in-place inside the workspace (auto-detected when opening this repo in Zed):
cargo build --release -p stratac -p strata_lsp
```

Ensure Zed has `wasm32-wasip2` (or `wasm32-wasip1`) installed in `rustup` when compiling dev extensions:

```bash
rustup target add wasm32-wasip2
```

---

## Installing via `zed: install dev extension`

1. Open Zed and invoke **`zed: install dev extension`** from the Command Palette (`Cmd+Shift+P` on macOS / `Ctrl+Shift+P` on Linux & Windows).
2. Select the `editors/zed` directory inside this repository (`/path/to/strata/editors/zed`).
3. Zed compiles `editors/zed` to WebAssembly, fetches and compiles `[grammars.strata]` to WASM, and activates Strata language support for all `*.strata` files.

### Developing Uncommitted Grammar Changes Locally

By default, `editors/zed/extension.toml` points `[grammars.strata]` at the canonical GitHub repository (`repository = "https://github.com/yaga-simha/bamabi-strata"`, `rev = "main"`, `path = "editors/tree-sitter-strata"`).

Zed fetches Tree-sitter grammars via `git` at a specific `rev`. When iterating locally on `editors/tree-sitter-strata` before pushing to `main`:

1. **Option A — Local monorepo commit:** Commit your `editors/tree-sitter-strata` changes locally (or on a scratch branch) and temporarily update `editors/zed/extension.toml`:
   ```toml
   [grammars.strata]
   repository = "file:///ABSOLUTE/PATH/TO/strata"
   rev = "HEAD"
   path = "editors/tree-sitter-strata"
   ```
2. **Option B — Temporary standalone grammar repo (zero commits in parent repo):** Initialize a temporary git commit inside `editors/tree-sitter-strata` (or a scratch copy) and omit `path`:
   ```toml
   [grammars.strata]
   repository = "file:///ABSOLUTE/PATH/TO/tree-sitter-strata"
   rev = "HEAD"
   ```
3. Run **`zed: rebuild extension`** (or re-run **`zed: install dev extension`**) in Zed to recompile `strata.wasm`. Remember to restore the canonical GitHub `[grammars.strata]` block in `extension.toml` before committing.

---

## Customizing `strata-lsp` in Zed `settings.json`

`strata-lsp` is auto-discovered from `$PATH` or `<workspace>/target/{release,debug}/strata-lsp`. You can optionally override the binary path, enable format-on-save / inlay hints, or point `strata-lsp` at a live `"BAMT"` telemetry socket (`tcp://...` or `unix://...`) in Zed's `settings.json`:

```json
{
  "lsp": {
    "strata-lsp": {
      "binary": {
        "path": "/custom/path/to/strata-lsp",
        "arguments": []
      },
      "settings": {
        "telemetryEndpoint": "tcp://127.0.0.1:15703"
      }
    }
  },
  "languages": {
    "Strata": {
      "format_on_save": "on",
      "inlay_hints": {
        "enabled": true
      }
    }
  }
}
```

---

## Developer Verification

`editors/zed/Cargo.toml` defines an isolated `[workspace]` so building or checking the Zed extension never touches the root `bamabi-strata` Cargo workspace or `Cargo.lock`:

```bash
# Lint & typecheck the extension crate:
cargo clippy --manifest-path editors/zed/Cargo.toml -- -D warnings
cargo check --manifest-path editors/zed/Cargo.toml --target wasm32-wasip2

# Validate all Zed Tree-sitter queries (.scm) against the grammar and cookbook corpus:
(cd editors/tree-sitter-strata && for scm in ../zed/languages/strata/*.scm; do
  npx --yes tree-sitter-cli query "$scm" ../../fixtures/cookbooks/*.strata >/dev/null
done)
```
