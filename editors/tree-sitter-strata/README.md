# `tree-sitter-strata`

Production Tree-sitter grammar for **Strata v2.0** (`bamabi-strata` `v0.3.0`), used by the Zed editor extension (`editors/zed/`) and CLI syntax tooling.

## Layout

- `grammar.js` — Full Strata v2.0 grammar definition (comments, SI unit literals, ECS declarations, `@soa` strata, `fsm`/`timeline`/`task`, queries `&mut?` / `?&`, dimensional unit algebra, expressions, and statements).
- `src/parser.c`, `src/node-types.json`, `src/grammar.json`, `src/tree_sitter/` — Generated C11 parser (Tree-sitter ABI 14, zero external scanner dependencies, WASM-ready).
- `queries/highlights.scm` — Reference syntax highlighting query (top-to-bottom match precedence).
- `test/corpus/` — Tree-sitter S-expression corpus test suites.
- `bindings/rust/` & `Cargo.toml` — Standalone Rust binding crate (isolated via `[workspace]`).

## Commands

```bash
# Regenerate C parser (ABI 14 for broad Zed & Tree-sitter compatibility)
npx tree-sitter-cli generate --abi 14

# Run corpus test suite
npx tree-sitter-cli test

# Parse all Strata cookbooks and fixtures
npx tree-sitter-cli parse ../../fixtures/cookbooks/*.strata

# Build WebAssembly grammar module
npx tree-sitter-cli build --wasm
```
