# Tests: `xtask`

```bash
cargo test -p xtask
```

## Suites
1. **Unit Tests (`xtask/src/main.rs` — 4 tests):**
   - `cli_parses_ci_and_test_flags_and_rejects_conflicts` — Verifies CLI parsing and rejects conflicting `--write-docs`/`--no-write-docs` and `--check-docs`/`--write-docs` combinations.
   - `benchmark_marker_validation_and_splicing` — Validates `BENCHMARKS.md` marker ordering, required headers, empty-report rejection, and deterministic splicing.
   - `bevy_tree_checker_distinguishes_bamabi_from_bevy` — Ensures `bamabi_*` workspace packages do not false-positive while genuine `bevy_*` transitive dependencies are rejected cleanly.
   - `wire_lock_parity_supports_git_rev_and_overlay_path_mode` — Verifies dynamic `abi-lock.toml` / `Cargo.lock` checking for both locked `bamabi-wire.git` revisions and active sibling path overlays.
