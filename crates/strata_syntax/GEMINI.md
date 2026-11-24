# Agent Guide: `strata_syntax`

Crate guide for **`strata_syntax`** (`v0.3.0`) — zero-Bevy, lossless CST frontend, canonical formatter, and Graph IR engine for Strata v2.0.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_syntax` (`edition = "2024"`, MSRV `1.95`)
- **Bevy Isolation:** **ZERO `bevy*` dependencies**.
- **Allowed Dependencies:** `logos`, `rowan`, `serde`, `serde_json`, `thiserror`. NEVER add `bamabi*` or `bevy*` dependencies.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`SyntaxKind` & `StrataLanguage` (`syntax_kind.rs`):** Full lossless token and CST node taxonomy for Strata v2.0.
- **`Lexer` (`lexer.rs`):** `logos` DFA tokenizer; preserves range `..` tokens adjacent to numbers (`0_f..18_f`, `0..10`) and never panics on invalid input.
- **`Parser` & `Parse` (`parser.rs`):** Error-recovering LL(2)/Pratt parser producing a lossless `rowan::SyntaxNode` (`syntax().text() == src` invariant) and structured `ParseError`s.
- **Typed AST (`ast.rs`):** Safe `rowan::ast::AstNode` wrappers over the CST consumed by `strata_sema`.
- **Canonical Formatter (`fmt.rs`):** Idempotent `stratafmt` formatter preserving trivia/comments.
- **Graph IR & Sidecars (`graph_ir.rs`):** Lossless CST <-> Graph IR JSON serialization (`export_graph_ir`, `apply_graph_patch`, `apply_graph_document`) and hash-isolated `.strata.graph.json` layout sidecars (`load_sidecar`, `merge_sidecar`, `save_sidecar`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_syntax --all-targets --all-features -- -D warnings
cargo test -p strata_syntax --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_syntax --no-deps --all-features
cargo tree -p strata_syntax | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
```
