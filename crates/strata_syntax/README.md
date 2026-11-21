# `strata_syntax`

Lossless green/red Concrete Syntax Tree (`rowan`), `logos` DFA lexer, error-recovering LL(2)/Pratt parser, and idempotent canonical formatter (`stratafmt`) for Strata v2.0.

- **Policy:** `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`
- **Isolation:** **ZERO** `bevy*` or `bamabi*` dependencies

## Usage

```rust
use strata_syntax::{format_source, parse};

let parsed = parse("module demo::sim @version(1.0.0);\ncomponent Pos { x: f32 = 0.0 }\n");
assert!(parsed.ok());
let canonical = format_source(&parsed.syntax().text().to_string()).unwrap();
```
