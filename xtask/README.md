# `xtask`

Zero-external-dependency workspace automation runner (`cargo xtask`) enforcing code quality, isolation policies, multi-tier test suites, Kani proofs, security audits, and benchmark documentation updates for `bamabi-strata`.

- **Policy:** `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, zero `[dependencies]`
- **Isolation:** **ZERO** `bevy*` dependencies

```bash
cargo xtask --help
cargo xtask ci
cargo xtask ci --full
```
