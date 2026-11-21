# `stratac`

Unified Strata v2.0 compiler driver, headless simulation test runner (`sim_test`), watch-mode hot-reloader, Ed25519 `.bampack` packager, and static Bevy native onboarding CLI.

- **Subcommands:** `check`, `fmt`, `layout`, `explain-par`, `test`, `build`, `watch`, `onboard`
- **Policy:** `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`
- **Features:** `eval-host` *(default)* enables headless `bamabi_host` execution (`test` subcommand, parity harness).
