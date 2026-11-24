use std::fs;
use std::path::Path;
use std::process::Command;

fn is_valid_git_rev(s: &str) -> bool {
    !s.is_empty() && s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn try_resolve_wire_rev(ws_root: &Path) -> Option<String> {
    let abi_lock = ws_root.join("abi-lock.toml");
    if abi_lock.is_file() {
        let content = fs::read_to_string(&abi_lock)
            .unwrap_or_else(|e| panic!("failed reading `{}`: {e}", abi_lock.display()));
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if let Some((key, val)) = line.split_once('=')
                && key.trim() == "wire_rev"
            {
                let rev = val.trim().trim_matches('"').trim_matches('\'').trim();
                if is_valid_git_rev(rev) {
                    return Some(rev.to_owned());
                }
                panic!("invalid `wire_rev` in `{}`: `{rev}`", abi_lock.display());
            }
        }
    }

    let cargo_lock = ws_root.join("Cargo.lock");
    if cargo_lock.is_file() {
        let content = fs::read_to_string(&cargo_lock)
            .unwrap_or_else(|e| panic!("failed reading `{}`: {e}", cargo_lock.display()));
        let mut in_pkg = false;
        let mut pkg_name: Option<String> = None;
        let mut pkg_source: Option<String> = None;
        let mut fallback: Option<String> = None;

        let flush_pkg = |name: Option<&str>,
                         source: Option<&str>,
                         fallback: &mut Option<String>|
         -> Option<String> {
            let src = source?;
            if !src.contains("bamabi-wire.git") {
                return None;
            }
            let rev = src.split_once('#')?.1.split(['"', '&', ' ']).next()?;
            if !is_valid_git_rev(rev) {
                return None;
            }
            if name == Some("bamabi_sys") {
                return Some(rev.to_owned());
            }
            if fallback.is_none() {
                *fallback = Some(rev.to_owned());
            }
            None
        };

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line == "[[package]]" {
                if in_pkg
                    && let Some(found) =
                        flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
                {
                    return Some(found);
                }
                in_pkg = true;
                pkg_name = None;
                pkg_source = None;
                continue;
            }
            if in_pkg && let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"');
                if k == "name" {
                    pkg_name = Some(v.to_owned());
                } else if k == "source" {
                    pkg_source = Some(v.to_owned());
                }
            }
        }
        if in_pkg
            && let Some(found) =
                flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
        {
            return Some(found);
        }
        if let Some(rev) = fallback {
            return Some(rev);
        }
    }

    None
}

pub(crate) fn write_patch_config(ws_root: &Path, crate_dir: &Path, include_core: bool) {
    let lock = ws_root.join("Cargo.lock");
    if lock.exists() {
        fs::copy(&lock, crate_dir.join("Cargo.lock")).expect("copy Cargo.lock");
    }

    let mut cfg = String::new();
    if let Ok(wire) = fs::canonicalize(ws_root.join("..").join("bamabi-wire")) {
        let w = wire.display();
        if let Some(wire_rev) = try_resolve_wire_rev(ws_root) {
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_macros = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_sdk_gen = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n"
            ));
        } else {
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ path = \"{w}/crates/bamabi_sys\" }}\n\
                 bamabi_macros = {{ path = \"{w}/crates/bamabi_macros\" }}\n\
                 bamabi_sdk_gen = {{ path = \"{w}/crates/bamabi_sdk_gen\" }}\n\
                 bamabi_guest_sys = {{ path = \"{w}/crates/bamabi_guest_sys\" }}\n\
                 bamabi_guest = {{ path = \"{w}/crates/bamabi_guest\" }}\n"
            ));
        }
    }
    if let Ok(tools) = fs::canonicalize(ws_root.join("..").join("bamabi-tools")) {
        let t = tools.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-tools.git\"]\n\
             bamabi_manifest = {{ path = \"{t}/crates/bamabi_manifest\" }}\n\
             bamabi_trust = {{ path = \"{t}/crates/bamabi_trust\" }}\n"
        ));
    }
    if include_core && let Ok(core) = fs::canonicalize(ws_root.join("..").join("bamabi-core")) {
        let c = core.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-core.git\"]\n\
             bamabi_host_sys = {{ path = \"{c}/crates/bamabi_host_sys\" }}\n\
             bamabi_host = {{ path = \"{c}/crates/bamabi_host\" }}\n"
        ));
    }
    if !cfg.is_empty() {
        let cargo_dir = crate_dir.join(".cargo");
        fs::create_dir_all(&cargo_dir).expect("mkdir .cargo");
        fs::write(cargo_dir.join("config.toml"), cfg).expect("write .cargo/config.toml");
    }
}

pub(crate) fn should_use_cargo_offline(ws_root: &Path) -> bool {
    ws_root.join("..").join("bamabi-wire").is_dir()
}

pub(crate) fn cargo_offline_flag() -> Option<&'static str> {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)?;
    should_use_cargo_offline(ws_root).then_some("--offline")
}

pub(crate) fn sanitized_cargo_cmd() -> Command {
    let cargo = std::env::var_os("CARGO")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_LLVM_COV_BUILD_DIR",
        "RUSTC_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    cmd
}
