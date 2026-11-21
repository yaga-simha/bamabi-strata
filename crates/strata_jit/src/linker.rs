//! Platform native shared library linker for Cranelift PIC object files (`.o` -> `.dylib`/`.so`/`.dll`).

use crate::JitError;
use std::path::Path;
use std::process::Command;

/// Links `obj_path` into a loadable native shared library at `out_dylib`.
pub fn link_shared_object(obj_path: &Path, out_dylib: &Path) -> Result<(), JitError> {
    let cc = find_linker_driver();
    let mut cmd = Command::new(cc);

    if cfg!(target_os = "macos") {
        cmd.arg("-dynamiclib")
            .arg("-Wl,-undefined,dynamic_lookup")
            .arg(obj_path)
            .arg("-o")
            .arg(out_dylib);
    } else if cfg!(target_os = "windows") {
        cmd.arg("-shared").arg(obj_path).arg("-o").arg(out_dylib);
    } else {
        cmd.arg("-shared")
            .arg("-fPIC")
            .arg(obj_path)
            .arg("-o")
            .arg(out_dylib);
    }

    let output = cmd.output().map_err(|e| {
        JitError::LinkFailed(format!("failed to execute linker driver `{cc}`: {e}"))
    })?;

    if !output.status.success() {
        return Err(JitError::LinkFailed(format!(
            "linker `{cc}` exited with {:?}:\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    Ok(())
}

fn find_linker_driver() -> &'static str {
    for tool in ["clang", "cc", "gcc"] {
        if let Ok(out) = Command::new(tool).arg("--version").output()
            && out.status.success()
        {
            return tool;
        }
    }
    "cc"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies linker locates a system C compiler driver and cleanly reports linker failures.
    #[test]
    fn linker_finds_driver_and_errors_on_missing_object() {
        let driver = find_linker_driver();
        assert!(!driver.is_empty());
        let res = link_shared_object(
            Path::new("/nonexistent_strata_jit_obj.o"),
            Path::new("/nonexistent_strata_jit_out.so"),
        );
        assert!(matches!(res, Err(JitError::LinkFailed(_))));
    }
}
