//! Command implementations for `stratac graph export` and `stratac graph apply`.

use crate::cli::OutputFormat;
use crate::exit_codes::{EXIT_COMPILE_ERROR, EXIT_OK};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use strata_sema::analyze_source;
use strata_syntax::graph_ir::{
    GraphIrPatch, GraphLayoutSidecar, apply_graph_patch, export_graph_ir_with_sidecar,
    load_sidecar, merge_sidecar, save_sidecar, sidecar_path_for,
};

/// JSON/text report for `stratac graph apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphApplyReport {
    /// Target `.strata` source file path.
    pub file: String,
    /// Path to the `.strata.graph.json` layout sidecar.
    pub sidecar_file: String,
    /// Deterministic 64-bit hex schema fingerprint (`"0x..."`).
    pub schema_fingerprint: String,
    /// `true` iff `.strata` source bytes were modified on disk.
    pub source_modified: bool,
    /// `true` iff `.strata.graph.json` sidecar was created or modified on disk.
    pub sidecar_modified: bool,
    /// Canonical node IDs whose `.strata` CST was updated.
    pub updated_nodes: Vec<String>,
    /// Canonical node IDs newly added to `.strata`.
    pub added_nodes: Vec<String>,
    /// Canonical node IDs removed from `.strata`.
    pub removed_nodes: Vec<String>,
}

fn validate_sidecar_coords(sc: &GraphLayoutSidecar, sc_path: &Path) -> Result<(), (i32, String)> {
    for (id, pos) in &sc.nodes {
        if !pos.x.is_finite() || !pos.y.is_finite() {
            return Err((
                EXIT_COMPILE_ERROR,
                format!(
                    "layout sidecar `{}` has non-finite coordinates for `{id}`",
                    sc_path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_patch_coords(patch: &GraphIrPatch) -> Result<(), (i32, String)> {
    match patch {
        GraphIrPatch::Document(doc) => {
            for node in &doc.nodes {
                if let Some(pos) = node.position
                    && (!pos.x.is_finite() || !pos.y.is_finite())
                {
                    return Err((
                        EXIT_COMPILE_ERROR,
                        format!(
                            "graph patch has non-finite coordinates for node `{}`",
                            node.id
                        ),
                    ));
                }
            }
        }
        GraphIrPatch::Delta(delta) => {
            for node in &delta.upsert {
                if let Some(pos) = node.position
                    && (!pos.x.is_finite() || !pos.y.is_finite())
                {
                    return Err((
                        EXIT_COMPILE_ERROR,
                        format!(
                            "graph patch has non-finite coordinates for node `{}`",
                            node.id
                        ),
                    ));
                }
            }
            for (id, pos) in &delta.positions {
                if !pos.x.is_finite() || !pos.y.is_finite() {
                    return Err((
                        EXIT_COMPILE_ERROR,
                        format!("graph patch has non-finite position coordinates for `{id}`"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Executes `stratac graph export`.
#[must_use]
pub fn cmd_graph_export(file: &Path, format: OutputFormat) -> (i32, String) {
    let src = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("error reading `{}`: {e}", file.display()),
            );
        }
    };

    let parsed = strata_syntax::parse(&src);
    if !parsed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            format!(
                "parse/syntax errors in `{}`: {:?}",
                file.display(),
                parsed.errors()
            ),
        );
    }

    let sc_path = sidecar_path_for(file);
    let sidecar = match load_sidecar(&sc_path) {
        Ok(sc) => sc,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("failed loading layout sidecar `{}`: {e}", sc_path.display()),
            );
        }
    };
    if let Some(sc) = &sidecar
        && let Err(err) = validate_sidecar_coords(sc, &sc_path)
    {
        return err;
    }

    let analyzed = analyze_source(file.display().to_string(), &src);
    let fp = format!("0x{:016X}", analyzed.net_schema_fingerprint);

    let doc = match export_graph_ir_with_sidecar(&src, Some(&fp), sidecar.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            return (EXIT_COMPILE_ERROR, format!("graph export error: {e}"));
        }
    };

    let out = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&doc).unwrap_or_default(),
        OutputFormat::Text => format!(
            "Graph IR {} (fp={}, {} nodes, {} edges)",
            doc.module_path,
            doc.schema_fingerprint,
            doc.nodes.len(),
            doc.edges.len()
        ),
    };
    (EXIT_OK, out)
}

/// Executes `stratac graph apply`.
#[must_use]
pub fn cmd_graph_apply(file: &Path, patch_path: &Path, format: OutputFormat) -> (i32, String) {
    let src = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("error reading `{}`: {e}", file.display()),
            );
        }
    };

    let patch_raw = match fs::read_to_string(patch_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("error reading patch `{}`: {e}", patch_path.display()),
            );
        }
    };

    let patch: GraphIrPatch = match serde_json::from_str(&patch_raw) {
        Ok(p) => p,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!(
                    "failed parsing graph patch JSON `{}`: {e}",
                    patch_path.display()
                ),
            );
        }
    };
    if let Err(err) = validate_patch_coords(&patch) {
        return err;
    }

    let sc_path = sidecar_path_for(file);
    let existing_sc = match load_sidecar(&sc_path) {
        Ok(sc) => sc,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("failed loading layout sidecar `{}`: {e}", sc_path.display()),
            );
        }
    };
    if let Some(sc) = &existing_sc
        && let Err(err) = validate_sidecar_coords(sc, &sc_path)
    {
        return err;
    }

    let applied = match apply_graph_patch(&src, &patch) {
        Ok(res) => res,
        Err(e) => {
            return (EXIT_COMPILE_ERROR, format!("graph apply error: {e}"));
        }
    };

    let analyzed = analyze_source(file.display().to_string(), &applied.source);
    if applied.source_modified && !analyzed.ok() {
        let diag_msg = match format {
            OutputFormat::Json => {
                serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default()
            }
            OutputFormat::Text => {
                let mut lines = vec![format!(
                    "semantic errors in patched `{}` (source not modified):",
                    file.display()
                )];
                for d in &analyzed.diagnostics {
                    lines.push(format!("  [{}] {}", d.code, d.message));
                }
                lines.join("\n")
            }
        };
        return (EXIT_COMPILE_ERROR, diag_msg);
    }

    let fp = format!("0x{:016X}", analyzed.net_schema_fingerprint);

    if applied.source_modified
        && let Err(e) = fs::write(file, &applied.source)
    {
        return (
            EXIT_COMPILE_ERROR,
            format!("failed writing `{}`: {e}", file.display()),
        );
    }

    let mut sidecar_modified = false;
    if existing_sc.is_some()
        || !applied.sidecar_updates.is_empty()
        || !applied.sidecar_removals.is_empty()
    {
        let next_sc = merge_sidecar(existing_sc.clone(), &applied, &fp);
        if existing_sc.as_ref() != Some(&next_sc) {
            if let Err(e) = save_sidecar(&sc_path, &next_sc) {
                return (
                    EXIT_COMPILE_ERROR,
                    format!("failed writing layout sidecar `{}`: {e}", sc_path.display()),
                );
            }
            sidecar_modified = true;
        }
    }

    let report = GraphApplyReport {
        file: file.display().to_string(),
        sidecar_file: sc_path.display().to_string(),
        schema_fingerprint: fp,
        source_modified: applied.source_modified,
        sidecar_modified,
        updated_nodes: applied.updated_nodes,
        added_nodes: applied.added_nodes,
        removed_nodes: applied.removed_nodes,
    };

    let out = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => format!(
            "Applied Graph IR to `{}` (fp={}, source_modified={}, sidecar_modified={}, updated={}, added={}, removed={})",
            report.file,
            report.schema_fingerprint,
            report.source_modified,
            report.sidecar_modified,
            report.updated_nodes.len(),
            report.added_nodes.len(),
            report.removed_nodes.len(),
        ),
    };
    (EXIT_OK, out)
}
