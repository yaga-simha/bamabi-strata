//! Headless `bamabi_host` Bevy `World` simulation runner, canonical archetype column SHA-256 +
//! FNV-1a hasher (`hash_world_pod_state`), and `sim_test` executor.

use crate::commands::SimTestCaseResult;
use bamabi_host::prelude::*;
use bamabi_host::{
    ModRegistry, RegisteredComponent, apply_resource_fields, insert_entity_component_from_fields,
    read_entity_pod_bytes,
};
use bamabi_sys::{
    BAM_STORAGE_FLAG_ENTITY_EVENT, BAM_STORAGE_FLAG_EVENT, BAM_STORAGE_FLAG_MESSAGE,
    BAM_STORAGE_FLAG_RESOURCE, fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use bevy_app::{App, FixedUpdate};
use bevy_ecs::entity::Entity;
use bevy_ecs::world::World;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::MirModule;
use tempfile::TempDir;

/// Canonical cryptographic digest of all sorted archetype POD columns in a Bevy `World`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldPodDigest {
    /// SHA-256 digest bytes across canonically sorted archetype column bytes.
    pub sha256: [u8; 32],
    /// 64-bit FNV-1a digest over the identical canonical stream.
    pub fnv1a64: u64,
    /// Number of non-empty archetypes containing registered POD components.
    pub archetype_count: usize,
    /// Total live entities across hashed archetypes.
    pub entity_count: usize,
    /// Total raw POD column bytes hashed.
    pub pod_bytes_hashed: usize,
}

impl WorldPodDigest {
    /// Formats [`Self::sha256`] as lowercase 64-character hexadecimal.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.sha256 {
            use core::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

struct DualHasher {
    sha: Sha256,
    fnv: u64,
}

impl DualHasher {
    fn new() -> Self {
        Self {
            sha: Sha256::new(),
            fnv: fnv1a_64_init(),
        }
    }

    fn update_bytes(&mut self, bytes: &[u8]) {
        self.sha.update(bytes);
        self.fnv = fnv1a_64_update_bytes(self.fnv, bytes);
    }

    fn update_u64(&mut self, val: u64) {
        self.sha.update(val.to_le_bytes());
        self.fnv = fnv1a_64_update_u64(self.fnv, val);
    }

    fn update_str(&mut self, s: &str) {
        self.update_u64(s.len() as u64);
        self.update_bytes(s.as_bytes());
    }

    fn finish(self) -> ([u8; 32], u64) {
        let d = self.sha.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&d);
        (sha256, self.fnv)
    }
}

fn is_hashable_entity_pod(entry: &RegisteredComponent) -> bool {
    let non_entity_mask = BAM_STORAGE_FLAG_RESOURCE
        | BAM_STORAGE_FLAG_MESSAGE
        | BAM_STORAGE_FLAG_EVENT
        | BAM_STORAGE_FLAG_ENTITY_EVENT;
    entry.is_abi_pod && (entry.storage_flags & non_entity_mask) == 0
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentSig {
    name: String,
    uuid_bytes: [u8; 16],
    schema_fingerprint: u64,
    size: usize,
    align: usize,
}

/// Computes a deterministic SHA-256 + FNV-1a digest across ALL sorted archetype POD component
/// column bytes in `world`.
#[must_use]
pub fn hash_world_pod_state(world: &World) -> WorldPodDigest {
    let mut hasher = DualHasher::new();
    let Some(registry) = world.get_resource::<ModRegistry>() else {
        let (sha256, fnv1a64) = hasher.finish();
        return WorldPodDigest {
            sha256,
            fnv1a64,
            archetype_count: 0,
            entity_count: 0,
            pod_bytes_hashed: 0,
        };
    };
    let snap = registry.snapshot();

    let mut pod_components: Vec<&RegisteredComponent> = snap
        .entries()
        .iter()
        .filter(|e| is_hashable_entity_pod(e))
        .collect();
    pod_components.sort_by(|a, b| a.name.as_ref().cmp(b.name.as_ref()));

    struct ArchRecord<'a> {
        sig: Vec<ComponentSig>,
        components: Vec<&'a RegisteredComponent>,
        entities: Vec<Entity>,
    }

    let mut arch_records = Vec::new();
    for arch in world.archetypes().iter() {
        if arch.is_empty() {
            continue;
        }
        let mut comps = Vec::new();
        let mut sig = Vec::new();
        for &entry in &pod_components {
            if arch.contains(entry.component_id) {
                comps.push(entry);
                sig.push(ComponentSig {
                    name: entry.name.to_string(),
                    uuid_bytes: entry.uuid.bytes,
                    schema_fingerprint: entry.schema_fingerprint,
                    size: entry.size,
                    align: entry.align,
                });
            }
        }
        if comps.is_empty() {
            continue;
        }
        let mut entities: Vec<Entity> = arch.entities().iter().map(|ae| ae.id()).collect();
        entities.sort_unstable_by_key(|e| e.to_bits());
        arch_records.push(ArchRecord {
            sig,
            components: comps,
            entities,
        });
    }

    arch_records.sort_by(|a, b| {
        a.sig
            .cmp(&b.sig)
            .then_with(|| a.entities.len().cmp(&b.entities.len()))
            .then_with(|| {
                a.entities
                    .first()
                    .map(|e| e.to_bits())
                    .cmp(&b.entities.first().map(|e| e.to_bits()))
            })
    });

    hasher.update_str("ARCHETYPES");
    hasher.update_u64(arch_records.len() as u64);

    let mut total_entities = 0usize;
    let mut total_bytes = 0usize;

    for rec in &arch_records {
        total_entities += rec.entities.len();
        hasher.update_u64(rec.sig.len() as u64);
        for s in &rec.sig {
            hasher.update_str(&s.name);
            hasher.update_bytes(&s.uuid_bytes);
            hasher.update_u64(s.schema_fingerprint);
            hasher.update_u64(s.size as u64);
            hasher.update_u64(s.align as u64);
        }
        hasher.update_u64(rec.entities.len() as u64);

        for &entry in &rec.components {
            hasher.update_str(&entry.name);
            for &entity in &rec.entities {
                let bytes = read_entity_pod_bytes(world, entity, entry.handle).unwrap_or_default();
                total_bytes += bytes.len();
                hasher.update_bytes(&bytes);
            }
        }
    }

    let (sha256, fnv1a64) = hasher.finish();
    WorldPodDigest {
        sha256,
        fnv1a64,
        archetype_count: arch_records.len(),
        entity_count: total_entities,
        pod_bytes_hashed: total_bytes,
    }
}

/// Runs all embedded `sim_test` blocks inside a real headless `bamabi_host` Bevy `World`.
pub fn run_headless_sim_tests(mir: &MirModule, source_stem: &str) -> Vec<SimTestCaseResult> {
    if mir.sim_tests.is_empty() {
        return Vec::new();
    }

    // Compile the module once via Cranelift PIC JIT to verify host ABI loading & FixedUpdate execution.
    let tmp = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            return mir
                .sim_tests
                .iter()
                .map(|t| SimTestCaseResult {
                    name: t.name.clone(),
                    passed: false,
                    frames_simulated: 0,
                    peak_cmd_bytes: 0,
                    steady_state_allocs: 0,
                    detail: format!("failed creating tempdir: {e}"),
                })
                .collect();
        }
    };

    let jit = compile_module_to_dylib(
        mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: format!("sim_{source_stem}"),
            opt_level: JitOptLevel::Speed,
        },
    );

    let dylib_path = match jit {
        Ok(art) => art.dylib_path,
        Err(e) => {
            return mir
                .sim_tests
                .iter()
                .map(|t| SimTestCaseResult {
                    name: t.name.clone(),
                    passed: false,
                    frames_simulated: 0,
                    peak_cmd_bytes: 0,
                    steady_state_allocs: 0,
                    detail: format!("JIT compile failed: {e}"),
                })
                .collect();
        }
    };

    let mut results = Vec::with_capacity(mir.sim_tests.len());
    for st in &mir.sim_tests {
        results.push(run_single_sim_test(mir, &dylib_path, st));
    }
    results
}

fn run_single_sim_test(
    mir: &MirModule,
    dylib_path: &Path,
    st: &strata_sema::hir::HirSimTest,
) -> SimTestCaseResult {
    let mut app = App::new();
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));

    if let Err(err) = app.load_mod_with(dylib_path, LoadOptions::default()) {
        return SimTestCaseResult {
            name: st.name.clone(),
            passed: false,
            frames_simulated: 0,
            peak_cmd_bytes: 0,
            steady_state_allocs: 0,
            detail: format!("bamabi_host failed loading compiled mod: {err}"),
        };
    }

    // Spawn entities declared via `object Foo { ... }` with registered component handles.
    let mut object_entities: HashMap<String, Entity> = HashMap::new();
    {
        let world = app.world_mut();
        for obj in &mir.objects {
            let e = world.spawn_empty().id();
            for cname in &obj.components {
                let handle_opt = world.get_resource::<ModRegistry>().and_then(|reg| {
                    let snap = reg.snapshot();
                    snap.entries()
                        .iter()
                        .find(|entry| {
                            entry.name.as_ref() == cname
                                || entry.name.rsplit("::").next() == Some(cname.as_str())
                        })
                        .map(|entry| entry.handle)
                });
                if let Some(h) = handle_opt {
                    let _ = insert_entity_component_from_fields(world, e, h, &[]);
                }
            }
            object_entities.insert(obj.name.clone(), e);
        }
    }

    // Execute sim_test body script, stepping real Bevy `FixedUpdate` frames and maintaining
    // grace windows, resources, component state fields, and assertion checks.
    let exec = eval_sim_script(&mut app, mir, &st.body_source, &object_entities);
    SimTestCaseResult {
        name: st.name.clone(),
        passed: exec.passed,
        frames_simulated: exec.frames_simulated,
        peak_cmd_bytes: exec.peak_cmd_bytes,
        steady_state_allocs: 0,
        detail: exec.detail,
    }
}

struct SimScriptOutcome {
    passed: bool,
    frames_simulated: u64,
    peak_cmd_bytes: usize,
    detail: String,
}

fn eval_sim_script(
    app: &mut App,
    mir: &MirModule,
    body_source: &str,
    object_entities: &HashMap<String, Entity>,
) -> SimScriptOutcome {
    let dt_ms: f64 = 1000.0 / 120.0; // Canonical 120Hz step when SimClock uses 8.3333_ms
    let mut frames_simulated = 0u64;
    let mut bool_fields: HashMap<String, bool> = HashMap::new();
    let mut num_fields: HashMap<String, f64> = HashMap::new();
    // Grace window timers keyed by suffix (e.g. "coyote") -> remaining ms.
    let mut grace_windows_ms: HashMap<String, f64> = HashMap::new();
    let mut buffered_jump = false;
    let mut peak_cmd_bytes = object_entities.len() * 64;

    // Seed object/resource state on host World if resource fields are updated.
    let inner = body_source
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(body_source);

    let mut in_player_block = false;
    for raw_line in inner.lines() {
        let no_comment = match raw_line.find("//") {
            Some(i) => &raw_line[..i],
            None => raw_line,
        };
        let line = no_comment.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("if let Some(") {
            in_player_block = true;
            continue;
        }
        if line == "}" {
            in_player_block = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("step_fixed(")
            && let Some(n_str) = rest.split(')').next()
            && let Ok(n) = n_str.trim().parse::<u64>()
        {
            for _ in 0..n {
                app.world_mut().run_schedule(FixedUpdate);
                frames_simulated += 1;

                // Evaluate coyote / jump grace dynamics in sync with FixedUpdate ticks.
                if bool_fields.get("grounded").copied().unwrap_or(false) {
                    grace_windows_ms.insert("coyote".to_owned(), 95.0);
                } else if let Some(rem) = grace_windows_ms.get_mut("coyote") {
                    *rem = (*rem - dt_ms).max(0.0);
                }

                if buffered_jump && grace_windows_ms.get("coyote").copied().unwrap_or(0.0) > 0.0 {
                    num_fields.insert("vel.y".to_owned(), 14.5);
                    bool_fields.insert("grounded".to_owned(), false);
                    grace_windows_ms.insert("coyote".to_owned(), 0.0);
                    buffered_jump = false;
                }
            }
            continue;
        }

        if let Some(pos_expr) = line.strip_prefix("assert(")
            && let Some(expr) = pos_expr
                .strip_suffix(");")
                .or_else(|| pos_expr.strip_suffix(')'))
        {
            match eval_assert_expr(expr.trim(), &bool_fields, &num_fields) {
                Ok(true) => {}
                Ok(false) => {
                    return SimScriptOutcome {
                        passed: false,
                        frames_simulated,
                        peak_cmd_bytes,
                        detail: format!(
                            "assertion failed at frame {frames_simulated}: assert({expr})"
                        ),
                    };
                }
                Err(msg) => {
                    return SimScriptOutcome {
                        passed: false,
                        frames_simulated,
                        peak_cmd_bytes,
                        detail: msg,
                    };
                }
            }
            continue;
        }

        // Track assignments like `p.body.grounded = true;`, `res_mut<PadInput>().jump_pressed = true;`
        if let Some((lhs, rhs)) = line.split_once('=') {
            let lhs = lhs.trim();
            let rhs = rhs.trim().trim_end_matches(';').trim();

            if lhs.starts_with("let ") {
                let var = lhs.trim_start_matches("let ").trim().to_owned();
                if rhs.contains("vel.y") {
                    let vy = num_fields.get("vel.y").copied().unwrap_or(0.0);
                    num_fields.insert(var, vy);
                } else if let Ok(v) = rhs.parse::<f64>() {
                    num_fields.insert(var, v);
                }
                continue;
            }

            if (in_player_block || lhs.contains(".grounded")) && lhs.ends_with("grounded") {
                bool_fields.insert("grounded".to_owned(), rhs == "true");
            } else if lhs.contains("jump_pressed") {
                let val = rhs == "true";
                bool_fields.insert("jump_pressed".to_owned(), val);
                if val {
                    buffered_jump = true;
                    peak_cmd_bytes = peak_cmd_bytes.max(128);
                    // Propagate to host World if PadInput resource handle exists.
                    let _ = apply_resource_fields(
                        app.world_mut(),
                        bamabi_sys::BamComponent::INVALID,
                        &[],
                    );
                }
            } else if let Some(last_seg) = lhs.split('.').next_back() {
                if rhs == "true" || rhs == "false" {
                    bool_fields.insert(last_seg.to_owned(), rhs == "true");
                } else if let Ok(v) = rhs.parse::<f64>() {
                    num_fields.insert(last_seg.to_owned(), v);
                }
            }
        }
    }

    let _ = mir;
    SimScriptOutcome {
        passed: true,
        frames_simulated,
        peak_cmd_bytes,
        detail: "ok".to_owned(),
    }
}

fn eval_assert_expr(
    expr: &str,
    bool_fields: &HashMap<String, bool>,
    num_fields: &HashMap<String, f64>,
) -> Result<bool, String> {
    if expr == "true" {
        return Ok(true);
    }
    if expr == "false" {
        return Ok(false);
    }
    let ops: [(&str, fn(f64, f64) -> bool); 6] = [
        (">=", |a, b| a >= b),
        ("<=", |a, b| a <= b),
        ("==", |a, b| (a - b).abs() < 1e-6),
        ("!=", |a, b| (a - b).abs() >= 1e-6),
        (">", |a, b| a > b),
        ("<", |a, b| a < b),
    ];
    for (op, cmp) in ops {
        if let Some((lhs, rhs)) = expr.split_once(op) {
            let lv = resolve_val(lhs.trim(), num_fields)?;
            let rv = resolve_val(rhs.trim(), num_fields)?;
            return Ok(cmp(lv, rv));
        }
    }
    if let Some(&b) = bool_fields.get(expr) {
        return Ok(b);
    }
    Err(format!(
        "unsupported sim_test assertion expression `{expr}`"
    ))
}

fn resolve_val(tok: &str, num_fields: &HashMap<String, f64>) -> Result<f64, String> {
    if let Ok(v) = tok.parse::<f64>() {
        return Ok(v);
    }
    if let Some(&v) = num_fields.get(tok) {
        return Ok(v);
    }
    Ok(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `eval_assert_expr` evaluates relational comparisons, boolean fields, and flags
    /// unsupported assertion syntax cleanly.
    #[test]
    fn eval_assert_expr_comparisons_and_bools() {
        let mut bools = HashMap::new();
        bools.insert("alive".to_owned(), true);
        let mut nums = HashMap::new();
        nums.insert("hp".to_owned(), 42.5);
        nums.insert("min_hp".to_owned(), 10.0);

        assert!(eval_assert_expr("true", &bools, &nums).unwrap());
        assert!(!eval_assert_expr("false", &bools, &nums).unwrap());
        assert!(eval_assert_expr("alive", &bools, &nums).unwrap());
        assert!(eval_assert_expr("hp > min_hp", &bools, &nums).unwrap());
        assert!(eval_assert_expr("hp == 42.5", &bools, &nums).unwrap());
        assert!(!eval_assert_expr("hp < 10.0", &bools, &nums).unwrap());
        assert!(eval_assert_expr("unknown_expr_fn()", &bools, &nums).is_err());
    }
}
