#![forbid(unsafe_code)]
//! Property-based (`proptest`) suites for [`strata_mir`] lowering, verification, and CSR partition
//! invariants.

use proptest::prelude::*;
use strata_mir::{csr_cell_range, lower_to_mir, verify_mir};
use strata_sema::analyze_source;

proptest! {
    /// Verifies `csr_cell_range` cleanly partitions monotonic offset arrays and never panics on
    /// arbitrary corrupted offset vectors and indices.
    #[test]
    fn csr_partition_and_adversarial_resilience(
        deltas in prop::collection::vec(0u32..32, 1..24),
        adv_offsets in prop::collection::vec(any::<u32>(), 0..16),
        adv_cell in 0usize..24,
        adv_total in 0usize..1024,
    ) {
        let mut offsets = Vec::with_capacity(deltas.len() + 1);
        offsets.push(0u32);
        let mut acc = 0u32;
        for d in deltas {
            acc = acc.saturating_add(d);
            offsets.push(acc);
        }
        let total = acc as usize + 5;
        let mut sum = 0usize;
        for cell in 0..(offsets.len() - 1) {
            let (s, e) = csr_cell_range(&offsets, cell, total).expect("valid CSR range");
            prop_assert!(s <= e && e <= total);
            sum += e - s;
        }
        prop_assert_eq!(sum, acc as usize);
        prop_assert!(csr_cell_range(&offsets, offsets.len() - 1, total).is_none());

        if let Some((s, e)) = csr_cell_range(&adv_offsets, adv_cell, adv_total) {
            prop_assert!(s <= e && e <= adv_total);
        }
    }

    /// Verifies arbitrary valid generated Strata modules lower to CFG MIR and pass `verify_mir`.
    #[test]
    fn generated_valid_modules_lower_and_verify(
        field_count in 1usize..6,
        det in any::<bool>(),
        selective in any::<bool>(),
        with_optional in any::<bool>(),
    ) {
        let det_attr = if det { " @deterministic" } else { "" };
        let fields: String = (0..field_count).map(|i| format!("f{i}: f32 = 1.0")).collect::<Vec<_>>().join(", ");
        let borrow = if selective { "&mut?" } else { "&mut" };
        let opt_decl = if with_optional { "component Bonus { val: f32 = 2.0 }\n" } else { "" };
        let opt_term = if with_optional { ", b: ?&Bonus" } else { "" };
        let opt_body = if with_optional {
            "if let Some(opt) = e.b { e.c.f0 += opt.val; } else { e.c.f0 += 1.0; }"
        } else {
            "e.c.f0 += 1.0;"
        };
        let src = format!(
            "module prop::mir @version(1.0.0){det_attr};\n\
             resource SimClock {{ dt: sec = 16.6667_ms }}\n\
             component C {{ {fields}, grace: GraceWindow }}\n\
             {opt_decl}\
             sys s() {{ for e in query(c: {borrow} C{opt_term}) {{ {opt_body} }} }}\n\
             schedule FixedUpdate {{ s }}\n"
        );
        let sema = analyze_source("prop_mir.strata", &src);
        prop_assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        prop_assert!(verify_mir(&mir).is_ok());
    }

    /// Verifies arbitrary `atomic { ... require_true(...) } on_rollback { ... }` and `spatial_grid`
    /// modules lower cleanly to pre-image undo logs + 2-pass CSR and pass `verify_mir`.
    #[test]
    fn generated_atomic_and_spatial_modules_lower_and_verify(
        cell_size in 1u32..32,
        cap in 16u32..512,
        opt_mut in any::<bool>(),
    ) {
        let opt_term = if opt_mut { ", b: ?&mut Bonus" } else { ", b: ?&Bonus" };
        let opt_body = if opt_mut {
            "if let Some(opt) = e.b { opt.val += 1.0; }"
        } else {
            "if e.b.is_some() { let _v = e.b.unwrap().val; }"
        };
        let src = format!(
            "module prop::atomic_spatial @version(1.0.0);\n\
             resource Vault {{ gold: i32 = 100 }}\n\
             component Pos2D {{ xy: vec2 = vec2::ZERO }}\n\
             component Bonus {{ val: f32 = 2.0 }}\n\
             spatial_grid G(cell_size: {cell_size}.0_m, bounds: vec2(-64.0_m, -64.0_m)..vec2(64.0_m, 64.0_m), capacity: {cap}) over Pos2D by Pos2D.xy;\n\
             sys s(v: &mut Vault) {{\n\
                 atomic {{\n\
                     v.gold -= 10;\n\
                     require_true(v.gold >= 0);\n\
                 }} on_rollback {{ }}\n\
                 for e in query(p: &Pos2D{opt_term}) {{ {opt_body} }}\n\
                 for cand in G.query_disc(vec2::ZERO, 8.0_m) {{ let _e = cand.entity; }}\n\
             }}\n\
             schedule FixedUpdate {{ s }}\n"
        );
        let sema = analyze_source("prop_atomic_spatial.strata", &src);
        prop_assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        prop_assert!(verify_mir(&mir).is_ok());
    }
}
