#![forbid(unsafe_code)]
//! Property-based (`proptest`) invariants for [`strata_sema`] `AbiPod` layout solving and Theorem
//! 0.1 `FilteredAccessSet` disjointness.

use proptest::prelude::*;
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::layout::{LayoutEnv, SchemaItemKind, solve_pod_layout};
use strata_sema::types::Ty;

fn field_ty_strategy() -> impl Strategy<Value = Ty> {
    prop::sample::select(vec![
        Ty::Bool,
        Ty::U8,
        Ty::I16,
        Ty::U32,
        Ty::I32,
        Ty::F32,
        Ty::F64,
        Ty::Mat3,
        Ty::Vec2,
        Ty::Vec3,
    ])
}

proptest! {
    /// Verifies `solve_pod_layout` produces strictly contiguous, aligned, zero-implicit-padding
    /// `#[repr(C)]` layouts whose field sizes sum exactly to `layout.size`.
    #[test]
    fn random_pod_structs_have_zero_implicit_padding_and_aligned_offsets(
        specs in prop::collection::vec(field_ty_strategy(), 1..12),
    ) {
        let fields: Vec<(String, Ty)> = specs
            .into_iter()
            .enumerate()
            .map(|(i, ty)| (format!("f_{i}"), ty))
            .collect();
        let env = LayoutEnv::default();
        let solved = solve_pod_layout(
            "prop::Struct",
            SchemaItemKind::Component,
            &fields,
            0,
            Vec::new(),
            &env,
        )
        .expect("random AbiPod struct must solve");

        prop_assert!(solved.is_abi_pod);
        prop_assert_eq!(solved.size % solved.align, 0);

        let mut cursor = 0usize;
        for f in &solved.fields {
            prop_assert_eq!(f.offset, cursor);
            prop_assert_eq!(f.offset % f.align.max(1), 0);
            cursor += f.size;
        }
        prop_assert_eq!(cursor, solved.size);
    }

    /// Verifies Theorem 0.1 disjointness symmetry and soundness against randomized filter masks.
    #[test]
    fn theorem01_query_disjointness_is_symmetric_and_sound(
        arch_mask in any::<u8>(),
        with_a in any::<u8>(),
        without_a in any::<u8>(),
        with_b in any::<u8>(),
        without_b in any::<u8>(),
    ) {
        let build_q = |w: u8, wo: u8| {
            let mut q = QueryAccessDesc {
                terms: vec![QueryTerm {
                    storage_key: "SharedComp".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::Write,
                    byte_start: 0,
                    byte_end: 1,
                }],
                ..QueryAccessDesc::default()
            };
            for bit in 0..8u8 {
                let name = format!("Tag{bit}");
                if (w & (1 << bit)) != 0 {
                    q.with_filters.insert(name.clone());
                }
                if (wo & (1 << bit)) != 0 {
                    q.without_filters.insert(name);
                }
            }
            q
        };

        let qa = build_q(with_a, without_a);
        let qb = build_q(with_b, without_b);
        prop_assert_eq!(qa.is_archetype_disjoint_from(&qb), qb.is_archetype_disjoint_from(&qa));

        let matches_a = (arch_mask & with_a) == with_a && (arch_mask & without_a) == 0;
        let matches_b = (arch_mask & with_b) == with_b && (arch_mask & without_b) == 0;
        if matches_a && matches_b {
            prop_assert!(!qa.is_archetype_disjoint_from(&qb));
            prop_assert!(!qa.conflicting_storages_with(&qb).is_empty());
        }
    }
}

proptest! {
    #[test]
    fn nested_option_bundle_record_and_authority_programs_never_ice_or_panic(
        is_server in any::<bool>(),
        is_mut in any::<bool>(),
        use_if in any::<bool>(),
        use_match in any::<bool>(),
        val in -1000i32..1000i32,
        arr_len in 1usize..=4,
    ) {
        let auth_attr = if is_server { "@authority(server)\n" } else { "@authority(client)\n" };
        let q_mode = if is_mut { "&mut" } else { "&" };
        let opt_mode = if is_mut { "Option<&mut Val>" } else { "Option<&Val>" };
        let mut arr_elems = Vec::with_capacity(arr_len);
        for i in 0..arr_len {
            arr_elems.push(format!("{}", val.saturating_add(i as i32)));
        }
        let arr_str = arr_elems.join(", ");

        let branch_expr = if use_if {
            format!("if {} {{ Some(row.v.x) }} else {{ None }}", if val >= 0 { "true" } else { "false" })
        } else {
            "match row.v.x { 0 => Some(1), _ => Some(2) }".to_owned()
        };
        let match_expr = if use_match {
            "match opt_v { Some(r) => r.x, None => 0 }"
        } else {
            "opt_v.unwrap_or(row.v).x"
        };

        let src = format!(
            r#"module fuzz::nested @version(1.0.0);

struct Meta {{ tag: i32 }}
{auth_attr}component Val {{ x: i32 = 0 }}
component Sub {{ meta: Option<Meta> }}
resource Bag {{ items: Option<Meta> }}

fn build_record(n: i32) -> i32 {{
    let rec = #{{ a: n, b: [{arr_str}] }};
    rec.a + rec.b[0]
}}

@net(hz = 30.0)
sys prop_sys(bag: &res Bag) {{
    let b = Bundle {{ Val {{ x: {val} }} }};
    let s = build_record({val});
    for row in query(v: {q_mode} Val, opt_v: {opt_mode}) {{
        let picked = {branch_expr};
        let m = {match_expr};
        let _ = (b, s, picked, m);
    }}
}}
"#
        );

        let analyzed = strata_sema::analyze_source("prop_nested.strata", &src);
        // Must never panic or emit an internal compiler error (ICE).
        for d in &analyzed.diagnostics {
            prop_assert!(!d.code.contains("ICE") && !d.message.contains("internal compiler error"));
        }
    }
}
