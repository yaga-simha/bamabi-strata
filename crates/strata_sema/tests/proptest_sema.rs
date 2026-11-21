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
