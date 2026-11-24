//! Bidirectional type inference, branch/array/numeric unification, and explicit coercion
//! insertion for Strata v2.0 HIR lowering.

use crate::access::TermAccessMode;
use crate::hir::{HirBinOp, HirCall, HirExpr, HirQuery, HirStmt};
use crate::hir_lower::LowerEnv;
use crate::types::{QueryRowTerm, Ty, UnitDim};

/// Returns `true` if `ty` is a primitive numeric scalar (`u8..u64`, `i8..i64`, `f32`, `f64`,
/// `fix32`, `fix64`).
#[inline]
pub(crate) fn is_numeric_scalar(ty: &Ty) -> bool {
    matches!(
        ty,
        Ty::U8
            | Ty::U16
            | Ty::U32
            | Ty::U64
            | Ty::I8
            | Ty::I16
            | Ty::I32
            | Ty::I64
            | Ty::F32
            | Ty::F64
            | Ty::Fix32
            | Ty::Fix64
    )
}

/// Unwraps any outer [`Ty::Borrow`] layers from `ty`.
#[inline]
pub(crate) fn unwrap_borrow_ty(mut ty: &Ty) -> &Ty {
    while let Ty::Borrow { inner, .. } = ty {
        ty = inner.as_ref();
    }
    ty
}

/// Unwraps any outer [`Ty::Borrow`] and [`Ty::Option`] layers to get the inner type of an
/// `Option<T>` / `&Option<T>` / `?&T` value.
pub(crate) fn unwrap_option_ty(ty: &Ty) -> Ty {
    match unwrap_borrow_ty(ty) {
        Ty::Option(inner) => (**inner).clone(),
        Ty::QueryRow(_) => ty.clone(),
        _ => Ty::Unknown,
    }
}

/// Unifies two numeric types according to Strata's widening precedence:
/// `F64 > UnitScalar > Fix64 > Fix32 > F32 > U64 > I64 > U32 > I32 > U16 > I16 > U8 > I8`.
pub(crate) fn unify_numeric(lhs: &Ty, rhs: &Ty) -> Ty {
    let lhs = unwrap_borrow_ty(lhs);
    let rhs = unwrap_borrow_ty(rhs);
    if *lhs == Ty::Unknown {
        return rhs.clone();
    }
    if *rhs == Ty::Unknown {
        return lhs.clone();
    }
    match (lhs, rhs) {
        (Ty::F64, _) | (_, Ty::F64) => Ty::F64,
        (Ty::UnitScalar { .. }, _) => lhs.clone(),
        (_, Ty::UnitScalar { .. }) => rhs.clone(),
        (Ty::Fix64, _) | (_, Ty::Fix64) => Ty::Fix64,
        (Ty::Fix32, _) | (_, Ty::Fix32) => Ty::Fix32,
        (Ty::F32, _) | (_, Ty::F32) => Ty::F32,
        (Ty::U64, _) | (_, Ty::U64) => Ty::U64,
        (Ty::I64, _) | (_, Ty::I64) => Ty::I64,
        (Ty::U32, _) | (_, Ty::U32) => Ty::U32,
        (Ty::I32, _) | (_, Ty::I32) => Ty::I32,
        (Ty::U16, _) | (_, Ty::U16) => Ty::U16,
        (Ty::I16, _) | (_, Ty::I16) => Ty::I16,
        (Ty::U8, _) | (_, Ty::U8) => Ty::U8,
        (Ty::I8, _) | (_, Ty::I8) => Ty::I8,
        _ => lhs.clone(),
    }
}

/// Inserts an explicit [`HirExpr::Cast`] when `expr` is a numeric scalar whose type differs from
/// numeric scalar `target_ty`.
pub(crate) fn maybe_cast_expr(expr: HirExpr, target_ty: &Ty) -> HirExpr {
    let src_ty = expr.ty();
    if src_ty == Ty::Unknown || *target_ty == Ty::Unknown || src_ty == *target_ty {
        return expr;
    }
    if is_numeric_scalar(&src_ty) && is_numeric_scalar(target_ty) {
        HirExpr::Cast {
            expr: Box::new(expr),
            target_ty: target_ty.clone(),
        }
    } else {
        expr
    }
}

/// Infers the result type of a binary expression from its operator and operand types.
pub(crate) fn infer_binop_ty(op: HirBinOp, lhs: &Ty, rhs: &Ty) -> Ty {
    let lhs = unwrap_borrow_ty(lhs);
    let rhs = unwrap_borrow_ty(rhs);
    match op {
        HirBinOp::Eq
        | HirBinOp::Ne
        | HirBinOp::Lt
        | HirBinOp::Le
        | HirBinOp::Gt
        | HirBinOp::Ge
        | HirBinOp::And
        | HirBinOp::Or => Ty::Bool,
        HirBinOp::Mul => match (lhs, rhs) {
            (Ty::UnitScalar { dim: a, .. }, Ty::UnitScalar { dim: b, .. }) => {
                let d = a.mul(*b);
                if d == UnitDim::NONE {
                    Ty::F32
                } else {
                    Ty::UnitScalar {
                        name: "unit".to_owned(),
                        dim: d,
                    }
                }
            }
            (Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4, _) => lhs.clone(),
            (_, Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4) => rhs.clone(),
            _ => unify_numeric(lhs, rhs),
        },
        HirBinOp::Div => match (lhs, rhs) {
            (Ty::UnitScalar { dim: a, .. }, Ty::UnitScalar { dim: b, .. }) => {
                let d = a.div(*b);
                if d == UnitDim::NONE {
                    Ty::F32
                } else {
                    Ty::UnitScalar {
                        name: "unit".to_owned(),
                        dim: d,
                    }
                }
            }
            (Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4, _) => lhs.clone(),
            _ => unify_numeric(lhs, rhs),
        },
        _ => {
            if matches!(
                lhs,
                Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4 | Ty::IVec2 | Ty::IVec3 | Ty::UVec2
            ) {
                lhs.clone()
            } else if matches!(
                rhs,
                Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4 | Ty::IVec2 | Ty::IVec3 | Ty::UVec2
            ) {
                rhs.clone()
            } else {
                unify_numeric(lhs, rhs)
            }
        }
    }
}

/// Coerces mixed numeric scalar operands in a binary expression by inserting [`HirExpr::Cast`]
/// on narrower operands, returning `(lhs, rhs, result_ty)`.
pub(crate) fn coerce_binary_operands(
    op: HirBinOp,
    lhs: HirExpr,
    rhs: HirExpr,
) -> (HirExpr, HirExpr, Ty) {
    let result_ty = infer_binop_ty(op, &lhs.ty(), &rhs.ty());
    let should_coerce_operands = matches!(
        op,
        HirBinOp::Add
            | HirBinOp::Sub
            | HirBinOp::Mul
            | HirBinOp::Div
            | HirBinOp::Rem
            | HirBinOp::BitAnd
            | HirBinOp::BitOr
            | HirBinOp::BitXor
            | HirBinOp::Eq
            | HirBinOp::Ne
            | HirBinOp::Lt
            | HirBinOp::Le
            | HirBinOp::Gt
            | HirBinOp::Ge
    );
    let is_int_ty = |t: &Ty| {
        matches!(
            unwrap_borrow_ty(t),
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64
        )
    };
    let is_nonneg_i32_lit = |e: &HirExpr| {
        matches!(
            e,
            HirExpr::IntLit {
                value,
                ty: Ty::I32
            } if *value >= 0
        )
    };
    if should_coerce_operands
        && is_numeric_scalar(&lhs.ty())
        && is_numeric_scalar(&rhs.ty())
        && lhs.ty() != rhs.ty()
        && !(is_int_ty(&lhs.ty()) && is_nonneg_i32_lit(&rhs))
        && !(is_int_ty(&rhs.ty()) && is_nonneg_i32_lit(&lhs))
    {
        let common = unify_numeric(&lhs.ty(), &rhs.ty());
        return (
            maybe_cast_expr(lhs, &common),
            maybe_cast_expr(rhs, &common),
            result_ty,
        );
    }
    (lhs, rhs, result_ty)
}

/// Coerces the RHS of a compound assignment (`+=`, `-=`, etc.) when the target is `Fix64`,
/// `Fix32`, `F64`, or `F32` and the RHS is a distinct numeric scalar.
pub(crate) fn coerce_compound_assign_rhs(target_ty: &Ty, value: HirExpr) -> HirExpr {
    let inner_target = unwrap_borrow_ty(target_ty);
    if matches!(inner_target, Ty::Fix64 | Ty::Fix32 | Ty::F64 | Ty::F32)
        && is_numeric_scalar(&value.ty())
        && value.ty() != *inner_target
    {
        HirExpr::Cast {
            expr: Box::new(value),
            target_ty: inner_target.clone(),
        }
    } else {
        value
    }
}

/// Recursively unifies two semantic types (including `Option<T>` + `None`, borrows, tuples,
/// arrays, and numeric widening).
pub(crate) fn unify_tys(a: &Ty, b: &Ty) -> Ty {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (Ty::Unknown, other) | (other, Ty::Unknown) => other.clone(),
        (Ty::Option(ia), Ty::Option(ib)) => Ty::Option(Box::new(unify_tys(ia, ib))),
        (Ty::Option(ia), other) | (other, Ty::Option(ia)) => {
            if *other == Ty::Unit {
                Ty::Option(ia.clone())
            } else {
                Ty::Option(Box::new(unify_tys(ia, other)))
            }
        }
        (
            Ty::Borrow {
                mutable: ma,
                inner: ia,
            },
            Ty::Borrow {
                mutable: mb,
                inner: ib,
            },
        ) => Ty::Borrow {
            mutable: *ma && *mb,
            inner: Box::new(unify_tys(ia, ib)),
        },
        (Ty::Borrow { inner, .. }, other) | (other, Ty::Borrow { inner, .. }) => {
            unify_tys(inner, other)
        }
        (Ty::Array { elem: ea, len: la }, Ty::Array { elem: eb, len: lb }) if la == lb => {
            Ty::Array {
                elem: Box::new(unify_tys(ea, eb)),
                len: *la,
            }
        }
        (Ty::Tuple(ta), Ty::Tuple(tb)) if ta.len() == tb.len() => {
            Ty::Tuple(ta.iter().zip(tb).map(|(x, y)| unify_tys(x, y)).collect())
        }
        (Ty::UnitScalar { dim: da, .. }, Ty::UnitScalar { dim: db, .. }) if da == db => a.clone(),
        _ if is_numeric_scalar(a) && is_numeric_scalar(b) => unify_numeric(a, b),
        (Ty::Unit, other) | (other, Ty::Unit) if *other != Ty::Unknown => other.clone(),
        _ => a.clone(),
    }
}

/// Returns `true` if evaluating `expr` definitely diverges (`return`, `break`, `continue`).
pub(crate) fn expr_definitely_diverges(expr: &HirExpr) -> bool {
    match expr {
        HirExpr::Block { stmts, tail, .. } => {
            stmts_definitely_diverges(stmts)
                || tail.as_deref().is_some_and(expr_definitely_diverges)
        }
        HirExpr::If {
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            let then_div = stmts_definitely_diverges(then_stmts)
                || then_tail.as_deref().is_some_and(expr_definitely_diverges);
            let else_div = (!else_stmts.is_empty() || else_tail.is_some())
                && (stmts_definitely_diverges(else_stmts)
                    || else_tail.as_deref().is_some_and(expr_definitely_diverges));
            then_div && else_div
        }
        HirExpr::Match(m) => {
            !m.arms.is_empty() && m.arms.iter().all(|a| expr_definitely_diverges(&a.body))
        }
        _ => false,
    }
}

/// Returns `true` if executing `stmts` definitely diverges before reaching the end.
pub(crate) fn stmts_definitely_diverges(stmts: &[HirStmt]) -> bool {
    for stmt in stmts {
        match stmt {
            HirStmt::Return(_) | HirStmt::Break(_) | HirStmt::Continue => return true,
            HirStmt::Expr(e) if expr_definitely_diverges(e) => return true,
            _ => {}
        }
    }
    false
}

/// Unifies branch/arm types `(ty, diverges)` for `if` and `match` expressions, preserving
/// resolved non-`Unit` types (Class B root fix) and `Some(T)` + `None` -> `Option<T>`.
pub(crate) fn unify_branch_tys(branches: &[(Ty, bool)], expected: Option<&Ty>) -> Ty {
    let mut acc: Option<Ty> = None;
    for (ty, diverges) in branches {
        if *diverges || *ty == Ty::Unknown {
            continue;
        }
        acc = Some(match acc {
            None => ty.clone(),
            Some(prev) => unify_tys(&prev, ty),
        });
    }
    match acc {
        Some(Ty::Option(inner)) if *inner == Ty::Unknown => {
            if let Some(exp @ Ty::Option(_)) = expected {
                exp.clone()
            } else {
                Ty::Option(inner)
            }
        }
        Some(t) => t,
        None => expected.cloned().unwrap_or(Ty::Unit),
    }
}

/// Builds a typed [`HirExpr::ArrayLit`] with unified element type and explicit [`HirExpr::Cast`]
/// coercions on mixed numeric scalar elements (e.g. `[1, 2.0]` -> `[f32; 2]`).
pub(crate) fn build_array_lit(elems: Vec<HirExpr>, expected: Option<&Ty>) -> HirExpr {
    let expected_elem = match expected {
        Some(Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }) => Some(elem.as_ref()),
        _ => None,
    };
    let len = elems.len();
    let mut unified: Option<Ty> = expected_elem.filter(|t| **t != Ty::Unknown).cloned();
    for e in &elems {
        if expr_definitely_diverges(e) {
            continue;
        }
        let ety = e.ty();
        if ety == Ty::Unknown {
            continue;
        }
        unified = Some(match unified {
            None => ety,
            Some(prev) => unify_tys(&prev, &ety),
        });
    }
    let elem_ty = unified.unwrap_or(Ty::Unknown);
    let elems = if is_numeric_scalar(&elem_ty) {
        elems
            .into_iter()
            .map(|e| maybe_cast_expr(e, &elem_ty))
            .collect()
    } else {
        elems
    };
    HirExpr::ArrayLit {
        elems,
        ty: Ty::Array {
            elem: Box::new(elem_ty),
            len,
        },
    }
}

/// Validates an expression's array/SmallVec literal length or capacity against an expected type,
/// returning a human-readable diagnostic message on mismatch.
pub(crate) fn check_array_or_smallvec_mismatch(expr: &HirExpr, expected: &Ty) -> Option<String> {
    match expected {
        Ty::Array { len: exp_len, .. } => match expr {
            HirExpr::ArrayLit { elems, .. } if elems.len() != *exp_len => Some(format!(
                "array literal length mismatch: expected `[_; {exp_len}]` ({exp_len} elements), found {} elements",
                elems.len()
            )),
            HirExpr::ArrayLit { .. }
            | HirExpr::Block { .. }
            | HirExpr::If { .. }
            | HirExpr::Match { .. } => None,
            _ => match expr.ty() {
                Ty::Array { len: act_len, .. } if act_len != *exp_len => Some(format!(
                    "array length mismatch: expected `[_; {exp_len}]`, found `[_; {act_len}]`"
                )),
                _ => None,
            },
        },
        Ty::SmallVec { cap: exp_cap, .. } => match expr {
            HirExpr::ArrayLit { elems, .. } if elems.len() > *exp_cap => Some(format!(
                "SmallVec literal exceeds capacity: capacity is {exp_cap}, found {} elements",
                elems.len()
            )),
            HirExpr::ArrayLit { .. }
            | HirExpr::Block { .. }
            | HirExpr::If { .. }
            | HirExpr::Match { .. } => None,
            _ => match expr.ty() {
                Ty::Array { len: act_len, .. } if act_len > *exp_cap => Some(format!(
                    "array length ({act_len}) exceeds SmallVec capacity ({exp_cap})"
                )),
                Ty::SmallVec { cap: act_cap, .. } if act_cap > *exp_cap => Some(format!(
                    "SmallVec capacity mismatch: expected capacity `<= {exp_cap}`, found `SmallVec<_, {act_cap}>`"
                )),
                _ => None,
            },
        },
        _ => None,
    }
}

/// Resolves the element type of an indexing expression `base[index]`.
pub(crate) fn resolve_index_ty(base: &HirExpr, env: &LowerEnv<'_>) -> Ty {
    if let HirExpr::Path { name, .. } = base
        && env.table_fields.contains_key(name)
    {
        return Ty::Named(format!("__table_row::{name}"));
    }
    let mut cur = base.ty();
    loop {
        match cur {
            Ty::Borrow { inner, .. } => cur = *inner,
            Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => return *elem,
            Ty::BitSet(_) => return Ty::Bool,
            _ => return Ty::Unknown,
        }
    }
}

/// Resolves the static type of a [`HirQuery`] expression (`U32` for `.count()`,
/// `Option<QueryRow>` for `query_one` without `.unwrap()`, `QueryRow` otherwise).
pub(crate) fn infer_query_ty(q: &HirQuery, env: &LowerEnv<'_>) -> Ty {
    if q.is_count {
        return Ty::U32;
    }
    let terms = q
        .terms
        .iter()
        .map(|t| QueryRowTerm {
            alias: t.alias.clone(),
            storage_key: t.storage_key.clone(),
            canonical_component: t.canonical_component.clone(),
            field_name: t.field_name.clone(),
            mode: t.mode,
            ty: resolve_query_term_inner_ty(t, env),
        })
        .collect();
    let row = Ty::QueryRow(terms);
    if q.is_point_lookup && !q.is_unwrap {
        Ty::Option(Box::new(row))
    } else {
        row
    }
}

/// Resolves the underlying value/struct type of a single [`crate::hir::HirQueryTerm`] (without
/// outer `Option` wrapper), using layouts and full `item_fields`.
pub(crate) fn resolve_query_term_inner_ty(
    term: &crate::hir::HirQueryTerm,
    env: &LowerEnv<'_>,
) -> Ty {
    if let Some(ref fname) = term.field_name {
        if let Some(layout) = env.find_layout(&term.canonical_component)
            && let Some(sf) = layout.fields.iter().find(|f| f.name == *fname)
        {
            return sf.ty.clone();
        }
        if let Some(fields) = env
            .find_item_fields(&term.canonical_component)
            .or_else(|| env.find_item_fields(&term.storage_key))
            && let Some((_, fty)) = fields.iter().find(|(n, _)| n == fname)
        {
            return fty.clone();
        }
        return Ty::Unknown;
    }
    if term.storage_key == "Entity" {
        return Ty::Ref("Entity".to_owned());
    }
    Ty::Named(term.storage_key.clone())
}

/// Resolves the full semantic type of a query term including optionality (`Option<&T>` / `?&T`)
/// and borrow wrapper when projected.
pub(crate) fn resolve_query_term_ty(term: &crate::hir::HirQueryTerm, env: &LowerEnv<'_>) -> Ty {
    let inner = resolve_query_term_inner_ty(term, env);
    if term.storage_key == "Entity" && term.field_name.is_none() {
        return Ty::Ref("Entity".to_owned());
    }
    let is_opt = matches!(
        term.mode,
        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
    );
    if term.field_name.is_some() {
        let borrow = Ty::Borrow {
            mutable: term.mode.is_mutable(),
            inner: Box::new(inner),
        };
        if is_opt {
            Ty::Option(Box::new(borrow))
        } else {
            borrow
        }
    } else if is_opt {
        Ty::Option(Box::new(Ty::Borrow {
            mutable: term.mode.is_mutable(),
            inner: Box::new(inner),
        }))
    } else {
        inner
    }
}

/// Resolves the return type of a direct or method call expression, handling `Option` combinators,
/// `res`/`res_mut`/`server_res`/`client_res`, math/unit builtins, and user `fn`s.
pub(crate) fn infer_call_ty(
    recv: Option<&HirExpr>,
    callee: &str,
    generic_args: &[String],
    args: &[HirExpr],
    env: &LowerEnv<'_>,
) -> Ty {
    if recv.is_none() {
        let short_callee = callee.rsplit("::").next().unwrap_or(callee);
        match short_callee {
            "vec2" | "Vec2" => return Ty::Vec2,
            "vec3" | "Vec3" => return Ty::Vec3,
            "vec3a" | "Vec3a" => return Ty::Vec3a,
            "vec4" | "Vec4" => return Ty::Vec4,
            "ivec2" | "IVec2" => return Ty::IVec2,
            "ivec3" | "IVec3" => return Ty::IVec3,
            "uvec2" | "UVec2" => return Ty::UVec2,
            "quat" | "Quat" => return Ty::Quat,
            "rgba" | "Rgba" => return Ty::Rgba,
            "bits" => return Ty::BitSet(32),
            "sec" | "ms" => {
                return Ty::UnitScalar {
                    name: short_callee.to_owned(),
                    dim: UnitDim::SEC,
                };
            }
            "meters" => {
                return Ty::UnitScalar {
                    name: "meters".to_owned(),
                    dim: UnitDim::METERS,
                };
            }
            "mps" => {
                return Ty::UnitScalar {
                    name: "mps".to_owned(),
                    dim: UnitDim::MPS,
                };
            }
            "mps2" => {
                return Ty::UnitScalar {
                    name: "mps2".to_owned(),
                    dim: UnitDim::MPS2,
                };
            }
            "hz" => {
                return Ty::UnitScalar {
                    name: "hz".to_owned(),
                    dim: UnitDim::HZ,
                };
            }
            "rad" | "deg" => {
                return Ty::UnitScalar {
                    name: short_callee.to_owned(),
                    dim: UnitDim::RAD,
                };
            }
            "frames" => {
                return Ty::UnitScalar {
                    name: "frames".to_owned(),
                    dim: UnitDim::FRAMES,
                };
            }
            _ => {}
        }
        match callee {
            "length" | "length_sq" | "distance" | "distance_sq" | "dot" => return Ty::F32,
            "min" | "max" | "clamp" | "abs" | "floor" | "ceil" | "round" | "sqrt" | "sqr"
            | "sin" | "cos" | "tan" | "atan2" | "pow" | "lerp" | "mix" | "cross" | "normalize" => {
                return args
                    .first()
                    .map_or(Ty::F32, |a| unwrap_borrow_ty(&a.ty()).clone());
            }
            "Some" | "Option::Some" => {
                let inner = args.first().map_or(Ty::Unknown, HirExpr::ty);
                return Ty::Option(Box::new(inner));
            }
            "Option::unwrap" | "Option::expect" | "Option::unwrap_or_else" => {
                return args
                    .first()
                    .map(|a| unwrap_option_ty(&a.ty()))
                    .unwrap_or(Ty::Unknown);
            }
            "Option::unwrap_or" => {
                let primary = args
                    .first()
                    .map(|a| unwrap_option_ty(&a.ty()))
                    .unwrap_or(Ty::Unknown);
                let fallback = args.get(1).map_or(Ty::Unknown, HirExpr::ty);
                return unify_tys(&primary, &fallback);
            }
            "Option::or" => {
                let primary = args.first().map_or(Ty::Unknown, HirExpr::ty);
                let fallback = args.get(1).map_or(Ty::Unknown, HirExpr::ty);
                return unify_tys(&primary, &fallback);
            }
            "Option::or_else" | "Option::filter" => {
                return args.first().map_or(Ty::Unknown, HirExpr::ty);
            }
            "Option::and" | "Option::and_then" => {
                return args.get(1).map_or(Ty::Unknown, HirExpr::ty);
            }
            "Option::as_ref" => {
                let inner = args
                    .first()
                    .map(|a| unwrap_option_ty(&a.ty()))
                    .unwrap_or(Ty::Unknown);
                return Ty::Option(Box::new(Ty::Borrow {
                    mutable: false,
                    inner: Box::new(inner),
                }));
            }
            "Option::as_mut" => {
                let inner = args
                    .first()
                    .map(|a| unwrap_option_ty(&a.ty()))
                    .unwrap_or(Ty::Unknown);
                return Ty::Option(Box::new(Ty::Borrow {
                    mutable: true,
                    inner: Box::new(inner),
                }));
            }
            "Option::take" => {
                let inner = args
                    .first()
                    .map(|a| unwrap_option_ty(&a.ty()))
                    .unwrap_or(Ty::Unknown);
                return Ty::Option(Box::new(inner));
            }
            "res" | "res_mut" | "server_res" | "client_res" => {
                return generic_args.first().map_or(Ty::Unknown, |g| {
                    let canon = env
                        .find_layout(g)
                        .map(|l| l.canonical_name.clone())
                        .unwrap_or_else(|| g.clone());
                    Ty::Named(canon)
                });
            }
            "step_fixed" | "assert" | "assert_eq" | "assert_ne" | "assert_converged"
            | "clients" | "spawn_client" | "server_step" | "client_step" | "step_net"
            | "send_rpc" | "server_spawn" | "client_spawn" | "require_true" | "despawn"
            | "trigger" | "emit" => {
                return Ty::Unit;
            }
            _ => {
                if let Some((type_name, method)) = callee.split_once("::")
                    && method == "start"
                {
                    return Ty::Named(type_name.to_owned());
                }
                if let Some(rt) = env.fn_ret_tys.get(callee) {
                    return rt.clone();
                }
            }
        }
    } else if let Some(recv_expr) = recv {
        match callee {
            "raw" | "as_secs" | "as_millis" => return Ty::F32,
            "is_active" | "consume" | "peek" | "get" | "in" | "is_some" | "is_none" => {
                return Ty::Bool;
            }
            "count_ones" => return Ty::U32,
            "arm" | "clear" | "push" | "set" | "tick" => return Ty::Unit,
            "sample" => {
                let cname = match recv_expr {
                    HirExpr::Path { name, .. } => name.as_str(),
                    HirExpr::Field { field, .. } => field.as_str(),
                    _ => "",
                };
                if let Some(rt) = env.curve_ret_tys.get(cname) {
                    return rt.clone();
                }
                return Ty::F32;
            }
            "unwrap" | "expect" | "unwrap_or_else" => return unwrap_option_ty(&recv_expr.ty()),
            "unwrap_or" => {
                let primary = unwrap_option_ty(&recv_expr.ty());
                let fallback = args.first().map_or(Ty::Unknown, HirExpr::ty);
                return unify_tys(&primary, &fallback);
            }
            "or" => {
                let fallback = args.first().map_or(Ty::Unknown, HirExpr::ty);
                return unify_tys(&recv_expr.ty(), &fallback);
            }
            "or_else" | "filter" => return recv_expr.ty(),
            "and" | "and_then" => return args.first().map_or(Ty::Unknown, HirExpr::ty),
            "as_ref" => {
                let inner = unwrap_option_ty(&recv_expr.ty());
                return Ty::Option(Box::new(Ty::Borrow {
                    mutable: false,
                    inner: Box::new(inner),
                }));
            }
            "as_mut" => {
                let inner = unwrap_option_ty(&recv_expr.ty());
                return Ty::Option(Box::new(Ty::Borrow {
                    mutable: true,
                    inner: Box::new(inner),
                }));
            }
            "take" => {
                let inner = unwrap_option_ty(&recv_expr.ty());
                return Ty::Option(Box::new(inner));
            }
            _ => {}
        }
    }
    Ty::Unknown
}

/// Returns `true` if `call` is an `Option` combinator call whose primary target is its receiver
/// or first argument.
pub(crate) fn option_call_primary(c: &HirCall) -> Option<&HirExpr> {
    if c.receiver.is_some()
        && matches!(
            c.callee.as_str(),
            "unwrap" | "expect" | "unwrap_or" | "as_ref" | "as_mut" | "take"
        )
    {
        c.receiver.as_deref()
    } else if c.receiver.is_none()
        && matches!(
            c.callee.as_str(),
            "Option::unwrap"
                | "Option::expect"
                | "Option::unwrap_or"
                | "Option::as_ref"
                | "Option::as_mut"
                | "Option::take"
        )
    {
        c.args.first()
    } else {
        None
    }
}
