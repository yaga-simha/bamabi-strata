//! Canonical idempotent `stratafmt` source code formatter.

use crate::parser::{ParseError, parse};
use crate::syntax_kind::{SyntaxKind, SyntaxNode, SyntaxToken};
use rowan::NodeOrToken;

/// Formats a Strata v2.0 source file into canonical 4-space style (`stratafmt`).
///
/// Preserves all comments, normalizes whitespace and indentation, and is strictly idempotent:
/// `format_source(&format_source(src)?)? == format_source(src)?`.
pub fn format_source(src: &str) -> Result<String, Vec<ParseError>> {
    let parsed = parse(src);
    if !parsed.ok() {
        return Err(parsed.errors().to_vec());
    }
    let root = parsed.syntax();
    let mut out = String::with_capacity(src.len() + 64);
    let mut string_spans = Vec::new();
    format_node(&root, &mut out, &mut string_spans);
    // Normalize trailing whitespace per line and ensure a single trailing newline,
    // preserving multi-line string literal contents verbatim.
    let normalized = normalize_lines(&out, &string_spans);
    Ok(normalized)
}

fn normalize_lines(raw: &str, protected_spans: &[(usize, usize)]) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut empty_run = 0usize;
    let mut line_start = 0usize;
    let mut span_idx = 0usize;

    let mut i = 0usize;
    while i <= bytes.len() {
        let is_end = i == bytes.len();
        let is_nl = !is_end && bytes[i] == b'\n';
        if !is_end && !is_nl {
            i += 1;
            continue;
        }

        if is_nl {
            while span_idx < protected_spans.len() && protected_spans[span_idx].1 <= i {
                span_idx += 1;
            }
            if span_idx < protected_spans.len()
                && protected_spans[span_idx].0 <= i
                && i < protected_spans[span_idx].1
            {
                // Newline is inside a StringLit token; keep it verbatim.
                i += 1;
                continue;
            }
        }

        let line_end = i;
        let last_protected_end = protected_spans
            .iter()
            .filter(|&&(s, e)| s >= line_start && e <= line_end)
            .map(|&(_, e)| e)
            .max();

        if let Some(prot_end) = last_protected_end {
            empty_run = 0;
            out.push_str(&raw[line_start..prot_end]);
            let tail = &raw[prot_end..line_end];
            let tail = tail.strip_suffix('\r').unwrap_or(tail);
            out.push_str(tail.trim_end());
            out.push('\n');
        } else {
            let line = &raw[line_start..line_end];
            let line = line.strip_suffix('\r').unwrap_or(line);
            let trimmed_end = line.trim_end();
            if trimmed_end.is_empty() {
                empty_run += 1;
                if empty_run <= 1 && !out.is_empty() {
                    out.push('\n');
                }
            } else {
                empty_run = 0;
                out.push_str(trimmed_end);
                out.push('\n');
            }
        }

        line_start = i + 1;
        i += 1;
    }

    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

fn next_non_comment_is_newline(items: &[FmtItem], idx: usize) -> bool {
    for item in items.iter().skip(idx + 1) {
        match item {
            FmtItem::Newline { .. } => return true,
            FmtItem::Comment(_) => continue,
            FmtItem::Token { .. } => return false,
        }
    }
    false
}

fn format_node(root: &SyntaxNode, out: &mut String, string_spans: &mut Vec<(usize, usize)>) {
    // Collect tokens preserving newline intent from original trivia.
    let mut items: Vec<FmtItem> = Vec::new();
    collect_tokens(root, &mut items);

    let mut indent: usize = 0;
    let mut at_line_start = true;
    let mut prev_kind: Option<SyntaxKind> = None;
    let mut prev_prev_kind: Option<SyntaxKind> = None;
    let mut prev_in_generic = false;
    let mut prev_is_unary_op = false;
    let mut angle_depth: usize = 0;
    let mut brace_stack: Vec<bool> = Vec::new(); // true if multiline brace block
    let mut paren_stack: Vec<bool> = Vec::new(); // true if multiline paren block
    let mut bracket_stack: Vec<bool> = Vec::new(); // true if multiline bracket block

    for (idx, item) in items.iter().enumerate() {
        match item {
            FmtItem::Newline { blank } => {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                if *blank && !out.ends_with("\n\n") && !out.is_empty() {
                    out.push('\n');
                }
                at_line_start = true;
                prev_kind = None;
                prev_in_generic = false;
                prev_is_unary_op = false;
            }
            FmtItem::Comment(text) => {
                if at_line_start {
                    push_indent(out, indent);
                } else if !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push_str(text.trim_end());
                at_line_start = false;
                prev_prev_kind = prev_kind;
                prev_kind = Some(SyntaxKind::LineComment);
                prev_in_generic = false;
                prev_is_unary_op = false;
            }
            FmtItem::Token {
                kind,
                text,
                in_generic,
                is_unary_op,
            } => {
                let next_is_newline = next_non_comment_is_newline(&items, idx);

                if *kind == SyntaxKind::RBrace {
                    if let Some(was_multiline) = brace_stack.pop()
                        && was_multiline
                    {
                        indent = indent.saturating_sub(1);
                    }
                } else if *kind == SyntaxKind::RParen {
                    if let Some(was_multiline) = paren_stack.pop()
                        && was_multiline
                    {
                        indent = indent.saturating_sub(1);
                    }
                } else if *kind == SyntaxKind::RBracket
                    && let Some(was_multiline) = bracket_stack.pop()
                    && was_multiline
                {
                    indent = indent.saturating_sub(1);
                }

                if at_line_start {
                    push_indent(out, indent);
                    at_line_start = false;
                } else if let Some(pk) = prev_kind
                    && needs_space(
                        pk,
                        prev_prev_kind,
                        prev_in_generic,
                        prev_is_unary_op,
                        *kind,
                        *in_generic || angle_depth > 0,
                    )
                {
                    out.push(' ');
                }

                let tok_start = out.len();
                out.push_str(text);
                if *kind == SyntaxKind::StringLit {
                    string_spans.push((tok_start, out.len()));
                }

                if *in_generic && *kind == SyntaxKind::Lt {
                    angle_depth += 1;
                } else if angle_depth > 0 && *kind == SyntaxKind::Gt {
                    angle_depth -= 1;
                } else if angle_depth > 0 && *kind == SyntaxKind::Shr {
                    angle_depth = angle_depth.saturating_sub(2);
                }

                if *kind == SyntaxKind::LBrace {
                    if next_is_newline {
                        indent += 1;
                        brace_stack.push(true);
                    } else {
                        brace_stack.push(false);
                    }
                } else if *kind == SyntaxKind::LParen {
                    if next_is_newline {
                        indent += 1;
                        paren_stack.push(true);
                    } else {
                        paren_stack.push(false);
                    }
                } else if *kind == SyntaxKind::LBracket {
                    if next_is_newline {
                        indent += 1;
                        bracket_stack.push(true);
                    } else {
                        bracket_stack.push(false);
                    }
                }

                prev_prev_kind = prev_kind;
                prev_kind = Some(*kind);
                prev_in_generic = *in_generic;
                prev_is_unary_op = *is_unary_op;
            }
        }
    }
}

#[derive(Debug, Clone)]
enum FmtItem {
    Newline {
        blank: bool,
    },
    Comment(String),
    Token {
        kind: SyntaxKind,
        text: String,
        in_generic: bool,
        is_unary_op: bool,
    },
}

fn collect_tokens(root: &SyntaxNode, out: &mut Vec<FmtItem>) {
    fn walk(node: &SyntaxNode, in_generic: bool, out: &mut Vec<FmtItem>) {
        let node_generic = in_generic
            || matches!(
                node.kind(),
                SyntaxKind::GenericArgs | SyntaxKind::GenericParams
            );
        let is_unary_node = matches!(
            node.kind(),
            SyntaxKind::PrefixExpr | SyntaxKind::RefType | SyntaxKind::PtrTermType
        );

        for child in node.children_with_tokens() {
            match child {
                NodeOrToken::Node(sub) => walk(&sub, node_generic, out),
                NodeOrToken::Token(tok) => push_token(&tok, node_generic, is_unary_node, out),
            }
        }
    }
    walk(root, false, out);
}

fn push_token(tok: &SyntaxToken, in_generic: bool, is_unary_op: bool, out: &mut Vec<FmtItem>) {
    match tok.kind() {
        SyntaxKind::Whitespace => {
            let newlines = tok.text().bytes().filter(|&b| b == b'\n').count();
            if newlines >= 2 {
                out.push(FmtItem::Newline { blank: true });
            } else if newlines == 1 {
                out.push(FmtItem::Newline { blank: false });
            }
        }
        SyntaxKind::LineComment | SyntaxKind::BlockComment => {
            out.push(FmtItem::Comment(tok.text().to_owned()));
        }
        SyntaxKind::Eof => {}
        kind => {
            out.push(FmtItem::Token {
                kind,
                text: tok.text().to_owned(),
                in_generic,
                is_unary_op,
            });
        }
    }
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("    ");
    }
}

fn is_word_like(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::Ident
            | SyntaxKind::IntLit
            | SyntaxKind::FloatLit
            | SyntaxKind::UnitLit
            | SyntaxKind::StringLit
            | SyntaxKind::CharLit
    ) || (kind as u16 >= SyntaxKind::KwModule as u16 && kind as u16 <= SyntaxKind::KwRemove as u16)
}

fn needs_space(
    prev: SyntaxKind,
    prev_prev: Option<SyntaxKind>,
    prev_in_generic: bool,
    prev_is_unary_op: bool,
    curr: SyntaxKind,
    in_generic: bool,
) -> bool {
    use SyntaxKind::*;

    // Never insert spaces around path separators, member dots, or `@`.
    if matches!(prev, ColonColon | Dot | At) || matches!(curr, ColonColon | Dot | Semi | Comma) {
        return false;
    }

    // No space inside empty delimiters or before closing paren/bracket.
    if matches!(prev, LParen | LBracket) || matches!(curr, RParen | RBracket) {
        return false;
    }

    // Ranges (`0_f..18_f`, `a..b`): keep tight unless spaced, normalize tight around `..`/`..=`.
    if matches!(prev, DotDot | DotDotEq) || matches!(curr, DotDot | DotDotEq) {
        return false;
    }

    // Generic `<...>` and call `(...)` spacing.
    if in_generic && (prev == Lt || curr == Lt || matches!(curr, Gt | Shr)) {
        return false;
    }
    if curr == LParen {
        if prev_in_generic && matches!(prev, Gt | Shr) {
            return false;
        }
        if prev_is_unary_op && matches!(prev, Minus | Amp) {
            return false;
        }
        return matches!(
            prev,
            KwIf | KwWhile
                | KwFor
                | KwMatch
                | KwReturn
                | KwBreak
                | KwAbortIf
                | KwWait
                | KwWaitUntil
                | KwOn
                | KwUsing
                | KwRunIf
                | KwBefore
                | KwAfter
                | KwWhere
                | KwIn
                | KwAs
                | Eq
                | Comma
                | Colon
                | FatArrow
                | ThinArrow
                | Plus
                | Minus
                | Star
                | Slash
                | Percent
                | EqEq
                | Ne
                | Lt
                | Le
                | Gt
                | Ge
                | Shl
                | Shr
                | AmpAmp
                | PipePipe
                | Amp
                | Pipe
                | Caret
        );
    }

    // Prefix / reference operators stay attached to operand.
    if prev_is_unary_op && matches!(prev, Bang | Tilde | Question | Minus) {
        return false;
    }
    if prev_is_unary_op && prev == Amp && !matches!(curr, Amp | AmpAmp) {
        return false;
    }

    // Optional `?` in `&mut? T` or `?&T` stays attached to `&mut` / `&`.
    if curr == Question || (prev == Question && curr == Amp) {
        return false;
    }

    // Indexing `arr[i]` keeps `[` attached to path/expr.
    if curr == LBracket && (is_word_like(prev) || matches!(prev, RParen | RBracket)) {
        return false;
    }

    // Pipe closures `|i|`
    if prev == Pipe && matches!(prev_prev, Some(RParen)) {
        return false;
    }

    // Default: separate adjacent tokens with a single space.
    true
}

#[cfg(test)]
mod tests {
    use super::format_source;
    use crate::parse;

    /// Verifies formatter normalizes indentation, preserves comments/operators, and is idempotent.
    #[test]
    fn formatter_normalizes_and_is_idempotent() {
        let raw = "module  demo :: game  @version( 1.0.0 );\ncomponent   Pos{ x : f32=0.0,y:f32 = 0.0 }\nsys  step( ){for e in query(p :&mut? Pos){e.p.x+= -9.81_mps2 ;}}";
        let once = format_source(raw).expect("valid strata source formats");
        let twice = format_source(&once).expect("re-format succeeds");
        assert_eq!(once, twice);
        let parsed = parse(&once);
        assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
    }

    /// Verifies `RpcDecl` and `NetSimTestDecl` format idempotently and preserve `50ms`/`10ms` units.
    #[test]
    fn formatter_rpc_and_net_sim_test_idempotent() {
        let raw = r#"@net_rpc(direction=client_to_server,reliability=reliable)
rpc   MoveInput{ @quantize(min=-1.0,max=1.0,bits=12) dx:f32,dy:f32,seq:u32 }
net_sim_test  "reconciles_under_loss"(latency:50ms,jitter:10ms,loss:0.05,seed:42){
// comment preserved
send_rpc(0,MoveInput{dx:1.0,dy:0.0,seq:1});
step_net(5);
}"#;
        let once = format_source(raw).expect("valid networking strata formats");
        let twice = format_source(&once).expect("re-format succeeds");
        assert_eq!(once, twice);
        assert!(once.contains("50ms"), "50ms unit must not split: {once}");
        assert!(once.contains("10ms"), "10ms unit must not split: {once}");
        assert!(
            once.contains("\"reconciles_under_loss\"("),
            "paren stays tight to test name: {once}"
        );
        assert!(once.contains("// comment preserved"));
        let parsed = parse(&once);
        assert!(parsed.errors().is_empty(), "{:?}", parsed.errors());
    }

    /// Verifies nested generics (`> >` / `>>`), double unary refs (`& &`), multiline parens,
    /// trailing comments after `{`, and multiline string literals format idempotently and cleanly.
    #[test]
    fn formatter_handles_nested_generics_double_ref_multiline_parens_comments_and_strings() {
        // 1. Spaced nested generics `> >` and `>>` in calls and types must be strictly idempotent.
        for src in [
            "fn f() { let s = server_res<Box<SimClock> >(); }\n",
            "fn f() { let s = server_res<Box<SimClock>>(); }\n",
            "fn f(x: Box<Box<u32> >) {}\n",
            "fn f() { let s = a<b<c<u32> > >(); }\n",
            "fn f() { let x = a > (b + 1); let y = 8 >> (1 + 1); }\n",
        ] {
            let fmt1 = format_source(src).expect("fmt1");
            let fmt2 = format_source(&fmt1).expect("fmt2");
            assert_eq!(fmt1, fmt2, "non-idempotent generic formatting for {src}");
            assert!(
                parse(&fmt1).ok(),
                "re-parse failed for {fmt1}: {:?}",
                parse(&fmt1).errors()
            );
        }

        // 2. `& &x`, `& &u32`, `& &mut x` must not collapse into `&&`.
        for src in [
            "fn f(x: u32) { let p = & &x; }\n",
            "fn f(x: & &u32) {}\n",
            "fn f(x: u32) { let p = & &mut x; }\n",
        ] {
            let fmt1 = format_source(src).expect("fmt1");
            assert!(
                !fmt1.contains("&&"),
                "& & collapsed into && in {fmt1} from {src}"
            );
            let fmt2 = format_source(&fmt1).expect("fmt2");
            assert_eq!(fmt1, fmt2);
            assert!(parse(&fmt1).ok(), "re-parse failed for {fmt1}");
        }

        // 3. Multiline `(...)` with inline `)` must not leak indent to subsequent items.
        let multiline_paren = "net_sim_test \"x\"(\n    latency: 50ms,\n    jitter: 10ms) {\n    step_net(1);\n}\ncomponent After { x: f32 }\n";
        let fmt_paren = format_source(multiline_paren).expect("multiline paren");
        assert_eq!(
            fmt_paren,
            "net_sim_test \"x\"(\n    latency : 50ms,\n    jitter : 10ms) {\n    step_net(1);\n}\ncomponent After { x : f32 }\n"
        );
        assert_eq!(format_source(&fmt_paren).expect("re-fmt"), fmt_paren);

        // 4. Inline comment after `{` must preserve body indentation.
        let brace_comment = "rpc Foo { // inline comment\n    x: f32,\n}\n";
        let fmt_comment = format_source(brace_comment).expect("brace comment");
        assert_eq!(
            fmt_comment,
            "rpc Foo { // inline comment\n    x : f32,\n}\n"
        );
        assert_eq!(format_source(&fmt_comment).expect("re-fmt"), fmt_comment);

        // 5. Multiline StringLit trailing spaces and blank lines must be preserved verbatim.
        let multiline_str = "net_sim_test \"line1  \n\n\nline2\"() {\n    step_net(1);\n}\n";
        let fmt_str = format_source(multiline_str).expect("multiline string");
        assert!(
            fmt_str.contains("\"line1  \n\n\nline2\""),
            "multiline StringLit mutated: {fmt_str:?}"
        );
        assert_eq!(format_source(&fmt_str).expect("re-fmt"), fmt_str);
    }

    /// Verifies `GenericParams` + `GenericArgs` `> >` and `>>` boundary formatting and re-parse
    /// idempotence, as well as unary `-` spacing after keywords.
    #[test]
    fn formatter_generic_params_boundary_and_unary_minus_after_keywords() {
        for src in [
            "struct S<T: Box<u32> > { x: T }\n",
            "struct S<T: Box<u32>> { x: T }\n",
            "struct S<T: Box<u32>, U: Box<u32> > { x: T, y: U }\n",
            "struct S<T: Box<u32>, U: Box<u32>> { x: T, y: U }\n",
            "fn f<T: Box<u32> >(x: T) {}\n",
            "fn f<T: Box<u32>>(x: T) {}\n",
            "fn f<T: Box<Box<u32> > >(x: T) {}\n",
            "fn f<T: Box<Box<u32>>>(x: T) {}\n",
            "struct S<T: Box<Box<Box<u32>>>> { x: T }\n",
            "fn f() { let s = server_res<Box<SimClock> >(); }\n",
        ] {
            let parsed = parse(src);
            assert!(
                parsed.ok(),
                "initial parse failed for {src:?}: {:?}",
                parsed.errors()
            );
            let fmt1 = format_source(src).expect("fmt1");
            let reparsed = parse(&fmt1);
            assert!(
                reparsed.ok(),
                "re-parse failed for {fmt1:?}: {:?}",
                reparsed.errors()
            );
            let fmt2 = format_source(&fmt1).expect("fmt2");
            assert_eq!(fmt1, fmt2, "non-idempotent formatting for {src:?}");
        }

        let ret_neg = format_source("fn f(x: i32) -> i32 { return -x; }\n").expect("ret_neg");
        assert_eq!(ret_neg, "fn f(x : i32) -> i32 { return -x; }\n");
        assert_eq!(format_source(&ret_neg).expect("re-fmt"), ret_neg);

        let if_neg = format_source("fn f(x: i32) { if -x > 0 { return; } }\n").expect("if_neg");
        assert_eq!(if_neg, "fn f(x : i32) { if -x > 0 { return; } }\n");
        assert_eq!(format_source(&if_neg).expect("re-fmt"), if_neg);

        let bin_vs_unary =
            format_source("fn f(a: i32, b: i32) -> i32 { return a - -b - -(a - b); }\n")
                .expect("bin_vs_unary");
        assert_eq!(
            bin_vs_unary,
            "fn f(a : i32, b : i32) -> i32 { return a - -b - -(a - b); }\n"
        );
        assert_eq!(format_source(&bin_vs_unary).expect("re-fmt"), bin_vs_unary);
    }
}
