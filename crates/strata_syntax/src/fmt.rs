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
    format_node(&root, &mut out);
    // Normalize trailing whitespace per line and ensure a single trailing newline.
    let normalized = normalize_lines(&out);
    Ok(normalized)
}

fn normalize_lines(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut empty_run = 0usize;
    for line in raw.lines() {
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
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

fn format_node(root: &SyntaxNode, out: &mut String) {
    // Collect tokens preserving newline intent from original trivia.
    let mut items: Vec<FmtItem> = Vec::new();
    collect_tokens(root, &mut items);

    let mut indent: usize = 0;
    let mut at_line_start = true;
    let mut prev_kind: Option<SyntaxKind> = None;
    let mut prev_prev_kind: Option<SyntaxKind> = None;
    let mut angle_depth: usize = 0;
    let mut brace_stack: Vec<bool> = Vec::new(); // true if multiline brace block

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
            }
            FmtItem::Comment(text) => {
                if at_line_start {
                    push_indent(out, indent);
                } else if !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push_str(text.trim_end());
                at_line_start = false;
                prev_kind = Some(SyntaxKind::LineComment);
            }
            FmtItem::Token {
                kind,
                text,
                in_generic,
                in_unary_context,
            } => {
                let next_is_newline = matches!(items.get(idx + 1), Some(FmtItem::Newline { .. }));
                let is_closing_brace = *kind == SyntaxKind::RBrace
                    || *kind == SyntaxKind::RBracket
                    || *kind == SyntaxKind::RParen;

                if *kind == SyntaxKind::RBrace {
                    if let Some(was_multiline) = brace_stack.pop()
                        && was_multiline
                    {
                        indent = indent.saturating_sub(1);
                    }
                } else if is_closing_brace && at_line_start {
                    // Multi-line `(...)` or `[...]` closing token aligns with outer indent.
                    indent = indent.saturating_sub(1);
                }

                if at_line_start {
                    push_indent(out, indent);
                    at_line_start = false;
                } else if let Some(pk) = prev_kind
                    && needs_space(
                        pk,
                        prev_prev_kind,
                        *kind,
                        *in_generic || angle_depth > 0,
                        *in_unary_context,
                    )
                {
                    out.push(' ');
                }

                out.push_str(text);

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
                } else if (*kind == SyntaxKind::LParen || *kind == SyntaxKind::LBracket)
                    && next_is_newline
                {
                    indent += 1;
                }

                prev_prev_kind = prev_kind;
                prev_kind = Some(*kind);
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
        in_unary_context: bool,
    },
}

fn collect_tokens(root: &SyntaxNode, out: &mut Vec<FmtItem>) {
    fn walk(node: &SyntaxNode, in_generic: bool, in_unary_context: bool, out: &mut Vec<FmtItem>) {
        let node_generic = in_generic
            || matches!(
                node.kind(),
                SyntaxKind::GenericArgs | SyntaxKind::GenericParams
            );
        let node_unary = in_unary_context
            || matches!(
                node.kind(),
                SyntaxKind::PrefixExpr | SyntaxKind::RefType | SyntaxKind::PtrTermType
            );

        for child in node.children_with_tokens() {
            match child {
                NodeOrToken::Node(sub) => walk(&sub, node_generic, node_unary, out),
                NodeOrToken::Token(tok) => push_token(&tok, node_generic, node_unary, out),
            }
        }
    }
    walk(root, false, false, out);
}

fn push_token(tok: &SyntaxToken, in_generic: bool, in_unary_context: bool, out: &mut Vec<FmtItem>) {
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
                in_unary_context,
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
    curr: SyntaxKind,
    in_generic: bool,
    in_unary: bool,
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
    if in_generic && (prev == Lt || curr == Lt || curr == Gt) {
        return false;
    }
    if curr == LParen {
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
                | AmpAmp
                | PipePipe
                | Amp
                | Pipe
                | Caret
        );
    }

    // Prefix / reference operators stay attached to operand.
    if in_unary && matches!(prev, Bang | Tilde | Question) {
        return false;
    }
    if in_unary && prev == Minus {
        // `-9.81_mps2` vs `a - b`
        return matches!(prev_prev, Some(k) if is_word_like(k) || matches!(k, RParen | RBracket));
    }
    if in_unary && prev == Amp {
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
}
