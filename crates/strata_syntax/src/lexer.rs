//! `logos`-backed DFA lexer for Strata v2.0.

use crate::syntax_kind::SyntaxKind;
use logos::Logos;
use rowan::{TextRange, TextSize};

/// A single lexed token with its kind, source slice, and byte [`TextRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    /// Concrete syntax kind produced by the lexer.
    pub kind: SyntaxKind,
    /// Borrowed UTF-8 slice of the original source text.
    pub text: &'a str,
    /// Byte offset range in the source text.
    pub range: TextRange,
}

fn lex_block_comment(lex: &mut logos::Lexer<'_, RawToken>) -> bool {
    let rem = lex.remainder();
    let bytes = rem.as_bytes();
    let mut depth: usize = 1;
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                lex.bump(i);
                return true;
            }
        } else {
            i += 1;
        }
    }
    // Unterminated block comment: consume remaining bytes as BlockComment (or Error) without panicking.
    lex.bump(bytes.len());
    false
}

fn lex_prefixed_int_lit(lex: &mut logos::Lexer<'_, RawToken>) {
    let slice = lex.slice().as_bytes();
    let is_digit: fn(u8) -> bool = if slice.starts_with(b"0x") {
        |b| b.is_ascii_hexdigit()
    } else if slice.starts_with(b"0b") {
        |b| matches!(b, b'0' | b'1')
    } else {
        |b| matches!(b, b'0'..=b'7')
    };

    let rem = lex.remainder().as_bytes();
    let mut i = 0usize;
    while i < rem.len() {
        if is_digit(rem[i]) || (rem[i] == b'_' && i + 1 < rem.len() && is_digit(rem[i + 1])) {
            i += 1;
        } else {
            break;
        }
    }

    for suffix in [
        &b"_u16"[..],
        b"_u32",
        b"_u64",
        b"_i16",
        b"_i32",
        b"_i64",
        b"_f32",
        b"_f64",
        b"_u8",
        b"_i8",
    ] {
        if rem[i..].starts_with(suffix) {
            i += suffix.len();
            break;
        }
    }
    lex.bump(i);
}

#[derive(Logos, Debug, Clone, Copy, PartialEq, Eq)]
enum RawToken {
    #[regex(r"[ \t\r\n]+")]
    Whitespace,

    #[regex(r"//[^\n]*")]
    LineComment,

    #[token("/*", |lex| {
        let _ = lex_block_comment(lex);
        logos::Filter::Emit(())
    })]
    BlockComment,

    // --- Keywords ---
    #[token("module")]
    KwModule,
    #[token("use")]
    KwUse,
    #[token("as")]
    KwAs,
    #[token("const")]
    KwConst,
    #[token("struct")]
    KwStruct,
    #[token("enum")]
    KwEnum,
    #[token("component")]
    KwComponent,
    #[token("tag")]
    KwTag,
    #[token("resource")]
    KwResource,
    #[token("event")]
    KwEvent,
    #[token("stream")]
    KwStream,
    #[token("relation")]
    KwRelation,
    #[token("table")]
    KwTable,
    #[token("curve")]
    KwCurve,
    #[token("spatial_grid")]
    KwSpatialGrid,
    #[token("spatial_history")]
    KwSpatialHistory,
    #[token("hash_index")]
    KwHashIndex,
    #[token("aspect")]
    KwAspect,
    #[token("prefab")]
    KwPrefab,
    #[token("object")]
    KwObject,
    #[token("timeline")]
    KwTimeline,
    #[token("task")]
    KwTask,
    #[token("fsm")]
    KwFsm,
    #[token("sys")]
    KwSys,
    #[token("obs")]
    KwObs,
    #[token("fn")]
    KwFn,
    #[token("migrate")]
    KwMigrate,
    #[token("schedule")]
    KwSchedule,
    #[token("assert_layout")]
    KwAssertLayout,
    #[token("assert_par")]
    KwAssertPar,
    #[token("sim_test")]
    KwSimTest,
    #[token("net_sim_test")]
    KwNetSimTest,
    #[token("let")]
    KwLet,
    #[token("mut")]
    KwMut,
    #[token("if")]
    KwIf,
    #[token("else")]
    KwElse,
    #[token("for")]
    KwFor,
    #[token("in")]
    KwIn,
    #[token("while")]
    KwWhile,
    #[token("loop")]
    KwLoop,
    #[token("match")]
    KwMatch,
    #[token("return")]
    KwReturn,
    #[token("break")]
    KwBreak,
    #[token("continue")]
    KwContinue,
    #[token("true")]
    KwTrue,
    #[token("false")]
    KwFalse,
    #[token("self")]
    KwSelfLower,
    #[token("Self")]
    KwSelfUpper,

    // --- Literals ---
    #[regex(r#"([0-9][0-9_]*(\.[0-9][0-9_]*)?([eE][+-]?[0-9][0-9_]*)?)_?(sec|ms|hz|Hz|frames|rad|deg|meters|mps2|mps|s|m|f)"#)]
    UnitLit,

    #[regex(r#"[0-9][0-9_]*\.[0-9][0-9_]*([eE][+-]?[0-9][0-9_]*)?(_(f32|f64))?|[0-9][0-9_]*[eE][+-]?[0-9][0-9_]*(_(f32|f64))?"#)]
    FloatLit,

    #[regex(r#"0x[0-9a-fA-F]|0b[01]|0o[0-7]"#, lex_prefixed_int_lit)]
    #[regex(r#"[0-9][0-9_]*(_(u8|u16|u32|u64|i8|i16|i32|i64|f32|f64))?"#)]
    IntLit,

    #[regex(r#""([^"\\]|\\.)*""#)]
    StringLit,

    #[regex(r#"'([^'\\]|\\.)'"#)]
    CharLit,

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]
    Ident,

    // --- Punctuation & Multi-Char Operators ---
    #[token("..=")]
    DotDotEq,
    #[token("..")]
    DotDot,
    #[token("::")]
    ColonColon,
    #[token("=>")]
    FatArrow,
    #[token("->")]
    ThinArrow,
    #[token("<=")]
    Le,
    #[token(">=")]
    Ge,
    #[token("==")]
    EqEq,
    #[token("!=")]
    Ne,
    #[token("&&")]
    AmpAmp,
    #[token("||")]
    PipePipe,
    #[token("+=")]
    PlusEq,
    #[token("-=")]
    MinusEq,
    #[token("*=")]
    StarEq,
    #[token("/=")]
    SlashEq,
    #[token("%=")]
    PercentEq,
    #[token("&=")]
    AmpEq,
    #[token("|=")]
    PipeEq,
    #[token("^=")]
    CaretEq,
    #[token("<<=")]
    ShlEq,
    #[token(">>=")]
    ShrEq,
    #[token("<<")]
    Shl,
    #[token(">>")]
    Shr,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(";")]
    Semi,
    #[token(",")]
    Comma,
    #[token(".")]
    Dot,
    #[token(":")]
    Colon,
    #[token("=")]
    Eq,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("/")]
    Slash,
    #[token("%")]
    Percent,
    #[token("!")]
    Bang,
    #[token("&")]
    Amp,
    #[token("|")]
    Pipe,
    #[token("^")]
    Caret,
    #[token("~")]
    Tilde,
    #[token("@")]
    At,
    #[token("?")]
    Question,
    #[token("#")]
    Hash,
}

impl From<RawToken> for SyntaxKind {
    fn from(raw: RawToken) -> Self {
        match raw {
            RawToken::Whitespace => Self::Whitespace,
            RawToken::LineComment => Self::LineComment,
            RawToken::BlockComment => Self::BlockComment,
            RawToken::KwModule => Self::KwModule,
            RawToken::KwUse => Self::KwUse,
            RawToken::KwAs => Self::KwAs,
            RawToken::KwConst => Self::KwConst,
            RawToken::KwStruct => Self::KwStruct,
            RawToken::KwEnum => Self::KwEnum,
            RawToken::KwComponent => Self::KwComponent,
            RawToken::KwTag => Self::KwTag,
            RawToken::KwResource => Self::KwResource,
            RawToken::KwEvent => Self::KwEvent,
            RawToken::KwStream => Self::KwStream,
            RawToken::KwRelation => Self::KwRelation,
            RawToken::KwTable => Self::KwTable,
            RawToken::KwCurve => Self::KwCurve,
            RawToken::KwSpatialGrid => Self::KwSpatialGrid,
            RawToken::KwSpatialHistory => Self::KwSpatialHistory,
            RawToken::KwHashIndex => Self::KwHashIndex,
            RawToken::KwAspect => Self::KwAspect,
            RawToken::KwPrefab => Self::KwPrefab,
            RawToken::KwObject => Self::KwObject,
            RawToken::KwTimeline => Self::KwTimeline,
            RawToken::KwTask => Self::KwTask,
            RawToken::KwFsm => Self::KwFsm,
            RawToken::KwSys => Self::KwSys,
            RawToken::KwObs => Self::KwObs,
            RawToken::KwFn => Self::KwFn,
            RawToken::KwMigrate => Self::KwMigrate,
            RawToken::KwSchedule => Self::KwSchedule,
            RawToken::KwAssertLayout => Self::KwAssertLayout,
            RawToken::KwAssertPar => Self::KwAssertPar,
            RawToken::KwSimTest => Self::KwSimTest,
            RawToken::KwNetSimTest => Self::KwNetSimTest,
            RawToken::KwLet => Self::KwLet,
            RawToken::KwMut => Self::KwMut,
            RawToken::KwIf => Self::KwIf,
            RawToken::KwElse => Self::KwElse,
            RawToken::KwFor => Self::KwFor,
            RawToken::KwIn => Self::KwIn,
            RawToken::KwWhile => Self::KwWhile,
            RawToken::KwLoop => Self::KwLoop,
            RawToken::KwMatch => Self::KwMatch,
            RawToken::KwReturn => Self::KwReturn,
            RawToken::KwBreak => Self::KwBreak,
            RawToken::KwContinue => Self::KwContinue,
            RawToken::KwTrue => Self::KwTrue,
            RawToken::KwFalse => Self::KwFalse,
            RawToken::KwSelfLower => Self::KwSelfLower,
            RawToken::KwSelfUpper => Self::KwSelfUpper,
            RawToken::UnitLit => Self::UnitLit,
            RawToken::FloatLit => Self::FloatLit,
            RawToken::IntLit => Self::IntLit,
            RawToken::StringLit => Self::StringLit,
            RawToken::CharLit => Self::CharLit,
            RawToken::Ident => Self::Ident,
            RawToken::DotDotEq => Self::DotDotEq,
            RawToken::DotDot => Self::DotDot,
            RawToken::ColonColon => Self::ColonColon,
            RawToken::FatArrow => Self::FatArrow,
            RawToken::ThinArrow => Self::ThinArrow,
            RawToken::Le => Self::Le,
            RawToken::Ge => Self::Ge,
            RawToken::EqEq => Self::EqEq,
            RawToken::Ne => Self::Ne,
            RawToken::AmpAmp => Self::AmpAmp,
            RawToken::PipePipe => Self::PipePipe,
            RawToken::PlusEq => Self::PlusEq,
            RawToken::MinusEq => Self::MinusEq,
            RawToken::StarEq => Self::StarEq,
            RawToken::SlashEq => Self::SlashEq,
            RawToken::PercentEq => Self::PercentEq,
            RawToken::AmpEq => Self::AmpEq,
            RawToken::PipeEq => Self::PipeEq,
            RawToken::CaretEq => Self::CaretEq,
            RawToken::ShlEq => Self::ShlEq,
            RawToken::ShrEq => Self::ShrEq,
            RawToken::Shl => Self::Shl,
            RawToken::Shr => Self::Shr,
            RawToken::LBrace => Self::LBrace,
            RawToken::RBrace => Self::RBrace,
            RawToken::LParen => Self::LParen,
            RawToken::RParen => Self::RParen,
            RawToken::LBracket => Self::LBracket,
            RawToken::RBracket => Self::RBracket,
            RawToken::Semi => Self::Semi,
            RawToken::Comma => Self::Comma,
            RawToken::Dot => Self::Dot,
            RawToken::Colon => Self::Colon,
            RawToken::Eq => Self::Eq,
            RawToken::Lt => Self::Lt,
            RawToken::Gt => Self::Gt,
            RawToken::Plus => Self::Plus,
            RawToken::Minus => Self::Minus,
            RawToken::Star => Self::Star,
            RawToken::Slash => Self::Slash,
            RawToken::Percent => Self::Percent,
            RawToken::Bang => Self::Bang,
            RawToken::Amp => Self::Amp,
            RawToken::Pipe => Self::Pipe,
            RawToken::Caret => Self::Caret,
            RawToken::Tilde => Self::Tilde,
            RawToken::At => Self::At,
            RawToken::Question => Self::Question,
            RawToken::Hash => Self::Hash,
        }
    }
}

/// Tokenizes `src` into lossless [`Token`]s covering every byte of `src` in order.
///
/// Unrecognized characters produce [`SyntaxKind::Error`] tokens and never panic.
pub fn lex(src: &str) -> Vec<Token<'_>> {
    let mut lexer = RawToken::lexer(src);
    let mut tokens = Vec::with_capacity(src.len() / 4 + 8);
    while let Some(res) = lexer.next() {
        let span = lexer.span();
        let kind = match res {
            Ok(raw) => SyntaxKind::from(raw),
            Err(()) => SyntaxKind::Error,
        };
        let text = lexer.slice();
        let range = TextRange::new(
            TextSize::try_from(span.start).unwrap_or(TextSize::from(0)),
            TextSize::try_from(span.end).unwrap_or(TextSize::from(0)),
        );
        tokens.push(Token { kind, text, range });
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `lex` is lossless across mixed trivia, operators, literals, and invalid ASCII/UTF-8 bytes.
    #[test]
    fn lex_covers_every_byte_without_gaps_or_panics() {
        let src = "module a::b @version(1.0.0); // comment\n/* block /* nested */ */ let x = 0..=10 + 9.81_mps2; ` @ $";
        let tokens = lex(src);
        let reconstructed: String = tokens.iter().map(|t| t.text).collect();
        assert_eq!(reconstructed, src);
        let mut cursor = 0u32;
        for tok in &tokens {
            assert_eq!(u32::from(tok.range.start()), cursor);
            cursor = u32::from(tok.range.end());
        }
        assert_eq!(cursor as usize, src.len());
        assert!(tokens.iter().any(|t| t.kind == SyntaxKind::DotDotEq));
        assert!(tokens.iter().any(|t| t.kind == SyntaxKind::Error));
    }

    /// Verifies unit-suffixed numbers and range operators tokenize distinctly.
    #[test]
    fn lex_separates_unit_literals_and_ranges() {
        let kinds: Vec<_> = lex("0..10 100_ms -9.81_mps2 2.5")
            .into_iter()
            .filter(|t| !t.kind.is_trivia())
            .map(|t| (t.kind, t.text))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (SyntaxKind::IntLit, "0"),
                (SyntaxKind::DotDot, ".."),
                (SyntaxKind::IntLit, "10"),
                (SyntaxKind::UnitLit, "100_ms"),
                (SyntaxKind::Minus, "-"),
                (SyntaxKind::UnitLit, "9.81_mps2"),
                (SyntaxKind::FloatLit, "2.5"),
            ]
        );
    }

    /// Verifies underscore-less unit literals, `net_sim_test`, contextual `rpc`, and numeric suffixes.
    #[test]
    fn lex_networking_units_and_keywords() {
        let kinds: Vec<_> = lex("net_sim_test rpc 50ms 10_ms 60Hz 1.5s 42_f32 0x1f 0.05 42")
            .into_iter()
            .filter(|t| !t.kind.is_trivia())
            .map(|t| (t.kind, t.text))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (SyntaxKind::KwNetSimTest, "net_sim_test"),
                (SyntaxKind::Ident, "rpc"),
                (SyntaxKind::UnitLit, "50ms"),
                (SyntaxKind::UnitLit, "10_ms"),
                (SyntaxKind::UnitLit, "60Hz"),
                (SyntaxKind::UnitLit, "1.5s"),
                (SyntaxKind::IntLit, "42_f32"),
                (SyntaxKind::IntLit, "0x1f"),
                (SyntaxKind::FloatLit, "0.05"),
                (SyntaxKind::IntLit, "42"),
            ]
        );
    }

    /// Verifies hex, binary, and octal integer literals keep `_u*`/`_i*`/`_f*` type suffixes attached.
    #[test]
    fn lex_non_decimal_integer_suffixes() {
        let kinds: Vec<_> = lex(
            "0x2a_u32 0x2A_u64 0b1010_u8 0o77_u16 0x2a_f32 0x10_i64 0b1010_0101_i16 0x1f 42_u32 1_000 1_000ms",
        )
        .into_iter()
        .filter(|t| !t.kind.is_trivia())
        .map(|t| (t.kind, t.text))
        .collect();
        assert_eq!(
            kinds,
            vec![
                (SyntaxKind::IntLit, "0x2a_u32"),
                (SyntaxKind::IntLit, "0x2A_u64"),
                (SyntaxKind::IntLit, "0b1010_u8"),
                (SyntaxKind::IntLit, "0o77_u16"),
                (SyntaxKind::IntLit, "0x2a_f32"),
                (SyntaxKind::IntLit, "0x10_i64"),
                (SyntaxKind::IntLit, "0b1010_0101_i16"),
                (SyntaxKind::IntLit, "0x1f"),
                (SyntaxKind::IntLit, "42_u32"),
                (SyntaxKind::IntLit, "1_000"),
                (SyntaxKind::UnitLit, "1_000ms"),
            ]
        );
    }
}
