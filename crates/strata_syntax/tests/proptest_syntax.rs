#![forbid(unsafe_code)]
//! Property-based (`proptest`) invariance suites for [`strata_syntax`] lexing, CST parsing, and
//! formatting.

use proptest::prelude::*;
use strata_syntax::{format_source, lex, parse};

fn strata_fragment_strategy() -> impl Strategy<Value = String> {
    let tokens = prop::sample::select(vec![
        "module ",
        "demo::mod ",
        "@version(1.0.0);\n",
        "component ",
        "Pos ",
        "Vel ",
        "{ ",
        "} ",
        "x: f32 = 0.0, ",
        "y: i32 = 1, ",
        "sys ",
        "step() ",
        "for e in query(p: &mut Pos, v: &Vel) ",
        "e.p.x += e.v.x * 0.016; ",
        "if e.p.x < 10.0 { return; } ",
        "0..10 ",
        "// comment\n",
        "/* c */ ",
        "??? ",
        "\"str\" ",
    ]);
    prop::collection::vec(tokens, 0..32).prop_map(|parts| parts.concat())
}

proptest! {
    /// Verifies `lex` concatenates to the exact original UTF-8 source for arbitrary strings.
    #[test]
    fn lex_lossless_on_arbitrary_utf8(src in "\\PC{0,256}") {
        let tokens = lex(&src);
        let reconstructed: String = tokens.iter().map(|t| t.text).collect();
        prop_assert_eq!(reconstructed, src);
    }

    /// Verifies `parse` never panics and preserves every input byte losslessly on arbitrary strings.
    #[test]
    fn parse_is_lossless_and_panic_free_on_arbitrary_utf8(src in "\\PC{0,256}") {
        let p = parse(&src);
        prop_assert_eq!(p.syntax().text().to_string(), src);
    }

    /// Verifies `parse` on semi-structured Strata token streams never panics and preserves all bytes,
    /// and when error-free `format_source` succeeds and is strictly idempotent.
    #[test]
    fn parse_and_format_semi_structured_fragments(src in strata_fragment_strategy()) {
        let p = parse(&src);
        prop_assert_eq!(p.syntax().text().to_string(), src.as_str());
        if let Ok(f1) = format_source(&src) {
            let f2 = format_source(&f1).expect("formatted output must re-format cleanly");
            prop_assert_eq!(f1, f2);
        }
    }
}
