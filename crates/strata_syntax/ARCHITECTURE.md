# Architecture: `strata_syntax`

## Modules
- `src/syntax_kind.rs`: Complete `SyntaxKind` token/node enum and `StrataLanguage` `rowan::Language` implementation backed by a 1-to-1 `SYNTAX_KIND_TABLE` (zero transmutes).
- `src/lexer.rs`: `logos` DFA tokenizer (`lex`) covering 100% of UTF-8 input bytes, separating range operators (`..`, `..=`) from numeric/SI-unit literals (`100_ms`, `9.81_mps2`).
- `src/parser.rs`: Error-recovering recursive-descent + Pratt parser supporting Strata declarations (`module`, `component`, `resource`, `@soa`, `timeline`, `task`, `fsm`, `sys`, `obs`, `schedule`, `sim_test`, `assert_layout`, `assert_par`).
- `src/ast.rs`: Typed `rowan` AST node wrappers over raw `SyntaxNode`s.
- `src/fmt.rs`: Token-preserving idempotent formatter (`format_source`).
