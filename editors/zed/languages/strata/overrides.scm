; =============================================================================
; Strata v2.0 — Zed Syntactic Scope Overrides (`overrides.scm`)
;
; Disables bracket/quote auto-closing (`not_in = ["string", "comment"]` in
; `config.toml`) inside string/character literals and line/doc/block comments.
; =============================================================================

[
  (doc_comment)
  (line_comment)
  (block_comment)
] @comment.inclusive

[
  (string_literal)
  (char_literal)
] @string
