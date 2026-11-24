; =============================================================================
; Strata v2.0 — Zed Bracket Matching Queries (`brackets.scm`)
;
; Matches balanced `()`, `[]`, `{}`, string quotes `""`, and generic `<...>`
; delimiters on `generic_parameters` / `generic_args` without misfiring on
; `<` or `>` comparison operators.
; =============================================================================

("(" @open ")" @close)
("[" @open "]" @close)
("{" @open "}" @close)

(string_literal
  "\"" @open
  "\"" @close)

(generic_parameters
  "<" @open
  ">" @close)

(generic_args
  "<" @open
  ">" @close)
