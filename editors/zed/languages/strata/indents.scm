; =============================================================================
; Strata v2.0 — Zed Auto-Indentation Queries (`indents.scm`)
; =============================================================================

; Delimited blocks, parameter/argument lists, arrays, and generic lists
(_ "{" @start "}" @end) @indent
(_ "(" @start ")" @end) @indent
(_ "[" @start "]" @end) @indent
(generic_parameters "<" @start ">" @end) @indent
(generic_args "<" @start ">" @end) @indent

; Multi-line match arms
(match_arm) @indent
