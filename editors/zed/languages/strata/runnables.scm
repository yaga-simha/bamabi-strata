; =============================================================================
; Strata v2.0 — Zed Runnable Gutter Targets (`runnables.scm`)
;
; Pairs with `editors/zed/languages/strata/tasks.json` via `#set! tag`.
; =============================================================================

(
  (sim_test_declaration
    "sim_test" @run
    name: (string_literal
      (string_content)? @strata_test_name)) @_strata_sim_test
  (#set! tag strata-test)
)

(
  (net_sim_test_declaration
    "net_sim_test" @run
    name: (string_literal
      (string_content)? @strata_test_name)) @_strata_net_sim_test
  (#set! tag strata-test)
)

(
  (module_declaration
    "module" @run
    name: (path) @strata_module_name) @_strata_module
  (#set! tag strata-module)
)
