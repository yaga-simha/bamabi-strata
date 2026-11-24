; =============================================================================
; Strata v2.0 — Zed Syntax Highlighting Queries (`highlights.scm`)
;
; Zed resolves Tree-sitter highlight captures top-to-bottom (first match wins
; for identical node ranges; child captures override enclosing parent ranges).
; Every capture name below belongs to Zed's documented theme syntax schema.
;
; Performance: exact-set predicates use native `#any-of?` / `#eq?` (zero regex
; DFA allocations), and single-char case checks use anchored 1-byte `#match?`
; patterns with redundant per-context uppercase rules folded into the global
; identifier rules.
; =============================================================================

; -----------------------------------------------------------------------------
; 1. Comments & Documentation
; -----------------------------------------------------------------------------

(doc_comment) @comment.doc
(line_comment) @comment
(block_comment) @comment

; -----------------------------------------------------------------------------
; 2. String, Character, Boolean & Numeric Literals (including SI Units)
; -----------------------------------------------------------------------------

(escape_sequence) @string.escape
(string_literal) @string
(char_literal) @string
(boolean_literal) @boolean
(unit_literal) @number
(float_literal) @number
(int_literal) @number
(semver) @number

; -----------------------------------------------------------------------------
; 3. Attributes (`@soa`, `@par`, `@authority`, `@net`, `@require`, ...)
; -----------------------------------------------------------------------------

(attribute
  "@" @attribute
  name: (identifier) @attribute)

(require_clause
  "@" @attribute
  "require" @attribute)

(attribute_argument
  key: (identifier) @property)

(require_item
  component: (path
    segment: (identifier) @type))

; -----------------------------------------------------------------------------
; 4. Types, Primitives, SI Unit Types, Containers & `@soa` Strata
; -----------------------------------------------------------------------------

; Enum declarations get `@enum` before generic `(type_identifier) @type`
(enum_declaration
  name: (type_identifier) @enum)

; Lowercase `@soa` stratum projections in types (`&mut CombatantBody::caps`)
(scoped_type_identifier
  name: (type_identifier) @label
  (#match? @label "^[a-z_]"))

; Built-in scalar, SIMD math, color, SI dimensional unit, ECS query filter,
; handle, and fixed-capacity ABI POD types (single `#any-of?` lookup)
((type_identifier) @type.builtin
  (#any-of? @type.builtin
    "u8" "u16" "u32" "u64" "usize" "u128"
    "i8" "i16" "i32" "i64" "isize" "i128"
    "f32" "f64" "fix32" "fix64"
    "bool" "char" "str" "String" "sym"
    "vec2" "vec3" "vec3a" "vec4" "ivec2" "ivec3" "uvec2"
    "quat" "Quat" "mat3" "mat4"
    "rgba8" "Rgba8" "rgba"
    "sec" "ms" "hz" "Hz" "frames" "rad" "deg" "meters" "mps" "mps2"
    "Option" "Result" "Ref" "Asset" "Trigger"
    "With" "Without" "Changed" "Added" "Allow" "Has"
    "SmallVec" "InlineStr" "BitSet" "InputBuffer" "GraceWindow"))

(self_type) @type.builtin
(type_identifier) @type

; Type/component paths in ECS clauses where `path` wraps `identifier` segments
(table_declaration
  key: (path
    segment: (identifier) @type))

(spatial_grid_declaration
  target: (path
    segment: (identifier) @type))

(spatial_history_declaration
  target: (path
    segment: (identifier) @type))

(hash_index_declaration
  target: (path
    segment: (identifier) @type))

; -----------------------------------------------------------------------------
; 5. Declarations: Systems, Observers, Tasks, Functions, FSM States & Schedules
; -----------------------------------------------------------------------------

(fn_declaration
  name: (identifier) @function)

(sys_declaration
  name: (identifier) @function)

(obs_declaration
  name: (identifier) @function)

(task_declaration
  name: (identifier) @function)

(stratum_block
  name: (identifier) @label)

(fsm_initial
  state: (identifier) @label)

(state_declaration
  name: (identifier) @label)

(transition_declaration
  target: (identifier) @label)

(timeline_window
  name: (identifier) @property)

(schedule_declaration
  name: (path
    segment: (identifier) @label))

(schedule_node
  name: (identifier) @label)

; -----------------------------------------------------------------------------
; 6. Calls: Built-in Type Constructors, ECS Intrinsics, Functions & Methods
; -----------------------------------------------------------------------------

(query_expression
  kind: _ @function.builtin)

; Built-in SIMD/unit value constructors (`vec2(...)`, `vec3(...)`, `meters(...)`)
(call_expression
  function: (identifier) @type.builtin
  (#any-of? @type.builtin
    "vec2" "vec3" "vec3a" "vec4" "ivec2" "ivec3" "uvec2"
    "quat" "mat3" "mat4" "rgba8" "rgba"
    "sec" "ms" "hz" "frames" "rad" "deg" "meters" "mps" "mps2"))

; Built-in Option/Result variant constructors (`Some(...)`, `Ok(...)`, `Err(...)`)
(call_expression
  function: (identifier) @constructor
  (#any-of? @constructor "Some" "Ok" "Err"))

; Built-in ECS, math, and deterministic simulation test intrinsics
(call_expression
  function: (identifier) @function.builtin
  (#any-of? @function.builtin
    "emit" "trigger" "despawn"
    "res" "res_mut" "server_res" "client_res"
    "step_fixed" "step_net" "server_step" "client_step"
    "clients" "spawn_client" "send_rpc" "server_spawn" "client_spawn"
    "assert" "assert_eq" "assert_ne" "assert_converged" "require_true"
    "min" "max" "clamp" "abs" "sqrt" "sin" "cos" "tan" "atan2"
    "floor" "ceil" "round" "lerp" "sum" "sqr"
    "length" "length_sq" "distance" "distance_sq" "normalize" "dot" "cross"
    "bits"))

(generic_function
  function: (identifier) @function.builtin
  (#any-of? @function.builtin "res" "res_mut" "server_res" "client_res"))

; General function and method calls
(call_expression
  function: (identifier) @function)

(call_expression
  function: (scoped_identifier
    name: (identifier) @function))

(call_expression
  function: (field_expression
    field: (field_identifier) @function.method))

(generic_function
  function: (identifier) @function)

(generic_function
  function: (scoped_identifier
    name: (identifier) @function))

(generic_function
  function: (field_expression
    field: (field_identifier) @function.method))

(query_filter_method
  name: (field_identifier) @function.method)

; -----------------------------------------------------------------------------
; 7. Constructors, Variants, Struct Literals, Patterns & Constants
; -----------------------------------------------------------------------------

(enum_variant
  name: (identifier) @constructor)

(table_row
  key: (identifier) @constructor)

(struct_literal
  type: (identifier) @type)

(struct_literal
  type: (scoped_identifier
    name: (identifier) @type))

(tuple_struct_pattern
  type: (identifier) @constructor)

(tuple_struct_pattern
  type: (scoped_identifier
    name: (identifier) @constructor))

(struct_pattern
  type: (identifier) @type)

(struct_pattern
  type: (scoped_identifier
    name: (identifier) @type))

(const_declaration
  name: (identifier) @constant)

; Built-in unit/option constants (`None`)
((identifier) @constant.builtin
  (#eq? @constant.builtin "None"))

; Built-in primitive/vector namespace prefixes (`vec3::ZERO`, `f32::EPSILON`)
(scoped_identifier
  path: (identifier) @type.builtin
  (#any-of? @type.builtin
    "u8" "u16" "u32" "u64" "i8" "i16" "i32" "i64"
    "f32" "f64" "fix32" "fix64"
    "vec2" "vec3" "vec3a" "vec4" "ivec2" "ivec3" "uvec2"
    "quat" "Quat" "mat3" "mat4" "rgba8" "Rgba8" "rgba"))

; `SCREAMING_SNAKE_CASE` constants (placed before `scoped_identifier` variant
; rule so `vec3::ZERO` resolves as `@constant` without a duplicate regex)
((identifier) @constant
  (#match? @constant "^[A-Z][A-Z0-9_]+$"))

; Enum variants (`Season::Spring`)
(scoped_identifier
  path: (identifier) @type
  name: (identifier) @constructor
  (#match? @type "^[A-Z]")
  (#match? @constructor "^[A-Z]"))

; Remaining `UpperCamelCase` identifiers (components/tables/curves/tasks in
; expressions, schedules, component_initializer, effect_entry, migrate, etc.)
((identifier) @type
  (#match? @type "^[A-Z]"))

; Lowercase segments in `field_path` and `assert_layout_declaration`
; (uppercase segments fall through to `((identifier) @type (#match? @type "^[A-Z]"))`)
(field_path
  segment: (identifier) @property
  (#match? @property "^[a-z_]"))

(assert_layout_declaration
  target: (path
    segment: (identifier) @label
    (#match? @label "^[a-z_]")))

; -----------------------------------------------------------------------------
; 8. Parameters, Projections, Fields & Special Variables
; -----------------------------------------------------------------------------

(parameter
  name: (identifier) @variable.parameter)

(system_parameter
  name: (identifier) @variable.parameter)

(migrate_declaration
  parameter: (identifier) @variable.parameter)

(query_term
  alias: (identifier) @variable.parameter)

(closure_parameter
  pattern: (identifier_pattern
    (identifier) @variable.parameter))

(spawn_batch_expression
  parameter: (identifier_pattern
    (identifier) @variable.parameter))

(net_sim_parameter
  name: (identifier) @property)

(reduce_entry
  name: (identifier) @property)

(effect_entry
  kind: (identifier) @property)

(named_argument
  name: (identifier) @property)

(field_identifier) @property

(self) @variable.special
(wildcard_pattern) @variable.special

; -----------------------------------------------------------------------------
; 9. Keywords (ECS Declarations, Control Flow, Coroutines, Transactions, Schedules)
; -----------------------------------------------------------------------------

(visibility_modifier) @keyword

[
  "module"
  "use"
  "as"
  "const"
  "type"
  "unit"
  "struct"
  "enum"
  "component"
  "tag"
  "resource"
  "event"
  "stream"
  "rpc"
  "relation"
  "table"
  "curve"
  "spatial_grid"
  "spatial_history"
  "hash_index"
  "aspect"
  "prefab"
  "object"
  "zone"
  "timeline"
  "task"
  "fsm"
  "sys"
  "obs"
  "fn"
  "migrate"
  "schedule"
  "assert_layout"
  "assert_par"
  "sim_test"
  "net_sim_test"
  "let"
  "mut"
  "uniform"
  "if"
  "else"
  "for"
  "in"
  "reduce"
  "while"
  "loop"
  "match"
  "return"
  "break"
  "continue"
  "abort_if"
  "race"
  "branch"
  "wait"
  "wait_until"
  "yield_tick"
  "atomic"
  "on_rollback"
  "spawn"
  "spawn_batch"
  "despawn_all"
  "insert"
  "remove"
  "hot"
  "cold"
  "by"
  "over"
  "key"
  "cache"
  "where"
  "window"
  "at"
  "on"
  "using"
  "initial"
  "state"
  "on_enter"
  "on_tick"
  "on_exit"
  "to"
  "when"
  "from"
  "effects"
  "run_if"
  "before"
  "after"
  "seq"
  "seq_weak"
  "par"
  "set"
  "res"
  "stream_in"
] @keyword

; -----------------------------------------------------------------------------
; 10. Punctuation & Operators (Generic `<...>` before `<`/`>` comparison ops!)
; -----------------------------------------------------------------------------

(generic_parameters
  [
    "<"
    ">"
  ] @punctuation.bracket)

(generic_args
  [
    "<"
    ">"
  ] @punctuation.bracket)

(closure_expression
  "|" @punctuation.delimiter)

(spawn_batch_expression
  "|" @punctuation.delimiter)

; Selective tick-dirtying (`&mut?`) and optional query term (`?T` / `?&T`) modifiers
(reference_type
  "?" @punctuation.special)

(optional_type
  "?" @punctuation.special)

(unary_expression
  "?" @punctuation.special)

[
  "("
  ")"
  "["
  "]"
  "{"
  "}"
] @punctuation.bracket

[
  ","
  ";"
  ":"
  "."
  "::"
] @punctuation.delimiter

[
  "="
  "+="
  "-="
  "*="
  "/="
  "%="
  "&="
  "|="
  "^="
  "<<="
  ">>="
  ".."
  "..="
  "||"
  "&&"
  "=="
  "!="
  "<"
  "<="
  ">"
  ">="
  "|"
  "^"
  "&"
  "<<"
  ">>"
  "+"
  "-"
  "*"
  "/"
  "%"
  "!"
  "~"
  "?"
  "->"
  "=>"
] @operator

; Fallback variable capture for remaining local value identifiers
(identifier) @variable
