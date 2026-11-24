; =============================================================================
; Strata v2.0 — Reference Tree-sitter Syntax Highlighting Queries
; Evaluated top-to-bottom (first matching rule wins in Zed & tree-sitter CLI).
; Uses native `#any-of?` / `#eq?` predicates for exact sets (zero regex DFA
; allocations) and stays synchronized with `editors/zed/languages/strata/highlights.scm`.
; =============================================================================

; Comments
(doc_comment) @comment.doc
(line_comment) @comment
(block_comment) @comment

; Attributes
(attribute
  "@" @attribute
  name: (identifier) @attribute)
(require_clause
  "@" @attribute
  "require" @attribute)

; Built-in Primitive, Vector, Matrix, Color, SI Unit & ECS/Pod Container Types
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

; General Types
(type_identifier) @type
(self_type) @type.builtin

; Function, System, Observer & Task Declarations
(fn_declaration name: (identifier) @function)
(sys_declaration name: (identifier) @function)
(obs_declaration name: (identifier) @function)
(task_declaration name: (identifier) @function)
(migrate_declaration target: (path segment: (identifier) @type))

; Built-in ECS & Simulation Intrinsics
(query_expression kind: _ @function.builtin)

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

; Function & Method Calls
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

; Struct & Enum Constructors / Constants
(struct_literal
  type: (identifier) @type)
(struct_literal
  type: (scoped_identifier
    name: (identifier) @type))
(enum_variant
  name: (identifier) @variant)
(table_row
  key: (identifier) @variant)
(fsm_initial
  state: (identifier) @variant)
(state_declaration
  name: (identifier) @variant)
(transition_declaration
  target: (identifier) @variant)
(timeline_window
  name: (identifier) @property)

(const_declaration
  name: (identifier) @constant)
((identifier) @constant
  (#match? @constant "^[A-Z][A-Z0-9_]+$"))
(scoped_identifier
  path: (identifier) @type
  name: (identifier) @constant
  (#match? @type "^[A-Z]"))
(scoped_identifier
  path: (identifier) @namespace)

; Parameters & Fields
(parameter name: (identifier) @variable.parameter)
(system_parameter name: (identifier) @variable.parameter)
(net_sim_parameter name: (identifier) @property)
(query_term alias: (identifier) @variable.parameter)
(reduce_entry name: (identifier) @property)
(effect_entry kind: (identifier) @property)
(attribute_argument key: (identifier) @property)
(named_argument name: (identifier) @property)
(field_identifier) @property

; Self
(self) @variable.special

; Literals
(unit_literal) @number
(float_literal) @number
(int_literal) @number
(semver) @number
(boolean_literal) @boolean
(string_literal) @string
(char_literal) @string
(escape_sequence) @string.escape

; Keywords
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

; Operators
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
  "::"
] @operator

; Punctuation
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
] @punctuation.delimiter
