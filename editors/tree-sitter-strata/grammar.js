/**
 * @file Tree-sitter grammar for Strata v2.0
 * @license MIT OR Apache-2.0
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

const PREC = {
  ASSIGN: 1,
  RANGE: 2,
  LOGICAL_OR: 3,
  LOGICAL_AND: 4,
  COMPARE: 5,
  BIT_OR: 6,
  BIT_XOR: 7,
  BIT_AND: 8,
  SHIFT: 9,
  ADD: 10,
  MUL: 11,
  CAST: 12,
  UNARY: 13,
  CALL: 14,
  FIELD: 15,
};

const NUMERIC_SUFFIX = /_(u8|u16|u32|u64|i8|i16|i32|i64|f32|f64)/;
const FLOAT_SUFFIX = /_(f32|f64)/;
const UNIT_SUFFIX = /_?(sec|ms|hz|Hz|frames|rad|deg|meters|mps2|mps|s|m|f)/;

/**
 * Builds a regex-compatible nested `/* ... *\/` sequence up to `depth` nesting levels.
 * @param {number} depth
 */
function nestedBlockComment(depth) {
  const nonDelim = choice(/[^/*]+/, /\*+[^/*]/, /\/+[^/*]/);
  if (depth <= 0) {
    return seq('/*', repeat(nonDelim), repeat('*'), '*/');
  }
  return seq(
    '/*',
    repeat(choice(nonDelim, nestedBlockComment(depth - 1))),
    repeat('*'),
    '*/',
  );
}

/**
 * Comma-separated list of zero or more `rule` occurrences with optional trailing comma.
 * @param {RuleOrLiteral} rule
 */
function commaSep(rule) {
  return optional(commaSep1(rule));
}

/**
 * Comma-separated list of one or more `rule` occurrences with optional trailing comma.
 * @param {RuleOrLiteral} rule
 */
function commaSep1(rule) {
  return seq(rule, repeat(seq(',', rule)), optional(','));
}

module.exports = grammar({
  name: 'strata',

  extras: $ => [
    /[ \t\r\n]+/,
    $.doc_comment,
    $.line_comment,
    $.block_comment,
  ],

  word: $ => $.identifier,

  supertypes: $ => [
    $._declaration,
    $._statement,
    $._expression,
    $._type,
    $._pattern,
    $._literal,
  ],

  conflicts: $ => [
    // Identifier/path followed by `{`: bare identifier in `if x { ... }` / `match m { ... }`
    // vs `Struct { ... }`.
    [$._primary_expression, $.struct_literal],
    // Standalone `{ ... }` with a single `Foo { ... }` item: `block` vs `bundle_literal`.
    [$._primary_expression, $.path],
    // Generic call `foo<T>(args)` / `x.bar<T>(args)` vs `<` comparison `a < b`.
    [$._primary_expression, $.generic_function],
    [$._expression, $.generic_function],
    // Split `>` + immediate `>` (`>>`) vs `>` comparison so nested generics `<A<B>>` never break.
    [$.binary_expression],
    // Contextual statement/expression keywords falling back to `identifier` when used as variables/calls.
    [$._contextual_expr_identifier, $.abort_if_statement],
    [$._contextual_expr_identifier, $.race_statement],
    [$._contextual_expr_identifier, $.wait_statement],
    [$._contextual_expr_identifier, $.wait_until_statement],
    [$._contextual_expr_identifier, $.yield_tick_statement],
    [$._contextual_expr_identifier, $.atomic_statement],
    [$._contextual_expr_identifier, $.spawn_expression],
    [$._contextual_expr_identifier, $.spawn_batch_expression],
    [$._contextual_expr_identifier, $.despawn_all_expression],
    [$._contextual_expr_identifier, $.insert_expression],
    [$._contextual_expr_identifier, $.remove_expression],
    [$._contextual_expr_identifier, $.query_expression],
  ],

  rules: {
    source_file: $ => repeat($._declaration),

    // =========================================================================
    // Comments
    // =========================================================================

    doc_comment: _ => token(prec(2, choice(
      seq('///', /[^/\n][^\n]*/),
      '///',
      seq('//!', /[^\n]*/),
    ))),

    line_comment: _ => token(prec(1, seq('//', /[^\n]*/))),

    block_comment: _ => token(nestedBlockComment(3)),

    // =========================================================================
    // Identifiers, Paths & Attributes
    // =========================================================================

    identifier: _ => /[a-zA-Z_][a-zA-Z0-9_]*/,

    self: _ => 'self',
    self_type: _ => 'Self',

    _contextual_expr_identifier: $ => alias(choice(
      'uniform',
      'abort_if',
      'race',
      'wait',
      'wait_until',
      'yield_tick',
      'atomic',
      'spawn',
      'spawn_batch',
      'despawn_all',
      'insert',
      'remove',
      'query',
      'query_one',
      'server_query',
      'client_query',
    ), $.identifier),

    _identifier: $ => choice(
      $.identifier,
      $._contextual_expr_identifier,
    ),

    _field_identifier: $ => choice(
      alias($.identifier, $.field_identifier),
      alias(choice(
        'self',
        'Self',
        'in',
        'match',
        'hot',
        'cold',
        'on_enter',
        'on_tick',
        'on_exit',
        'to',
        'query',
        'query_one',
        'server_query',
        'client_query',
        'spawn',
        'spawn_batch',
        'despawn_all',
        'insert',
        'remove',
        'wait',
        'wait_until',
        'yield_tick',
        'abort_if',
        'race',
        'branch',
        'atomic',
        'on_rollback',
        'uniform',
        'reduce',
      ), $.field_identifier),
    ),

    path: $ => prec.left(seq(
      field('segment', choice($._identifier, $.self, $.self_type)),
      repeat(seq('::', field('segment', choice($._identifier, $.self, $.self_type)))),
    )),

    field_path: $ => prec.left(seq(
      field('segment', $._identifier),
      repeat(seq(choice('::', '.'), field('segment', $._identifier))),
    )),

    scoped_identifier: $ => prec(1, seq(
      field('path', choice($._identifier, $.self, $.self_type, $.scoped_identifier)),
      '::',
      field('name', $._identifier),
    )),

    scoped_type_identifier: $ => prec(1, seq(
      field('path', choice(
        alias($.identifier, $.type_identifier),
        $.self,
        $.self_type,
        $.scoped_type_identifier,
      )),
      '::',
      field('name', alias($.identifier, $.type_identifier)),
    )),

    visibility_modifier: _ => 'pub',

    attribute: $ => seq(
      '@',
      field('name', $.identifier),
      optional(field('arguments', $.attribute_argument_list)),
    ),

    attribute_argument_list: $ => seq(
      '(',
      commaSep($.attribute_argument),
      ')',
    ),

    attribute_argument: $ => choice(
      $.semver,
      prec(2, seq(field('key', $.identifier), '=', field('value', $._expression))),
      field('value', $._expression),
    ),

    semver: _ => token(prec(4, /[0-9]+\.[0-9]+\.[0-9]+/)),

    require_clause: $ => prec(2, seq(
      '@',
      'require',
      '(',
      commaSep($.require_item),
      ')',
    )),

    require_item: $ => seq(
      field('component', $.path),
      optional(seq('=', field('value', $._expression))),
    ),

    _inline_modifier: $ => choice(
      $.require_clause,
      $.attribute,
    ),

    generic_parameters: $ => seq(
      '<',
      commaSep($.generic_parameter),
      '>',
    ),

    generic_parameter: $ => seq(
      field('name', alias($.identifier, $.type_identifier)),
      optional(seq(':', field('bound', $._type))),
    ),

    generic_args: $ => seq(
      '<',
      commaSep(choice(
        $._type,
        $.int_literal,
        $.float_literal,
        $.unit_literal,
      )),
      '>',
    ),

    // =========================================================================
    // Top-Level Declarations
    // =========================================================================

    _declaration: $ => choice(
      $.module_declaration,
      $.use_declaration,
      $.const_declaration,
      $.type_alias_declaration,
      $.unit_declaration,
      $.struct_declaration,
      $.enum_declaration,
      $.component_declaration,
      $.tag_declaration,
      $.resource_declaration,
      $.event_declaration,
      $.stream_declaration,
      $.rpc_declaration,
      $.relation_declaration,
      $.table_declaration,
      $.curve_declaration,
      $.spatial_grid_declaration,
      $.spatial_history_declaration,
      $.hash_index_declaration,
      $.aspect_declaration,
      $.prefab_declaration,
      $.object_declaration,
      $.zone_declaration,
      $.timeline_declaration,
      $.task_declaration,
      $.fsm_declaration,
      $.sys_declaration,
      $.obs_declaration,
      $.fn_declaration,
      $.migrate_declaration,
      $.schedule_declaration,
      $.assert_layout_declaration,
      $.assert_par_declaration,
      $.sim_test_declaration,
      $.net_sim_test_declaration,
    ),

    module_declaration: $ => seq(
      repeat($.attribute),
      'module',
      field('name', $.path),
      repeat($.attribute),
      ';',
    ),

    use_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'use',
      field('argument', $._use_clause),
      ';',
    ),

    _use_clause: $ => choice(
      $._identifier,
      $.self,
      $.self_type,
      $.scoped_identifier,
      $.use_as_clause,
      $.use_list,
      $.scoped_use_list,
      $.use_wildcard,
    ),

    use_as_clause: $ => seq(
      field('path', choice($._identifier, $.self, $.self_type, $.scoped_identifier)),
      'as',
      field('alias', $._identifier),
    ),

    scoped_use_list: $ => seq(
      field('path', choice($._identifier, $.self, $.self_type, $.scoped_identifier)),
      '::',
      field('list', $.use_list),
    ),

    use_wildcard: $ => seq(
      field('path', choice($._identifier, $.self, $.self_type, $.scoped_identifier)),
      '::',
      '*',
    ),

    use_list: $ => seq(
      '{',
      commaSep($._use_clause),
      '}',
    ),

    const_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'const',
      field('name', $.identifier),
      ':',
      field('type', $._type),
      '=',
      field('value', $._expression),
      ';',
    ),

    type_alias_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'type',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('type_parameters', $.generic_parameters)),
      '=',
      field('type', $._type),
      ';',
    ),

    unit_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'unit',
      field('name', alias($.identifier, $.type_identifier)),
      '=',
      field('type', $._type),
      ';',
    ),

    struct_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'struct',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('type_parameters', $.generic_parameters)),
      repeat($._inline_modifier),
      field('body', $.field_declaration_list),
    ),

    enum_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'enum',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('type_parameters', $.generic_parameters)),
      repeat($._inline_modifier),
      field('body', $.enum_variant_list),
    ),

    enum_variant_list: $ => seq(
      '{',
      commaSep($.enum_variant),
      '}',
    ),

    enum_variant: $ => seq(
      repeat($.attribute),
      field('name', $.identifier),
      optional(choice(
        seq('(', commaSep(choice($.field_declaration, $._type)), ')'),
        field('body', $.field_declaration_list),
        seq('=', field('value', $._expression)),
      )),
    ),

    component_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'component',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('type_parameters', $.generic_parameters)),
      repeat($._inline_modifier),
      choice(
        ';',
        field('body', $.component_body),
      ),
    ),

    component_body: $ => seq(
      '{',
      repeat(choice(
        $.stratum_block,
        seq($.field_declaration, optional(choice(',', ';'))),
      )),
      '}',
    ),

    stratum_block: $ => seq(
      choice(
        'hot',
        seq('cold', field('name', $.identifier)),
      ),
      field('body', $.field_declaration_list),
    ),

    tag_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'tag',
      commaSep1(field('name', alias($.identifier, $.type_identifier))),
      ';',
    ),

    resource_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'resource',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      choice(
        ';',
        field('body', $.field_declaration_list),
      ),
    ),

    event_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'event',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      choice(
        ';',
        field('body', $.field_declaration_list),
      ),
    ),

    stream_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'stream',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      choice(
        ';',
        field('body', $.field_declaration_list),
      ),
    ),

    rpc_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'rpc',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      choice(
        ';',
        field('body', $.field_declaration_list),
      ),
    ),

    relation_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'relation',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('flags', $.relation_flags)),
      repeat($._inline_modifier),
      choice(
        ';',
        seq(field('body', $.field_declaration_list), optional(';')),
      ),
    ),

    relation_flags: $ => seq(
      '[',
      commaSep($.identifier),
      ']',
    ),

    table_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'table',
      field('name', alias($.identifier, $.type_identifier)),
      'by',
      field('key', $.path),
      field('columns', $.field_declaration_list),
      '=',
      '{',
      commaSep($.table_row),
      '}',
      ';',
    ),

    table_row: $ => seq(
      field('key', $.identifier),
      '=>',
      field('values', $.field_initializer_list),
    ),

    curve_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'curve',
      field('name', alias($.identifier, $.type_identifier)),
      '(',
      field('domain', $._type),
      '->',
      field('codomain', $._type),
      ')',
      '=',
      '[',
      commaSep($.curve_point),
      ']',
      ';',
    ),

    curve_point: $ => seq(
      '(',
      field('x', $._expression),
      ',',
      field('y', $._expression),
      ')',
    ),

    spatial_grid_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'spatial_grid',
      field('name', alias($.identifier, $.type_identifier)),
      '(',
      optional($.field_initializer_items),
      ')',
      'over',
      field('target', $.path),
      'by',
      field('field', $.field_path),
      optional(seq('cache', '(', optional($.query_term_list), ')')),
      ';',
    ),

    spatial_history_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'spatial_history',
      field('name', alias($.identifier, $.type_identifier)),
      '(',
      optional($.field_initializer_items),
      ')',
      'over',
      field('target', $.path),
      'by',
      field('field', $.field_path),
      optional(seq('cache', '(', optional($.query_term_list), ')')),
      ';',
    ),

    hash_index_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'hash_index',
      field('name', alias($.identifier, $.type_identifier)),
      '(',
      optional($.field_initializer_items),
      ')',
      'over',
      field('target', $.path),
      'by',
      'key',
      '(',
      field('field', $.field_path),
      ')',
      optional(seq('cache', '(', optional($.query_term_list), ')')),
      ';',
    ),

    aspect_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'aspect',
      field('name', alias($.identifier, $.type_identifier)),
      '(',
      optional($.query_term_list),
      ')',
      repeat($.query_filter_method),
      optional(seq('where', field('guard', $._expression))),
      ';',
    ),

    query_filter_method: $ => seq(
      '.',
      field('name', $._field_identifier),
      optional(field('type_arguments', $.generic_args)),
      optional(field('arguments', $.argument_list)),
    ),

    prefab_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'prefab',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      field('body', $.component_initializer_list),
    ),

    object_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'object',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      field('body', $.component_initializer_list),
    ),

    zone_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'zone',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      field('body', $.field_declaration_list),
    ),

    timeline_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'timeline',
      field('name', alias($.identifier, $.type_identifier)),
      repeat($._inline_modifier),
      field('body', $.timeline_body),
    ),

    timeline_body: $ => seq(
      '{',
      repeat(choice(
        $.timeline_window,
        $.timeline_at,
      )),
      '}',
    ),

    timeline_window: $ => seq(
      'window',
      field('name', $.identifier),
      '=',
      field('range', $._expression),
      ';',
    ),

    timeline_at: $ => seq(
      'at',
      field('time', $._expression),
      '=>',
      field('action', $._statement),
    ),

    task_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'task',
      field('name', $.identifier),
      field('parameters', $.parameter_list),
      optional(seq('on', '(', optional($.query_term_list), ')')),
      repeat($.query_filter_method),
      optional(seq('using', field('using_parameters', $.system_parameter_list))),
      field('body', $.block),
    ),

    fsm_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'fsm',
      field('name', alias($.identifier, $.type_identifier)),
      optional(field('parameters', $.system_parameter_list)),
      repeat($._inline_modifier),
      field('body', $.fsm_body),
    ),

    fsm_body: $ => seq(
      '{',
      repeat(choice(
        $.fsm_initial,
        $.state_declaration,
      )),
      '}',
    ),

    fsm_initial: $ => seq(
      'initial',
      field('state', $.identifier),
      optional(field('arguments', $.field_initializer_list)),
      ';',
    ),

    state_declaration: $ => seq(
      'state',
      field('name', $.identifier),
      '{',
      repeat(choice(
        $.state_hook,
        $.transition_declaration,
        seq($.field_declaration, optional(choice(',', ';'))),
      )),
      '}',
    ),

    state_hook: $ => seq(
      field('kind', choice('on_enter', 'on_tick', 'on_exit')),
      field('body', $.block),
    ),

    transition_declaration: $ => seq(
      'to',
      field('target', $.identifier),
      optional(field('arguments', $.field_initializer_list)),
      optional(seq('when', field('guard', $._expression))),
      repeat($.attribute),
      ';',
    ),

    sys_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'sys',
      field('name', $.identifier),
      field('parameters', $.system_parameter_list),
      optional(field('effects', $.effects_clause)),
      field('body', $.block),
    ),

    obs_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'obs',
      field('name', $.identifier),
      field('parameters', $.system_parameter_list),
      optional(field('effects', $.effects_clause)),
      field('body', $.block),
    ),

    effects_clause: $ => seq(
      'effects',
      '(',
      commaSep($.effect_entry),
      ')',
    ),

    effect_entry: $ => seq(
      field('kind', $.identifier),
      ':',
      '[',
      commaSep($.path),
      ']',
    ),

    fn_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'fn',
      field('name', $.identifier),
      optional(field('type_parameters', $.generic_parameters)),
      field('parameters', $.parameter_list),
      optional(seq('->', field('return_type', $._type))),
      field('body', $.block),
    ),

    migrate_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'migrate',
      field('target', $.path),
      'from',
      field('from_version', $.semver),
      'to',
      field('to_version', $.semver),
      '(',
      field('parameter', $.identifier),
      ':',
      field('parameter_type', $._type),
      ')',
      '->',
      field('return_type', $.path),
      field('body', $.block),
    ),

    schedule_declaration: $ => seq(
      repeat($.attribute),
      optional($.visibility_modifier),
      'schedule',
      field('name', $.path),
      repeat($.schedule_modifier),
      field('body', $.schedule_body),
    ),

    schedule_body: $ => seq(
      '{',
      repeat($.schedule_node),
      '}',
    ),

    schedule_modifier: $ => choice(
      seq('run_if', '(', field('condition', $._expression), ')'),
      seq('before', '(', field('target', $.path), ')'),
      seq('after', '(', field('target', $.path), ')'),
    ),

    schedule_node: $ => choice(
      seq(
        field('kind', choice('seq', 'seq_weak', 'par', 'set')),
        field('name', $.identifier),
        repeat($.schedule_modifier),
        field('body', $.schedule_body),
      ),
      seq(
        field('target', $.path),
        repeat($.schedule_modifier),
        optional(choice(',', ';')),
      ),
    ),

    assert_layout_declaration: $ => seq(
      repeat($.attribute),
      'assert_layout',
      '(',
      field('target', $.path),
      repeat(seq(',', $._expression)),
      optional(','),
      ')',
      ';',
    ),

    assert_par_declaration: $ => seq(
      repeat($.attribute),
      'assert_par',
      '(',
      commaSep($.path),
      ')',
      ';',
    ),

    sim_test_declaration: $ => seq(
      repeat($.attribute),
      'sim_test',
      field('name', $.string_literal),
      field('body', $.block),
    ),

    net_sim_test_declaration: $ => seq(
      repeat($.attribute),
      'net_sim_test',
      field('name', $.string_literal),
      optional(field('parameters', $.net_sim_parameter_list)),
      field('body', $.block),
    ),

    net_sim_parameter_list: $ => seq(
      '(',
      commaSep($.net_sim_parameter),
      ')',
    ),

    net_sim_parameter: $ => seq(
      field('name', $.identifier),
      ':',
      field('value', $._expression),
    ),

    // =========================================================================
    // Fields, Parameters & Query Terms
    // =========================================================================

    field_declaration_list: $ => seq(
      '{',
      repeat(seq(
        $.field_declaration,
        optional(choice(',', ';')),
      )),
      '}',
    ),

    field_declaration: $ => seq(
      repeat($.attribute),
      field('name', $._field_identifier),
      ':',
      field('type', $._type),
      optional(seq('=', field('default', $._expression))),
    ),

    field_initializer_list: $ => seq(
      '{',
      optional($.field_initializer_items),
      '}',
    ),

    field_initializer_items: $ => commaSep1($.field_initializer),

    field_initializer: $ => seq(
      field('field', $._field_identifier),
      optional(seq(':', field('value', $._expression))),
    ),

    component_initializer_list: $ => seq(
      '{',
      commaSep($.component_initializer),
      '}',
    ),

    component_initializer: $ => prec.dynamic(1, seq(
      field('type', $.path),
      optional(field('fields', $.field_initializer_list)),
    )),

    parameter_list: $ => seq(
      '(',
      commaSep($.parameter),
      ')',
    ),

    parameter: $ => seq(
      field('name', $._identifier),
      ':',
      field('type', $._type),
      optional(seq('=', field('default', $._expression))),
    ),

    system_parameter_list: $ => seq(
      '(',
      commaSep($.system_parameter),
      ')',
    ),

    system_parameter: $ => seq(
      field('name', $._identifier),
      ':',
      field('type', $._type),
    ),

    query_term_list: $ => commaSep1($.query_term),

    query_term: $ => seq(
      optional(seq(field('alias', $._identifier), ':')),
      field('type', $._type),
    ),

    // =========================================================================
    // Types
    // =========================================================================

    _type: $ => choice(
      $._cast_target_type,
      $.dimensional_type,
    ),

    _cast_target_type: $ => choice(
      $.optional_type,
      $.reference_type,
      $.array_type,
      $.slice_type,
      $.tuple_type,
      $._type_atom,
    ),

    _type_atom: $ => choice(
      alias($.identifier, $.type_identifier),
      $.self_type,
      $.scoped_type_identifier,
      $.stream_in_type,
      $.field_projection_type,
      $.generic_type,
    ),

    optional_type: $ => prec.right(2, seq(
      '?',
      field('type', $._cast_target_type),
    )),

    reference_type: $ => prec.right(3, seq(
      '&',
      optional(seq('mut', optional('?'))),
      optional('res'),
      field('type', $._cast_target_type),
    )),

    stream_in_type: $ => seq(
      'stream_in',
      field('type_arguments', $.generic_args),
    ),

    field_projection_type: $ => prec.left(4, seq(
      field('type', choice(
        alias($.identifier, $.type_identifier),
        $.scoped_type_identifier,
        $.field_projection_type,
      )),
      '.',
      field('field', $._field_identifier),
    )),

    generic_type: $ => prec(5, seq(
      field('type', choice(
        alias($.identifier, $.type_identifier),
        $.scoped_type_identifier,
        $.field_projection_type,
      )),
      field('type_arguments', $.generic_args),
    )),

    array_type: $ => seq(
      '[',
      field('element', $._type),
      ';',
      field('length', $._expression),
      ']',
    ),

    slice_type: $ => seq(
      '[',
      field('element', $._type),
      ']',
    ),

    tuple_type: $ => seq(
      '(',
      commaSep($._type),
      ')',
    ),

    dimensional_type: $ => choice(
      prec.left(1, seq(field('left', $._type), field('operator', choice('*', '/')), field('right', $._type))),
      prec.left(2, seq(field('base', $._type), '^', optional('-'), field('exponent', $.int_literal))),
    ),

    // =========================================================================
    // Blocks, Statements & Patterns
    // =========================================================================

    block: $ => seq(
      '{',
      repeat($._statement),
      optional($._expression),
      '}',
    ),

    _statement: $ => choice(
      $.let_statement,
      $.uniform_let_statement,
      $.return_statement,
      $.break_statement,
      $.continue_statement,
      $.abort_if_statement,
      $.race_statement,
      $.wait_statement,
      $.wait_until_statement,
      $.yield_tick_statement,
      $.atomic_statement,
      $.while_statement,
      $.loop_statement,
      $.expression_statement,
    ),

    let_statement: $ => seq(
      'let',
      field('pattern', $._pattern),
      optional(seq(':', field('type', $._type))),
      '=',
      field('value', $._expression),
      optional(seq('else', field('alternative', $.block))),
      ';',
    ),

    uniform_let_statement: $ => seq(
      'uniform',
      'let',
      field('pattern', $._pattern),
      optional(seq(':', field('type', $._type))),
      '=',
      field('value', $._expression),
      ';',
    ),

    return_statement: $ => seq(
      'return',
      optional(field('value', $._expression)),
      ';',
    ),

    break_statement: $ => seq(
      'break',
      optional(field('value', $._expression)),
      ';',
    ),

    continue_statement: _ => seq('continue', ';'),

    abort_if_statement: $ => prec.dynamic(1, seq(
      'abort_if',
      field('condition', $._expression),
      field('consequence', $.block),
    )),

    race_statement: $ => prec.dynamic(2, seq(
      'race',
      '{',
      repeat($.branch_statement),
      '}',
    )),

    branch_statement: $ => seq(
      'branch',
      field('body', $.block),
    ),

    wait_statement: $ => prec.dynamic(1, seq(
      'wait',
      field('duration', $._expression),
      ';',
    )),

    wait_until_statement: $ => prec.dynamic(1, seq(
      'wait_until',
      field('condition', $._expression),
      ';',
    )),

    yield_tick_statement: _ => prec.dynamic(2, seq('yield_tick', ';')),

    atomic_statement: $ => prec.dynamic(2, seq(
      'atomic',
      field('body', $.block),
      optional(seq('on_rollback', field('rollback', $.block))),
    )),

    while_statement: $ => seq(
      'while',
      choice(
        seq('let', field('pattern', $._pattern), '=', field('condition', $._expression)),
        field('condition', $._expression),
      ),
      field('body', $.block),
    ),

    loop_statement: $ => seq(
      'loop',
      field('body', $.block),
    ),

    expression_statement: $ => choice(
      seq($._expression, ';'),
      prec(1, $._block_expression),
    ),

    _pattern: $ => choice(
      $.wildcard_pattern,
      $.tuple_pattern,
      $.tuple_struct_pattern,
      $.struct_pattern,
      $.literal_pattern,
      $.identifier_pattern,
      $.or_pattern,
    ),

    wildcard_pattern: _ => '_',

    tuple_pattern: $ => seq(
      '(',
      commaSep($._pattern),
      ')',
    ),

    tuple_struct_pattern: $ => seq(
      optional('mut'),
      field('type', choice($._identifier, $.scoped_identifier)),
      '(',
      commaSep($._pattern),
      ')',
    ),

    struct_pattern: $ => seq(
      field('type', choice($._identifier, $.scoped_identifier)),
      '{',
      commaSep(choice(
        seq(field('field', $._field_identifier), optional(seq(':', $._pattern))),
        '..',
      )),
      '}',
    ),

    literal_pattern: $ => seq(
      optional('-'),
      $._literal,
    ),

    identifier_pattern: $ => seq(
      optional('mut'),
      choice($._identifier, $.scoped_identifier),
    ),

    or_pattern: $ => prec.left(1, seq(
      $._pattern,
      '|',
      $._pattern,
    )),

    // =========================================================================
    // Expressions
    // =========================================================================

    _expression: $ => choice(
      $._primary_expression,
      $._block_expression,
      $.assignment_expression,
      $.range_expression,
      $.binary_expression,
      $.cast_expression,
      $.unary_expression,
      $.call_expression,
      $.field_expression,
      $.index_expression,
      $.try_expression,
      $.closure_expression,
    ),

    _block_expression: $ => choice(
      $.block,
      $.if_expression,
      $.match_expression,
      $.for_expression,
    ),

    _primary_expression: $ => choice(
      $._literal,
      $._identifier,
      $.self,
      $.self_type,
      $.scoped_identifier,
      $.parenthesized_expression,
      $.tuple_expression,
      $.array_expression,
      $.struct_literal,
      $.record_literal,
      $.bundle_literal,
      $.query_expression,
      $.spawn_expression,
      $.spawn_batch_expression,
      $.despawn_all_expression,
      $.insert_expression,
      $.remove_expression,
    ),

    parenthesized_expression: $ => seq(
      '(',
      $._expression,
      ')',
    ),

    tuple_expression: $ => seq(
      '(',
      optional(seq(
        $._expression,
        ',',
        commaSep($._expression),
      )),
      ')',
    ),

    array_expression: $ => seq(
      '[',
      optional(choice(
        seq($._expression, ';', field('length', $._expression)),
        commaSep1($._expression),
      )),
      ']',
    ),

    struct_literal: $ => prec.dynamic(-1, seq(
      field('type', choice($._identifier, $.scoped_identifier)),
      field('body', $.field_initializer_list),
    )),

    record_literal: $ => seq(
      '{',
      commaSep1($.record_field),
      '}',
    ),

    record_field: $ => seq(
      field('field', $._field_identifier),
      ':',
      field('value', $._expression),
    ),

    bundle_literal: $ => prec.dynamic(1, seq(
      '{',
      commaSep1($.component_initializer),
      '}',
    )),

    query_expression: $ => prec.dynamic(5, choice(
      seq(
        field('kind', choice('query', 'query_one', 'server_query')),
        '(',
        optional($.query_term_list),
        ')',
      ),
      seq(
        field('kind', 'client_query'),
        '(',
        field('client', $._expression),
        optional(seq(',', optional($.query_term_list))),
        ')',
      ),
    )),

    spawn_expression: $ => prec.dynamic(5, seq(
      'spawn',
      repeat($.attribute),
      field('body', $.component_initializer_list),
    )),

    spawn_batch_expression: $ => prec.dynamic(5, seq(
      'spawn_batch',
      field('arguments', $.argument_list),
      '|',
      field('parameter', $._pattern),
      '|',
      field('body', $.block),
    )),

    despawn_all_expression: $ => prec.dynamic(5, seq(
      'despawn_all',
      field('type_arguments', $.generic_args),
      field('arguments', $.argument_list),
    )),

    insert_expression: $ => prec.dynamic(5, seq(
      'insert',
      repeat(alias($.insert_attribute, $.attribute)),
      field('arguments', $.argument_list),
    )),

    insert_attribute: $ => seq(
      '@',
      field('name', $.identifier),
    ),

    remove_expression: $ => prec.dynamic(5, seq(
      'remove',
      field('type_arguments', $.generic_args),
      field('arguments', $.argument_list),
    )),

    if_expression: $ => prec.right(seq(
      'if',
      choice(
        seq('let', field('pattern', $._pattern), '=', field('condition', $._expression)),
        field('condition', $._expression),
      ),
      field('consequence', $.block),
      optional(seq('else', field('alternative', choice($.if_expression, $.block)))),
    )),

    match_expression: $ => seq(
      'match',
      field('value', $._expression),
      '{',
      repeat($.match_arm),
      '}',
    ),

    match_arm: $ => seq(
      field('pattern', $._pattern),
      optional(seq('if', field('guard', $._expression))),
      '=>',
      field('value', $._expression),
      optional(','),
    ),

    for_expression: $ => seq(
      'for',
      field('pattern', $._pattern),
      'in',
      field('iterator', $._expression),
      choice(
        field('reduce', $.reduce_clause),
        field('body', $.block),
      ),
    ),

    reduce_clause: $ => seq(
      'reduce',
      '(',
      commaSep($.reduce_entry),
      ')',
    ),

    reduce_entry: $ => seq(
      field('name', $.identifier),
      ':',
      field('value', $._expression),
    ),

    closure_expression: $ => prec.right(PREC.ASSIGN, seq(
      choice(
        '||',
        seq('|', commaSep($.closure_parameter), '|'),
      ),
      choice(
        seq('->', field('return_type', $._type), field('body', $.block)),
        field('body', $._expression),
      ),
    )),

    closure_parameter: $ => seq(
      field('pattern', $._pattern),
      optional(seq(':', field('type', $._type))),
    ),

    assignment_expression: $ => prec.right(PREC.ASSIGN, seq(
      field('left', $._expression),
      field('operator', choice(
        '=',
        '+=',
        '-=',
        '*=',
        '/=',
        '%=',
        '&=',
        '|=',
        '^=',
        '<<=',
        '>>=',
      )),
      field('right', $._expression),
    )),

    range_expression: $ => prec.left(PREC.RANGE, seq(
      field('left', $._expression),
      field('operator', choice('..', '..=')),
      field('right', $._expression),
    )),

    binary_expression: $ => {
      /** @type {[number, RuleOrLiteral][]} */
      const table = [
        [PREC.LOGICAL_OR, '||'],
        [PREC.LOGICAL_AND, '&&'],
        [PREC.COMPARE, choice('==', '!=', '<', '<=', '>', '>=')],
        [PREC.BIT_OR, '|'],
        [PREC.BIT_XOR, '^'],
        [PREC.BIT_AND, '&'],
        [PREC.SHIFT, choice('<<', alias(seq('>', token.immediate('>')), '>>'))],
        [PREC.ADD, choice('+', '-')],
        [PREC.MUL, choice('*', '/', '%')],
      ];

      return choice(...table.map(([precedence, operator]) =>
        prec.left(precedence, seq(
          field('left', $._expression),
          field('operator', operator),
          field('right', $._expression),
        )),
      ));
    },

    cast_expression: $ => prec.left(PREC.CAST, seq(
      field('value', $._expression),
      'as',
      field('type', $._cast_target_type),
    )),

    unary_expression: $ => prec.right(PREC.UNARY, choice(
      seq(
        field('operator', choice('-', '!', '~', '*')),
        field('operand', $._expression),
      ),
      seq(
        field('operator', '&'),
        optional(seq('mut', optional('?'))),
        field('operand', $._expression),
      ),
    )),

    generic_function: $ => prec.dynamic(2, seq(
      field('function', choice($._identifier, $.scoped_identifier, $.field_expression)),
      field('type_arguments', $.generic_args),
    )),

    call_expression: $ => prec.dynamic(2, prec.left(PREC.CALL, seq(
      field('function', choice($._expression, $.generic_function)),
      field('arguments', $.argument_list),
    ))),

    argument_list: $ => seq(
      '(',
      commaSep(choice(
        $.named_argument,
        $._expression,
      )),
      ')',
    ),

    named_argument: $ => seq(
      field('name', $._identifier),
      ':',
      field('value', $._expression),
    ),

    field_expression: $ => prec.left(PREC.FIELD, seq(
      field('value', $._expression),
      '.',
      field('field', $._field_identifier),
    )),

    index_expression: $ => prec.left(PREC.CALL, seq(
      field('value', $._expression),
      '[',
      field('index', $._expression),
      ']',
    )),

    try_expression: $ => prec.left(PREC.CALL, seq(
      field('value', $._expression),
      '?',
    )),

    // =========================================================================
    // Literals
    // =========================================================================

    _literal: $ => choice(
      $.unit_literal,
      $.float_literal,
      $.int_literal,
      $.string_literal,
      $.char_literal,
      $.boolean_literal,
    ),

    unit_literal: _ => token(seq(
      /[0-9][0-9_]*/,
      optional(seq('.', /[0-9][0-9_]*/)),
      optional(seq(/[eE][+-]?/, /[0-9][0-9_]*/)),
      UNIT_SUFFIX,
    )),

    float_literal: _ => token(choice(
      seq(
        /[0-9][0-9_]*/,
        '.',
        /[0-9][0-9_]*/,
        optional(seq(/[eE][+-]?/, /[0-9][0-9_]*/)),
        optional(FLOAT_SUFFIX),
      ),
      seq(
        /[0-9][0-9_]*/,
        /[eE][+-]?/,
        /[0-9][0-9_]*/,
        optional(FLOAT_SUFFIX),
      ),
    )),

    int_literal: _ => token(choice(
      seq(/0x[0-9a-fA-F](_?[0-9a-fA-F])*/, optional(NUMERIC_SUFFIX)),
      seq(/0b[01](_?[01])*/, optional(NUMERIC_SUFFIX)),
      seq(/0o[0-7](_?[0-7])*/, optional(NUMERIC_SUFFIX)),
      seq(/[0-9][0-9_]*/, optional(NUMERIC_SUFFIX)),
    )),

    string_literal: $ => seq(
      '"',
      repeat(choice(
        alias(token.immediate(prec(1, /[^"\\]+/)), $.string_content),
        $.escape_sequence,
      )),
      token.immediate('"'),
    ),

    char_literal: $ => seq(
      "'",
      choice(
        token.immediate(/[^'\\]/),
        $.escape_sequence,
      ),
      token.immediate("'"),
    ),

    escape_sequence: _ => token.immediate(seq(
      '\\',
      choice(
        /[\\'"nrt0]/,
        /x[0-9a-fA-F]{2}/,
        /u\{[0-9a-fA-F]{1,6}\}/,
        /./,
      ),
    )),

    boolean_literal: _ => choice('true', 'false'),
  },
});
