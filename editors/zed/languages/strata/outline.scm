; =============================================================================
; Strata v2.0 — Zed Code Outline & Breadcrumbs (`outline.scm`)
; =============================================================================

(module_declaration
  "module" @context
  name: (path) @name) @item

(const_declaration
  "const" @context
  name: (identifier) @name) @item

(type_alias_declaration
  "type" @context
  name: (type_identifier) @name) @item

(unit_declaration
  "unit" @context
  name: (type_identifier) @name) @item

(struct_declaration
  "struct" @context
  name: (type_identifier) @name) @item

(enum_declaration
  "enum" @context
  name: (type_identifier) @name) @item

(enum_variant
  name: (identifier) @name) @item

(component_declaration
  "component" @context
  name: (type_identifier) @name) @item

(stratum_block
  "hot" @name) @item

(stratum_block
  "cold" @context
  name: (identifier) @name) @item

(tag_declaration
  "tag" @context
  name: (type_identifier) @name) @item

(resource_declaration
  "resource" @context
  name: (type_identifier) @name) @item

(event_declaration
  "event" @context
  name: (type_identifier) @name) @item

(stream_declaration
  "stream" @context
  name: (type_identifier) @name) @item

(rpc_declaration
  "rpc" @context
  name: (type_identifier) @name) @item

(relation_declaration
  "relation" @context
  name: (type_identifier) @name) @item

(table_declaration
  "table" @context
  name: (type_identifier) @name) @item

(curve_declaration
  "curve" @context
  name: (type_identifier) @name) @item

(spatial_grid_declaration
  "spatial_grid" @context
  name: (type_identifier) @name) @item

(spatial_history_declaration
  "spatial_history" @context
  name: (type_identifier) @name) @item

(hash_index_declaration
  "hash_index" @context
  name: (type_identifier) @name) @item

(aspect_declaration
  "aspect" @context
  name: (type_identifier) @name) @item

(prefab_declaration
  "prefab" @context
  name: (type_identifier) @name) @item

(object_declaration
  "object" @context
  name: (type_identifier) @name) @item

(zone_declaration
  "zone" @context
  name: (type_identifier) @name) @item

(timeline_declaration
  "timeline" @context
  name: (type_identifier) @name) @item

(timeline_window
  "window" @context
  name: (identifier) @name) @item

(task_declaration
  "task" @context
  name: (identifier) @name) @item

(fsm_declaration
  "fsm" @context
  name: (type_identifier) @name) @item

(state_declaration
  "state" @context
  name: (identifier) @name) @item

(sys_declaration
  "sys" @context
  name: (identifier) @name) @item

(obs_declaration
  "obs" @context
  name: (identifier) @name) @item

(fn_declaration
  "fn" @context
  name: (identifier) @name) @item

(migrate_declaration
  "migrate" @context
  target: (path) @name) @item

(schedule_declaration
  "schedule" @context
  name: (path) @name) @item

(schedule_node
  kind: _ @context
  name: (identifier) @name) @item

(sim_test_declaration
  "sim_test" @context
  name: (string_literal) @name) @item

(net_sim_test_declaration
  "net_sim_test" @context
  name: (string_literal) @name) @item
