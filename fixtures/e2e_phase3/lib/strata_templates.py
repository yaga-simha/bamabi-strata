"""Verified reusable .strata source, sidecar, and Graph IR templates for Phase 3 E2E tests."""

from __future__ import annotations

import copy
import json
from typing import Any

from .cli_driver import CaseFailure, replace_json_scalar


def doc_pure_arithmetic() -> str:
    return """module e2e::f1_pure_math @version(1.0.0);

@node_pure
fn clamp_damage(dmg: f32, mult: f32) -> f32 {
    let raw = dmg * mult;
    if raw > 100.0 {
        100.0
    } else if raw < 0.0 {
        0.0
    } else {
        raw
    }
}

component Dummy { hp: f32 = 100.0 }
"""


def doc_pure_chain() -> str:
    return """module e2e::f1_pure_chain @version(1.0.0);

@node_pure
fn sq(x: f32) -> f32 {
    x * x
}

@node_pure
fn dist_sq(dx: f32, dy: f32) -> f32 {
    sq(dx) + sq(dy)
}
"""


def doc_node_group_basic() -> str:
    return """module e2e::f1_group_basic @version(1.0.0);

@node_group("Combat/Core")
component CombatHealth {
    hp: f32 = 100.0,
    max_hp: f32 = 100.0,
}

@node_group("Combat/Core")
@node_pure
fn scale_hit(base: f32, factor: f32) -> f32 {
    base * factor
}

@node_group("Combat/Core")
sys regen_health() {
    for h in query(c: &mut? CombatHealth) {
        if h.c.hp < h.c.max_hp {
            h.c.hp += scale_hit(1.0, 0.5);
        }
    }
}
"""


def doc_node_group_graph_items() -> str:
    return """module e2e::f1_group_items @version(1.0.0);

enum AIKind { Idle = 0, Attack = 1 }

component BossStats {
    hp: f32 = 500.0,
    phase: u8 = 0,
}

event BossRoarEvent { power: f32 }

@node_group("AI/Behavior")
table BossTier by AIKind {
    speed: f32,
} = {
    Idle   => { speed: 1.0 },
    Attack => { speed: 4.5 },
};

@node_group("AI/Behavior")
curve EnrageCurve(f32 -> f32) = [
    (0.0, 1.0),
    (0.5, 1.5),
    (1.0, 2.5),
];

@node_group("AI/Behavior")
@sparse
timeline BossSwing @rate(60_hz) @duration(12_f) {
    window windup = 0_f .. 4_f;
    window active = 4_f .. 8_f;
    at 4_f => emit(BossRoarEvent { power: 10.0 });
}

@node_group("AI/Behavior")
fsm BossFsm {
    initial Calm;
    state Calm {
        to Enraged when false;
    }
    state Enraged {
        on_tick { }
    }
}

@node_group("AI/Behavior")
task BossRecoverTask(rate: f32) on (b: &mut BossStats) {
    yield_tick;
    b.hp += rate;
}

sys boss_tick() {
    for b in query(s: &mut BossStats) {
        b.s.phase = 0;
    }
}

@node_group("AI/Behavior")
schedule FixedUpdate {
    set BossLoop { boss_tick, BossSwing, BossFsm, BossRecoverTask }
}
"""


def doc_pure_enum_match() -> str:
    return """module e2e::f1_pure_match @version(1.0.0);

enum BossPhase { PhaseOne = 0, PhaseTwo = 1, Enraged = 2 }

@node_pure
fn phase_mult(p: BossPhase) -> f32 {
    let base = 1.0;
    match p {
        BossPhase::PhaseOne => base,
        BossPhase::PhaseTwo => base * 1.5,
        BossPhase::Enraged  => base * 2.25,
    }
}
"""


def doc_pure_called_from_sys() -> str:
    return """module e2e::f1_sys_call @version(1.0.0);

component TargetHp {
    hp: f32 = 100.0,
}

@node_group("Math")
@node_pure
fn apply_mitigation(raw: f32, armor: f32) -> f32 {
    let reduced = raw - armor;
    if reduced < 1.0 {
        1.0
    } else {
        reduced
    }
}

sys tick_mitigated_damage() {
    for t in query(c: &mut TargetHp) {
        t.c.hp -= apply_mitigation(10.0, 4.0);
    }
}
"""


def doc_all_eight_graph_kinds(module_name: str = "e2e::boss_graph") -> str:
    return f"""// Header banner comment preserved across Graph IR edits
module {module_name} @version(1.0.0);

enum BossMode {{ Patrol = 0, Cleave = 1 }}

resource GraphClock {{ dt: sec = 16.6667_ms }}

@node_group("Boss/Core")
component BossHealth {{
    hp: f32 = 100.0,
    armor: f32 = 12.0,
}}

event BossStrikeEvent {{ dmg: f32 }}

@node_group("Boss/Math")
@node_pure
fn scale_boss_dmg(base: f32, rage: f32) -> f32 {{
    base * rage
}}

@node_group("Boss/Data")
table BossModeStats by BossMode {{
    mult: f32,
}} = {{
    Patrol => {{ mult: 1.0 }},
    Cleave => {{ mult: 2.0 }},
}};

@node_group("Boss/Data")
curve BossRageCurve(f32 -> f32) = [
    (0.0, 34.0),
    (100.0, 68.0),
];

// Untouched timeline comment
@node_group("Boss/AI")
@sparse
timeline BossCleaveTimeline @rate(60_hz) @duration(16_f) {{
    window startup = 0_f .. 6_f;
    window active  = 6_f .. 12_f;
    at 6_f => emit(BossStrikeEvent {{ dmg: 30.0 }});
}}

// Untouched fsm comment
@node_group("Boss/AI")
fsm BossPhaseFsm(clk: &res GraphClock) {{
    initial Idle;
    state Idle {{
        to Berserk when false;
    }}
    state Berserk {{
        on_tick {{ let _dt = clk.dt; }}
    }}
}}

// Untouched task comment
@node_group("Boss/AI")
task BossRegenTask(amount: f32) on (h: &mut BossHealth) using (clk: &res GraphClock) {{
    yield_tick;
    h.hp += scale_boss_dmg(amount, clk.dt.as_secs());
}}

sys boss_update(clk: &res GraphClock) {{
    for b in query(h: &mut BossHealth) {{
        b.h.hp = b.h.hp - 0.0 * clk.dt.as_secs();
    }}
}}

@node_group("Boss/Schedule")
schedule FixedUpdate {{
    seq BossSequence {{
        set BossStep {{ boss_update, BossCleaveTimeline, BossPhaseFsm, BossRegenTask }}
    }}
}}
"""


def doc_three_systems_for_lsp(module_name: str = "demo::boss") -> str:
    return f"""module {module_name} @version(1.0.0);

component CounterA {{ val: u32 = 0 }}
component CounterB {{ val: u32 = 0 }}
component CounterC {{ val: u32 = 0 }}

sys sys_a() {{
    for a in query(c: &mut CounterA) {{
        a.c.val += 1;
    }}
}}

sys sys_b() {{
    for b in query(c: &mut CounterB) {{
        b.c.val += 2;
    }}
}}

sys sys_c() {{
    for c in query(x: &mut CounterC) {{
        c.x.val += 3;
    }}
}}

schedule FixedUpdate {{
    seq AllSys {{
        set Step {{ sys_a, sys_b, sys_c }}
    }}
}}
"""


def doc_net_minimal(module_name: str = "e2e::net_basic") -> str:
    return f"""module {module_name} @version(1.0.0);

@authority(server)
@net(reliable, rate = 20Hz, channel = 0)
component NetPos {{
    @quantize(min = -512.0, max = 512.0, bits = 16)
    x: f32 = 0.0,
    @quantize(min = -512.0, max = 512.0, bits = 16)
    y: f32 = 0.0,
    flags: u32 = 0,
}}

@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput {{
    dx: f32,
    dy: f32,
    seq: u32,
}}

@authority(server)
sys server_tick() {{
    for p in query(pos: &mut? NetPos) {{
        if p.pos.flags != 0 {{
            p.pos.x += 1.0;
        }}
    }}
}}

@authority(client)
sys client_hud() {{
    for p in query(pos: &NetPos) {{
        let _x = p.pos.x;
    }}
}}
"""


def doc_net_quantize_bits(bits: int, min_v: float = 0.0, max_v: float = 1.0) -> str:
    return f"""module e2e::quant_bits_{bits} @version(1.0.0);

@authority(server)
@net(unreliable, rate = 30Hz, channel = 1)
component QuantSample {{
    @quantize(min = {min_v}, max = {max_v}, bits = {bits})
    sample: f32 = {min_v},
}}

@authority(server)
sys drive_quant() {{
    for q in query(s: &mut? QuantSample) {{
        if q.s.sample < {max_v} {{
            q.s.sample = {max_v};
        }}
    }}
}}
"""


def doc_net_v1_or_v2(version_two: bool = False) -> str:
    extra_field = "\n    z: f32 = 0.0," if version_two else ""
    mod = "e2e::handshake_v2" if version_two else "e2e::handshake_v1"
    return f"""module {mod} @version(1.0.0);

@authority(server)
@net(reliable, rate = 20Hz, channel = 0)
component WirePose {{
    @quantize(min = -100.0, max = 100.0, bits = 16)
    x: f32 = 0.0,
    y: f32 = 0.0,{extra_field}
}}

@authority(server)
sys update_pose() {{
    for p in query(w: &mut WirePose) {{
        p.w.x += 0.25;
    }}
}}
"""


def build_position_patch(
    exported_ir: dict[str, Any],
    updates: dict[str, tuple[float, float]],
    collapsed_updates: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Create a Graph IR patch updating positions (and optional collapsed flags) on exported nodes."""
    patched = copy.deepcopy(exported_ir)
    nodes = patched.get("nodes")
    if not isinstance(nodes, list):
        raise CaseFailure("Graph export JSON missing 'nodes' list")
    found: set[str] = set()
    for node in nodes:
        nid = node.get("id")
        if nid in updates:
            x, y = updates[nid]
            pos = node.get("position")
            if isinstance(pos, dict):
                pos["x"] = x
                pos["y"] = y
            else:
                node["position"] = {"x": x, "y": y}
            found.add(nid)
        if collapsed_updates and nid in collapsed_updates:
            pos = node.get("position")
            if not isinstance(pos, dict):
                pos = {"x": 0.0, "y": 0.0}
                node["position"] = pos
            pos["collapsed"] = collapsed_updates[nid]
    missing = set(updates.keys()) - found
    if missing:
        raise CaseFailure(f"Requested node IDs not found in Graph IR: {sorted(missing)}")
    return patched


def build_payload_patch(
    exported_ir: dict[str, Any],
    target_node_id: str,
    old_val: Any,
    new_val: Any,
) -> dict[str, Any]:
    """Create a Graph IR patch updating a scalar value inside one node's payload."""
    patched = copy.deepcopy(exported_ir)
    nodes = patched.get("nodes")
    if not isinstance(nodes, list):
        raise CaseFailure("Graph export JSON missing 'nodes' list")
    for node in nodes:
        if node.get("id") == target_node_id:
            new_payload, count = replace_json_scalar(node.get("payload"), old_val, new_val)
            if count == 0:
                raise CaseFailure(
                    f"Value {old_val!r} not found in payload of node {target_node_id!r}: {node.get('payload')!r}"
                )
            node["payload"] = new_payload
            return patched
    raise CaseFailure(f"Node ID {target_node_id!r} not found in Graph IR")


def dumps_json(obj: Any) -> str:
    return json.dumps(obj, indent=2) + "\n"
