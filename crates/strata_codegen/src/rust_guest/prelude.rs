//! RustGuest runtime prelude string (`STRATA_RUNTIME_PRELUDE`).

pub(super) const STRATA_RUNTIME_PRELUDE: &str = r#"
#[derive(Clone, Copy, Debug, PartialEq)]
enum StrataPtr {
    Null,
    Slot { sid: usize, off: u32 },
    Res { decl_idx: usize, comp_id: usize, off: u32, is_mut: bool },
    ChunkCol { qi: usize, phys_col: usize, comp_id: usize, is_mut: bool, is_untracked: bool, is_sparse: bool },
    ChunkRow { qi: usize, phys_col: usize, comp_id: usize, row: usize, off: u32, is_mut: bool, is_untracked: bool, is_sparse: bool },
    ChunkEntities { qi: usize },
    SpatialHits { idx: usize },
    EntityPoint { qi: usize, phys_col: usize, comp_id: usize, entity: FfiEntity, off: u32, is_mut: bool },
    EventPayload { off: u32 },
    MigrateSrc { off: u32 },
    MigrateDst { off: u32 },
}

impl StrataPtr {
    fn with_added_offset(self, add_off: u32) -> Self {
        match self {
            Self::Slot { sid, off } => Self::Slot { sid, off: off.saturating_add(add_off) },
            Self::Res { decl_idx, comp_id, off, is_mut } => Self::Res { decl_idx, comp_id, off: off.saturating_add(add_off), is_mut },
            Self::ChunkRow { qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse } => {
                Self::ChunkRow { qi, phys_col, comp_id, row, off: off.saturating_add(add_off), is_mut, is_untracked, is_sparse }
            }
            Self::EntityPoint { qi, phys_col, comp_id, entity, off, is_mut } => {
                Self::EntityPoint { qi, phys_col, comp_id, entity, off: off.saturating_add(add_off), is_mut }
            }
            Self::EventPayload { off } => Self::EventPayload { off: off.saturating_add(add_off) },
            Self::MigrateSrc { off } => Self::MigrateSrc { off: off.saturating_add(add_off) },
            Self::MigrateDst { off } => Self::MigrateDst { off: off.saturating_add(add_off) },
            other => other,
        }
    }

    fn set_exact_offset(self, exact_off: u32) -> Self {
        match self {
            Self::Slot { sid, .. } => Self::Slot { sid, off: exact_off },
            Self::Res { decl_idx, comp_id, is_mut, .. } => Self::Res { decl_idx, comp_id, off: exact_off, is_mut },
            Self::ChunkRow { qi, phys_col, comp_id, row, is_mut, is_untracked, is_sparse, .. } => {
                Self::ChunkRow { qi, phys_col, comp_id, row, off: exact_off, is_mut, is_untracked, is_sparse }
            }
            Self::EntityPoint { qi, phys_col, comp_id, entity, is_mut, .. } => {
                Self::EntityPoint { qi, phys_col, comp_id, entity, off: exact_off, is_mut }
            }
            Self::EventPayload { .. } => Self::EventPayload { off: exact_off },
            Self::MigrateSrc { .. } => Self::MigrateSrc { off: exact_off },
            Self::MigrateDst { .. } => Self::MigrateDst { off: exact_off },
            other => other,
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Self::Null => true,
            Self::EntityPoint { entity, .. } => entity.is_null(),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
enum StrataVal {
    Unit,
    Bool(bool),
    I32(i32),
    Fix32(i32),
    U32(u32),
    I64(i64),
    Fix64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Vec2([f32; 2]),
    Vec3([f32; 3]),
    Vec4([f32; 4]),
    IVec2([i32; 2]),
    IVec3([i32; 3]),
    UVec2([u32; 2]),
    Entity(FfiEntity),
    Asset(FfiAssetHandle),
    Str(String),
    Checkpoint(usize),
    Ptr(StrataPtr),
    Arr(Vec<StrataVal>),
    Words(Vec<u32>),
    Obj(StrataObj),
}

impl Default for StrataVal {
    fn default() -> Self {
        Self::Unit
    }
}

impl StrataVal {
    fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::I32(v) | Self::Fix32(v) => *v != 0,
            Self::U32(v) => *v != 0,
            Self::I64(v) | Self::Fix64(v) => *v != 0,
            Self::U64(v) => *v != 0,
            Self::F32(v) => *v != 0.0,
            Self::F64(v) => *v != 0.0,
            Self::Entity(e) => !e.is_null(),
            Self::Ptr(p) => !p.is_null(),
            Self::Obj(_) => true,
            _ => false,
        }
    }

    fn as_i32(&self) -> i32 {
        match self {
            Self::Bool(b) => i32::from(*b),
            Self::I32(v) => *v,
            Self::Fix32(v) => *v / 65_536,
            Self::U32(v) => *v as i32,
            Self::I64(v) => *v as i32,
            Self::Fix64(v) => (*v / 4_294_967_296) as i32,
            Self::U64(v) => *v as i32,
            Self::F32(v) => *v as i32,
            Self::F64(v) => *v as i32,
            _ => 0,
        }
    }

    fn as_u32(&self) -> u32 {
        match self {
            Self::Bool(b) => u32::from(*b),
            Self::I32(v) => *v as u32,
            Self::Fix32(v) => (*v / 65_536) as u32,
            Self::U32(v) => *v,
            Self::I64(v) => *v as u32,
            Self::Fix64(v) => (*v / 4_294_967_296) as u32,
            Self::U64(v) => *v as u32,
            Self::F32(v) => *v as u32,
            Self::F64(v) => *v as u32,
            Self::Entity(e) => e.to_bits() as u32,
            _ => 0,
        }
    }

    fn as_i64(&self) -> i64 {
        match self {
            Self::Bool(b) => i64::from(*b),
            Self::I32(v) => i64::from(*v),
            Self::Fix32(v) => i64::from(*v / 65_536),
            Self::U32(v) => i64::from(*v),
            Self::I64(v) => *v,
            Self::Fix64(v) => *v / 4_294_967_296,
            Self::U64(v) => *v as i64,
            Self::F32(v) => *v as i64,
            Self::F64(v) => *v as i64,
            Self::Entity(e) => e.to_bits() as i64,
            _ => 0,
        }
    }

    fn as_u64(&self) -> u64 {
        match self {
            Self::Bool(b) => u64::from(*b),
            Self::I32(v) => *v as u64,
            Self::Fix32(v) => (*v / 65_536) as u64,
            Self::U32(v) => u64::from(*v),
            Self::I64(v) => *v as u64,
            Self::Fix64(v) => (*v / 4_294_967_296) as u64,
            Self::U64(v) => *v,
            Self::F32(v) => *v as u64,
            Self::F64(v) => *v as u64,
            Self::Entity(e) => e.to_bits(),
            _ => 0,
        }
    }

    fn as_f32(&self) -> f32 {
        match self {
            Self::Bool(b) => if *b { 1.0 } else { 0.0 },
            Self::I32(v) => *v as f32,
            Self::Fix32(v) => (*v as f32) / 65_536.0,
            Self::U32(v) => *v as f32,
            Self::I64(v) => *v as f32,
            Self::Fix64(v) => ((*v as f64) / 4_294_967_296.0) as f32,
            Self::U64(v) => *v as f32,
            Self::F32(v) => *v,
            Self::F64(v) => *v as f32,
            _ => 0.0,
        }
    }

    fn as_f64(&self) -> f64 {
        match self {
            Self::Bool(b) => if *b { 1.0 } else { 0.0 },
            Self::I32(v) => f64::from(*v),
            Self::Fix32(v) => f64::from(*v) / 65_536.0,
            Self::U32(v) => f64::from(*v),
            Self::I64(v) => *v as f64,
            Self::Fix64(v) => (*v as f64) / 4_294_967_296.0,
            Self::U64(v) => *v as f64,
            Self::F32(v) => f64::from(*v),
            Self::F64(v) => *v,
            _ => 0.0,
        }
    }

    fn as_fix32(&self) -> i32 {
        match self {
            Self::Fix32(v) => *v,
            Self::Fix64(v) => (*v >> 16) as i32,
            Self::I32(v) => i64::from(*v).saturating_mul(65_536) as i32,
            Self::I64(v) => v.saturating_mul(65_536) as i32,
            Self::U32(v) => i64::from(*v).saturating_mul(65_536) as i32,
            Self::U64(v) => (*v as i64).saturating_mul(65_536) as i32,
            Self::F32(v) => {
                if v.is_finite() {
                    (f64::from(*v) * 65_536.0).round() as i32
                } else {
                    0
                }
            }
            Self::F64(v) => {
                if v.is_finite() {
                    (*v * 65_536.0).round() as i32
                } else {
                    0
                }
            }
            Self::Bool(b) => if *b { 65_536 } else { 0 },
            _ => 0,
        }
    }

    fn as_fix64(&self) -> i64 {
        match self {
            Self::Fix64(v) => *v,
            Self::Fix32(v) => i64::from(*v) << 16,
            Self::I32(v) => i64::from(*v).wrapping_shl(32),
            Self::I64(v) => v.wrapping_shl(32),
            Self::U32(v) => i64::from(*v).wrapping_shl(32),
            Self::U64(v) => (*v as i64).wrapping_shl(32),
            Self::F32(v) => {
                if v.is_finite() {
                    (f64::from(*v) * 4_294_967_296.0).round() as i64
                } else {
                    0
                }
            }
            Self::F64(v) => {
                if v.is_finite() {
                    (*v * 4_294_967_296.0).round() as i64
                } else {
                    0
                }
            }
            Self::Bool(b) => if *b { 1i64 << 32 } else { 0 },
            _ => 0,
        }
    }

    fn as_vec2(&self) -> [f32; 2] {
        match self {
            Self::Vec2(v) => *v,
            Self::Vec3(v) => [v[0], v[1]],
            Self::Vec4(v) => [v[0], v[1]],
            Self::F32(s) => [*s, *s],
            Self::F64(s) => [*s as f32, *s as f32],
            _ => [0.0, 0.0],
        }
    }

    fn as_vec3(&self) -> [f32; 3] {
        match self {
            Self::Vec3(v) => *v,
            Self::Vec4(v) => [v[0], v[1], v[2]],
            Self::Vec2(v) => [v[0], v[1], 0.0],
            Self::F32(s) => [*s, *s, *s],
            _ => [0.0, 0.0, 0.0],
        }
    }

    fn as_vec4(&self) -> [f32; 4] {
        match self {
            Self::Vec4(v) => *v,
            Self::Vec3(v) => [v[0], v[1], v[2], 0.0],
            Self::Vec2(v) => [v[0], v[1], 0.0, 0.0],
            Self::F32(s) => [*s, *s, *s, *s],
            _ => [0.0, 0.0, 0.0, 0.0],
        }
    }

    fn as_ivec2(&self) -> [i32; 2] {
        match self {
            Self::IVec2(v) => *v,
            Self::Vec2(v) => [v[0] as i32, v[1] as i32],
            _ => [0, 0],
        }
    }

    fn as_ivec3(&self) -> [i32; 3] {
        match self {
            Self::IVec3(v) => *v,
            Self::Vec3(v) => [v[0] as i32, v[1] as i32, v[2] as i32],
            _ => [0, 0, 0],
        }
    }

    fn as_uvec2(&self) -> [u32; 2] {
        match self {
            Self::UVec2(v) => *v,
            Self::Vec2(v) => [v[0] as u32, v[1] as u32],
            _ => [0, 0],
        }
    }

    fn as_entity(&self) -> FfiEntity {
        match self {
            Self::Entity(e) => *e,
            Self::U64(u) => FfiEntity::from_bits(*u),
            Self::I64(i) => FfiEntity::from_bits(*i as u64),
            _ => FfiEntity::NULL,
        }
    }

    fn as_ptr(&self) -> StrataPtr {
        match self {
            Self::Ptr(p) => *p,
            _ => StrataPtr::Null,
        }
    }

    fn as_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            _ => String::new(),
        }
    }

    fn as_checkpoint(&self) -> usize {
        match self {
            Self::Checkpoint(c) => *c,
            Self::U64(v) => *v as usize,
            Self::U32(v) => *v as usize,
            _ => 0,
        }
    }
}

trait StrataLePack {
    fn strata_pack(&self, out: &mut Vec<u8>);
    fn strata_unpack(&mut self, bytes: &[u8]);
}

impl StrataLePack for u64 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])); }
}
impl StrataLePack for u32 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0u8; 4])); }
}
impl StrataLePack for u16 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u16::from_le_bytes(bytes[..2].try_into().unwrap_or([0u8; 2])); }
}
impl StrataLePack for u8 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.push(*self); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = bytes[0]; }
}

fn strata_push_le_into<T: StrataLePack>(out: &mut Vec<u8>, v: T) {
    v.strata_pack(out);
}

const fn strata_write_le_bytes<const N: usize, const M: usize>(
    out: &mut [u8; N],
    off: usize,
    bytes: [u8; M],
) {
    let mut i = 0usize;
    while i < M {
        if off + i < N {
            out[off + i] = bytes[i];
        }
        i += 1;
    }
}

fn strata_copy_le_slice<T: StrataLePack>(dst: &mut T, bytes: &[u8]) {
    dst.strata_unpack(bytes);
}

fn strata_short_key(name: &str) -> &str {
    name.trim()
}

fn strata_decode_sub_field(bytes: &[u8], off: usize, field: &str) -> StrataVal {
    let rem = bytes.get(off..).unwrap_or(&[]);
    if rem.len() >= 4 {
        let w0 = u32::from_le_bytes(rem[0..4].try_into().unwrap_or([0u8; 4]));
        if field.contains("is_") || field.contains("has_") || field.contains("active") || field.contains("flag") {
            return StrataVal::Bool(rem[0] != 0);
        }
        if rem.len() >= 8 && (field == "xy" || field == "vel" || field == "pos") {
            let f0 = f32::from_bits(w0);
            let f1 = f32::from_le_bytes(rem[4..8].try_into().unwrap_or([0u8; 4]));
            return StrataVal::Vec2([f0, f1]);
        }
        return StrataVal::F32(f32::from_bits(w0));
    } else if !rem.is_empty() {
        return StrataVal::U32(u32::from(rem[0]));
    }
    StrataVal::Unit
}

fn strata_coerce_arr_fix32(v: StrataVal) -> StrataVal {
    match v {
        StrataVal::Arr(xs) => StrataVal::Arr(xs.into_iter().map(strata_coerce_arr_fix32).collect()),
        other => StrataVal::Fix32(other.as_fix32()),
    }
}

fn strata_coerce_arr_fix64(v: StrataVal) -> StrataVal {
    match v {
        StrataVal::Arr(xs) => StrataVal::Arr(xs.into_iter().map(strata_coerce_arr_fix64).collect()),
        other => StrataVal::Fix64(other.as_fix64()),
    }
}

fn strata_encode_sub_field(bytes: &mut [u8], off: usize, val: &StrataVal) {
    let Some(dst) = bytes.get_mut(off..) else { return; };
    match val {
        StrataVal::Bool(b) => { if !dst.is_empty() { dst[0] = u8::from(*b); } }
        StrataVal::I32(v) | StrataVal::Fix32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::U32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::I64(v) | StrataVal::Fix64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::U64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::F32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::F64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::Vec2(v) => {
            if dst.len() >= 8 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
            }
        }
        StrataVal::Vec3(v) => {
            if dst.len() >= 12 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
                dst[8..12].copy_from_slice(&v[2].to_le_bytes());
            }
        }
        StrataVal::Vec4(v) => {
            if dst.len() >= 16 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
                dst[8..12].copy_from_slice(&v[2].to_le_bytes());
                dst[12..16].copy_from_slice(&v[3].to_le_bytes());
            }
        }
        StrataVal::Entity(e) => {
            if dst.len() >= 8 { dst[..8].copy_from_slice(&e.to_bits().to_le_bytes()); }
        }
        StrataVal::Words(w) => {
            for (i, word) in w.iter().enumerate() {
                if i * 4 + 4 <= dst.len() {
                    dst[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
            }
        }
        _ => {}
    }
}

fn strata_bytes_read_f32(b: &[u8], off: usize) -> f32 {
    if off + 4 <= b.len() {
        f32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0u8; 4]))
    } else {
        0.0
    }
}

fn strata_bytes_write_f32(b: &mut [u8], off: usize, v: f32) {
    if off + 4 <= b.len() {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_bytes_read_u16(b: &[u8], off: usize) -> u16 {
    if off + 2 <= b.len() {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap_or([0u8; 2]))
    } else {
        0
    }
}

fn strata_bytes_write_u16(b: &mut [u8], off: usize, v: u16) {
    if off + 2 <= b.len() {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_bytes_read_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 <= b.len() {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0u8; 4]))
    } else {
        0
    }
}

fn strata_bytes_write_u32(b: &mut [u8], off: usize, v: u32) {
    if off + 4 <= b.len() {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_grace_arm_bytes(b: &mut [u8], off: usize, dur: f32) {
    let cur = strata_bytes_read_f32(b, off);
    strata_bytes_write_f32(b, off, if dur > cur { dur } else { cur });
}

fn strata_grace_tick_bytes(b: &mut [u8], off: usize, dt: f32) {
    let cur = strata_bytes_read_f32(b, off);
    let nxt = (cur - dt).max(0.0);
    strata_bytes_write_f32(b, off, nxt);
}

fn strata_grace_active_bytes(b: &[u8], off: usize) -> bool {
    strata_bytes_read_f32(b, off) > 0.0
}

fn strata_grace_clear_bytes(b: &mut [u8], off: usize) {
    strata_bytes_write_f32(b, off, 0.0);
}

fn strata_input_buf_push_bytes(b: &mut [u8], off: usize, cap: u32, action: u16, win_sec: f32) {
    if win_sec <= 0.0 || cap == 0 {
        return;
    }
    let n = cap as usize;
    let mut empty_slot: Option<usize> = None;
    let mut min_slot = 0usize;
    let mut min_rem = f32::MAX;
    for i in 0..n {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            strata_bytes_write_f32(b, s + 4, win_sec.max(rem));
            return;
        }
        if (aid == u16::MAX || rem <= 0.0) && empty_slot.is_none() {
            empty_slot = Some(i);
        } else if rem < min_rem {
            min_rem = rem;
            min_slot = i;
        }
    }
    let target = empty_slot.unwrap_or(min_slot);
    let s = off + target * 8;
    if s + 8 <= b.len() {
        strata_bytes_write_u16(b, s, action);
        strata_bytes_write_u16(b, s + 2, 0);
        strata_bytes_write_f32(b, s + 4, win_sec);
    }
}

fn strata_input_buf_consume_bytes(b: &mut [u8], off: usize, cap: u32, action: u16) -> bool {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            strata_bytes_write_u16(b, s, u16::MAX);
            strata_bytes_write_f32(b, s + 4, 0.0);
            return true;
        }
    }
    false
}

fn strata_input_buf_peek_bytes(b: &[u8], off: usize, cap: u32, action: u16) -> bool {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            return true;
        }
    }
    false
}

fn strata_input_buf_tick_bytes(b: &mut [u8], off: usize, cap: u32, dt: f32) {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let cur_rem = strata_bytes_read_f32(b, s + 4);
        if aid != u16::MAX && cur_rem > 0.0 {
            let rem = (cur_rem - dt).max(0.0);
            strata_bytes_write_f32(b, s + 4, rem);
            if rem <= 0.0 {
                strata_bytes_write_u16(b, s, u16::MAX);
            }
        }
    }
}

fn strata_bitset_set_bytes(b: &mut [u8], off: usize, words: u32, bit: u32) {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        let cur = strata_bytes_read_u32(b, s);
        strata_bytes_write_u32(b, s, cur | (1u32 << (bit % 32)));
    }
}

fn strata_bitset_get_bytes(b: &[u8], off: usize, words: u32, bit: u32) -> bool {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        (strata_bytes_read_u32(b, s) & (1u32 << (bit % 32))) != 0
    } else {
        false
    }
}

fn strata_bitset_clear_bytes(b: &mut [u8], off: usize, words: u32, bit: u32) {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        let cur = strata_bytes_read_u32(b, s);
        strata_bytes_write_u32(b, s, cur & !(1u32 << (bit % 32)));
    }
}

fn strata_timeline_advance_bytes(
    b: &mut [u8],
    off: usize,
    dt_sec: f32,
    rate_hz: u32,
    duration_frames: u32,
    windows: &[(u32, u32, u32)],
) -> u32 {
    if off + 12 > b.len() {
        return 0;
    }
    let mut cur_frame = u32::from(strata_bytes_read_u16(b, off));
    let flags = strata_bytes_read_u16(b, off + 2);
    let mut accum = strata_bytes_read_f32(b, off + 8);
    let hz = rate_hz.max(1) as f32;
    let step = 1.0f32 / hz;
    accum += dt_sec.max(0.0);
    while accum >= step {
        accum -= step;
        if duration_frames > 0 && cur_frame + 1 < duration_frames {
            cur_frame += 1;
        } else if (flags & 1) != 0 && duration_frames > 0 {
            cur_frame = 0;
        }
    }
    let mut mask = 0u32;
    for &(start, end, bit) in windows {
        if cur_frame >= start && cur_frame <= end && bit < 32 {
            mask |= 1u32 << bit;
        }
    }
    strata_bytes_write_u16(b, off, cur_frame as u16);
    strata_bytes_write_u32(b, off + 4, mask);
    strata_bytes_write_f32(b, off + 8, accum);
    mask
}

fn strata_timeline_in_window_bytes(b: &[u8], off: usize, window_bit: u32) -> bool {
    if off + 8 > b.len() || window_bit >= 32 {
        return false;
    }
    (strata_bytes_read_u32(b, off + 4) & (1u32 << window_bit)) != 0
}

fn strata_sample_curve_slice(pts: &[(f64, f64)], x: f64) -> f64 {
    if pts.is_empty() {
        return 0.0;
    }
    if x <= pts[0].0 {
        return pts[0].1;
    }
    let last = pts.len() - 1;
    if x >= pts[last].0 {
        return pts[last].1;
    }
    for w in pts.windows(2) {
        let (x0, y0) = w[0];
        let (x1, y1) = w[1];
        if x <= x1 {
            let span = x1 - x0;
            if span.abs() <= f64::EPSILON {
                return y1;
            }
            let t = (x - x0) / span;
            return y0 + (y1 - y0) * t;
        }
    }
    pts[last].1
}

fn strata_binop(op: &str, lhs: &StrataVal, rhs: &StrataVal, allow_fma: bool) -> StrataVal {
    let _ = allow_fma;
    // Vector binary ops
    match (lhs, rhs) {
        (StrataVal::Vec2(a), StrataVal::Vec2(b)) => {
            return match op {
                "+" => StrataVal::Vec2([a[0] + b[0], a[1] + b[1]]),
                "-" => StrataVal::Vec2([a[0] - b[0], a[1] - b[1]]),
                "*" => StrataVal::Vec2([a[0] * b[0], a[1] * b[1]]),
                "/" => StrataVal::Vec2([a[0] / b[0], a[1] / b[1]]),
                "==" => StrataVal::Bool(a[0] == b[0] && a[1] == b[1]),
                "!=" => StrataVal::Bool(a[0] != b[0] || a[1] != b[1]),
                _ => StrataVal::Vec2(*a),
            };
        }
        (StrataVal::Vec2(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec2([a[0] * *s, a[1] * *s]),
                "/" => StrataVal::Vec2([a[0] / *s, a[1] / *s]),
                "+" => StrataVal::Vec2([a[0] + *s, a[1] + *s]),
                "-" => StrataVal::Vec2([a[0] - *s, a[1] - *s]),
                _ => StrataVal::Vec2(*a),
            };
        }
        (StrataVal::F32(s), StrataVal::Vec2(b)) => {
            return match op {
                "*" => StrataVal::Vec2([*s * b[0], *s * b[1]]),
                "+" => StrataVal::Vec2([*s + b[0], *s + b[1]]),
                _ => StrataVal::Vec2(*b),
            };
        }
        (StrataVal::Vec3(a), StrataVal::Vec3(b)) => {
            return match op {
                "+" => StrataVal::Vec3([a[0] + b[0], a[1] + b[1], a[2] + b[2]]),
                "-" => StrataVal::Vec3([a[0] - b[0], a[1] - b[1], a[2] - b[2]]),
                "*" => StrataVal::Vec3([a[0] * b[0], a[1] * b[1], a[2] * b[2]]),
                "/" => StrataVal::Vec3([a[0] / b[0], a[1] / b[1], a[2] / b[2]]),
                "==" => StrataVal::Bool(a == b),
                "!=" => StrataVal::Bool(a != b),
                _ => StrataVal::Vec3(*a),
            };
        }
        (StrataVal::Vec3(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec3([a[0] * *s, a[1] * *s, a[2] * *s]),
                "/" => StrataVal::Vec3([a[0] / *s, a[1] / *s, a[2] / *s]),
                "+" => StrataVal::Vec3([a[0] + *s, a[1] + *s, a[2] + *s]),
                "-" => StrataVal::Vec3([a[0] - *s, a[1] - *s, a[2] - *s]),
                _ => StrataVal::Vec3(*a),
            };
        }
        (StrataVal::Vec4(a), StrataVal::Vec4(b)) => {
            return match op {
                "+" => StrataVal::Vec4([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]]),
                "-" => StrataVal::Vec4([a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3]]),
                "*" => StrataVal::Vec4([a[0] * b[0], a[1] * b[1], a[2] * b[2], a[3] * b[3]]),
                "/" => StrataVal::Vec4([a[0] / b[0], a[1] / b[1], a[2] / b[2], a[3] / b[3]]),
                _ => StrataVal::Vec4(*a),
            };
        }
        (StrataVal::Vec4(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec4([a[0] * *s, a[1] * *s, a[2] * *s, a[3] * *s]),
                "/" => StrataVal::Vec4([a[0] / *s, a[1] / *s, a[2] / *s, a[3] / *s]),
                _ => StrataVal::Vec4(*a),
            };
        }
        (StrataVal::Entity(a), StrataVal::Entity(b)) => {
            return match op {
                "==" => StrataVal::Bool(a == b),
                "!=" => StrataVal::Bool(a != b),
                _ => StrataVal::Bool(false),
            };
        }
        (StrataVal::Ptr(a), StrataVal::Ptr(b)) => {
            return match op {
                "==" => StrataVal::Bool(if a.is_null() || b.is_null() {
                    a.is_null() && b.is_null()
                } else {
                    a == b
                }),
                "!=" => StrataVal::Bool(if a.is_null() || b.is_null() {
                    a.is_null() != b.is_null()
                } else {
                    a != b
                }),
                _ => StrataVal::Bool(false),
            };
        }
        (
            StrataVal::Ptr(p),
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
        )
        | (
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
            StrataVal::Ptr(p),
        ) => {
            return match op {
                "==" => StrataVal::Bool(p.is_null()),
                "!=" => StrataVal::Bool(!p.is_null()),
                _ => StrataVal::Bool(false),
            };
        }
        (
            StrataVal::Obj(_),
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
        )
        | (
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
            StrataVal::Obj(_),
        ) => {
            return match op {
                "==" => StrataVal::Bool(false),
                "!=" => StrataVal::Bool(true),
                _ => StrataVal::Bool(false),
            };
        }
        (
            StrataVal::Unit,
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
        )
        | (
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
            StrataVal::Unit,
        ) => {
            return match op {
                "==" => StrataVal::Bool(true),
                "!=" => StrataVal::Bool(false),
                _ => StrataVal::Bool(false),
            };
        }
        (
            StrataVal::Entity(e),
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
        )
        | (
            StrataVal::I32(0) | StrataVal::U32(0) | StrataVal::I64(0) | StrataVal::U64(0),
            StrataVal::Entity(e),
        ) => {
            return match op {
                "==" => StrataVal::Bool(e.is_null()),
                "!=" => StrataVal::Bool(!e.is_null()),
                _ => StrataVal::Bool(false),
            };
        }
        (StrataVal::Bool(a), StrataVal::Bool(b)) => {
            return match op {
                "&&" | "&" => StrataVal::Bool(*a && *b),
                "||" | "|" => StrataVal::Bool(*a || *b),
                "==" => StrataVal::Bool(*a == *b),
                "!=" => StrataVal::Bool(*a != *b),
                _ => StrataVal::Bool(*a),
            };
        }
        _ => {}
    }

    if matches!(lhs, StrataVal::Fix64(_)) || matches!(rhs, StrataVal::Fix64(_)) {
        let a = lhs.as_fix64();
        let b = rhs.as_fix64();
        return match op {
            "+" => StrataVal::Fix64(a.wrapping_add(b)),
            "-" => StrataVal::Fix64(a.wrapping_sub(b)),
            "*" => StrataVal::Fix64(((i128::from(a) * i128::from(b)) >> 32) as i64),
            "/" => StrataVal::Fix64(if b != 0 { ((i128::from(a) << 32) / i128::from(b)) as i64 } else { 0 }),
            "%" => StrataVal::Fix64(if b != 0 { a % b } else { 0 }),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::Fix64(a),
        };
    }
    if matches!(lhs, StrataVal::Fix32(_)) || matches!(rhs, StrataVal::Fix32(_)) {
        let a = lhs.as_fix32();
        let b = rhs.as_fix32();
        return match op {
            "+" => StrataVal::Fix32(a.wrapping_add(b)),
            "-" => StrataVal::Fix32(a.wrapping_sub(b)),
            "*" => StrataVal::Fix32(((i64::from(a) * i64::from(b)) >> 16) as i32),
            "/" => StrataVal::Fix32(if b != 0 { ((i64::from(a) << 16) / i64::from(b)) as i32 } else { 0 }),
            "%" => StrataVal::Fix32(if b != 0 { a % b } else { 0 }),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::Fix32(a),
        };
    }
    if matches!(lhs, StrataVal::F64(_)) || matches!(rhs, StrataVal::F64(_)) {
        let a = lhs.as_f64();
        let b = rhs.as_f64();
        return match op {
            "+" => StrataVal::F64(a + b),
            "-" => StrataVal::F64(a - b),
            "*" => StrataVal::F64(a * b),
            "/" => StrataVal::F64(a / b),
            "%" => StrataVal::F64(a % b),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::F64(a),
        };
    }
    if matches!(lhs, StrataVal::F32(_)) || matches!(rhs, StrataVal::F32(_)) {
        let a = lhs.as_f32();
        let b = rhs.as_f32();
        return match op {
            "+" => StrataVal::F32(a + b),
            "-" => StrataVal::F32(a - b),
            "*" => StrataVal::F32(a * b),
            "/" => StrataVal::F32(a / b),
            "%" => StrataVal::F32(a % b),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::F32(a),
        };
    }
    if matches!(lhs, StrataVal::U64(_)) || matches!(rhs, StrataVal::U64(_)) {
        let a = lhs.as_u64();
        let b = rhs.as_u64();
        return match op {
            "+" => StrataVal::U64(a.wrapping_add(b)),
            "-" => StrataVal::U64(a.wrapping_sub(b)),
            "*" => StrataVal::U64(a.wrapping_mul(b)),
            "/" => StrataVal::U64(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::U64(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::U64(a & b),
            "|" => StrataVal::U64(a | b),
            "^" => StrataVal::U64(a ^ b),
            "<<" => StrataVal::U64(a.wrapping_shl(b as u32)),
            ">>" => StrataVal::U64(a.wrapping_shr(b as u32)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::U64(a),
        };
    }
    if matches!(lhs, StrataVal::I64(_)) || matches!(rhs, StrataVal::I64(_)) {
        let a = lhs.as_i64();
        let b = rhs.as_i64();
        return match op {
            "+" => StrataVal::I64(a.wrapping_add(b)),
            "-" => StrataVal::I64(a.wrapping_sub(b)),
            "*" => StrataVal::I64(a.wrapping_mul(b)),
            "/" => StrataVal::I64(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::I64(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::I64(a & b),
            "|" => StrataVal::I64(a | b),
            "^" => StrataVal::I64(a ^ b),
            "<<" => StrataVal::I64(a.wrapping_shl(b as u32)),
            ">>" => StrataVal::I64(a.wrapping_shr(b as u32)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::I64(a),
        };
    }
    if (matches!(lhs, StrataVal::U32(_)) && !matches!(rhs, StrataVal::I32(v) if *v < 0))
        || (matches!(lhs, StrataVal::I32(v) if *v >= 0) && matches!(rhs, StrataVal::U32(_)))
    {
        let a = lhs.as_u32();
        let b = rhs.as_u32();
        return match op {
            "+" => StrataVal::U32(a.wrapping_add(b)),
            "-" => StrataVal::U32(a.wrapping_sub(b)),
            "*" => StrataVal::U32(a.wrapping_mul(b)),
            "/" => StrataVal::U32(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::U32(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::U32(a & b),
            "|" => StrataVal::U32(a | b),
            "^" => StrataVal::U32(a ^ b),
            "<<" => StrataVal::U32(a.wrapping_shl(b)),
            ">>" => StrataVal::U32(a.wrapping_shr(b)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::U32(a),
        };
    }
    let a = lhs.as_i32();
    let b = rhs.as_i32();
    match op {
        "+" => StrataVal::I32(a.wrapping_add(b)),
        "-" => StrataVal::I32(a.wrapping_sub(b)),
        "*" => StrataVal::I32(a.wrapping_mul(b)),
        "/" => StrataVal::I32(if b != 0 { a / b } else { 0 }),
        "%" => StrataVal::I32(if b != 0 { a % b } else { 0 }),
        "&" => StrataVal::I32(a & b),
        "|" => StrataVal::I32(a | b),
        "^" => StrataVal::I32(a ^ b),
        "<<" => StrataVal::I32(a.wrapping_shl(b as u32)),
        ">>" => StrataVal::I32(a.wrapping_shr(b as u32)),
        "<" => StrataVal::Bool(a < b),
        "<=" => StrataVal::Bool(a <= b),
        ">" => StrataVal::Bool(a > b),
        ">=" => StrataVal::Bool(a >= b),
        "==" => StrataVal::Bool(a == b),
        "!=" => StrataVal::Bool(a != b),
        "&&" => StrataVal::Bool(lhs.as_bool() && rhs.as_bool()),
        "||" => StrataVal::Bool(lhs.as_bool() || rhs.as_bool()),
        _ => StrataVal::I32(a),
    }
}

fn strata_unop(op: &str, v: &StrataVal) -> StrataVal {
    match op {
        "!" => StrataVal::Bool(!v.as_bool()),
        "~" => StrataVal::I32(!v.as_i32()),
        "-" => match v {
            StrataVal::F32(x) => StrataVal::F32(-*x),
            StrataVal::F64(x) => StrataVal::F64(-*x),
            StrataVal::Fix32(x) => StrataVal::Fix32(x.wrapping_neg()),
            StrataVal::Fix64(x) => StrataVal::Fix64(x.wrapping_neg()),
            StrataVal::I32(x) => StrataVal::I32(x.wrapping_neg()),
            StrataVal::I64(x) => StrataVal::I64(x.wrapping_neg()),
            StrataVal::Vec2(a) => StrataVal::Vec2([-a[0], -a[1]]),
            StrataVal::Vec3(a) => StrataVal::Vec3([-a[0], -a[1], -a[2]]),
            StrataVal::Vec4(a) => StrataVal::Vec4([-a[0], -a[1], -a[2], -a[3]]),
            _ => StrataVal::I32(v.as_i32().wrapping_neg()),
        },
        _ => v.clone(),
    }
}

fn strata_intrinsic(name: &str, args: &[StrataVal]) -> StrataVal {
    let a0 = args.first().cloned().unwrap_or_default();
    let a1 = args.get(1).cloned().unwrap_or_default();
    let a2 = args.get(2).cloned().unwrap_or_default();
    match name {
        "sqrt" => StrataVal::F32(a0.as_f32().sqrt()),
        "abs" => match &a0 {
            StrataVal::I32(x) => StrataVal::I32(x.wrapping_abs()),
            StrataVal::Fix32(x) => StrataVal::Fix32(x.wrapping_abs()),
            StrataVal::I64(x) => StrataVal::I64(x.wrapping_abs()),
            StrataVal::Fix64(x) => StrataVal::Fix64(x.wrapping_abs()),
            StrataVal::F64(x) => StrataVal::F64(x.abs()),
            _ => StrataVal::F32(a0.as_f32().abs()),
        },
        "floor" => StrataVal::F32(a0.as_f32().floor()),
        "ceil" => StrataVal::F32(a0.as_f32().ceil()),
        "round" => StrataVal::F32(a0.as_f32().round()),
        "trunc" => StrataVal::F32(a0.as_f32().trunc()),
        "fract" => StrataVal::F32(a0.as_f32().fract()),
        "signum" | "sign" => StrataVal::F32(a0.as_f32().signum()),
        "sin" => StrataVal::F32(a0.as_f32().sin()),
        "cos" => StrataVal::F32(a0.as_f32().cos()),
        "tan" => StrataVal::F32(a0.as_f32().tan()),
        "asin" => StrataVal::F32(a0.as_f32().asin()),
        "acos" => StrataVal::F32(a0.as_f32().acos()),
        "atan" => StrataVal::F32(a0.as_f32().atan()),
        "atan2" => StrataVal::F32(a0.as_f32().atan2(a1.as_f32())),
        "exp" => StrataVal::F32(a0.as_f32().exp()),
        "ln" | "log" => StrataVal::F32(a0.as_f32().ln()),
        "log2" => StrataVal::F32(a0.as_f32().log2()),
        "log10" => StrataVal::F32(a0.as_f32().log10()),
        "pow" | "powf" => StrataVal::F32(a0.as_f32().powf(a1.as_f32())),
        "min" => match (&a0, &a1) {
            (StrataVal::I32(x), StrataVal::I32(y)) => StrataVal::I32((*x).min(*y)),
            (StrataVal::Fix32(x), StrataVal::Fix32(y)) => StrataVal::Fix32((*x).min(*y)),
            (StrataVal::Fix64(x), StrataVal::Fix64(y)) => StrataVal::Fix64((*x).min(*y)),
            (StrataVal::U32(x), StrataVal::U32(y)) => StrataVal::U32((*x).min(*y)),
            (StrataVal::Vec2(x), StrataVal::Vec2(y)) => StrataVal::Vec2([x[0].min(y[0]), x[1].min(y[1])]),
            _ => StrataVal::F32(a0.as_f32().min(a1.as_f32())),
        },
        "max" => match (&a0, &a1) {
            (StrataVal::I32(x), StrataVal::I32(y)) => StrataVal::I32((*x).max(*y)),
            (StrataVal::Fix32(x), StrataVal::Fix32(y)) => StrataVal::Fix32((*x).max(*y)),
            (StrataVal::Fix64(x), StrataVal::Fix64(y)) => StrataVal::Fix64((*x).max(*y)),
            (StrataVal::U32(x), StrataVal::U32(y)) => StrataVal::U32((*x).max(*y)),
            (StrataVal::Vec2(x), StrataVal::Vec2(y)) => StrataVal::Vec2([x[0].max(y[0]), x[1].max(y[1])]),
            _ => StrataVal::F32(a0.as_f32().max(a1.as_f32())),
        },
        "clamp" => match (&a0, &a1, &a2) {
            (StrataVal::I32(x), StrataVal::I32(lo), StrataVal::I32(hi)) => StrataVal::I32((*x).clamp(*lo, *hi)),
            (StrataVal::Fix32(x), StrataVal::Fix32(lo), StrataVal::Fix32(hi)) => StrataVal::Fix32((*x).clamp(*lo, *hi)),
            (StrataVal::Fix64(x), StrataVal::Fix64(lo), StrataVal::Fix64(hi)) => StrataVal::Fix64((*x).clamp(*lo, *hi)),
            (StrataVal::U32(x), StrataVal::U32(lo), StrataVal::U32(hi)) => StrataVal::U32((*x).clamp(*lo, *hi)),
            _ => {
                let lo = a1.as_f32();
                let hi = a2.as_f32();
                StrataVal::F32(a0.as_f32().clamp(lo, hi.max(lo)))
            }
        },
        "saturate" => StrataVal::F32(a0.as_f32().clamp(0.0, 1.0)),
        "lerp" | "mix" => {
            let t = a2.as_f32();
            match &a0 {
                StrataVal::Vec2(x) => {
                    let y = a1.as_vec2();
                    StrataVal::Vec2([x[0] + (y[0] - x[0]) * t, x[1] + (y[1] - x[1]) * t])
                }
                StrataVal::Vec3(x) => {
                    let y = a1.as_vec3();
                    StrataVal::Vec3([x[0] + (y[0] - x[0]) * t, x[1] + (y[1] - x[1]) * t, x[2] + (y[2] - x[2]) * t])
                }
                _ => {
                    let x = a0.as_f32();
                    let y = a1.as_f32();
                    StrataVal::F32(x + (y - x) * t)
                }
            }
        }
        "mul_add" | "fma" => StrataVal::F32(a0.as_f32().mul_add(a1.as_f32(), a2.as_f32())),
        "vec2" | "Vec2" => StrataVal::Vec2([a0.as_f32(), args.get(1).map_or(a0.as_f32(), |v| v.as_f32())]),
        "vec3" | "Vec3" => StrataVal::Vec3([a0.as_f32(), a1.as_f32(), a2.as_f32()]),
        "vec3a" | "Vec3a" => StrataVal::Vec4([a0.as_f32(), a1.as_f32(), a2.as_f32(), 0.0]),
        "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => StrataVal::Vec4([a0.as_f32(), a1.as_f32(), a2.as_f32(), args.get(3).map_or(0.0, |v| v.as_f32())]),
        "ivec2" | "IVec2" => StrataVal::IVec2([a0.as_i32(), a1.as_i32()]),
        "ivec3" | "IVec3" => StrataVal::IVec3([a0.as_i32(), a1.as_i32(), a2.as_i32()]),
        "uvec2" | "UVec2" => StrataVal::UVec2([a0.as_u32(), a1.as_u32()]),
        "dot" => match &a0 {
            StrataVal::Vec3(x) => {
                let y = a1.as_vec3();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1] + x[2] * y[2])
            }
            StrataVal::Vec4(x) => {
                let y = a1.as_vec4();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1] + x[2] * y[2] + x[3] * y[3])
            }
            _ => {
                let x = a0.as_vec2();
                let y = a1.as_vec2();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1])
            }
        },
        "cross" => {
            let a = a0.as_vec3();
            let b = a1.as_vec3();
            if matches!(a0, StrataVal::Vec4(_)) {
                StrataVal::Vec4([
                    a[1] * b[2] - a[2] * b[1],
                    a[2] * b[0] - a[0] * b[2],
                    a[0] * b[1] - a[1] * b[0],
                    0.0,
                ])
            } else {
                StrataVal::Vec3([
                    a[1] * b[2] - a[2] * b[1],
                    a[2] * b[0] - a[0] * b[2],
                    a[0] * b[1] - a[1] * b[0],
                ])
            }
        }
        "length" | "len" => match &a0 {
            StrataVal::Vec3(x) => StrataVal::F32((x[0] * x[0] + x[1] * x[1] + x[2] * x[2]).sqrt()),
            StrataVal::Vec4(x) => StrataVal::F32((x[0] * x[0] + x[1] * x[1] + x[2] * x[2] + x[3] * x[3]).sqrt()),
            _ => {
                let x = a0.as_vec2();
                StrataVal::F32((x[0] * x[0] + x[1] * x[1]).sqrt())
            }
        },
        "length_sq" | "len_sq" => match &a0 {
            StrataVal::Vec3(x) => StrataVal::F32(x[0] * x[0] + x[1] * x[1] + x[2] * x[2]),
            _ => {
                let x = a0.as_vec2();
                StrataVal::F32(x[0] * x[0] + x[1] * x[1])
            }
        },
        "distance" | "dist" => match &a0 {
            StrataVal::Vec3(x) => {
                let y = a1.as_vec3();
                let dx = x[0] - y[0];
                let dy = x[1] - y[1];
                let dz = x[2] - y[2];
                StrataVal::F32((dx * dx + dy * dy + dz * dz).sqrt())
            }
            _ => {
                let x = a0.as_vec2();
                let y = a1.as_vec2();
                let dx = x[0] - y[0];
                let dy = x[1] - y[1];
                StrataVal::F32((dx * dx + dy * dy).sqrt())
            }
        },
        "normalize" | "norm" => match &a0 {
            StrataVal::Vec3(x) => {
                let l = (x[0] * x[0] + x[1] * x[1] + x[2] * x[2]).sqrt();
                if l > 1e-6 { StrataVal::Vec3([x[0] / l, x[1] / l, x[2] / l]) } else { StrataVal::Vec3([0.0; 3]) }
            }
            _ => {
                let x = a0.as_vec2();
                let l = (x[0] * x[0] + x[1] * x[1]).sqrt();
                if l > 1e-6 { StrataVal::Vec2([x[0] / l, x[1] / l]) } else { StrataVal::Vec2([0.0; 2]) }
            }
        },
        "step" => {
            let edge = a0.as_f32();
            let x = a1.as_f32();
            StrataVal::F32(if x < edge { 0.0 } else { 1.0 })
        }
        "smoothstep" => {
            let e0 = a0.as_f32();
            let e1 = a1.as_f32();
            let x = a2.as_f32();
            let d = (e1 - e0).max(1e-6);
            let t = ((x - e0) / d).clamp(0.0, 1.0);
            StrataVal::F32(t * t * (3.0 - 2.0 * t))
        }
        "raw" | "to_bits" => match &a0 {
            StrataVal::Entity(e) => StrataVal::U64(e.to_bits()),
            StrataVal::Bool(b) => StrataVal::U32(u32::from(*b)),
            other => other.clone(),
        },
        "is_null" => StrataVal::Bool(a0.as_entity().is_null()),
        "is_valid" => StrataVal::Bool(!a0.as_entity().is_null()),
        _ => StrataVal::F32(a0.as_f32()),
    }
}

fn strata_reduce_accum(acc: &StrataVal, op: &str, val: &StrataVal) -> StrataVal {
    match op {
        "min" | "Min" => strata_intrinsic("min", &[acc.clone(), val.clone()]),
        "max" | "Max" => strata_intrinsic("max", &[acc.clone(), val.clone()]),
        "sum" | "Sum" | "+" | "+=" => strata_binop("+", acc, val, false),
        "prod" | "Prod" | "*" | "*=" => strata_binop("*", acc, val, false),
        "any" | "Any" | "||" => StrataVal::Bool(acc.as_bool() || val.as_bool()),
        "all" | "All" | "&&" => StrataVal::Bool(acc.as_bool() && val.as_bool()),
        "count" | "Count" => {
            let add = if val.as_bool() { 1 } else { 0 };
            strata_binop("+", acc, &StrataVal::U32(add), false)
        }
        _ => strata_binop("+", acc, val, false),
    }
}

fn strata_point_seg_dist_sq(p: [f32; 4], a: [f32; 4], b: [f32; 4]) -> f32 {
    let ab = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
    let ap = [p[0] - a[0], p[1] - a[1], p[2] - a[2]];
    let len_sq = ab[0] * ab[0] + ab[1] * ab[1] + ab[2] * ab[2];
    let t = if len_sq > 1e-8 {
        ((ap[0] * ab[0] + ap[1] * ab[1] + ap[2] * ab[2]) / len_sq).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let dx = a[0] + ab[0] * t - p[0];
    let dy = a[1] + ab[1] * t - p[1];
    let dz = a[2] + ab[2] * t - p[2];
    dx * dx + dy * dy + dz * dz
}

fn strata_query_disc_hits(
    world: &Arc<Mutex<StrataWorldState>>,
    grid_name: &str,
    center: [f32; 4],
    radius: f32,
) -> Vec<(FfiEntity, [f32; 4])> {
    let r = radius.max(0.0);
    let r2 = r * r;
    let Ok(w) = world.lock() else { return Vec::new(); };
    let Some(g) = w.spatial.get(grid_name) else { return Vec::new(); };
    if g.ring.is_empty() || g.cols == 0 || g.rows == 0 { return Vec::new(); }
    let f = g.head_tick % g.ring.len();
    let fr = &g.ring[f];
    let total = (fr.count as usize).min(fr.entities.len());
    let ax0 = (g.plane_axes[0] as usize).min(2);
    let ax1 = (g.plane_axes[1] as usize).min(2);
    let min_cx = StrataSpatialGridState::clamp_cell_coord(center[ax0] - r, g.bounds_min[0], g.inv_cell_size, g.cols);
    let max_cx = StrataSpatialGridState::clamp_cell_coord(center[ax0] + r, g.bounds_min[0], g.inv_cell_size, g.cols);
    let min_cy = StrataSpatialGridState::clamp_cell_coord(center[ax1] - r, g.bounds_min[1], g.inv_cell_size, g.rows);
    let max_cy = StrataSpatialGridState::clamp_cell_coord(center[ax1] + r, g.bounds_min[1], g.inv_cell_size, g.rows);
    let mut out = Vec::new();
    for cy in min_cy..=max_cy {
        for cx in min_cx..=max_cx {
            let cell = (cy as usize) * (g.cols as usize) + (cx as usize);
            if let Some((start, end)) = StrataSpatialGridState::csr_cell_range(&fr.cell_offsets, cell, total) {
                for k in start..end {
                    let p = fr.positions[k];
                    let dx = p[0] - center[0];
                    let dy = p[1] - center[1];
                    let dz = p[2] - center[2];
                    if dx * dx + dy * dy + dz * dz <= r2 {
                        out.push((fr.entities[k], p));
                        if out.len() >= 64 { return out; }
                    }
                }
            }
        }
    }
    out
}

fn strata_query_segment_hits(
    world: &Arc<Mutex<StrataWorldState>>,
    hist_name: &str,
    start: [f32; 4],
    end: [f32; 4],
    radius: f32,
    tick_offset: u32,
) -> Vec<(FfiEntity, [f32; 4])> {
    let r = radius.max(0.0);
    let r2 = r * r;
    let Ok(w) = world.lock() else { return Vec::new(); };
    let Some(g) = w.spatial.get(hist_name) else { return Vec::new(); };
    if g.ring.is_empty() || g.cols == 0 || g.rows == 0 { return Vec::new(); }
    let frames = g.ring.len();
    let f = (g.head_tick + frames - ((tick_offset as usize) % frames)) % frames;
    let fr = &g.ring[f];
    let total = (fr.count as usize).min(fr.entities.len());
    let ax0 = (g.plane_axes[0] as usize).min(2);
    let ax1 = (g.plane_axes[1] as usize).min(2);
    let min_x = start[ax0].min(end[ax0]) - r;
    let max_x = start[ax0].max(end[ax0]) + r;
    let min_y = start[ax1].min(end[ax1]) - r;
    let max_y = start[ax1].max(end[ax1]) + r;
    let min_cx = StrataSpatialGridState::clamp_cell_coord(min_x, g.bounds_min[0], g.inv_cell_size, g.cols);
    let max_cx = StrataSpatialGridState::clamp_cell_coord(max_x, g.bounds_min[0], g.inv_cell_size, g.cols);
    let min_cy = StrataSpatialGridState::clamp_cell_coord(min_y, g.bounds_min[1], g.inv_cell_size, g.rows);
    let max_cy = StrataSpatialGridState::clamp_cell_coord(max_y, g.bounds_min[1], g.inv_cell_size, g.rows);
    let mut out = Vec::new();
    for cy in min_cy..=max_cy {
        for cx in min_cx..=max_cx {
            let cell = (cy as usize) * (g.cols as usize) + (cx as usize);
            if let Some((cs, ce)) = StrataSpatialGridState::csr_cell_range(&fr.cell_offsets, cell, total) {
                for k in cs..ce {
                    let p = fr.positions[k];
                    if strata_point_seg_dist_sq(p, start, end) <= r2 {
                        out.push((fr.entities[k], p));
                        if out.len() >= 64 { return out; }
                    }
                }
            }
        }
    }
    out
}

enum HostBridge<'r, 'c, 'i> {
    System(&'r mut SystemContext<'i>),
    ParChunkReadonly(&'r Chunk<'c, 'i>),
    ParChunkMut(&'r mut Chunk<'c, 'i>),
    Commands(&'r mut GuestCommands<'i>),
    Pure,
}
"#;
