//! Zero-allocation `#[repr(C)]` zero-padding runtime primitives backing Strata v2.0 gameplay
//! types (`GraceWindow`, `InputBuffer`, `TimelineCursor`, `BitSet`, `InlineStr`, `SmallVecPod`,
//! `Fixed32`, `Fixed64`).

use core::ops::{Add, Div, Mul, Neg, Sub};

/// 4-byte `#[repr(C)]` coyote-time / grace countdown window (`GraceWindow`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct GraceWindow {
    /// Remaining active duration in seconds (`<= 0.0` means inactive).
    pub remaining_sec: f32,
}

const _: () = {
    assert!(core::mem::size_of::<GraceWindow>() == 4);
    assert!(core::mem::align_of::<GraceWindow>() == 4);
};

impl GraceWindow {
    /// Creates an inactive grace window.
    #[inline]
    pub const fn new() -> Self {
        Self { remaining_sec: 0.0 }
    }

    /// Arms or refreshes the grace window for `duration_sec` seconds.
    #[inline]
    pub fn arm(&mut self, duration_sec: f32) {
        if duration_sec > self.remaining_sec {
            self.remaining_sec = duration_sec;
        }
    }

    /// Advances the countdown by `dt_sec` seconds, clamping at `0.0`.
    #[inline]
    pub fn tick(&mut self, dt_sec: f32) {
        if self.remaining_sec > 0.0 {
            self.remaining_sec = (self.remaining_sec - dt_sec).max(0.0);
        }
    }

    /// Returns `true` while the grace window remains active (`remaining_sec > 0.0`).
    #[inline]
    pub fn is_active(self) -> bool {
        self.remaining_sec > 0.0
    }

    /// Clears the grace window immediately.
    #[inline]
    pub fn clear(&mut self) {
        self.remaining_sec = 0.0;
    }
}

/// 8-byte `#[repr(C)]` buffered action entry stored inside [`InputBuffer`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct InputBufferEntry {
    /// Action discriminant (`u16::MAX` when slot is empty).
    pub action_id: u16,
    /// Explicit zero padding.
    pub _pad: u16,
    /// Remaining validity window in seconds (`<= 0.0` when expired).
    pub remaining_sec: f32,
}

const _: () = {
    assert!(core::mem::size_of::<InputBufferEntry>() == 8);
    assert!(core::mem::align_of::<InputBufferEntry>() == 4);
};

impl InputBufferEntry {
    /// Empty sentinel slot.
    pub const EMPTY: Self = Self {
        action_id: u16::MAX,
        _pad: 0,
        remaining_sec: 0.0,
    };

    #[inline]
    fn is_live(&self) -> bool {
        self.action_id != u16::MAX && self.remaining_sec > 0.0
    }
}

/// Fixed-capacity `#[repr(C)]` action input buffer (`InputBuffer<Action, N>`).
///
/// For `N = 4`, occupies exactly `32` bytes (`align = 4`) with zero implicit padding.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InputBuffer<const N: usize> {
    /// Inline ring/array of buffered actions.
    pub entries: [InputBufferEntry; N],
}

const _: () = {
    assert!(core::mem::size_of::<InputBuffer<4>>() == 32);
    assert!(core::mem::align_of::<InputBuffer<4>>() == 4);
};

impl<const N: usize> Default for InputBuffer<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> InputBuffer<N> {
    /// Creates an empty input buffer.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: [InputBufferEntry::EMPTY; N],
        }
    }

    /// Pushes `action_id` with validity `window_sec`, refreshing an existing entry or overwriting
    /// the shortest-remaining slot if full.
    pub fn push(&mut self, action_id: u16, window_sec: f32) {
        if window_sec <= 0.0 || N == 0 {
            return;
        }
        let mut empty_idx: Option<usize> = None;
        let mut min_idx = 0usize;
        let mut min_rem = f32::MAX;

        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_live() && slot.action_id == action_id {
                slot.remaining_sec = slot.remaining_sec.max(window_sec);
                return;
            }
            if !slot.is_live() && empty_idx.is_none() {
                empty_idx = Some(i);
            }
            if slot.remaining_sec < min_rem {
                min_rem = slot.remaining_sec;
                min_idx = i;
            }
        }
        let dst = empty_idx.unwrap_or(min_idx);
        self.entries[dst] = InputBufferEntry {
            action_id,
            _pad: 0,
            remaining_sec: window_sec,
        };
    }

    /// Returns `true` if `action_id` is currently buffered without consuming it.
    pub fn peek(&self, action_id: u16) -> bool {
        self.entries
            .iter()
            .any(|slot| slot.is_live() && slot.action_id == action_id)
    }

    /// Consumes and clears the newest buffered occurrence of `action_id`, returning `true` if found.
    pub fn consume(&mut self, action_id: u16) -> bool {
        let mut best_idx: Option<usize> = None;
        let mut best_rem = -1.0_f32;
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.is_live() && slot.action_id == action_id && slot.remaining_sec > best_rem {
                best_rem = slot.remaining_sec;
                best_idx = Some(i);
            }
        }
        if let Some(idx) = best_idx {
            self.entries[idx] = InputBufferEntry::EMPTY;
            true
        } else {
            false
        }
    }

    /// Advances all active input timers by `dt_sec`, expiring entries whose remaining time hits zero.
    pub fn tick(&mut self, dt_sec: f32) {
        for slot in &mut self.entries {
            if slot.is_live() {
                slot.remaining_sec -= dt_sec;
                if slot.remaining_sec <= 0.0 {
                    *slot = InputBufferEntry::EMPTY;
                }
            }
        }
    }

    /// Clears every entry in this buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.entries = [InputBufferEntry::EMPTY; N];
    }
}

/// 16-byte `#[repr(C)]` `@sparse` cursor emitted for Strata `timeline` declarations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TimelineCursor {
    /// Current timeline frame index.
    pub cur_frame: u16,
    /// Control flags (`bit 0 = active`).
    pub flags: u16,
    /// Bitmask of currently active `window`s (`1 << window_idx`).
    pub active_mask: u32,
    /// Sub-frame fractional accumulator in seconds.
    pub accum_sec: f32,
    /// Explicit zero-initialized trailing padding (`4` bytes).
    pub _pad: [u8; 4],
}

const _: () = {
    assert!(core::mem::size_of::<TimelineCursor>() == 16);
    assert!(core::mem::align_of::<TimelineCursor>() == 4);
};

impl TimelineCursor {
    /// Flag bit indicating an active running timeline.
    pub const FLAG_ACTIVE: u16 = 1 << 0;

    /// Constructs a freshly started timeline cursor at frame `0`.
    #[inline]
    pub const fn start() -> Self {
        Self {
            cur_frame: 0,
            flags: Self::FLAG_ACTIVE,
            active_mask: 0,
            accum_sec: 0.0,
            _pad: [0; 4],
        }
    }

    /// Returns `true` if `(self.active_mask & window_mask) != 0`.
    #[inline]
    pub const fn in_window(self, window_mask: u32) -> bool {
        (self.active_mask & window_mask) != 0
    }

    /// Returns `true` while the timeline has not finished/stopped.
    #[inline]
    pub const fn is_active(self) -> bool {
        (self.flags & Self::FLAG_ACTIVE) != 0
    }

    /// Marks the timeline cursor inactive.
    #[inline]
    pub fn stop(&mut self) {
        self.flags &= !Self::FLAG_ACTIVE;
        self.active_mask = 0;
    }
}

/// Inline fixed-size `#[repr(C)]` bitset backed by `WORDS` `u32` words (`BitSet<BITS>` ->
/// `WORDS = BITS.div_ceil(32)`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitSet<const WORDS: usize> {
    /// Backing 32-bit word array.
    pub words: [u32; WORDS],
}

const _: () = {
    assert!(core::mem::size_of::<BitSet<1>>() == 4);
    assert!(core::mem::size_of::<BitSet<8>>() == 32);
    assert!(core::mem::align_of::<BitSet<1>>() == 4);
};

impl<const WORDS: usize> Default for BitSet<WORDS> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> BitSet<WORDS> {
    /// Creates an all-zero bitset.
    #[inline]
    pub const fn new() -> Self {
        Self { words: [0; WORDS] }
    }

    /// Sets bit `idx` to `1` (no-op if out of bounds).
    #[inline]
    pub fn set(&mut self, idx: u32) {
        let word = (idx / 32) as usize;
        if let Some(slot) = self.words.get_mut(word) {
            *slot |= 1u32 << (idx % 32);
        }
    }

    /// Clears bit `idx` to `0` (no-op if out of bounds).
    #[inline]
    pub fn clear(&mut self, idx: u32) {
        let word = (idx / 32) as usize;
        if let Some(slot) = self.words.get_mut(word) {
            *slot &= !(1u32 << (idx % 32));
        }
    }

    /// Returns `true` iff bit `idx` is set (returns `false` if out of bounds).
    #[inline]
    pub fn get(&self, idx: u32) -> bool {
        let word = (idx / 32) as usize;
        self.words
            .get(word)
            .is_some_and(|w| (*w & (1u32 << (idx % 32))) != 0)
    }

    /// Returns the total number of set bits across all words.
    #[inline]
    pub fn count_ones(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }
}

/// Fixed-capacity `#[repr(C)]` UTF-8 string (`InlineStr<N>`).
///
/// `N` should be a multiple of `4` so `size_of == 4 + N` with zero implicit padding.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineStr<const N: usize> {
    /// Active byte length (`<= N`).
    pub len: u32,
    /// Inline UTF-8 byte buffer (zero-padded).
    pub bytes: [u8; N],
}

const _: () = {
    assert!(core::mem::size_of::<InlineStr<32>>() == 36);
    assert!(core::mem::align_of::<InlineStr<32>>() == 4);
};

impl<const N: usize> Default for InlineStr<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> InlineStr<N> {
    /// Creates an empty `InlineStr`.
    #[inline]
    pub const fn new() -> Self {
        const {
            assert!(
                N.is_multiple_of(4),
                "InlineStr capacity must be a multiple of 4 for zero-padding ABI layout"
            )
        };
        Self {
            len: 0,
            bytes: [0; N],
        }
    }

    /// Constructs an `InlineStr` by truncating `s` cleanly on a UTF-8 char boundary up to `N` bytes.
    pub fn from_str_trunc(s: &str) -> Self {
        let mut out = Self::new();
        let mut end = s.len().min(N);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        out.bytes[..end].copy_from_slice(&s.as_bytes()[..end]);
        out.len = end as u32;
        out
    }

    /// Views the initialized UTF-8 contents as `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        let len = (self.len as usize).min(N);
        core::str::from_utf8(&self.bytes[..len]).unwrap_or("")
    }
}

/// Fixed-capacity `#[repr(C)]` zero-heap vector (`SmallVec<T, N>`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SmallVecPod<T: Copy, const N: usize> {
    /// Number of initialized elements (`<= N`).
    pub len: u32,
    /// Explicit 4-byte zero padding ensuring zero gaps for up to 8-byte aligned elements.
    pub _pad: u32,
    /// Inline element array.
    pub data: [T; N],
}

const _: () = {
    assert!(core::mem::size_of::<SmallVecPod<[f32; 3], 4>>() == 8 + 48);
};

impl<T: Copy + Default, const N: usize> Default for SmallVecPod<T, N> {
    #[inline]
    fn default() -> Self {
        Self {
            len: 0,
            _pad: 0,
            data: [T::default(); N],
        }
    }
}

impl<T: Copy, const N: usize> SmallVecPod<T, N> {
    /// Pushes `val` if capacity remains; returns `true` on success, `false` when full.
    #[inline]
    pub fn push(&mut self, val: T) -> bool {
        let idx = self.len as usize;
        if idx >= N {
            return false;
        }
        self.data[idx] = val;
        self.len += 1;
        true
    }

    /// Views active elements as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        let len = (self.len as usize).min(N);
        &self.data[..len]
    }
}

/// Deterministic Q16.16 signed fixed-point scalar (`fix32`) for `@deterministic` gameplay math.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fixed32(pub i32);

impl Fixed32 {
    /// Fractional scale (`2^16 = 65536`).
    pub const SCALE: i64 = 1 << 16;

    /// Converts an integer into Q16.16 fixed-point.
    #[inline]
    pub const fn from_int(v: i16) -> Self {
        Self((v as i32) << 16)
    }

    /// Converts an `f32` into Q16.16 fixed-point with deterministic round-to-nearest (`0` on non-finite).
    #[inline]
    pub fn from_f32(v: f32) -> Self {
        if v.is_finite() {
            Self(((v as f64) * (Self::SCALE as f64)).round() as i32)
        } else {
            Self(0)
        }
    }

    /// Converts this Q16.16 fixed-point value to `f32`.
    #[inline]
    pub fn to_f32(self) -> f32 {
        (self.0 as f32) / (Self::SCALE as f32)
    }
}

impl Add for Fixed32 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for Fixed32 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Mul for Fixed32 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self((((self.0 as i64) * (rhs.0 as i64)) >> 16) as i32)
    }
}

impl Div for Fixed32 {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        if rhs.0 == 0 {
            return Self(0);
        }
        Self((((self.0 as i64) << 16) / (rhs.0 as i64)) as i32)
    }
}

impl Neg for Fixed32 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

/// Deterministic Q32.32 signed fixed-point scalar (`fix64`) for `@deterministic` coordinates.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fixed64(pub i64);

impl Fixed64 {
    /// Fractional scale (`2^32`).
    pub const SCALE: i128 = 1 << 32;

    /// Converts a 32-bit integer into Q32.32 fixed-point.
    #[inline]
    pub const fn from_int(v: i32) -> Self {
        Self((v as i64) << 32)
    }

    /// Converts an `f64` into Q32.32 fixed-point (`0` on non-finite).
    #[inline]
    pub fn from_f64(v: f64) -> Self {
        if v.is_finite() {
            Self((v * (Self::SCALE as f64)).round() as i64)
        } else {
            Self(0)
        }
    }

    /// Converts this Q32.32 fixed-point value to `f64`.
    #[inline]
    pub fn to_f64(self) -> f64 {
        (self.0 as f64) / (Self::SCALE as f64)
    }

    /// Reference 96-by-64 unsigned restoring division matching C99 (`strata_fix64_div`) and
    /// Cranelift JIT (`__strata_fix64_div`) Q32.32 semantics without `i128` division, returning
    /// `Fixed64(0)` on zero divisor.
    #[inline]
    pub const fn div_restoring(self, rhs: Self) -> Self {
        if rhs.0 == 0 {
            return Self(0);
        }
        let neg = (self.0 ^ rhs.0) < 0;
        let ua = self.0.unsigned_abs();
        let ub = rhs.0.unsigned_abs();
        let mut rem = (ua >> 32) % ub;
        let mut lo = ua << 32;
        let mut quo = 0u64;
        let mut i = 0;
        while i < 64 {
            let carry = rem >> 63;
            rem = (rem << 1) | (lo >> 63);
            lo <<= 1;
            quo <<= 1;
            if carry != 0 || rem >= ub {
                rem = rem.wrapping_sub(ub);
                quo |= 1;
            }
            i += 1;
        }
        Self(if neg {
            quo.wrapping_neg() as i64
        } else {
            quo as i64
        })
    }
}

impl Add for Fixed64 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for Fixed64 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Mul for Fixed64 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self((((self.0 as i128) * (rhs.0 as i128)) >> 32) as i64)
    }
}

impl Div for Fixed64 {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        if rhs.0 == 0 {
            return Self(0);
        }
        Self((((self.0 as i128) << 32) / (rhs.0 as i128)) as i64)
    }
}

impl Neg for Fixed64 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `GraceWindow` arming, monotonic countdown clamping at `0.0`, and clearing.
    #[test]
    fn grace_window_arm_tick_and_clear() {
        let mut g = GraceWindow::new();
        assert!(!g.is_active());
        g.arm(0.15);
        assert!(g.is_active());
        // Shorter re-arm does not shrink existing grace window.
        g.arm(0.05);
        assert!((g.remaining_sec - 0.15).abs() < 1e-6);
        g.tick(0.10);
        assert!(g.is_active());
        g.tick(0.10);
        assert!(!g.is_active());
        assert_eq!(g.remaining_sec, 0.0);
        g.arm(0.2);
        g.clear();
        assert!(!g.is_active());
    }

    /// Verifies `InputBuffer<2>` evicts the shortest-remaining entry on capacity pressure and
    /// expires elapsed entries on `tick`.
    #[test]
    fn input_buffer_eviction_consume_and_expiry() {
        let mut buf: InputBuffer<2> = InputBuffer::new();
        buf.push(1, 0.25);
        buf.push(2, 0.10);
        buf.push(3, 0.50);
        assert!(buf.peek(1));
        assert!(!buf.peek(2));
        assert!(buf.peek(3));
        assert!(buf.consume(1));
        assert!(!buf.consume(1));
        buf.tick(0.50);
        assert!(!buf.peek(3));
    }

    /// Verifies `TimelineCursor::start`, `in_window`, and `stop` mask invariants.
    #[test]
    fn timeline_cursor_window_flags() {
        let mut cur = TimelineCursor::start();
        assert!(cur.is_active());
        cur.active_mask = 0b0101;
        assert!(cur.in_window(0b0001));
        assert!(!cur.in_window(0b0010));
        cur.stop();
        assert!(!cur.is_active());
        assert!(!cur.in_window(u32::MAX));
    }

    /// Verifies `BitSet` out-of-bounds safety and set/clear/count_ones parity.
    #[test]
    fn bitset_set_clear_and_bounds() {
        let mut bs: BitSet<2> = BitSet::new();
        bs.set(0);
        bs.set(33);
        bs.set(63);
        bs.set(64);
        assert!(bs.get(0) && bs.get(33) && bs.get(63) && !bs.get(64));
        assert_eq!(bs.count_ones(), 3);
        bs.clear(33);
        assert!(!bs.get(33));
        assert_eq!(bs.count_ones(), 2);
    }

    /// Verifies `InlineStr` multi-byte UTF-8 boundary truncation and `SmallVecPod` capacity limits.
    #[test]
    fn inline_str_utf8_truncation_and_small_vec_bounds() {
        // "abc" (3 bytes) + 4-byte emoji = 7 bytes; capacity 4 cuts strictly before emoji.
        let s = InlineStr::<4>::from_str_trunc("abc\u{1F980}");
        assert_eq!(s.as_str(), "abc");
        let mut v: SmallVecPod<u16, 2> = SmallVecPod::default();
        assert!(v.push(10));
        assert!(v.push(20));
        assert!(!v.push(30));
        assert_eq!(v.as_slice(), &[10, 20]);
    }

    /// Verifies `Fixed32` and `Fixed64` Q-format conversions and basic arithmetic.
    #[test]
    fn fixed_point_arithmetic_round_trip() {
        let a = Fixed32::from_int(3);
        let b = Fixed32::from_f32(1.5);
        assert_eq!((a + b).to_f32(), 4.5);
        assert_eq!((a * b).to_f32(), 4.5);
        assert_eq!((a / b).to_f32(), 2.0);
        let d = Fixed64::from_int(5) - Fixed64::from_f64(1.25);
        assert_eq!(d.to_f64(), 3.75);
        assert_eq!(
            Fixed64::from_f64(7.5) / Fixed64::from_f64(2.5),
            Fixed64::from_int(3)
        );
        assert_eq!(
            Fixed64::from_f64(-7.5) / Fixed64::from_f64(2.5),
            Fixed64::from_int(-3)
        );
        assert_eq!(
            Fixed64::from_int(1) / Fixed64::from_int(3),
            Fixed64((1i64 << 32) / 3)
        );
        // Zero-divisor totality and negative/MIN restoring parity
        assert_eq!(Fixed32::from_int(3) / Fixed32(0), Fixed32(0));
        assert_eq!(Fixed64::from_int(5) / Fixed64(0), Fixed64(0));
        assert_eq!(Fixed32::from_f32(f32::NAN), Fixed32(0));
        assert_eq!(Fixed32::from_f32(f32::INFINITY), Fixed32(0));
        assert_eq!(Fixed32::from_f32(f32::NEG_INFINITY), Fixed32(0));
        assert_eq!(Fixed64::from_f64(f64::NAN), Fixed64(0));
        assert_eq!(Fixed64::from_f64(f64::INFINITY), Fixed64(0));
        assert_eq!(Fixed64::from_f64(f64::NEG_INFINITY), Fixed64(0));
        for &(a, b) in &[
            (i64::MIN, -1),
            (i64::MIN, i64::MIN),
            (i64::MIN, 2),
            (i64::MAX, -3),
            (-1_234_567_890_123, 987_654_321),
            (0, -1),
            (1, 0),
        ] {
            let lhs = Fixed64(a);
            let rhs = Fixed64(b);
            assert_eq!(lhs / rhs, lhs.div_restoring(rhs), "a={a} b={b}");
        }
    }
}
