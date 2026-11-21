//! Contiguous SIMD-friendly slice iteration and selective `&mut?` tick-range coalescing over
//! Bevy `0.20` [`Query`] tables.

use bevy_ecs::change_detection::{ContiguousComponentTicksMut, ContiguousMut};
use bevy_ecs::query::{
    ArchetypeFilter, ContiguousQueryData, QueryContiguousIter, QueryContiguousParIter, QueryData,
    QueryFilter, QueryNotDenseError,
};
use bevy_ecs::system::Query;

/// Extension trait on Bevy `0.20` [`Query`] providing dense contiguous slice iteration helpers for
/// Strata `@par(chunk = ...)` and SIMD loops.
pub trait ChunkSliceQueryExt<'w, 's, D: QueryData, F: QueryFilter> {
    /// Returns a sequential read-only contiguous table-slice iterator (`BAM_RESTRICT`-equivalent
    /// non-aliasing slices).
    fn strata_contiguous_iter(
        &self,
    ) -> Result<QueryContiguousIter<'_, 's, D::ReadOnly, F>, QueryNotDenseError>
    where
        D::ReadOnly: ContiguousQueryData,
        F: ArchetypeFilter;

    /// Returns a sequential mutable contiguous table-slice iterator.
    fn strata_contiguous_iter_mut(
        &mut self,
    ) -> Result<QueryContiguousIter<'_, 's, D, F>, QueryNotDenseError>
    where
        D: ContiguousQueryData,
        F: ArchetypeFilter;

    /// Returns a parallel read-only contiguous table-slice iterator.
    fn strata_contiguous_par_iter(
        &self,
    ) -> Result<QueryContiguousParIter<'_, 's, D::ReadOnly, F>, QueryNotDenseError>
    where
        D::ReadOnly: ContiguousQueryData,
        F: ArchetypeFilter;

    /// Returns a parallel mutable contiguous table-slice iterator.
    fn strata_contiguous_par_iter_mut(
        &mut self,
    ) -> Result<QueryContiguousParIter<'_, 's, D, F>, QueryNotDenseError>
    where
        D: ContiguousQueryData,
        F: ArchetypeFilter;
}

impl<'w, 's, D: QueryData, F: QueryFilter> ChunkSliceQueryExt<'w, 's, D, F>
    for Query<'w, 's, D, F>
{
    #[inline]
    fn strata_contiguous_iter(
        &self,
    ) -> Result<QueryContiguousIter<'_, 's, D::ReadOnly, F>, QueryNotDenseError>
    where
        D::ReadOnly: ContiguousQueryData,
        F: ArchetypeFilter,
    {
        self.contiguous_iter()
    }

    #[inline]
    fn strata_contiguous_iter_mut(
        &mut self,
    ) -> Result<QueryContiguousIter<'_, 's, D, F>, QueryNotDenseError>
    where
        D: ContiguousQueryData,
        F: ArchetypeFilter,
    {
        self.contiguous_iter_mut()
    }

    #[inline]
    fn strata_contiguous_par_iter(
        &self,
    ) -> Result<QueryContiguousParIter<'_, 's, D::ReadOnly, F>, QueryNotDenseError>
    where
        D::ReadOnly: ContiguousQueryData,
        F: ArchetypeFilter,
    {
        self.contiguous_par_iter()
    }

    #[inline]
    fn strata_contiguous_par_iter_mut(
        &mut self,
    ) -> Result<QueryContiguousParIter<'_, 's, D, F>, QueryNotDenseError>
    where
        D: ContiguousQueryData,
        F: ArchetypeFilter,
    {
        self.contiguous_par_iter_mut()
    }
}

/// Pure, allocation-free interval coalescing state machine for `&mut? T` selective change
/// tracking.
///
/// Adjacent or overlapping dirty row indices/ranges `[start, end)` are merged in registers into a
/// single `pending_run`; disjoint ranges flush the previous run immediately via `on_flush`.
/// Extracting this state machine allows both [`SelectiveMutSlice`] and standalone unit,
/// `proptest`, and Kani proofs to verify exact interval bounds with zero Bevy world setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRunCoalescer {
    row_count: u32,
    pending_run: Option<(u32, u32)>,
    flushed_rows: usize,
}

impl DirtyRunCoalescer {
    /// Creates an empty run coalescer bounded to `row_count` rows.
    #[inline]
    #[must_use]
    pub const fn new(row_count: u32) -> Self {
        Self {
            row_count,
            pending_run: None,
            flushed_rows: 0,
        }
    }

    /// Returns the total row count bound configured on this coalescer.
    #[inline]
    #[must_use]
    pub const fn row_count(self) -> u32 {
        self.row_count
    }

    /// Returns the currently buffered contiguous range `[start, end)`, if any.
    #[inline]
    #[must_use]
    pub const fn pending_run(self) -> Option<(u32, u32)> {
        self.pending_run
    }

    /// Returns the cumulative number of rows already committed via `on_flush`.
    #[inline]
    #[must_use]
    pub const fn flushed_rows(self) -> usize {
        self.flushed_rows
    }

    /// Records a single row `idx`, extending or flushing the active run as needed. Out-of-bounds
    /// indices are ignored safely without overflow.
    #[inline]
    pub fn mark_row(&mut self, idx: usize, on_flush: impl FnMut(u32, u32)) {
        if let Ok(idx_u32) = u32::try_from(idx)
            && idx_u32 < self.row_count
        {
            self.mark_range(idx_u32, idx_u32 + 1, on_flush);
        }
    }

    /// Records the half-open row range `[start, end)`, clamping `end` to `row_count`. Empty or
    /// inverted ranges (`start >= clamped_end`) are no-ops.
    #[inline]
    pub fn mark_range(&mut self, start: u32, end: u32, mut on_flush: impl FnMut(u32, u32)) {
        let clamped_end = end.min(self.row_count);
        if start >= clamped_end {
            return;
        }
        match self.pending_run {
            Some((cur_start, cur_end)) if start <= cur_end && clamped_end >= cur_start => {
                self.pending_run = Some((cur_start.min(start), cur_end.max(clamped_end)));
            }
            Some((cur_start, cur_end)) => {
                on_flush(cur_start, cur_end);
                self.flushed_rows += (cur_end - cur_start) as usize;
                self.pending_run = Some((start, clamped_end));
            }
            None => {
                self.pending_run = Some((start, clamped_end));
            }
        }
    }

    /// Flushes any remaining pending run and returns the cumulative flushed row count.
    #[inline]
    pub fn finish(&mut self, mut on_flush: impl FnMut(u32, u32)) -> usize {
        if let Some((start, end)) = self.pending_run.take() {
            on_flush(start, end);
            self.flushed_rows += (end - start) as usize;
        }
        self.flushed_rows
    }
}

/// Safe wrapper over a contiguous mutable table slice implementing Strata's `&mut? T` selective
/// tick-range coalescing.
///
/// Underlying component data is accessed without eagerly stamping the table dirty. Callers mark
/// individual rows (`mark_dirty_row`) or ranges (`mark_dirty_range`) and flush coalesced runs once
/// per table via [`Self::flush_dirty_runs`] (or `Drop`). If zero rows were mutated, Bevy `0.20`
/// `summary_tick` stays completely clean.
pub struct SelectiveMutSlice<'w, T> {
    values: &'w mut [T],
    ticks: ContiguousComponentTicksMut<'w>,
    coalescer: DirtyRunCoalescer,
}

impl<'w, T> SelectiveMutSlice<'w, T> {
    /// Wraps a Bevy `ContiguousMut<'w, T>` without eagerly marking all rows as changed.
    #[inline]
    pub fn from_contiguous_mut(cm: ContiguousMut<'w, T>) -> Self {
        let (values, ticks) = ContiguousMut::bypass_change_detection_split(cm);
        let row_count = u32::try_from(values.len()).unwrap_or(u32::MAX);
        Self {
            values,
            ticks,
            coalescer: DirtyRunCoalescer::new(row_count),
        }
    }

    /// Returns the number of rows in this contiguous table slice.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if this slice contains zero rows.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns a shared slice over all component values without marking ticks dirty.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.values
    }

    /// Returns an untracked mutable slice over all component values.
    ///
    /// Callers MUST invoke [`Self::mark_dirty_row`] or [`Self::mark_dirty_range`] for every
    /// actually-mutated row index so downstream `Changed<T>` queries remain sound.
    #[inline]
    pub fn as_mut_untracked(&mut self) -> &mut [T] {
        self.values
    }

    /// Reads row `idx` without dirtying its change tick.
    #[inline]
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.values.get(idx)
    }

    /// Mutably borrows row `idx` without eagerly marking it changed; combine with
    /// [`Self::mark_dirty_row`] inside conditional mutation branches.
    #[inline]
    pub fn get_mut_untracked(&mut self, idx: usize) -> Option<&mut T> {
        self.values.get_mut(idx)
    }

    /// Applies `f` to row `idx` and marks that row dirty iff `f` returns `true`, coalescing
    /// contiguous dirty runs in registers.
    #[inline]
    pub fn update_if(&mut self, idx: usize, f: impl FnOnce(&mut T) -> bool) {
        if let Some(item) = self.values.get_mut(idx)
            && f(item)
        {
            self.mark_dirty_row(idx);
        }
    }

    /// Records row `idx` as mutated, extending the active contiguous run `(start, end)` if
    /// adjacent or flushing the previous run first.
    #[inline]
    pub fn mark_dirty_row(&mut self, idx: usize) {
        let ticks = &mut self.ticks;
        self.coalescer.mark_row(idx, |start, end| {
            ticks.reborrow().slice(start..end).mark_all_as_changed();
        });
    }

    /// Records the half-open row range `[start, end)` as mutated, coalescing contiguous runs.
    #[inline]
    pub fn mark_dirty_range(&mut self, start: u32, end: u32) {
        let ticks = &mut self.ticks;
        self.coalescer.mark_range(start, end, |s, e| {
            ticks.reborrow().slice(s..e).mark_all_as_changed();
        });
    }

    /// Flushes any buffered contiguous dirty run to Bevy's change ticks (including `summary_tick`).
    ///
    /// Returns the total number of rows marked dirty across this slice's lifetime.
    #[inline]
    pub fn flush_dirty_runs(&mut self) -> usize {
        let ticks = &mut self.ticks;
        self.coalescer.finish(|start, end| {
            ticks.reborrow().slice(start..end).mark_all_as_changed();
        })
    }
}

impl<T> Drop for SelectiveMutSlice<'_, T> {
    #[inline]
    fn drop(&mut self) {
        let _ = self.flush_dirty_runs();
    }
}

#[cfg(test)]
mod tests {
    use super::DirtyRunCoalescer;

    /// Verifies contiguous single-row mutations coalesce into one `[start, end)` flush and
    /// disjoint mutations flush immediately with exact half-open bounds.
    #[test]
    fn coalesces_adjacent_and_flushes_disjoint_runs() {
        let mut c = DirtyRunCoalescer::new(16);
        let mut flushes = Vec::new();
        for row in [2usize, 3, 4, 8, 9, 7, 15, 999] {
            c.mark_row(row, |s, e| flushes.push((s, e)));
        }
        let total = c.finish(|s, e| flushes.push((s, e)));
        assert_eq!(flushes, vec![(2, 5), (7, 10), (15, 16)]);
        assert_eq!(total, 7);
        assert_eq!(c.pending_run(), None);
        assert_eq!(c.flushed_rows(), 7);
    }

    /// Verifies inverted, zero-width, and past-end ranges become no-ops and do not inflate count.
    #[test]
    fn clamps_and_ignores_invalid_ranges() {
        let mut c = DirtyRunCoalescer::new(5);
        let mut flushes = Vec::new();
        c.mark_range(3, 3, |s, e| flushes.push((s, e)));
        c.mark_range(4, 2, |s, e| flushes.push((s, e)));
        c.mark_range(5, 10, |s, e| flushes.push((s, e)));
        c.mark_range(3, 100, |s, e| flushes.push((s, e)));
        let total = c.finish(|s, e| flushes.push((s, e)));
        assert_eq!(flushes, vec![(3, 5)]);
        assert_eq!(total, 2);
    }
}
