//! Defines the Row type which makes up lines in the grid.

use std::cmp::{max, min};
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo, RangeToInclusive};
use std::{ptr, slice};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::grid::GridCell;
use crate::index::Column;
use crate::term::cell::ResetDiscriminant;

/// A row in the grid.
#[derive(Default, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize), serde(from = "StoredRow<T>"))]
pub struct Row<T> {
    inner: Vec<T>,

    /// Maximum number of occupied entries.
    ///
    /// This is the upper bound on the number of elements in the row, which have been modified
    /// since the last reset. All cells after this point are guaranteed to be equal.
    pub(crate) occ: usize,

    /// Width of the row. A compacted row stores fewer cells: all after `inner` equal `tail`.
    columns: usize,
    tail: Option<T>,
}

/// A row as upstream serializes it: every cell, compacted or not.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
struct StoredRow<T> {
    inner: Vec<T>,
    occ: usize,
}

#[cfg(feature = "serde")]
impl<T> From<StoredRow<T>> for Row<T> {
    fn from(row: StoredRow<T>) -> Self {
        Row::from_vec(row.inner, row.occ)
    }
}

#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for Row<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        struct Cells<'a, T>(&'a Row<T>);
        impl<T: Serialize> Serialize for Cells<'_, T> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_seq(self.0)
            }
        }

        let mut row = serializer.serialize_struct("Row", 2)?;
        row.serialize_field("inner", &Cells(self))?;
        row.serialize_field("occ", &self.occ)?;
        row.end()
    }
}

impl<T: PartialEq> PartialEq for Row<T> {
    fn eq(&self, other: &Self) -> bool {
        self.columns == other.columns && (0..self.columns).all(|i| self.cell(i) == other.cell(i))
    }
}

impl<T: Default> Row<T> {
    /// Create a new terminal row.
    ///
    /// Ideally the `template` should be `Copy` in all performance sensitive scenarios.
    pub fn new(columns: usize) -> Row<T> {
        debug_assert!(columns >= 1);

        let mut inner: Vec<T> = Vec::with_capacity(columns);

        // This is a slightly optimized version of `std::vec::Vec::resize`.
        unsafe {
            let mut ptr = inner.as_mut_ptr();

            for _ in 1..columns {
                ptr::write(ptr, T::default());
                ptr = ptr.offset(1);
            }
            ptr::write(ptr, T::default());

            inner.set_len(columns);
        }

        Row { inner, occ: 0, columns, tail: None }
    }

    /// Increase the number of columns in the row.
    #[inline]
    pub fn grow(&mut self, columns: usize)
    where
        T: Clone,
    {
        self.expand();
        if self.inner.len() >= columns {
            return;
        }

        self.inner.resize_with(columns, T::default);
        self.columns = columns;
    }

    /// Reduce the number of columns in the row.
    ///
    /// This will return all non-empty cells that were removed.
    pub fn shrink(&mut self, columns: usize) -> Option<Vec<T>>
    where
        T: GridCell,
    {
        self.expand();
        if self.inner.len() <= columns {
            return None;
        }

        // Split off cells for a new row.
        let mut new_row = self.inner.split_off(columns);
        self.columns = columns;
        let index = new_row.iter().rposition(|c| !c.is_empty()).map_or(0, |i| i + 1);
        new_row.truncate(index);

        self.occ = min(self.occ, columns);

        if new_row.is_empty() { None } else { Some(new_row) }
    }

    /// Reset all cells in the row to the `template` cell.
    #[inline]
    pub fn reset<D>(&mut self, template: &T)
    where
        T: ResetDiscriminant<D> + GridCell,
        D: PartialEq,
    {
        self.expand();
        debug_assert!(!self.inner.is_empty());

        // Mark all cells as dirty if template cell changed.
        let len = self.inner.len();
        if self.inner[len - 1].discriminant() != template.discriminant() {
            self.occ = len;
        }

        // Reset every dirty cell in the row.
        for item in &mut self.inner[0..self.occ] {
            item.reset(template);
        }

        self.occ = 0;
    }
}

#[allow(clippy::len_without_is_empty)]
impl<T> Row<T> {
    #[inline]
    pub fn from_vec(vec: Vec<T>, occ: usize) -> Row<T> {
        Row { columns: vec.len(), inner: vec, occ, tail: None }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.columns
    }

    #[inline]
    fn cell(&self, index: usize) -> &T {
        self.inner.get(index).unwrap_or_else(|| {
            assert!(index < self.columns, "column {index} out of {}", self.columns);
            self.tail.as_ref().expect("a compacted row has a tail cell")
        })
    }

    /// Store every cell again, as a compacted row leaves the trailing ones out.
    #[inline]
    fn expand(&mut self)
    where
        T: Clone,
    {
        if let Some(tail) = self.tail.take() {
            self.inner.resize(self.columns, tail);
        }
    }

    /// Stop storing the run of identical cells at the end of the row; reads still see them.
    pub(crate) fn compact(&mut self)
    where
        T: Clone + PartialEq,
    {
        let Some(last) = self.inner.last().filter(|_| self.tail.is_none()) else {
            return;
        };
        // Cells from `occ` on all equal `last`, so only the ones before it need a look.
        let end = min(self.occ, self.inner.len());
        let keep = self.inner[..end].iter().rposition(|cell| cell != last).map_or(0, |i| i + 1);
        // Too few cells to be worth a reallocation.
        if self.columns - keep < 8 {
            return;
        }
        self.tail = Some(last.clone());
        // A new buffer, so the whole full-width one is freed: shrinking it in place would
        // leave a hole in the heap that only a smaller allocation can reuse.
        self.inner = self.inner[..keep].to_vec();
    }

    /// Compact the row, and hand its full buffer to `spare`, a compacted row about to be reset,
    /// so neither needs to rebuild the trailing cells.
    pub(crate) fn compact_into(&mut self, spare: &mut Row<T>)
    where
        T: Clone + PartialEq,
    {
        let Some(last) = self.inner.last().filter(|_| self.tail.is_none()) else {
            return;
        };
        if spare.tail.is_none() || spare.columns != self.columns {
            return self.compact();
        }
        let end = min(self.occ, self.inner.len());
        let keep = self.inner[..end].iter().rposition(|cell| cell != last).map_or(0, |i| i + 1);
        if self.columns - keep < 8 {
            return;
        }
        // Cells after `occ` stay equal in the handed-over buffer, as reset expects.
        self.tail = Some(last.clone());
        let used = self.inner[..keep].to_vec();
        spare.inner = std::mem::replace(&mut self.inner, used);
        spare.occ = self.occ;
        spare.tail = None;
    }

    #[inline]
    pub fn last(&self) -> Option<&T> {
        self.columns.checked_sub(1).map(|i| self.cell(i))
    }

    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T>
    where
        T: Clone,
    {
        self.expand();
        self.occ = self.inner.len();
        self.inner.last_mut()
    }

    #[inline]
    pub fn append(&mut self, vec: &mut Vec<T>)
    where
        T: GridCell + Clone,
    {
        self.expand();
        self.occ += vec.len();
        self.inner.append(vec);
        self.columns = self.inner.len();
    }

    #[inline]
    pub fn append_front(&mut self, mut vec: Vec<T>)
    where
        T: Clone,
    {
        self.expand();
        self.occ += vec.len();

        vec.append(&mut self.inner);
        self.inner = vec;
        self.columns = self.inner.len();
    }

    /// Check if all cells in the row are empty.
    #[inline]
    pub fn is_clear(&self) -> bool
    where
        T: GridCell,
    {
        self.inner.iter().all(GridCell::is_empty) && self.tail.as_ref().is_none_or(GridCell::is_empty)
    }

    #[inline]
    pub fn front_split_off(&mut self, at: usize) -> Vec<T>
    where
        T: Clone,
    {
        self.expand();
        self.occ = self.occ.saturating_sub(at);

        let mut split = self.inner.split_off(at);
        std::mem::swap(&mut split, &mut self.inner);
        self.columns = self.inner.len();
        split
    }
}

impl<'a, T> IntoIterator for &'a Row<T> {
    type IntoIter =
        std::iter::Chain<slice::Iter<'a, T>, std::iter::Flatten<std::iter::RepeatN<Option<&'a T>>>>;
    type Item = &'a T;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        let tail = std::iter::repeat_n(self.tail.as_ref(), self.columns - self.inner.len());
        self.inner.iter().chain(tail.flatten())
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut Row<T> {
    type IntoIter = slice::IterMut<'a, T>;
    type Item = &'a mut T;

    #[inline]
    fn into_iter(self) -> slice::IterMut<'a, T> {
        self.expand();
        self.occ = self.len();
        self.inner.iter_mut()
    }
}

impl<T> Index<Column> for Row<T> {
    type Output = T;

    #[inline]
    fn index(&self, index: Column) -> &T {
        self.cell(index.0)
    }
}

impl<T: Clone> IndexMut<Column> for Row<T> {
    #[inline]
    fn index_mut(&mut self, index: Column) -> &mut T {
        self.expand();
        self.occ = max(self.occ, *index + 1);
        &mut self.inner[index.0]
    }
}

impl<T> Index<Range<Column>> for Row<T> {
    type Output = [T];

    #[inline]
    fn index(&self, index: Range<Column>) -> &[T] {
        &self.inner[(index.start.0)..(index.end.0)]
    }
}

impl<T: Clone> IndexMut<Range<Column>> for Row<T> {
    #[inline]
    fn index_mut(&mut self, index: Range<Column>) -> &mut [T] {
        self.expand();
        self.occ = max(self.occ, *index.end);
        &mut self.inner[(index.start.0)..(index.end.0)]
    }
}

impl<T> Index<RangeTo<Column>> for Row<T> {
    type Output = [T];

    #[inline]
    fn index(&self, index: RangeTo<Column>) -> &[T] {
        &self.inner[..(index.end.0)]
    }
}

impl<T: Clone> IndexMut<RangeTo<Column>> for Row<T> {
    #[inline]
    fn index_mut(&mut self, index: RangeTo<Column>) -> &mut [T] {
        self.expand();
        self.occ = max(self.occ, *index.end);
        &mut self.inner[..(index.end.0)]
    }
}

impl<T> Index<RangeFrom<Column>> for Row<T> {
    type Output = [T];

    #[inline]
    fn index(&self, index: RangeFrom<Column>) -> &[T] {
        &self.inner[(index.start.0)..]
    }
}

impl<T: Clone> IndexMut<RangeFrom<Column>> for Row<T> {
    #[inline]
    fn index_mut(&mut self, index: RangeFrom<Column>) -> &mut [T] {
        self.expand();
        self.occ = self.len();
        &mut self.inner[(index.start.0)..]
    }
}

impl<T> Index<RangeFull> for Row<T> {
    type Output = [T];

    #[inline]
    fn index(&self, _: RangeFull) -> &[T] {
        &self.inner[..]
    }
}

impl<T: Clone> IndexMut<RangeFull> for Row<T> {
    #[inline]
    fn index_mut(&mut self, _: RangeFull) -> &mut [T] {
        self.expand();
        self.occ = self.len();
        &mut self.inner[..]
    }
}

impl<T> Index<RangeToInclusive<Column>> for Row<T> {
    type Output = [T];

    #[inline]
    fn index(&self, index: RangeToInclusive<Column>) -> &[T] {
        &self.inner[..=(index.end.0)]
    }
}

impl<T: Clone> IndexMut<RangeToInclusive<Column>> for Row<T> {
    #[inline]
    fn index_mut(&mut self, index: RangeToInclusive<Column>) -> &mut [T] {
        self.expand();
        self.occ = max(self.occ, *index.end + 1);
        &mut self.inner[..=(index.end.0)]
    }
}

#[cfg(test)]
mod tests {
    use super::Row;
    use crate::index::Column;
    use crate::term::cell::{Cell, LineLength};
    use crate::vte::ansi::{Color, NamedColor};

    #[test]
    fn compacted_row_reads_and_writes_like_a_full_row() {
        let mut row = Row::<Cell>::new(80);
        row[Column(0)].c = 'a';
        row[Column(1)].c = 'b';
        // A coloured run to the end of the line, as an erase with a background colour leaves.
        for column in 2..80 {
            row[Column(column)].bg = Color::Named(NamedColor::Red);
        }
        let full = row.clone();

        row.compact();
        assert_eq!(row.inner.len(), 2);
        assert_eq!((row.len(), row.line_length()), (80, Column(2)));
        assert_eq!(row[Column(79)].bg, Color::Named(NamedColor::Red));
        assert_eq!(row.last(), full.last());
        assert_eq!((&row).into_iter().rev().count(), 80);
        assert!(row == full && !row.is_clear());

        // Handing over the buffer: the spare gets every cell back and clears like a new row.
        let (mut leaving, mut spare) = (full.clone(), Row::<Cell>::new(80));
        spare.compact();
        leaving.compact_into(&mut spare);
        assert!(leaving == full && leaving.inner.len() == 2 && spare.inner.len() == 80);
        spare.reset(&Cell::default());
        assert!(spare == Row::new(80));

        // A write stores every cell again.
        row[Column(50)].c = 'c';
        assert_eq!(row.inner.len(), 80);
        assert_eq!((row[Column(50)].c, row[Column(79)].bg), ('c', Color::Named(NamedColor::Red)));
    }
}
