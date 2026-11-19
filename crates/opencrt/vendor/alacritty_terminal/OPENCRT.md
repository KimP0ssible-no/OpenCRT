# alacritty_terminal 0.26.0, with a smaller scrollback step and compact history

A copy of [alacritty_terminal](https://crates.io/crates/alacritty_terminal)
0.26.0 (the Alacritty authors, Apache-2.0; see LICENSE-APACHE), used through
`[patch.crates-io]` in the root `Cargo.toml` and in `crates/opencrt/fuzz/Cargo.toml`.

The one change is in `src/grid/storage.rs`: `MAX_CACHE_SIZE` is 100 instead of
1000. The scrollback grows by that many empty rows at a time, and every row
holds a full line of 24-byte cells. With 1000, a tab added about 2.4 MB at 101
columns the first time it scrolled, even with a few lines of history. With 100,
that step is about 240 KB. The upstream reference tests (`tests/`) are not
copied.

The second change keeps history lines compact. Upstream stores every line at
the full window width, 24 bytes per cell, so a full 10,000-line scrollback in
a wide window took tens of MB even for short lines. Now:

- `Row` (`src/grid/row.rs`) has a `columns` width and an optional `tail` cell.
  A compacted row stores its cells only up to the last change, and every cell
  after them equals `tail`. Reads past the stored cells return `tail`. Every
  method that changes the row stores all cells again first.
- `Grid::scroll_up` (`src/grid/mod.rs`) compacts the lines that go into
  history. `Storage::compact_into` hands each one's full buffer to a new line
  at the bottom that is about to be cleared, so a full scrollback costs no
  extra allocation per line. `Grid::resize` (`src/grid/resize.rs`) compacts
  the history again after a reflow.
- `Storage::swap` (`src/grid/storage.rs`) uses `slice::swap`. Upstream copied
  rows as four machine words, which is wrong once `Row` is larger.
- `LineLength::line_length` (`src/term/cell.rs`) reads the row cell by cell,
  and `GridCell` requires `Clone + PartialEq`.
- Rows serialize as upstream does (every cell and `occ`), so the upstream
  reference tests in `tests/` pass unchanged.

Delete this copy and the patches once a released alacritty_terminal makes the
step smaller or configurable and stores history compactly.
