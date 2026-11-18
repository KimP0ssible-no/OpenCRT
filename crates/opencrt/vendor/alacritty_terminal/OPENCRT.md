# alacritty_terminal 0.26.0, with a smaller scrollback step

A copy of [alacritty_terminal](https://crates.io/crates/alacritty_terminal)
0.26.0 (the Alacritty authors, Apache-2.0; see LICENSE-APACHE), used through
`[patch.crates-io]` in the root `Cargo.toml` and in `crates/opencrt/fuzz/Cargo.toml`.

The one change is in `src/grid/storage.rs`: `MAX_CACHE_SIZE` is 100 instead of
1000. The scrollback grows by that many empty rows at a time, and every row
holds a full line of 24-byte cells. With 1000, a tab added about 2.4 MB at 101
columns the first time it scrolled, even with a few lines of history. With 100,
that step is about 240 KB. The upstream reference tests (`tests/`) are not
copied.

Delete this copy and the patches once a released alacritty_terminal makes the
step smaller or configurable.
