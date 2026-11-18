# vte 0.15.0, without the up-front sync buffer

A copy of [vte](https://crates.io/crates/vte) 0.15.0 (the Alacritty authors,
Apache-2.0 OR MIT; see LICENSE-APACHE and LICENSE-MIT), used through
`[patch.crates-io]` in the root `Cargo.toml` and in `crates/opencrt/fuzz/Cargo.toml`.

The one change is in `src/ansi.rs` (`SyncState::default`): the buffer for
synchronized updates starts empty instead of with 2 MB reserved. Every tab has
its own parser, and glibc served those 2 MB from heap pages that were already
in use, so each tab cost about 1.5 MB more even when no program used
synchronized updates. The buffer now grows only when a program uses them, up
to the same 2 MB limit.

Delete this copy and the patches once a released vte stops reserving the
buffer up front.
