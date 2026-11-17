# Contributing to OpenCRT

Thank you for helping. This page describes how a change gets into OpenCRT.

## Before you start

- To report a bug or ask for a feature, open an issue with one of the issue forms.
- If you plan a larger change, open an issue first, so that we can agree on the approach before you write code.
- For a small fix, open a pull request directly.

## Clean-room rule

OpenCRT is a clean-room reimplementation of SecureCRT. SecureCRT's features and behaviour are learned only from its public documentation and from using the product.

- Do not copy SecureCRT source code, binaries, decompiled or disassembled code, strings or other assets.
- Do not paste text from SecureCRT's documentation into the code or the docs.
- Write every line from scratch.

## Build and test

The README section "Build and run" lists what you need to install. CI runs these commands on Windows, macOS and Linux, and a pull request must pass them:

```
cargo clippy --all-targets -- -D warnings
cargo test
```

If you change the RDP helper (`crates/opencrt-rdp`), also run its own commands:

```
cargo clippy --manifest-path crates/opencrt-rdp/Cargo.toml --target-dir target --all-targets -- -D warnings
cargo test --manifest-path crates/opencrt-rdp/Cargo.toml --target-dir target
```

The README section "Development" describes local test servers for SSH and RDP.

## How we write code

- Make the smallest change that solves the problem, and reuse what the code already has.
- Add one small test for each change that is not trivial.
- Write a comment only when the reason for the code is not clear from the code itself.
- Do not run `cargo fmt`. The code is formatted by hand, and `cargo fmt` rewrites whole files. Match the style of the code around your change.

## Interface text

The interface is translated into 29 languages.

- Mark new interface text with `@tr("...")` in Slint files and with `tr!("...")` in Rust.
- After you add or change interface text, run `crates/opencrt/lang/update-template.sh`.
- You do not need to translate your new text. The maintainer adds the translations before a release.
- If a translation in your own language reads wrong, a pull request that corrects the `.po` file in `crates/opencrt/lang/` is welcome.

## IronRDP

The RDP helper uses local copies of four IronRDP crates, in `crates/opencrt-rdp/vendor/`, with our own fixes. If you change one of them, describe the change in that crate's `OPENCRT.md`.

## Pull requests

- Keep each pull request to one topic.
- In the description, say what changed, why, and how you tested it. The pull request template has these headings.
- For a pull request from a first-time contributor, GitHub holds the CI run until the maintainer approves it.
- The maintainer merges with squash, so the title becomes the commit message on `main`. Use the form "Area: what changed", for example "RDP: resizes with xrdp 0.10.1".

## Licence

Contributions are accepted under the Apache License 2.0, as section 5 of `LICENSE` says. The README section "Licence" explains how Slint's GPL-3.0 applies to the `opencrt` program.

## Code of conduct

Everyone who takes part in this project follows the [code of conduct](CODE_OF_CONDUCT.md).
