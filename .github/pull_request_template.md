## What and why

<!-- What does this change, and which problem does it solve? Name the issue, e.g. "Fixes #123". -->

## How it was tested

<!-- The commands you ran, and what you tried by hand (operating system, server). -->

## Checklist

- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo test` pass (also for `crates/opencrt-rdp` if it changed)
- [ ] No code, text or assets from SecureCRT ([clean-room rule](https://github.com/KimP0ssible-no/OpenCRT/blob/main/CONTRIBUTING.md#clean-room-rule))
- [ ] New or changed interface text: `crates/opencrt/lang/update-template.sh` run
