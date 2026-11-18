# Security policy

## Supported versions

Only the newest release of OpenCRT gets security fixes. OpenCRT looks for new releases once a day and updates itself, and the Linux package repositories always carry the newest release.

## Report a vulnerability

Do not report a vulnerability in a public issue.

1. Open the repository's Security tab on GitHub.
2. Click "Report a vulnerability".
3. Describe the problem, the affected version and operating system, and the steps that show it.

If you cannot use GitHub, send the report by email to opencrt@attr.ee.

You get an answer to every report. When a fix is ready, it comes out in a new release, and the release notes name the problem. If you want, the advisory also names you.

## Scope

The policy covers the `opencrt` program, the RDP helper `opencrt-rdp`, the installers and packages on the release page, and the Linux package repositories.

Every night, `cargo deny` compares the Rust crates that OpenCRT uses with the RustSec advisory database. A known advisory in a dependency does not need a report, but a report that shows how it affects OpenCRT is welcome.
