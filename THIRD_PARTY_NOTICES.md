# Third-party software and source availability

Second Brain is an independent installer, process-isolation wrapper and set of
operator instructions. It is not the original SilverBullet project and does not
claim authorship of SilverBullet, its fonts, icons or dependencies. No upstream
endorsement is implied.

## SilverBullet

- Original project: https://github.com/silverbulletmd/silverbullet
- Copyright 2022, Zef Hemel and the respective upstream contributors.
- License: MIT; the unmodified notice is in `LICENSE.silverbullet.md`.
- Distributed binary: unmodified upstream Linux x86_64 release asset.
- Exact source revision and binary SHA256: `manifest.json`.
- Corresponding upstream source archive URL is recorded in that manifest.

The MIT license in the root `LICENSE` applies to our installer/wrapper and its
documentation. It does not replace any license or copyright notice for bundled
third-party software.

## Dependencies

`licenses/dependency-inventory.json` records the verified package versions,
license declarations, exact source locations and notice directories. The notice
set conservatively covers all upstream Cargo.lock registry crates, production
npm lock packages and the pinned Git dependencies. Optional, development and
other-platform packages in this superset are not necessarily linked into the
distributed server. Their inclusion is not a statement that every alternative
license applies to this wrapper.

The complete collected copyright, license, AUTHORS and NOTICE files are in
`licenses/dependencies/`. Multi-license components retain the alternatives
offered by their authors. Obligations under compound AND expressions are retained.

## MPL source offer

This distribution includes the complete unmodified published source packages:

- `licenses/sources/option-ext-0.2.0.crate` — MPL-2.0.
- `licenses/sources/htmlescape-0.3.1.crate` — the MPL-2.0 alternative of its
  declared Apache-2.0 / MIT / MPL-2.0 licensing.

The MPL-2.0 text is provided at `licenses/common/MPL-2.0.txt`. Recipients can
extract, use, modify and redistribute those covered source files under MPL-2.0;
this distribution imposes no further restrictions on those source-code rights.
See `licenses/sources/README.md`. The source packages are included locally so
obtaining this source does not require network access.

The unmodified MIT-licensed `bezier-js` source archive is also included, together
with its original author attribution to Pomax, original MIT declarations and the
MIT license terms.

## Fonts and icons

- iA Writer / IBM Plex typefaces: the original OFL-1.1 notice in
  `licenses/fonts/iA-Writer-IBM-Plex-OFL-1.1.txt`.
- Inter typeface: the original OFL-1.1 notice in `licenses/fonts/Inter-OFL-1.1.txt`.
- Material Design icons used through react-icons/md: Apache-2.0;
  `licenses/icons/Material-Design-Apache-2.0.txt` and react-icons notices.
- Feather icons: MIT; `licenses/icons/Feather-MIT.txt` and preact-feather notices.

The fonts and icon resources in the upstream binary are not renamed or modified.
Fonts are bundled with the application, not sold on their own. Their original
licenses remain applicable; the wrapper's MIT license does not relicense them.

## Rust and static C runtime

The upstream binary identifies Rust 1.99.1, source revision
`58cf8f9c35b355199727627d07ae34a4e2846d67`. `licenses/rust-runtime/` preserves
the copyright documents and license texts from the matching official compiler
distribution, including `COPYRIGHT-library.html`, plus musl's COPYRIGHT notice.
Runtime exceptions and component-specific notices remain in force. Additional
license texts in that directory are not a relicense of this wrapper.

Python, systemd, strace and libseccomp are separately installed system components;
their executables/libraries are not redistributed inside this runtime archive.

Copyright-holder names and public upstream contact details in legal notices are
intentional attributions. They are not deployment-host or operator metadata.
