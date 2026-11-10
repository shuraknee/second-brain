# License review and publication scope

## Own code

The independent Python installer, wrapper, tests and operator documentation are
released under MIT (`LICENSE`), as selected by the project owner. The SilverBullet
binary and resources remain owned/licensed by their respective upstream authors.
This project does not claim original authorship of the SilverBullet core.
The offline patch is also MIT; original upstream copyright notices remain intact.

## Review performed for this fixed binary

1. Verified the pinned upstream source revision and preserved SilverBullet's MIT
   copyright and permission notice.
2. Downloaded the exact 532 registry crate packages in Cargo.lock and 143
   production npm packages in package-lock.json as data. Checked their archive
   hashes against the lockfiles; no package hooks or source code were executed.
3. Collected original license/copyright/NOTICE/AUTHORS files. Where a published
   package omitted notices, obtained them from its recorded upstream VCS revision
   or its matching parent package. Preserved original declarations and full
   source packages for the remaining small packages as documented in the inventory.
4. Reviewed the two pinned Candle Git components and preserved their MIT/Apache
   notices from the exact recorded revision.
5. Included source and MPL-2.0 terms for option-ext and htmlescape; no restriction
   is imposed on recipients' MPL source rights.
6. Preserved the OFL font notices, the licenses for the icon sets used by the
   frontend, and Rust standard-library/static-runtime notices.
7. Added build-time integrity checks for every collected legal file and the
   included source packages. A missing/changed legal file blocks packaging.

Details: `licenses/audit.json`, `licenses/dependency-inventory.json`, and
`THIRD_PARTY_NOTICES.md`. The inventory is a conservative superset rather than
a reconstructed exact linker map. A package's inclusion in the notice collection
does not imply that optional/dev/other-target code was linked into the server.

This review concerns the declared licenses and redistribution requirements of
the recorded upstream releases. It does not assert ownership of upstream work,
grant trademark rights, or provide an endorsement by an upstream author.

The offline rebuild removes external transports and fixes UTF-8 path headers.
Its Cargo lockfile introduces no new package/version/source compared with the
reviewed upstream lockfile; the notice collection remains a conservative superset.
The compiler remains the reviewed Rust 1.99.1; musl notices remain included.
Original upstream licensing applies to the modified core, with our modifications
under MIT. Patch/source provenance is recorded in manifest.json and patches/.

## Release rules

- Keep the original and offline binary checksums, source reference and patch. A different upstream
  binary requires a new dependency/resource license review.
- Ship `LICENSE`, `LICENSE.silverbullet.md`, `THIRD_PARTY_NOTICES.md`, this file,
  and the complete verified `licenses/` directory with every binary package.
- Do not remove copyright notices or author names for anonymization. Exclude
  host reports and deployment metadata, not legally required attributions.
- Publish only if the legal inventory has no unresolved package and every legal
  file/source checksum is verified. Preserve exact source packages and MPL rights.
- Never claim that the upstream application was authored by this repository.

Primary references: the pinned SilverBullet license, SIL OFL-1.1, and MPL-2.0
sections 3.1–3.4. Full source URLs and original notices are included locally;
reading them does not require downloading anything at application startup.
