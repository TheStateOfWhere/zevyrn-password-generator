# Validation and release process

## Consolidated PR validation

`quality-security.yml` validates PR heads with read-only permissions. Its Linux
job runs application tests, type checks, actual Compose rendering, the dependency
audit and compiler-integrity verification. One BuildKit builder shares its cache
between the builder target and the retained Linux/amd64 runtime OCI output.

The runtime archive is inspected and loaded locally. Scans, image-configuration
secret checks, the SBOM and hardened execution are bound to its immutable image
ID. Runtime package floors, nonroot execution, read-only operation, permissions,
security headers, health and graceful shutdown remain enforced.

The Windows job consumes the Linux job's exact artifact ID and ZIP checksum. It
checks repository/source, workflow/run/attempt, retained file checksums, OCI
identity and extracted asset inventory before running all eight Edge suites.
It tests the archive's assets rather than rebuilding the application. Fork and
Dependabot PRs receive no registry-write privileges or publication secrets.
The artifact reader needs only `contents: read` and `actions: read`.

Quality records and browser results explicitly have `purpose: quality` and
`promotionEligible: false`, including on main. They are not release qualification
artifacts and cannot be supplied to the existing publication workflow.

`quality-security.yml` is the sole automatic PR validation workflow.
`qualify-maintenance-image.yml` no longer runs on PR events; it remains available
for explicitly dispatched release-purpose qualification on main. Quality and
PR evidence remain non-promotable.

Security failures retain sanitized reports and stage summaries. Raw secret
matches, snippets and failed-image archives are not uploaded as diagnostics.
Successful image packets and browser results are retained for seven days.

## Existing maintenance release path

Milestone 1 does not change manual release qualification or protected publication.
Do not promote a PR or quality packet. Prepare and review coordinated version
metadata through a PR, then validate the exact merged main source.

1. Dispatch `qualify-maintenance-image.yml` on main with the exact approved
   `source_commit`. It performs release-purpose qualification and retains the
   sealed archive and evidence.
2. Review its successful run and immutable artifact/source identities. Create the
   exact release tag at the qualified commit only after authorization. Stop on
   an existing conflicting tag; never overwrite release tags or images.
3. Authorize only that exact tag in `zevyrn-ghcr-publication`, preserving existing
   protections. Dispatch `publish-maintenance-image.yml` from the tag with the
   approved `qualification_run_id`.
4. Review validation before giving protected owner approval. Publication rechecks
   source and retained bytes, the 24-hour qualification limit and one-hour
   promotion database freshness limit. It copies the qualified OCI graph without
   rebuilding, then verifies the public registry digest and anonymous access.

Current maintenance guards remain version-specific to 1.2.3. A later release
requires reviewed metadata and guard updates; these commands are not permission
to republish 1.2.3. Builder-only dispositions remain exact package/version/path
authorizations, not runtime exceptions or a requirement that findings persist.

Public source and images remain supported. Running deployments are supported
only on private/internal networks or localhost. Use the documented Docker and
Compose installation paths; release validation does not authorize deployment.

## Hosted validation and accepted coverage

Local integrity, workflow, Bash and configuration tests do not substitute for
Linux Docker execution or the Windows artifact/browser transfer. Milestone 1B
quality run [45486924463](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45486924463)
and PR qualification run [45486924580](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45486924580)
passed for commit `5781788ae71813dfea8a86a4b7abf7f7a590b6d0`. Their downloaded
evidence had identical runtime asset and SBOM package inventories. Hosted
coverage equivalence was accepted before removing the redundant PR trigger.

For subsequent PR revisions, require consolidated quality to pass its retained
OCI, scans, SBOM, package floors, hardening, authenticated artifact/ZIP handling
and all eight Windows suites. Failure/cancellation retention is supported by
regression tests and workflow conditions; the successful comparison runs were
not deliberately failed or cancelled. Do not dispatch release qualification or
publication merely to test automatic PR validation.
