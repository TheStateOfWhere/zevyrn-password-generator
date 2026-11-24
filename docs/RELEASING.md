# Validation and release process

## Transitional PR validation

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

During migration, automatic PR qualification also continues in
`qualify-maintenance-image.yml`. This temporary overlap is intentional. Do not
remove its PR trigger until hosted coverage has been independently accepted and
trigger removal separately authorized.

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

## Hosted migration acceptance

Local integrity, workflow, Bash and configuration tests do not substitute for
Linux Docker execution or the Windows artifact/browser transfer. Before trigger
retirement, verify both workflows on a candidate PR: retained OCI identity,
fresh builder/runtime and configuration-secret scans, SBOM, all patched-package
and hardening checks, authenticated artifact transport, and all eight suites.
Confirm failure summaries and sanitized evidence on controlled negative cases.
No release qualification/publication rerun is needed merely to test this PR path.
