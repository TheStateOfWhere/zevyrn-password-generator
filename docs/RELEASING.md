# Validation and release process

## Milestone 2B engineering acceptance — complete

Accepted main `52ed2054bfe0618ec7c76ba3e541638300feaceb` has tree
`e25442675684647e251dc2a63fdf12c9bd945ef3`.
[Main quality 45738635825](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45738635825)
and [read-only combined verification 45739286399](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45739286399)
passed on their first attempts. The actual single builder OCI export, authenticated
Skopeo/Docker load, exact configuration bytes, ordered layers and scan-archive
checksum round trip passed; the original configuration mismatch is resolved.
All seven retained artifacts were independently verified. Existing evidence is
preserved; this closeout does not rerun or extend its eligibility.

Runtime vulnerabilities and secrets were zero; unapproved blocking builder
findings were zero. The three exact authorized HIGH builder occurrences remained
visible. Publication and consumer jobs were skipped. The verification receipt and
original quality packets remain non-promotable and cannot publish v1.2.4.

Observed read-only qualification used 95 runner-seconds and 105 elapsed seconds,
compared with the archived 273 and 284 seconds: reductions of 65.2% and 63.0%.
Main quality retained 116,545,978 bytes; verification retained 116,546,361 bytes,
including the authoritative builder OCI. Increased storage is accepted;
optimization is deferred. No publication/consumer performance is claimed.

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

Current maintenance guards are version-specific to 1.2.4. The published v1.2.3
identity remains immutable; these commands are not permission to republish it. Builder-only dispositions remain exact package/version/path
authorizations, not runtime exceptions or a requirement that findings persist.

Public source and images remain supported. Running deployments are supported
only on private/internal networks or localhost. Use the documented Docker and
Compose installation paths; release validation does not authorize deployment.

## Combined release workflow — v1.2.4 activation candidate

`release.yml` is prepared for v1.2.4 with source-level
`LIVE_PUBLICATION_ENABLED: 'true'` and the temporary literal-false job gate
removed. Publication still requires the exact `refs/tags/v1.2.4` ref, the existing
tag-prefix, resolver-output and event/mode predicates, and successful resolve
and qualify dependencies. Local preparation does not authorize commit, push,
merge, tag creation, dispatch or publication. The existing maintenance workflows
remain available with coordinated v1.2.4 guards; no workflow is retired.
No PR, main push or schedule invokes the release workflow.

Manual dispatch defaults to `operation: verify` and requires an exact
`quality_run_id`. Verification is accepted only on main and is structurally
read-only: only `resolve` and `qualify` run. The `publish` job explicitly excludes
verification dispatch, including with an inconsistent resolver publication output. Verification cannot
request the protected environment or obtain `packages: write`; its record has
`purpose: verification`, `promotionEligible: false`. Original quality records
always remain unchanged and non-promotable.

Controlled recovery uses the distinct `operation: release` mode from the exact
version tag, with an explicit quality run. It is rejected on main, on any other
tag. After separately authorized integration and release execution,
it requires the same source, security, freshness and protected owner approval as
a tag push. No dispatch input can change the activation lock or bypass approval.

Successful main push and main manual quality runs retain a separate
`quality-builder-RUN-ATTEMPT` artifact containing the exact scanned builder's
OCI graph, identity and checksum inventory. The existing single main builder
build exports that authoritative OCI directly. Its index, manifests, configuration
and layers are verified before loading it into Docker; the loaded image ID and
DiffIDs must match. The Docker-save scan archive is then derived from that exact
image and verified against the original OCI. The retained OCI is never reconstructed
from a separately serialized Docker image. PRs keep their existing builder-load
path and do not retain a builder archive. This introduces no additional image
build. Transport compression may differ, but configuration bytes and ordered
uncompressed layer identities must match exactly. Only successful
security, hardening and packet validation permit upload. Runtime quality evidence
binds the builder artifact ID, ZIP digest and image identity through
`builder-reference.json`. PRs and Windows do not download the builder archive;
Windows receives only the small reference alongside the runtime packet.
Builder identity failures retain a sanitized stage/category and, for configuration
digest mismatches, only the expected and observed digests. Raw configuration,
labels and environment values are not included in those diagnostics.

For a future authorized tag release, the combined path:

1. Resolves the exact version tag/source/tree from reviewed main history. The
   selected quality run must come from this repository and the active reviewed
   quality workflow revision at that source. Source SHA alone is insufficient.
2. Selects the newest exact-source main push quality run, without falling back
   past failure or incomplete execution. Manual selection may explicitly
   select a successful main manual refresh, but the latest successful exact-source
   main push CI prerequisite is still independently required. All required jobs
   must have succeeded in their current attempt.
3. Authenticates runtime, builder and browser artifact IDs/checksums and their
   repository, source, workflow, run and attempt bindings. The strict native ZIP
   entry checks run before extraction; retained inventories, OCI blobs, image
   configuration, SBOM, assets, hardened execution evidence and all eight browser
   suite results are revalidated afterward. No artifact-provided code is run.
4. Reuses the bound application/compiler/Compose tests, SBOM and browser results.
   It freshly scans both retained images, including file and configuration
   secrets, using the existing pinned scanner and verified fresh database.
   Exact builder-only dispositions remain unchanged; zero remaining approved
   findings is valid. A separate release-purpose record references the originals.
5. Requests the existing `zevyrn-ghcr-publication` owner approval. Registry-write
   authority exists only in this protected job. Existing exact-tag restrictions,
   self-review rules and disabled administrator bypass must remain unchanged.
6. After approval, authenticates the current release attempt's completed
   read-only jobs, upstream runs/artifacts, tag, archive bytes and security receipt
   again. Qualification expires no later than 24 hours after the reused main
   workflow run was created; neither a rerun nor a new receipt resets that clock. The fresh
   release scanner database must have been downloaded in this release attempt,
   remain valid, and be at most one hour old at promotion.
7. Rejects any existing destination version, even one with the same digest.
   It shares the legacy publisher's version concurrency lane and copies the
   exact qualified OCI graph using `--all --preserve-digests`. Existing version
   tags and images are never overwritten.
8. Runs anonymous verification on a separate Ubuntu runner without checkout,
   publication credentials or registry login. An empty Docker client configuration
   is used for actual Engine pulls by version tag and exact OCI index, selecting
   linux/amd64. Evidence includes Engine version, commands, exit codes, repository
   digests, image ID/platform and version/source labels.

Publication and consumer verification are separate outcomes. If the push succeeds
but anonymous pulls fail, the release is published with consumer verification
failed; do not republish, overwrite or automatically rerun it.

### Missing or stale evidence and controlled recovery

The accepted Milestone 1 main packet predates separate builder retention and is
not eligible for this new path. Run the existing quality workflow after this
implementation is merged; do not rebuild merely to archive an existing image.
Seven-day artifact retention does not extend the 24-hour eligibility window.

Missing, expired, ambiguous or mismatched evidence stops execution. Review the
specific source/run/attempt and diagnostics. If the exact approved source is
still main, explicitly dispatch the existing quality workflow on main, then
manually verify that exact refresh run. For an activated, separately authorized
release recovery, dispatch `operation: release` from the unchanged version tag
with that explicit refresh run ID. This reruns quality deliberately; the
release workflow never silently rebuilds, switches source, selects older runs,
or retries. If main has advanced, stop and review the new source/version rather
than moving a tag. An expired owner wait requires a newly authorized read-only
qualification attempt and fresh approval; there is no bypass or automatic rerun.

Current version guards are 1.2.4. Fresh exact-source main quality is required
after integration; the accepted Milestone 2B packet cannot publish this release.
Before a separately authorized tag event, add only the exact tag `v1.2.4` to
`zevyrn-ghcr-publication`, retaining the existing owner reviewer, self-review
policy, disabled administrator bypass and all existing tag allowances. This
local candidate does not change that environment or create the tag.

### Replacement before retirement and cost

Milestone 2B main retention and read-only verification are accepted above.
Validate this activation candidate locally, then obtain separate authorization
for its commit, hosted PR validation, integration and a real version-tag release,
including protected approval and anonymous Docker pulls. Only after that path is
accepted may the two superseded maintenance workflows be disabled under separate
authorization. Preserve their files/history and legacy validators throughout
migration; historical v1.2.1 tooling is outside this change.

Main quality gains one builder artifact of measured compressed size B. The
combined qualification artifact retains approximately runtime packet R + builder
packet B + small browser, receipt and scan records for seven days. This temporary
second copy costs approximately B + (R+B) extra stored bytes per main/release pair;
measured Milestone 2B sizes and runner time are recorded above. PR artifact scope does
not gain builder bytes. Qualification performs zero image/application builds and
zero browser-suite reruns, but adds fresh two-image scanning, authenticated
downloads/inspection and post-publication Docker pulls. Locked tool installation
is retained. The observed qualification reductions above exclude publication and consumer stages.

The standalone v1.2.3 anonymous Docker Engine pull check remains deferred, not
passed and nonblocking; a later release's consumer check cannot clear it.

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
