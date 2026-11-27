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
Quality and PR evidence remain non-promotable; release-purpose qualification
is performed separately by the combined release workflow.

Security failures retain sanitized reports and stage summaries. Raw secret
matches, snippets and failed-image archives are not uploaded as diagnostics.
Successful image packets and browser results are retained for seven days.

## Active combined release process

The tag-driven [combined release workflow](../.github/workflows/release.yml)
successfully released v1.2.4 in
[run 45944211344, attempt 1](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45944211344).
Source tag `v1.2.4` resolves to `7459eb85141be8f8ac7745fd180ec3a9b71e0e34`
(tree `27d9df1e244f5f25ac37ea25d0602af97f65c4c3`). The qualified and public
OCI index is `sha256:936ad9a0f9221475fb7864823ad349319a05b2f166024b5a36f7ec23f729ff76`.
Actual anonymous Docker tag and digest pulls passed on a separate runner.
Live runtime health/hardening checks are bound main quality evidence; the
consumer job pulls and inspects images without starting a container.

Prepare coordinated metadata through a reviewed PR, then require successful
exact-source main quality. After separate authorization, create the immutable
version tag and authorize only that exact tag in the existing protected
environment without altering any other protections. Its tag push invokes the
combined process below. Review qualification before giving manual owner
approval; after publication, review the separate anonymous consumer result.
Never overwrite an existing source tag or image, including the same digest.

The current activation and publication guards remain specific to v1.2.4, which
is already published. These instructions do not authorize republishing it or
publishing a future version. Future version guards require a separate reviewed
change; dispatch inputs cannot bypass the source-level activation or approval.
PRs, main pushes and schedules do not invoke the release workflow.

Public source and images, standard Docker/Compose installation and supported
build-from-source guidance remain available in [installation](../INSTALLATION.md).
Running deployments are supported only on private/internal networks or
localhost. Release validation does not authorize deployment.

Manual dispatch defaults to `operation: verify` and requires an exact
`quality_run_id`. Verification is accepted only on main and is structurally
read-only: only `resolve` and `qualify` run. The `publish` job explicitly excludes
verification dispatch, including with an inconsistent resolver publication output. Verification cannot
request the protected environment or obtain `packages: write`; its record has
`purpose: verification`, `promotionEligible: false`. Original quality records
always remain unchanged and non-promotable.

Controlled recovery uses the distinct `operation: release` mode from the exact
version tag, with an explicit quality run. It is rejected on main, on any other
tag. It requires the same source, security, freshness and protected owner approval as
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

For an authorized eligible tag release, the combined path:

1. Resolves the exact version tag/source/tree from reviewed main history. The
   selected quality run must come from this repository and the active reviewed
   quality workflow revision at that source. Source SHA alone is insufficient.
2. Selects evidence automatically from exact-source main push and supported main
   manual-refresh quality executions. Complete, bounded pagination is required.
   The newest original creation timestamp wins, with run ID as the tie-breaker;
   updated/upload times never extend validity. The selected run must authenticate
   and pass all required jobs in its current attempt. Newer failed, expired or
   invalid evidence blocks release without fallback to an older success.
   The latest exact-source main push CI prerequisite remains independently
   required and must succeed, including when a manual refresh supplies evidence.
   Explicit manual release-recovery selection remains available under separate
   authorization and receives the same authentication and freshness checks.
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
   It retains the fixed version publication concurrency lane and copies the
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

Main evidence must include the separate authenticated builder OCI retention.
Older packets without it are ineligible. Seven-day artifact retention does not
extend the 24-hour eligibility window.

Missing, expired, ambiguous or mismatched evidence stops execution. Review the
specific source/run/attempt and diagnostics. If the exact approved source is
still main, explicitly dispatch the existing quality workflow on main, then
verify that exact refresh run. Automatic tag selection can use this new main
refresh while preserving the original successful push-CI prerequisite. A rerun
of an expired run retains its original creation timestamp and stays expired.
For an activated, separately authorized
release recovery, dispatch `operation: release` from the unchanged version tag
with that explicit refresh run ID. The preceding quality refresh is deliberate; the
release workflow never silently rebuilds, switches source, selects older runs,
or retries. If main has advanced, stop and review the new source/version rather
than moving a tag. An expired owner wait requires a newly authorized read-only
qualification attempt and fresh approval; there is no bypass or automatic rerun.

### Superseded maintenance workflow retirement

The successful protected v1.2.4 publication and anonymous Engine pulls establish
replacement coverage. Milestone 2D removes only these maintenance entry points:

| Retired path under `.github/workflows/` | Last retained Git blob |
| --- | --- |
| `qualify-maintenance-image.yml` | `3601122058f57fab546f900c99827f1415d12df2` |
| `publish-maintenance-image.yml` | `ef248e5ff8ba1c369f21d83d47d85ee8daf37a14` |

Restoration source commit: `7459eb85141be8f8ac7745fd180ec3a9b71e0e34`.
If separately authorized, restore the files on a feature branch with
`git restore --source=7459eb85141be8f8ac7745fd180ec3a9b71e0e34 -- .github/workflows/qualify-maintenance-image.yml .github/workflows/publish-maintenance-image.yml`.
Restoration requires renewed review and configuration-test updates before
integration; restoring these files does not authorize dispatch or publication.
Git history preserves the original files; no archived YAML copies are needed.
Shared legacy validators, historical fixtures, release evidence and Python
controllers remain intact. Unknown external callers of the retired dispatch
endpoints have not been verified absent; operators must use the combined entry
point and its documented inputs. The historical `publish-qualified-image.yml`
and `ghcr-readonly-diagnostic.yml` remain unchanged for Milestone 4 review.

Workflow files decrease from six to four; the final maintained target is two.
Deleting inactive entry points adds no measured runner-time savings. The actual
v1.2.4 release used one workflow/four jobs and 174 runner-seconds versus 364
seconds for the prior comparable release path (52.2% lower; cache/runner timing
varies). It added no qualification builds or repeated application/browser tests,
and required zero routine manual release dispatches, while preserving protected
owner approval. The earlier freshness refresh and resolver correction are
separate recovery costs, not normal-path savings. Main builder retention and the
combined qualification packet remain unchanged; no storage reduction is claimed.
Historical freshness refresh `45939378824` belongs to source
`b422d7b02074ffa0e0148f7770ac87995b6b4ea2`; it cannot qualify another source.

The standalone v1.2.3 anonymous Docker Engine pull check remains deferred, not
passed and nonblocking; a later release's consumer check cannot clear it.

## Weekly dependency maintenance

[Dependabot configuration](../.github/dependabot.yml) checks root npm dependencies,
Docker base images and GitHub Actions weekly. GitHub's default weekly day is
Monday, at a GitHub-assigned time. Updates use ordinary individual PRs targeting
the default branch; no grouping, automatic approval, merging or publication is
configured. See the [official configuration reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).

The Actions entry uses documented `exclude-paths`, relative to `/`, for only
`.github/workflows/publish-qualified-image.yml` and
`.github/workflows/ghcr-readonly-diagnostic.yml`. Their files and history remain
intact. `quality-security.yml` and `release.yml` remain eligible, including actions
also used by the excluded files. Review new full commit SHA pins and their release
references; do not replace SHA pins with floating tags. Docker PRs require review
of both tag and immutable digest, supported platform, final runtime metadata,
package floors and fresh security results. Custom scanner downloads, APK upgrade
constraints and compiler catalogs are not managed by this configuration.

All dependency PRs must pass the existing application, compiler, Compose,
container/security, artifact and eight browser gates. npm updates, including
Playwright, can invalidate the seals on the entire `package.json` and lockfile.
Use the established reviewed compiler catalog/hash coordination process; compiler
payload changes also require official artifact-byte verification. Dependabot has
no catalog regeneration or hash-approval hook. Keep a failed compiler-integrity
check failed until the approved correction is reviewed; never bypass the gate or
ignore useful npm updates to hide the coordination requirement. Dependency PRs
must not increment the application release version or change coordinated image
metadata, publication activation, source tags or environment eligibility. An
accepted dependency change still needs separate protected release authorization.

The existing PR workflow uses read-only permissions and authenticated artifacts,
without registry-write access, protected environments, privileged repository
secrets or `pull_request_target`. PR evidence remains non-promotable. This
configuration does not enable Dependabot security updates or alerts; security
updates were disabled at assessment. Security/notification settings, auto-merge,
branch protections, rulesets and workflow permissions require separate owner
authorization and are unchanged here. Public source/images, standard Docker and
Compose installation and private/internal-network-or-localhost deployment support
remain unchanged.

After authorized push, require consolidated PR quality. After main integration,
verify GitHub accepts the configuration, then observe a natural Dependabot job and
update PR when available, including its read-only quality execution and absence
of publication. Local YAML/contract checks do not establish live bot operation.
If no update is available, record configuration acceptance separately from pending
update-PR observation; do not manufacture an update or weaken pins to force one.

## Reviewed scanner identity

`scripts/ci-toolchain.json` is the single active Trivy version/archive-SHA-256
authority. The maintained workflows and report/freshness validators read it from
their checked-out source; artifacts, environment variables and resolver outputs
cannot select another configuration. Keep scanner updates in reviewed PRs with
the version, official Linux archive identity and checksum coordinated. This
consolidation preserves Trivy 0.76.0 and its approved archive checksum.

Missing, malformed, ambiguous or unsupported configuration fails closed. Workflows
authenticate the download before extraction/execution and check the executed
version before fetching the database. Report versions must match reviewed source.
The existing vulnerability/secret gates, exact builder dispositions, fresh database
verification, original 24-hour evidence limit and one-hour promotion limit remain.
Protected publication uses validators from the authenticated release source after
owner approval; a packet cannot override their scanner policy. Historical fixed
fixtures and workflows remain unchanged; interpret historical evidence with its
original Git source/validators rather than granting it new eligibility. Local
stub tests do not establish actual hosted scanner installation or execution.

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
