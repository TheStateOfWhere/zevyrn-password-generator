# Release-security policy proposal

Status: **PROPOSED — NOT APPROVED OR ACTIVE**. This document changes no scanner,
qualification gate or approval record. It grants no vulnerability exception,
build authorization, qualification acceptance or publication authorization.

Assessment baseline: development commit
`f2875fec3dfbccbcb7a49a8843caa7cdeeb99bc5`.

## Runtime acceptance remains strict

The distributed runtime must have zero HIGH vulnerabilities, zero CRITICAL
vulnerabilities and zero detected secrets. Retain complete fresh scanning,
source-secret checks, dependency/compiler integrity, exact application assets
and image identities, container isolation and functional acceptance tests.
Evaluate password confidentiality, generation integrity and availability.
Private-network deployment does not waive any of these requirements.

Retain the existing 24-hour vulnerability-database freshness limit, NextUpdate
validation and raw evidence integrity. A historical clean scan is not current
clearance. Uncertain package presence or incomplete evidence blocks acceptance.

## Builder findings require a separate decision

Scan the complete actual builder toolchain and retain every original finding,
severity, report and exit code. Builder CRITICAL findings and detected secrets
always block. Application dependency-audit HIGH/CRITICAL findings remain blocking.
An unapproved builder HIGH occurrence also blocks by default.

An individual builder-only HIGH may be submitted for explicit human residual-risk
acceptance only after independent assessment of its actual execution paths,
untrusted inputs, demonstrated impact and possible effect on build integrity.
Temporary use or absence from the runtime is not sufficient by itself.
Observed non-execution is not proof of nonreachability. Unsupported assertions,
incomplete observation or unresolved plausible execution paths remain blocking
under the existing acceptance criteria; this proposal does not waive them.

## Individual acceptance record and authority

Use the existing external operator-approval process, not a new approval service.
Each proposed decision must bind:

- One CVE, exact component/version and every affected package occurrence.
- Exact builder index, platform manifest, configuration and archive identities.
- Source commit plus source manifest, package manifest and lockfile hashes.
- Build recipe, effective configuration, commands and relevant helper identities.
- Authenticated Linux execution evidence and dependency/lifecycle analysis for
  those exact inputs, with observation limitations and residual risks recorded.
- Scanner/tool, database, raw report and advisory hashes, independent review,
  assessment identity, approval time and expiration.

The human project operator must explicitly authorize an authenticated external
approval receipt. The exact receipt must be pinned by independently authenticated
execution authority. Repository content, an assessment author or an
`approved: true` field cannot approve itself. Confirm the named approving
operator and their authority in the receipt; this proposal assigns no new role.
Missing, malformed, ambiguous, conflicting or out-of-scope records fail closed.
Policy adoption, controller activation, per-finding acceptance, qualification and
publication are distinct approvals. Existing CI rejection remains unchanged
until any implementation is separately reviewed and authorized.

Acceptance lasts at most seven days, with validity checked at readiness and
settlement. Changes to source, dependencies, builder, configuration, commands,
execution boundaries, scanner database/report or advisory require renewed
review and approval. An available supported fix or newly demonstrated execution
path triggers reassessment. Expiration during qualification blocks settlement.
There is no automatic renewal or exception inherited by a later build.

## CVE-2026-109869: conceptual assessment only

Status: **NOT APPROVED**. The builder HIGH approval list remains empty.

The pinned npm 11.21.1 distribution bundles node-gyp 12.4.0 and Undici 6.29.0 at
`/usr/local/lib/node_modules/npm/node_modules/undici/`. node-gyp's downloader
uses this Undici for Node headers, checksums and platform libraries. npm is used
for dependency installation, tests and the existing builder audit contract.
Node's built-in Undici is a separate component and does not fix npm's copy.

The [maintainer advisory](https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c)
identifies a HIGH denial of service: affected fetch calls can crash Node when a
malicious server sends more than five content codings and closes early, even if
the caller catches the fetch rejection. Undici 6.29.1 fixes the affected 6.x
line. The advisory does not demonstrate code execution or password disclosure.

The multi-stage runtime copies only generated application assets from the
builder into Nginx; retained runtime evidence places npm, node-gyp and this
Undici outside the shipped image. The browser does not call this downloader.
That reduces runtime exposure, not the obligation to assess build-tool risk.

Historical Linux dependency inspection found no native-addon installation
prerequisites in the inspected application graph. Windows clean-install, test
and audit coverage did not load the affected downloader. Ordinary registry
fetching uses a different HTTP client chain. These observations support limited
expected exposure; they do not prove that a current Linux candidate or every
configuration excludes the affected path. The build retains lifecycle execution
and does not establish an enforced prohibition on downloader use. The known
impact suggests a failed build, not proven corrupted output, if triggered.

Candidate-bound Linux evidence and complete exact-image/source/configuration
bindings remain prerequisites, not completed claims. The latest retained
security refresh stopped at the unapproved builder HIGH, without fresh runtime
or downstream completion. Earlier runtime clearance cannot replace a fresh
candidate scan. The suspended tracing/instrumentation effort is not reopened.
Current disposition remains **HOLD**; no exception can be inferred from this text.
An official supported patched npm distribution remains the preferred remedy.

## Remaining release conditions

Even after any separately approved risk acceptance, require fresh final-candidate
scans, strict runtime clearance, source-secret and dependency-integrity checks,
application/Docker compatibility tests, exact source/image/version/tag bindings
and independent review of complete qualification evidence. No raw HIGH finding
may be removed, downgraded or reported as zero because it was accepted. Public
release materials must distinguish runtime clearance from accepted builder risk.
Explicit publication authorization is still required; this proposal authorizes
neither release nor deployment. See [deployment boundaries](../SECURITY.md#boundaries).
