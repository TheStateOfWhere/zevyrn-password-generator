# Zevyrn 1.2.4 — release automation maintenance — in preparation, 2026-11-25

- Consolidates automatic PR validation into one quality/security workflow. Linux
  builds, scans, SBOM and hardening checks bind the retained runtime OCI; Windows
  authenticates that archive and runs all eight browser suites without a separate
  application compilation. Canonical compiler-byte checks remain on both platforms.
- Prepares the combined release workflow to qualify retained main runtime and
  builder images with fresh vulnerability and file/configuration-secret scans,
  reusing already-bound application, Compose, compiler, SBOM, hardening and browser
  evidence without rebuilding or repeating those tests.
- Preserves the builder's authoritative OCI directly from its single Buildx build,
  verifies exact configuration bytes and ordered layers across Docker loading and
  scanning, and retains sanitized identity diagnostics. Milestone 2B confirmed the
  actual round trip and resolution of the prior configuration mismatch.
- Enables the local source activation controls for exact v1.2.4 tag publication.
  Owner approval, post-approval identity/freshness checks, the original 24-hour
  evidence limit and one-hour promotion database limit remain mandatory. Publication
  preserves the qualified OCI graph; anonymous Docker verification is a separate,
  credential-free consumer job. Verification and quality records remain non-promotable.
- Coordinates application, container, Compose and release-guard metadata at 1.2.4,
  refreshing project/catalog hash anchors without dependency or compiler payload
  changes. The pinned patched Nginx base and package security floors are unchanged.

No intended application functionality, password-generation, dictionary, UI or
deployment requirement changes beyond the visible v1.2.4 version. Existing security
thresholds, exact builder dispositions, runtime hardening and public source/image
availability remain unchanged. Private/internal-or-localhost deployment remains
supported. Artifact storage increases are accepted; optimization is deferred.

This candidate is uncommitted and unpublished. Fresh exact-source main quality,
protected environment tag eligibility and separately authorized release execution
are required after integration. Milestone 2B evidence does not qualify v1.2.4.
The historical v1.2.3 anonymous Docker Engine pull remains deferred, not passed
and nonblocking. Historical release records below are preserved.

---

# Zevyrn 1.2.3 — security maintenance — in preparation, 2026-11-24

- Updates the official Nginx stable Alpine base to 1.30.8 at immutable index
  `sha256:6437a63b5c529f0e06162b3f593c0154cff6fa2ea0f94fd7c27928cb399e022d`.
  The validated candidate contains Nginx 1.30.8-r1, libxml2 2.13.9-r3,
  libxpm 3.5.20-r0, zlib 1.4-r0 and libexpat 2.10.0-r0, with patched
  libcrypto3/libssl3 3.5.9-r1. Existing package security floors are retained,
  including the explicit libxml2 floor added by the correction.
- Remediates the previously reported runtime Nginx findings, including
  CRITICAL CVE-2026-113425, CVE-2026-121810, CVE-2026-123007 and CVE-2026-123633,
  and HIGH CVE-2026-118899 and CVE-2026-123634; also remediates HIGH
  CVE-2026-86144 in libxml2 and the reported lower-severity runtime findings.
- Separates runtime scanning, builder scanning, SBOM generation and final
  acceptance, with actionable failure summaries identifying scope, image,
  findings, fixed versions, dispositions and scanner/database information.
- Retains available sanitized security evidence on qualification/publication
  validation failures. Secret matches and sensitive snippets remain excluded;
  published SBOM inventories retain image binding without arbitrary image labels.
- Corrects builder-disposition validation so remediated findings need not remain
  present. Zero through three remaining exact authorized Undici occurrences can
  pass; unapproved HIGH, CRITICAL and secret findings continue to block.
- Coordinates application, container, Compose and release-guard metadata at
  1.2.3 while retaining the compiler artifact verification and refreshed exact
  project/catalog hash anchors. Dependency versions and compiler payloads are unchanged.

No intended changes to application functionality, password generation, dictionary,
UI behavior or deployment requirements. The visible version changes to v1.2.3.
Nonroot/read-only hardening, private/internal-or-localhost support, Linux/amd64,
existing Compose compatibility, security thresholds, authorized builder-only
dispositions, freshness requirements and protected publication approval are retained.

## Engineering acceptance and publication status

The Phase 1 candidate `6b450f0f3663706302529f9a19025061677782d9` passed
[quality/security run 45342687883](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45342687883)
and [PR qualification run 45342687863](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/45342687863)
on their first attempts on 2026-11-24. Fresh Trivy 0.76.0 scans reported zero
runtime vulnerabilities of any severity and zero detected secrets. The builder
retained three authorized HIGH findings, twelve MEDIUM and four LOW findings,
with zero unapproved blocking findings and zero detected secrets. Builds, SBOM,
237 Linux host tests, eight browser suites and runtime hardening checks passed.

For comparison, the same day's fresh scan of the exact published v1.2.2 digest
reported four CRITICAL, three HIGH, ten MEDIUM and four LOW runtime findings.
These are dated findings, not a guarantee against future disclosures.

**v1.2.3 is not yet published.** The evidence above applies to the earlier
candidate identity, not the newly versioned source. PR-only artifacts remain
non-promotable. A fresh qualification of the final approved main commit and
protected publication of that same retained artifact are still required.
Planned image: `ghcr.io/thestateofwhere/zevyrn:1.2.3`; final release source,
published OCI digest and publication workflow record are pending. The Nginx base
digest above is not a Zevyrn release digest. Existing tags/images remain immutable.

# Zevyrn 1.2.2 — security maintenance — 2026-11-17

- Incorporates the runtime package maintenance validated at
  `7b82c4970b7c724c030a8c1da9d43981d09cc76c`.
- Requires patched libexpat, zlib, libxslt and musl-utils while retaining
  the existing Alpine branch, pinned base images and other security floors.
- Aligns application, container and installation metadata with version 1.2.2.

Application behavior, password generation, dictionary, UI layout, runtime
configuration, security gates and the three approved builder-only exceptions
are unchanged. The visible version text changes to v1.2.2.

Published image: `ghcr.io/thestateofwhere/zevyrn:1.2.2` (Linux/amd64).
Source commit: `76696d1d573feaa455ca31a00c9e86a3c6f08c4e`.
Immutable OCI index: `sha256:4992d66fcbc8a73723f2cf9a65eba86f4c4048acdf8359032895ae5e5d4fca31`.

[Final-source qualification](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/44031484596)
passed application/configuration checks, exact OCI and asset identity validation,
builder/runtime vulnerability and secret scans, runtime SBOM generation, hardened
runtime checks and all eight Microsoft Edge browser suites. The
[protected publication](https://github.com/TheStateOfWhere/zevyrn-password-generator/actions/runs/44033904930)
rescanned and published that qualified OCI archive without rebuilding it.

At publication, the runtime had zero HIGH/CRITICAL findings and no detected
secrets, including image-configuration secrets. One MEDIUM finding remained:
`CVE-2026-94287` in `libxpm 3.5.19-r0` (reported fix: `3.5.20-r0`).
Three scoped builder-only HIGH findings in npm-bundled Undici 6.29.0 remained
visible under the existing approved policy; they are outside the shipped runtime.
See [security policy and limitations](SECURITY.md#published-release-qualification).
These dated results are not a guarantee against future findings.

Supported deployment remains private/internal networks or localhost only.
No intended application feature or configuration changes accompany this release.

# Zevyrn 1.2.1 — published 2026-10-27

- Keep existing passwords when generation fails without a settings change.
  Changing the active settings still clears results that no longer apply.
- Show copying, success and failure feedback on the Copy control you used,
  including in long batches. Delayed responses cannot replace newer feedback.
- Provide clear reload guidance when the application cannot start, and keep
  generation unavailable until initialization succeeds.
- Show a compact summary of the active password settings as you edit them.
- Identify spaces, including leading and trailing spaces, separately from the
  password text. Selection and copying preserve the exact characters.
- Support Docker source builds from an ordinary Git checkout without historical
  workspace preparation, while retaining compiler and dependency integrity checks.
- Clarify Compose installation, supported platforms, updates, health checks,
  startup troubleshooting and reporting problems without exposing secrets.

Password-generation algorithms, the dictionary, entropy requirements, approved
visual themes and legacy installation compatibility remain unchanged.

The published v1.2.1 image was built from source commit
`d358bb49cdf28ec278f7979e81fbd1fc36a35031`. Its tag, image, archives and
qualification records remain historical evidence for those exact bytes.
The v1.2.2 preparation does not overwrite or requalify them.

# Zevyrn 1.2.0 — 2026-10-17

Additive Zevyrn-native standalone, Traefik and Caddy installation examples use
the `zevyrn` service, `zevyrn:1.2.0-local` image and `ZEVYRN_*` settings. Legacy
KeySmith installation files remain unchanged and supported. New settings accept
legacy variable fallbacks; a nonempty Zevyrn setting wins. Separate Traefik
configuration directories prevent duplicate route loading.

Installation documentation separates new installations from existing updates.
Password generation, security protections, themes and deployment hostnames are
unchanged. Docker images are not published; build from source.

# Zevyrn 1.1.0 — historical

Zevyrn replaced KeySmith branding with the Gradient Eye logo and five accessible
themes, preserving password-generation behavior. README screenshots are genuine
v1.1.0 captures. The published v1.1.0 tag and release remain unchanged.

# KeySmith 1.0.0

Browser-only password generation with Readable, Strong Random and Custom Policy
profiles; Focus and Password Sheet views; copying controls, Large Text and five
themes. The source includes regression tests, a hardened static Nginx runtime,
and standalone, Traefik and Caddy Compose examples.

Build from source using README.md. No official public KeySmith container image
is provided by this source package. Linux/amd64 is the supported container target.
The application is MIT-licensed; dictionary attribution and separate licenses are
retained under data/ and bundled into /licenses/.
