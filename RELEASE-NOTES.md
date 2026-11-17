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
