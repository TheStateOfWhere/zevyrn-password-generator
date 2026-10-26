# Zevyrn 1.2.1 — unreleased

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

These changes have not been published. The planned GHCR image,
`ghcr.io/thestateofwhere/zevyrn:1.2.1`, remains unavailable pending publication
and public-pull verification. Compose remains the recommended installation method.

Earlier v1.2.1 artifacts and their qualification records remain historical
evidence for their exact baseline; they do not qualify this development version.
The existing builder security blocker remains unresolved. An eventual release
requires a separately approved final artifact, applicable security qualification
and publication verification. Historical tags, archives and evidence are preserved.

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
