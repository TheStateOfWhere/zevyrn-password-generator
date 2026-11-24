# Security

## Reporting a vulnerability

Use the repository's [private reporting page](https://github.com/TheStateOfWhere/zevyrn-password-generator/security/advisories/new)
when GitHub's **Report a vulnerability** option is available. Do not put unpatched
vulnerability details, real passwords, credentials or private keys in public
issues. If private reporting is unavailable, ask the maintainer for a confidential
channel without including the vulnerability details in that request.

No response-time or maintenance-lifetime guarantee is made. Report the affected
version, impact and a minimal nonsecret reproduction.

## Boundaries

Zevyrn generates passwords in the browser using Web Crypto, unbiased sampling
and exact password-space checks. Generation requires an estimated space of at
least 2^64; this is not a guarantee against every password attack. Passwords and
policies are not sent to a backend or stored by the application. Only a validated
theme identifier is saved to localStorage.

HTTPS or localhost is required for browser clipboard access. Clear and Hide do
not securely erase memory or OS clipboard history. Browser extensions, compromised
devices and malicious same-origin content remain outside this protection.

Source code and images are intended for public distribution. Running Zevyrn is
supported only on private/internal networks or localhost; direct internet-facing
deployment is unsupported. Operators control network access and provide TLS and
certificate renewal as needed. Internal HTTPS reverse proxies are supported.
The current scope does not require an application authentication system. Private
placement does not eliminate application or build-tool vulnerabilities. See
[internal access guidance](INSTALLATION.md#access-from-other-internal-devices).
Preserve the bundled CSP and other security headers.
Never publish the Docker API or share a Docker socket with the application.

Review dependency/base-image updates and scan newly built images as appropriate
for your deployment. A successful build or earlier clean scan is not proof of
vulnerability freedom. Do not bypass build tests, float pinned inputs to work
around errors, or commit secrets and certificate keys.

## Published release qualification

The prepared v1.2.3 [qualification workflow](.github/workflows/qualify-maintenance-image.yml)
binds source commit/tree, an exact Linux/amd64 OCI archive, runtime assets,
builder/runtime vulnerability and secret scans, image-configuration secret scans,
runtime SBOM, hardened runtime checks and eight Microsoft Edge browser suites.
The [protected publication workflow](.github/workflows/publish-maintenance-image.yml)
verifies the retained evidence, performs fresh runtime scanning and promotes the
same OCI archive without rebuilding it. See [release notes](RELEASE-NOTES.md)
for published historical records. v1.2.3 is not yet published: its final source
and release digest require fresh release qualification. PR-only artifacts are
not eligible for publication.

Runtime HIGH/CRITICAL findings or detected secrets block acceptance. Builder
CRITICAL findings, detected secrets and unapproved HIGH findings also block.
The three exact builder-only Undici 6.29.0 HIGH exceptions are recorded in
[the active CI exception policy](scripts/ci-builder-exceptions.json):
`CVE-2026-109869`, `CVE-2026-109383` and `CVE-2026-87018`.
They do not apply to the runtime or other package/version/path occurrences,
and accepted findings remain visible rather than being removed from reports.

At v1.2.2 publication on 2026-11-17, the runtime had no HIGH/CRITICAL findings or
detected secrets, but retained MEDIUM `CVE-2026-94287` in `libxpm 3.5.19-r0`
(reported fix: `3.5.20-r0`). These are dated scan results, not a claim of
vulnerability freedom or current clearance for a different build.

On 2026-11-24, fresh scanning of the published v1.2.2 digest found four CRITICAL
and three HIGH runtime findings. The accepted Phase 1 candidate at
`6b450f0f3663706302529f9a19025061677782d9` remediated all reported runtime findings;
see the candidate workflow records in [release notes](RELEASE-NOTES.md).
Changing its version metadata to v1.2.3 creates a new source/artifact identity
and does not transfer that candidate's qualification.

The historical [builder-versus-runtime policy proposal](docs/release-security-policy-proposal.md)
remains a proposal, not active policy or an exception approval. Its historical
HOLD statements do not describe the published v1.2.2 qualification result.
