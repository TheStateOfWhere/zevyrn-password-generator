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

## Daily monitoring of the published image

The quality workflow schedules an isolated scan of the reviewed published runtime
at **06:41 UTC** daily. `.github/published-image.json` pins the version, immutable
source, OCI index, Linux/amd64 manifest and configuration; future accepted releases
need a reviewed target update. Main's application version and mutable image tags
cannot substitute another monitoring target. Anonymous digest retrieval uses an
empty Docker client configuration. The published application is not run or rebuilt.

Monitoring uses the centralized reviewed scanner identity and fresh vulnerability
intelligence. Runtime HIGH/CRITICAL vulnerabilities and any file or image-config
secrets block acceptance. Builder exceptions never apply. Image retrieval,
identity, scanner/database or malformed evidence failures are failures, not clean
scans. Maintainers review findings and fixes; no automatic remediation, dependency
update, rebuild, release or deployment is performed.

Distinct non-promotable monitoring reports retain only sanitized identities,
vulnerability summaries, secret counts and scanner/database information for seven
days. Raw secret matches, configuration and archives are not uploaded. A monitoring
run cannot replace PR/main quality or release qualification, and the existing
weekly source validation remains in place. This adds no deployment requirements
and does not extend support beyond private/internal networks or localhost.

The scheduled-workflow maintainer must enable GitHub Actions failure notifications
and check run history; delivery depends on account preferences. GitHub schedules
can be delayed/dropped and public-repository inactivity can disable them. Daily
monitoring is best effort, not a guarantee of vulnerability freedom or an alerting
SLA. See [monitoring and release guidance](docs/RELEASING.md).

## Published release qualification

The [combined release workflow](.github/workflows/release.yml) qualified and
published v1.2.4 through protected owner approval. It authenticates exact-source
main quality artifacts, including OCI bytes, runtime assets, builder/runtime
scans, configuration secret checks, SBOM, licenses, hardened execution and all
eight archive-bound Edge suites. It freshly scans both retained images and
creates a separate release-purpose receipt; original quality and PR records
remain non-promotable. Manual verification on main has no publication authority.

Publication revalidates the immutable tag, source and authenticated evidence
after approval, preserves the 24-hour original-evidence limit and one-hour
promotion database freshness limit, rejects existing destination versions, and
copies the exact OCI graph without rebuilding. Registry-write authority is
confined to the protected publication job. Actual anonymous Docker Engine pulls
by version and digest run on a separate runner without publication credentials.
The two superseded maintenance entry points are retired; shared validators and
historical release records remain. See [release process](docs/RELEASING.md) for
selection, manual refresh/recovery and Git restoration instructions, and
[release notes](RELEASE-NOTES.md) for historical records. The v1.2.3 anonymous
Docker Engine check remains deferred, not passed and nonblocking.

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
