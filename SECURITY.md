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

A [builder-versus-runtime policy proposal](docs/release-security-policy-proposal.md)
is available for review only. It is not active policy and approves no exception.
