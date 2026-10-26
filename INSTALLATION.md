# Docker installation

These instructions target **Zevyrn v1.2.1** from the
[canonical GitHub repository](https://github.com/TheStateOfWhere/zevyrn-password-generator).
See the [rename notes](docs/REPOSITORY-RENAME.md) for the completed repository
rename and retained configuration identifiers.

## Supported deployment model

Zevyrn source code and container images are intended for public distribution;
the running application is supported only on private or internal networks,
including localhost. Direct internet-facing deployment is unsupported. You are
responsible for keeping access limited to your intended internal users.

The current scope does not require application accounts or a login system.
Internal reverse proxies and trusted HTTPS are supported options. This network
boundary does not remove application vulnerabilities, browser risks or the need
to review updates and security findings.

## Prebuilt image (recommended)

### Platforms and prerequisites

- Supported container target: **Linux/amd64** on x86-64 Linux or Docker Desktop
  in Linux-container mode. Native Windows containers are not supported.
- ARM hosts require amd64 emulation; ARM/emulated execution is not validated.
- Use maintained Docker Engine 28+ (or Docker Desktop), Compose supporting
  `--wait` and `--wait-timeout`, and `curl` for the HTTP checks. Source builds
  also require Git and Buildx. Host Node, npm and Python are unnecessary.
- Examples use a POSIX shell. In PowerShell use `curl.exe` for HTTP commands;
  edit `.env` directly rather than using POSIX shell variable assignments.
- With a remote Docker context, loopback ports belong to the Docker host,
  not the computer running the CLI.

Select `compose.ghcr.yaml` for the prebuilt image, `compose.zevyrn.yaml` for a
source build, or one complete Zevyrn Traefik/Caddy file for HTTPS. Do not combine
these files. Existing installations keep their original files; the default
`compose.yaml` deliberately uses legacy names.

Planned public image: **`ghcr.io/thestateofwhere/zevyrn:1.2.1`**, Linux/amd64.
**Not yet published or registry-verified during release preparation.** Use these
instructions after the release image and its registry digest are published.
A local Docker image ID is not a registry manifest digest.

Requirements: maintained Docker Engine 28+ or Docker Desktop using Linux
containers, and Docker Compose v2 or newer supporting `--wait` and `--wait-timeout`.
No host Node/npm, source checkout, database or persistent app volume is needed.
Download `compose.ghcr.yaml` from the intended published release into a new
directory. It contains only the `zevyrn` app service, no build directive, Docker
socket, host bind mounts or external networks. Commands use a POSIX shell.
Use your existing Docker access method; do not change daemon permissions.

```sh
docker compose -p zevyrn -f compose.ghcr.yaml config
docker compose -p zevyrn -f compose.ghcr.yaml pull zevyrn
docker compose -p zevyrn -f compose.ghcr.yaml up -d --no-build --pull never --wait --wait-timeout 120 zevyrn
docker compose -p zevyrn -f compose.ghcr.yaml ps
curl --fail http://127.0.0.1:18080/healthz
```

Expect HTTP 200 and `ok`. Open `http://localhost:18080` on that same host.
The app listens on container port 8080; the sample publishes loopback port 18080.
Its built-in health check queries `/healthz` inside the container. It runs as
UID/GID 10001:10001, with a read-only filesystem, dropped capabilities,
no-new-privileges and bounded tmpfs, memory, CPU and process limits.

Optional `.env` entries (the app requires no environment configuration):

```dotenv
ZEVYRN_PORT=18080
ZEVYRN_IMAGE=ghcr.io/thestateofwhere/zevyrn:1.2.1
```

Use an explicit version rather than `latest`. For immutable selection, replace
the image with `ghcr.io/thestateofwhere/zevyrn@sha256:<published-manifest-digest>`
after obtaining the real manifest digest from the release. The placeholder is
not runnable. Shell variables override `.env`; keep the same settings for every
command. Public GHCR packages can be pulled anonymously once made public.
Registry access is needed for the initial pull and updates.

### Access from other internal devices

The standalone examples bind to `127.0.0.1`; another device cannot use its own
`localhost` to reach the Docker host. Changing `ZEVYRN_PORT` changes only the
host port, not this loopback binding. Keep that default for host-only use.

For internal-device access, use your existing internal HTTPS proxy as described
below, or one complete source-build HTTPS example. For those source-build
examples, set `ZEVYRN_BIND_IP` to the Docker host's actual private LAN address
(for example `192.168.1.20`, only if assigned to that host), set `ZEVYRN_DOMAIN`
to a hostname your internal clients resolve to it, and supply the matching
trusted certificate. Open `https://<your-hostname>` from those devices and check
`https://<your-hostname>/healthz`. Follow the certificate prerequisites below.

Do not select `0.0.0.0`, `::`, or a public host address for these examples. Do not
forward the application or proxy port from the Internet, or expose it through
a public proxy or tunnel. A private address, HTTPS or a DNS name alone does not
enforce internal-only access: confirm your existing routing and access controls
limit reachability to intended users, including IPv6 where configured. These
examples do not configure those controls. Do not publish backend port 8080.
Remote plain HTTP does not provide the browser secure context needed for copying.

Docker's [port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/)
explains host-address binding; omitting an address normally publishes on all
interfaces. Retain the explicit bindings in the supplied files.

### Optional reverse proxy

For an internal proxy on the Docker host, route your own HTTPS hostname to
`http://127.0.0.1:18080`. Configure a valid matching certificate and normal browser
trust. If a proxy runs in another container, its localhost is not the app:
connect it and Zevyrn to an explicitly chosen dedicated network and route to
`http://zevyrn:8080`, or use your reviewed host-routing arrangement. Such a
network change is operator configuration, not included in `compose.ghcr.yaml`.
Do not expose the Docker API or mount its socket for application operation.
No particular infrastructure, external proxy network or private CA is required.
Copy requires localhost or HTTPS; remote plain HTTP is not a secure context.
The app has no login; control access at your proxy/network. The source-build
Traefik/Caddy files below are complete alternatives using your own existing
certificate, not overlays on `compose.ghcr.yaml`, and build separate local images.

### Updating a prebuilt installation

Read the new release notes, then set `ZEVYRN_IMAGE` in your `.env` to the desired
published version or digest. Preserve the same project, file and port settings:

```sh
docker compose -p zevyrn -f compose.ghcr.yaml config
docker compose -p zevyrn -f compose.ghcr.yaml pull zevyrn
docker compose -p zevyrn -f compose.ghcr.yaml up -d --no-build --pull never --no-deps --wait --wait-timeout 120 zevyrn
curl --fail http://127.0.0.1:18080/healthz
```

Use your configured port and test the HTTPS route if present. No automatic
updater is enabled. For an existing legacy installation preserve its project,
service and settings; change only its reviewed app image reference. See
[existing installations](#existing-installations). To remove this installation
use `docker compose -p zevyrn -f compose.ghcr.yaml down` with its actual settings;
do not add broad prune or volume-removal commands.

### Offline operation and privacy

Once the image and app assets are available, generation works without Internet
access. The browser must still reach your local server to load/reload the app;
this is not an installed offline PWA. An air-gapped Docker host can load an image
archive transferred from a trusted machine: verify the archive hash and image
identity against the release information, then use the loaded tag with
`--pull never`. Never substitute an unverified image.
Passwords use browser Web Crypto; there is no backend password storage,
telemetry, remote dictionary service or password network request. Only the theme
identifier is saved locally. Clear/reload does not securely wipe memory or erase
OS clipboard history. Browsers/extensions and the OS remain trust dependencies.

## Optional source-build installation

The remaining sections describe developer build examples. Build from source as
shown in [README.md](README.md); `compose.zevyrn*.yaml` uses the local
`zevyrn:1.2.1-local` image, not GHCR. It needs Git and Buildx, with registry,
npm and Alpine access for the first build. A new build does not inherit the
retained release image's qualification. The standalone default needs no
environment file. For remote browsers, choose an HTTPS alternative below.

Select a reference containing the portable-build correction; historical tags
remain unchanged. The exact LF bytes of `package.json`, `package-lock.json` and
the compiler catalog are authenticated, as are all installed compiler files.
`.gitattributes` enforces LF on Windows and Linux. No Git executable is needed
inside the builder, no files are rewritten by verification, and historical
qualification archives are not build prerequisites. Manually converted CRLF
or altered files fail closed.

This contract is distinct from reproducing the old qualified CRLF artifact.
Development tests do not qualify a newly built image; the existing builder
security blocker remains unresolved.

## Choose a hostname and client trust

Replace the sample `keys.example.com` with a name you control, such as
`keys.your-domain.com`. Set `ZEVYRN_DOMAIN` in `.env` to the bare hostname,
without a scheme, path or port, and use that same name in DNS and the certificate's
DNS SAN. `ZEVYRN_BIND_IP` is an address assigned to the Docker host, not the
client's address. These examples publish HTTPS on TCP 443 at that address.

- **Public DNS name:** create the record with your domain's DNS provider. A name
  under a public domain can also be used with internal or split DNS. Publishing
  the DNS record does not itself expose the application; routing and access
  restrictions are separate administrator decisions.
- **Internal DNS name:** create the record in the DNS service used by your
  internal clients. VPN clients must use a resolver that can resolve that name
  and have a route to the Docker host. Do not expect public resolvers to know a
  private DNS zone.

A publicly trusted certificate is suitable for a name it covers, including a
public-domain name used internally. A private-only name generally needs your
organization's private CA. Obtain certificates through your existing issuer;
these examples do not enroll certificates or create a CA. For a private CA,
distribute its public root certificate through your normal client trust process
to every browser/device that will access Zevyrn. Supplying the server's
certificate files to a container does not establish client trust.

For a command-line check using an explicitly trusted private root:

```sh
curl --fail --cacert /path/to/your-root-ca.pem https://YOUR_HOSTNAME/healthz
```

Replace both placeholders. The URL name must match the certificate SAN; do not
substitute an IP address unless the certificate also contains that IP SAN.
Never disable certificate verification to make an installation test pass.

## Existing-certificate prerequisites

1. Create an A record for your hostname pointing to the Docker host. Add AAAA only
   if you intend to support and configure IPv6 access.
2. Obtain a server certificate with that DNS SAN and a matching private key.
   `fullchain.pem` contains the PEM leaf followed by intermediate certificates;
   do not append the trusted root. `privkey.pem` contains the matching PEM key.
3. Keep both files in a protected directory **outside the clone**, for example
   `/etc/zevyrn/tls`. Both example proxies run as UID/GID `65532`. Arrange for
   that identity to read the directory and files: a typical Linux setup uses
   owner `root`, group `65532`, directories `0750` and key `0640`. Also permit
   traversal of parent directories. Do not make the key world-readable.
4. Confirm browsers trust the issuing CA. Certificate issuance and renewal are
   your responsibility; these examples use existing certificates, not ACME.
5. Make the intended private host address and TCP 443 reachable only by your
   intended internal users. Backend 8080, Docker API and proxy administration ports are not published. The app
   has no login system; choose access appropriate to your installation.

```sh
cp zevyrn.env.example .env
# Edit .env: ZEVYRN_DOMAIN, ZEVYRN_BIND_IP and ZEVYRN_TLS_DIR.
```

Use a fresh `.env` file, not an existing file belonging to another application.
It contains configuration, not private-key contents. The default bind address in
the example is loopback; for other internal devices select the host's private
LAN address as described
in [internal-device access](#access-from-other-internal-devices).
The TLS directory must already exist and contain the two files above. Do not use
an unrelated application's certificate or network without its owner's permission.

### Variable precedence

The new files use a nonempty `ZEVYRN_*` value first, then the corresponding
`KEYSMITH_*` value for compatibility. Empty values act as unset. If both port
values are empty or unset, the loopback port defaults to 18080. HTTPS domain,
bind IP and TLS directory must resolve to nonempty values or `compose config`
fails. Shell environment variables take precedence over `.env` for the same
name; a nonempty Zevyrn name still wins over a conflicting legacy name. Remove
unwanted shell overrides before testing `.env`. This fallback does not rename
existing projects or services. Validate the resolved configuration before startup.

## Traefik

```sh
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml config
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml build zevyrn
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml pull --policy always traefik
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml up -d --no-build --pull never --wait --wait-timeout 120
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml ps
curl --fail https://YOUR_HOSTNAME/healthz
```

Replace `YOUR_HOSTNAME` with `ZEVYRN_DOMAIN`; expect `ok`. Traefik uses the file
provider with only `examples/traefik/zevyrn-dynamic` mounted. The hostname is
supplied through its environment.
It reads certificates from a read-only bind mount, listens internally on 8443 and
receives host TCP 443. Routing is `zevyrn:8080` on this project's private bridge.
No certificate resolver, labels for discovery or Docker socket is required.
The dedicated network is a normal bridge: an internal-only Docker network cannot
provide the published HTTPS listener used here. Backend 8080 remains unpublished.

## Caddy

Use this alternative instead of the Traefik or standalone file:

```sh
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml config
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml build zevyrn
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml pull --policy always caddy
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml up -d --no-build --pull never --wait --wait-timeout 120
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml ps
curl --fail https://YOUR_HOSTNAME/healthz
```

`examples/caddy/Caddyfile.zevyrn` uses the same hostname and certificate files. It disables
the administration API and automatic HTTP redirects, so only TCP 443 is published.
Its backend is `zevyrn:8080`, not localhost. Writable Caddy scratch directories
are bounded tmpfs mounts; no persistent certificate database is needed for these
manually supplied certificates. Do not replace this with `tls internal` unless
you deliberately want to manage a different CA and client trust.

The pinned official Caddy binary has a `NET_BIND_SERVICE` file capability. Its
service drops all capabilities and adds back only `NET_BIND_SERVICE` so Linux
can execute that binary. Removing this exception can cause
`exec /usr/bin/caddy: operation not permitted`, even though Caddy listens on
unprivileged container port 8443. Zevyrn receives no added capabilities; both
services remain non-root with read-only filesystems and `no-new-privileges`.

## Health, troubleshooting and maintenance

Application `/healthz` returns HTTP 200 and `ok`. Compose waits for the app's
health check before starting its proxy. The HTTPS request above verifies the
internal HTTPS route and normal certificate validation; Compose status alone
does not.
Check Generate, Copy, settings and themes in your browser after setup.

Use the same project/file options for status and bounded logs:

```sh
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml logs --tail 100 zevyrn traefik
```

For Caddy substitute its project, file and service. Check file permissions for
certificate-loading errors, hostname/DNS and CA trust for TLS failures, and app
health/network membership for 502 responses. Do not disable read-only mode or
run the app as root to conceal an error. No real generated passwords belong in
logs, screenshots or support issues.

### Diagnostic checklist

Use your actual project, file and service names. For the prebuilt example:

```sh
docker compose -p zevyrn -f compose.ghcr.yaml config
docker compose -p zevyrn -f compose.ghcr.yaml ps --all
docker compose -p zevyrn -f compose.ghcr.yaml logs --tail 100 zevyrn
# Obtain the application container ID (including an exited container):
docker compose -p zevyrn -f compose.ghcr.yaml ps --all --quiet zevyrn
# Replace CONTAINER_ID with that output; do not paste the placeholder literally:
docker inspect --format '{{json .State}}' CONTAINER_ID
curl --fail http://127.0.0.1:18080/healthz
```

- **Image cannot be pulled:** confirm publication/public visibility, exact name,
  version and architecture. The planned v1.2.1 image is not yet public-verified.
- **Port already allocated:** choose another `ZEVYRN_PORT`, run `config` again,
  and use that port in your browser/health request. Do not stop unrelated apps.
- **Exited/restarting:** inspect the exit code, `OOMKilled`, error and bounded
  logs. Report repeated failures; do not remove isolation controls to hide them.
- **Unhealthy:** `.State.Health` includes recent probe output. The health check
  uses container port 8080; changing the host port does not change it.
- **Empty logs:** normal requests are not access-logged. Nginx errors go to
  stderr; empty logs alone do not establish a failure.
- **Healthy, but page will not load:** `/healthz` checks Nginx, not JavaScript
  initialization or every asset. Reload, confirm the configured URL, and check
  Firefox/other browser Developer Tools Network and Console for missing or
  rejected local resources. Record filenames/statuses, never password values.
- **Copy fails:** use localhost or normally trusted HTTPS and check the visible
  browser guidance. Do not disable browser protections or certificate checks.
- **Build integrity failure:** use a clean reviewed checkout with Git LF bytes;
  do not rewrite hashes, normalize installed compiler packages or skip tests.
  If an exact pinned Alpine package is unavailable, report it rather than
  substituting a floating version.

`unless-stopped` restarts an exited process; it does not itself restart a
container merely because it becomes unhealthy. Diagnose the failed probe first.

### Reporting an application problem

Open an issue in the canonical repository with the app version/source commit,
image tag and digest, OS/CPU architecture, Docker/Compose versions, selected
Compose file, minimal reproduction, expected/actual behavior and sanitized
bounded logs or health errors. Include browser/version for UI or copying issues.
Review `config` and inspection output before sharing it: redact secrets, private
paths/hostnames and credentials. Do not attach `.env`, TLS keys, generated
passwords or raw clipboard contents. For vulnerabilities use the private route
in [SECURITY.md](SECURITY.md), not a public issue.

## Updates

This section applies to optional source-build installations. For the prebuilt
image use [Updating a prebuilt installation](#updating-a-prebuilt-installation).

Review the upstream release notes before updating. Start in your existing clone
and preserve your external TLS files and `.env` settings. If `git status` shows
local tracked-file changes, review them before switching versions; do not discard
them automatically. Use a real published release tag or a reviewed full commit:

```sh
git status --short
git fetch origin --tags
RELEASE_REF='vX.Y.Z' # Replace with the intended published tag or full commit.
git show --no-patch "$RELEASE_REF"
git checkout --detach "$RELEASE_REF"
```

Use only the commands for your existing installation, with its original project,
file and environment settings. A separate build step is required; `up --no-build`
does not rebuild the application.

The next three examples update Zevyrn-native installations. If your service is
still named `keysmith`, use [Existing installations](#existing-installations)
instead; keep your original project name and configuration.

Standalone:

```sh
docker compose -p zevyrn -f compose.zevyrn.yaml config
docker compose -p zevyrn -f compose.zevyrn.yaml build zevyrn
docker compose -p zevyrn -f compose.zevyrn.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Traefik:

```sh
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml config
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml build zevyrn
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml pull --policy always traefik
docker compose -p zevyrn-traefik -f compose.zevyrn.traefik.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Caddy:

```sh
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml config
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml build zevyrn
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml pull --policy always caddy
docker compose -p zevyrn-caddy -f compose.zevyrn.caddy.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Repeat the health request and browser checks above after updating. For standalone,
check `http://127.0.0.1:18080/healthz` (or your configured loopback port). For HTTPS,
use your hostname and normal CA trust, or the explicit private-root check above.
Changes to pinned dependencies require review, not automatic substitution.
New builds are separate images; prior vulnerability results do not qualify them.
The existing `keysmith.theme` preference key is retained for compatibility.
Legacy Automatic/Light map to Zevyrn, Dark to Midnight, Emerald to Aurora, and
Amethyst to Dusk. New installations default to Zevyrn; Slate is a new choice.
Only a theme identifier is saved. Password generation is unchanged.
No automatic updater, custom release framework or retained rollback image is
required by these examples.

## Existing installations

The original `compose.yaml`, `compose.traefik.yaml`, `compose.caddy.yaml`,
`.env.example`, `examples/traefik/dynamic/keysmith.yaml` and
`examples/caddy/Caddyfile` remain available and unchanged. The private/internal
network support boundary also applies to these examples. Keep the same project,
service, `KEYSMITH_*` settings, external certificates and any operator-specific
proxy configuration. The local image name `keysmith:1.0.0-local` is a retained
compatibility identifier; rebuilding it from this source produces Zevyrn v1.2.1.
Do not switch to a Zevyrn project/service as an ordinary update: Compose would
create a separate installation and may conflict on ports. No migration is required.

After selecting a reviewed release or commit using the Git commands above,
use only the original command family for your installation:

```sh
# Legacy standalone (retain any original -p override and port settings):
docker compose -f compose.yaml config
docker compose -f compose.yaml build keysmith
docker compose -f compose.yaml up -d --no-build --pull never --wait --wait-timeout 120

# Legacy Traefik; retain your original project name if different:
docker compose -p keysmith-traefik -f compose.traefik.yaml config
docker compose -p keysmith-traefik -f compose.traefik.yaml build keysmith
docker compose -p keysmith-traefik -f compose.traefik.yaml pull --policy always traefik
docker compose -p keysmith-traefik -f compose.traefik.yaml up -d --no-build --pull never --wait --wait-timeout 120

# Legacy Caddy; retain your original project name if different:
docker compose -p keysmith-caddy -f compose.caddy.yaml config
docker compose -p keysmith-caddy -f compose.caddy.yaml build keysmith
docker compose -p keysmith-caddy -f compose.caddy.yaml pull --policy always caddy
docker compose -p keysmith-caddy -f compose.caddy.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Use the same original `-p`, `-f` and environment settings for logs, stop/start and
removal, then verify health and trusted HTTPS. Custom/shared-proxy installations
must continue using their own reviewed configuration; these examples do not
replace it. New Traefik routes live outside the legacy watched directory so
updating this repository does not load duplicate proxy routes.

For certificate renewal, obtain replacement files from your issuer, verify the
hostname/chain/key match, replace them securely in the external TLS directory,
and restart only the proxy with your same project/file options. Verify the served
certificate afterward. Do not change the app image for certificate renewal.

To remove an installation, run `docker compose down` with its exact project/file
options. Do not add broad prune, volume-removal or unrelated-project commands.
The external TLS files are not managed or deleted by Compose.

References: [Docker installation](https://docs.docker.com/engine/install/ubuntu/),
[Traefik file configuration](https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/file/),
[Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

Prebuilt-image references: [Compose up and health waiting](https://docs.docker.com/reference/cli/docker/compose/up/),
[GHCR visibility and digest pulls](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
