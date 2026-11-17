# Repository rename and compatibility

The existing public repository was renamed in place from
`TheStateOfWhere/keysmith-password-generator` to
[TheStateOfWhere/zevyrn-password-generator](https://github.com/TheStateOfWhere/zevyrn-password-generator).
Its identity, owner, default branch, Git history and historical releases were
preserved. Active README, installation, security and clone links use the new
canonical address. The old repository URL redirects; do not reuse the old name.

In an existing clone, inspect the current remote before updating only the
appropriate repository:

```sh
git remote -v
git remote set-url origin https://github.com/TheStateOfWhere/zevyrn-password-generator.git
git remote -v
```

External integrations and clone consumers may retain the previous URL; their
absence is not assumed. Update known active references with their owners. The
rename does not require changing deploy keys or other access permissions.
Relative documentation and screenshot paths remain unchanged.

Keep existing `keysmith` Compose services, project/image identifiers, proxy route
filenames, `KEYSMITH_*` variables and external TLS paths for compatibility. The
retained `keysmith:1.0.0-local` image tag is a local compatibility name; application
and OCI version metadata is 1.2.2 when built from this source. No legacy Compose change is required.
A repository rename does not require changing application hostnames or deployment
resources. Historical licenses, dictionary provenance and release notes remain
historical. Preserve the existing KeySmith v1.0.0 tag/release exactly.

The application version in this source is 1.2.2. A source update does not create a version tag or
GitHub Release and does not update an existing deployment. Follow
[INSTALLATION.md](../INSTALLATION.md#updates) when choosing an approved release
or reviewed commit to install.

New prebuilt installations use `compose.ghcr.yaml`; see
[the installation guide](../INSTALLATION.md#prebuilt-image-recommended).
Optional source builds use `compose.zevyrn.yaml`, `compose.zevyrn.traefik.yaml` or
`compose.zevyrn.caddy.yaml`, the `zevyrn` service and `zevyrn:1.2.2-local` image.
Copy `zevyrn.env.example` for the new `ZEVYRN_*` settings. New files accept legacy
variable fallbacks, but do not provide old Compose service-name aliases.
Existing installations should follow the [legacy update path](../INSTALLATION.md#existing-installations)
without renaming projects, services, networks, volumes, routes or hostnames.
This local v1.2.0 preparation does not change historical v1.1.0 releases.
