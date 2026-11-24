FROM node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /app
# Freeze the reviewed npm artifact before installation; application locks stay intact.
RUN mkdir /tmp/zevyrn-npm-tool \
    && npm pack npm@11.21.1 --registry=https://registry.npmjs.org --ignore-scripts --json --pack-destination /tmp/zevyrn-npm-tool > /tmp/zevyrn-npm-tool/pack.json \
    && node -e 'const fs=require("node:fs"),crypto=require("node:crypto"),assert=require("node:assert/strict"),root="/tmp/zevyrn-npm-tool/",expected="sha512-YTzL6QBEJXyHcTu0JiUc7RKMp+mzlJtl7rGLmERaXUQeFHIMc9atdr6G9M9C8vDWbv40epoTQAzNL2/PtZVDhQ==";const rows=JSON.parse(fs.readFileSync(root+"pack.json","utf8"));assert.ok(Array.isArray(rows));assert.equal(rows.length,1);const p=rows[0];assert.equal(p.name,"npm");assert.equal(p.version,"11.21.1");assert.equal(p.filename,"npm-11.21.1.tgz");assert.equal(p.integrity,expected);assert.equal("sha512-"+crypto.createHash("sha512").update(fs.readFileSync(root+p.filename)).digest("base64"),expected);' \
    && npm install --global /tmp/zevyrn-npm-tool/npm-11.21.1.tgz --ignore-scripts --no-audit --no-fund \
    && test "$(npm --version)" = "11.21.1" \
    && rm -rf /tmp/zevyrn-npm-tool
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts
COPY tests ./tests
COPY data ./data
# Configuration regression tests run inside the build stage as well as locally.
COPY compose.yaml compose.traefik.yaml compose.caddy.yaml .gitignore .dockerignore Dockerfile LICENSE ./
COPY compose.zevyrn.yaml compose.zevyrn.traefik.yaml compose.zevyrn.caddy.yaml zevyrn.env.example ./
COPY examples ./examples
RUN npm test

FROM nginx:1.30.8-alpine@sha256:6437a63b5c529f0e06162b3f593c0154cff6fa2ea0f94fd7c27928cb399e022d AS runtime-rootfs
# Upgrade only existing Alpine 3.24 runtime packages requiring newer fixes.
# Minimum security versions allow newer fixes without changing Alpine branches.
# Patch libx11 inherited through Nginx's retained image-filter dependencies.
RUN apk add --no-cache --upgrade \
    'libexpat>=2.10.0-r0' 'zlib>=1.4-r0' \
    'libx11>=1.8.14-r0' 'brotli-libs>=1.2.1-r0' \
    'curl>=8.23.0-r0' 'libcurl>=8.23.0-r0' \
    'libxslt>=1.1.43-r4' 'musl-utils>=1.2.6-r3' \
    'libxml2>=2.13.9-r3'
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=10001:10001 /app/dist /usr/share/nginx/html

# EXPOSE is additive: inherit the patched filesystem, not the base's port 80.
# Standard multi-stage COPY retains source ownership; do not apply --chown here.
FROM scratch AS runtime
COPY --from=runtime-rootfs / /
# Preserve the pinned base's environment, working directory and shutdown signal.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NGINX_VERSION=1.30.8 PKG_RELEASE=1 DYNPKG_RELEASE=1 \
    NJS_VERSION=1.0.2 NJS_RELEASE=1 ACME_VERSION=0.4.2
WORKDIR /
STOPSIGNAL SIGQUIT
LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>" \
      org.opencontainers.image.title="Zevyrn" \
      org.opencontainers.image.version="1.2.2" \
      org.opencontainers.image.description="Browser-only password generator with local validation and no password storage"
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
# Bypass the stock entrypoint scripts so startup never writes to /etc/nginx.
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
