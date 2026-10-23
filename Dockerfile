FROM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
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

FROM nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5 AS runtime-rootfs
# Upgrade only existing Alpine 3.24 runtime libraries requiring newer fixes.
# Exact pins fail closed if unavailable; do not switch Alpine branches.
# Patch libx11 inherited through Nginx's retained image-filter dependencies.
RUN apk add --no-cache --upgrade \
      libexpat=2.9.0-r0 zlib=1.3.2-r1 libx11=1.8.14-r0
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=10001:10001 /app/dist /usr/share/nginx/html

# EXPOSE is additive: inherit the patched filesystem, not the base's port 80.
# Standard multi-stage COPY retains source ownership; do not apply --chown here.
FROM scratch AS runtime
COPY --from=runtime-rootfs / /
# Preserve the pinned base's environment, working directory and shutdown signal.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NGINX_VERSION=1.30.6 PKG_RELEASE=1 DYNPKG_RELEASE=1 \
    NJS_VERSION=1.0.2 NJS_RELEASE=1 ACME_VERSION=0.4.1
WORKDIR /
STOPSIGNAL SIGQUIT
LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>" \
      org.opencontainers.image.title="Zevyrn" \
      org.opencontainers.image.version="1.2.1" \
      org.opencontainers.image.description="Browser-only password generator with local validation and no password storage"
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
# Bypass the stock entrypoint scripts so startup never writes to /etc/nginx.
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
