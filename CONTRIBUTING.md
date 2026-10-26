# Contributing

Use Node.js 22 or newer and npm for local development. Keep the checkout's
Git LF bytes as selected by `.gitattributes`; compiler verification authenticates
project metadata and exact installed compiler files without rewriting either.
Do not convert project metadata to historical qualified CRLF bytes. Historical
artifact reproduction is a separate process, not a normal development prerequisite.

Before dependency installation, the source-checkout checks can run with Node alone:

```sh
node --input-type=module -e "import {compilerPolicy} from './scripts/verify-compiler.mjs'; await compilerPolicy();"
node --test tests/source-build-portability.mjs
```

Then use the existing locked dependencies:

```sh
npm ci
npm test
npx --no-install tsc6 --noEmit
npm run dev
```

The development server binds to localhost:4173. Run `npm run build` again after
source changes; the small development server does not rebuild automatically.

Keep changes focused. Preserve exact entropy calculations, unbiased sampling,
dictionary provenance, character exclusions, browser privacy and accessibility
behavior. Dictionary inputs and reports under `data/` are pinned; do not change
them or their hashes without reviewing the intended data change.

`npm test` builds the application and runs the source regression tests. Browser
suites use development-only Playwright pinned in package-lock.json (`npm ci`)
and an installed Microsoft Edge. Set `KEYSMITH_BROWSER_PATH` to the Edge
executable; `KEYSMITH_PLAYWRIGHT_MODULE` remains an optional compatibility override.
These variables are test-only and do not affect the Docker runtime. The CI
workflow lists eight maintained suites explicitly; browser-*.mjs also includes
helpers and a separately maintained combined-layout regression suite.
Configuration tests can use an official standalone Compose binary through the
test-only `ZEVYRN_COMPOSE_BIN` override. They execute `config`, never start
containers, and do not require access to a Docker daemon.
Automated browser captures belong in the ignored `artifacts/` directory, not a
source release. Curated README images under `docs/screenshots/` are reviewed
documentation assets captured from the real application. Use only public test
examples that will never serve as credentials; never capture personal passwords
or other sensitive information.

Do not commit credentials, TLS material, `.env`, logs, dependencies, generated
`dist/`, or test artifacts. See SECURITY.md for confidential reporting and LICENSE
plus data/NOTICE.md for application and dictionary licensing.
