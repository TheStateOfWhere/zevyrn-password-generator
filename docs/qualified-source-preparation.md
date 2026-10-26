# Qualified source-byte preparation

This document concerns reproduction of the **historical qualified artifact**.
Ordinary development and Docker source builds use exact canonical Git LF
metadata and do not use this preparer. New development bytes do not acquire
historical qualification merely by passing the current compiler integrity gate.
The historical archives, controller authority and preparation approvals remain
unchanged; this development correction does not activate a new controller profile.

Git's LF blobs identify the repository source. The authenticated v1.2.1
qualification used CRLF bytes for the 17 files below. Logical newline equivalence
does not establish byte identity. A Git archive alone is therefore insufficient
as the input to frozen-source tests or reproduction of qualified static assets.

`scripts/prepare-qualified-source.py` prepares a **new**, separate validation
view. It copies the exact authenticated original payload for every mapped file;
it does not normalize, reformat, regenerate or overwrite repository files.
Every other source file is copied unchanged from the authenticated Git export.
The existing controller and its source catalog remain unchanged.

## Authority and execution

The preparer cannot authorize itself. Direct execution fails with
`EXTERNAL_BOOTSTRAP_REQUIRED`. Before importing its code, an independently
authenticated external bootstrap must authenticate an operator-approved authority
record and the preparer's exact SHA-256. It must execute the captured verified
bytes and supply its private capability. Neither a repository file, environment
variable nor a command-line expected hash is an approval.

An external bootstrap template accompanies the isolated engineering evidence;
it is not part of this Git proposal and has an empty approval-pin set. Test
copies contain only synthetic or explicitly test-only pins. No production
preparation profile or vulnerability exception is activated by this proposal.
The bootstrap itself, Python interpreter and any future operator approval need
independent authentication before operational use. Possession of arbitrary
Python execution already lies outside this source-data trust boundary.

The external authority binds:

- The exact helper path and SHA-256, input source root, Git commit and tree.
- The raw Git commit record and the complete closed source inventory, including
  path, byte length, SHA-256, Git blob ID and mode.
- All 17 mappings, their Git and qualified lengths and hashes, and exact archive
  member names.
- The original qualification bundle, embedded source-manifest hash and separately
  authenticated source-provenance record.
- A dedicated external workspace, new output directory and new external receipt.

The preparer recomputes Git blob, tree and commit identities, authenticates the
qualification bundle, and verifies every one of the 97 original source payloads.
The original 97-file manifest and the later 100-file frozen application fixture
have different scopes; neither is relabelled as the other. All 17 mapped files
are covered by both the original manifest and the provenance record.

## The 17 mappings

Each qualified payload is the member
`qualification-dk02-20261019-02/source/<path>` in the original bundle.

| Repository-relative path | Existing CI preparation |
| --- | --- |
| `SECURITY.md` | No |
| `package-lock.json` | Yes |
| `package.json` | Yes |
| `public/styles.css` | No |
| `public/theme.js` | No |
| `scripts/ci-security.mjs` | No |
| `scripts/compiler-integrity.json` | Yes |
| `scripts/verify-compiler.mjs` | No |
| `tests/advanced.test.mjs` | No |
| `tests/approved-theme-tokens.json` | No |
| `tests/browser-focus-copy.mjs` | No |
| `tests/browser-profiles.mjs` | No |
| `tests/browser-themes.mjs` | No |
| `tests/browser-ui-corrections.mjs` | No |
| `tests/ci-security.test.mjs` | No |
| `tests/release-config.test.mjs` | No |
| `tests/theme.test.mjs` | No |

Exact per-file hashes, lengths and external source descriptors belong in the
independently approved execution record, not a self-approving repository policy.
The isolated evidence includes the complete real qualification mapping.

## Failure and output contract

Missing, modified, duplicated, ambiguous, unapproved or substituted inputs fail
closed. Unexpected files, unsafe paths, links, hard-linked inputs, changed
source, mismatched Git identities, wrong members, lengths or hashes are rejected.
Archive reads are bounded and do not extract filesystem paths. All input checks
finish before creating output. Existing outputs and receipts are refused.

The output is outside the source, code and evidence trees. Output and receipt
names reject reserved names, alternate data streams and existing directory
entries, including dangling links. Files use exclusive creation and are read
back; a final complete inventory and hash sweep precedes the receipt. On POSIX,
the output root is mode 0700, directories 0755, files 0644 and receipt 0600.
Windows validation does not prove POSIX permissions.
An I/O failure may leave a partial new workspace for diagnosis, but must not
produce a successful receipt. Operator cleanup requires separate authorization.
The external workspace must remain private against concurrent untrusted writers;
this helper is not a filesystem sandbox.

The receipt records the **input** Git commit/tree separately from the prepared
file hashes. The prepared 17 files intentionally differ from Git blob bytes.
The receipt explicitly grants neither qualification success nor vulnerability
approval. Existing pre-import authentication, source manifests, runtime and
builder security gates, readiness and settlement checks still apply. Installing
this helper does not activate a controller or make its receipt automatically
eligible for qualification.

## Focused tests

Run the standalone Python test file with `-I -S -B`, supplying the external
empty-pin bootstrap template through `QUALIFIED_PREPARATION_TEST_TEMPLATE`.
That variable is consumed only by the test harness. Synthetic test copies alone
receive pins. The tests execute the real bootstrap and preparer in subprocesses,
without network, Docker, release operations or production approvals. The real
17-file reconstruction, frozen-source regression and generated-asset comparison
are recorded separately in the isolated integration evidence.
