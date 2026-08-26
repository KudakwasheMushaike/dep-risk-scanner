# Dependency Risk Scanner

A CLI tool that resolves a project's full dependency tree (direct + transitive),
checks every resolved package against OSV.dev and GitHub Security Advisories, and
produces a vulnerability report — in both human-readable console output and JSON.
Supports **npm** (`package.json` + lockfile) and **Python** (`requirements.txt`).

## Quick start

```bash
npm install
./cli.js <path-to-manifest> [--json-out report.json]
```

Examples:

```bash
./cli.js ./path/to/package.json --json-out report.json
./cli.js ./path/to/requirements.txt --json-out report.json
```

Optional: set `GITHUB_TOKEN` in a `.env` file at the project root to raise the GHSA
API rate limit from 60/hr (unauthenticated) to 5000/hr:

```
GITHUB_TOKEN=ghp_your_token_here
```

The CLI loads this automatically via `process.loadEnvFile(".env")` — no need to
`export` it manually or remember a `--env-file` flag.

## Architecture

```
manifest (package.json / requirements.txt)
        │
        ▼
   parsers/           npm.js — reads package.json + lockfile (npm/yarn v2/v3)
                       python.js — reads requirements.txt (exact == pins only)
        │
        ▼
   resolver.js         npm: walks the lockfile's already-resolved graph (BFS)
   parsers/python.js   Python: BFS over live PyPI lookups, since bare
                        requirements.txt has no lockfile to walk
        │
        ▼
   vulnSources/         osv.js — batched OSV.dev queries + full advisory details
                         ghsa.js — per-package GitHub Security Advisories queries
        │
        ▼
   merge.js             de-dupes overlapping advisories across the two sources
        │
        ▼
   report.js             console output (human-readable) + JSON output
```

Both ecosystems converge on the same flat `Dependency` shape
(`{name, version, ecosystem, direct, parents}`) after resolution, so every stage
after parsing — vulnerability querying, merging, reporting — is ecosystem-agnostic.

## What it does

- Resolves **direct and transitive** dependencies for both ecosystems.
- Queries **both OSV.dev and GitHub Security Advisories**, de-duplicating
  overlapping advisories (the same vulnerability is frequently reported under both a
  `GHSA-...` and a source-specific ID like `PYSEC-...`, cross-linked via `aliases`).
- Produces a report with: vulnerable packages (name, version, severity, CVE IDs,
  description, advisory link), a **recommended upgrade** per package (the highest
  fixed version across all of that package's vulnerabilities — a single upgrade
  target instead of several to reconcile), and summary statistics (total
  dependencies, vulnerable count/percentage, severity breakdown).
- Outputs both a human-readable console report and a JSON file.
- Handles real-world edge cases found by testing against actual projects (see
  Known Limitations below) rather than only synthetic examples.

## Usage

```
./cli.js <manifest> [--json-out <path>]
```

- `<manifest>` — path to `package.json` or `requirements.txt`. The ecosystem is
  detected from the filename.
- `--json-out <path>` — optional; also writes the full report as JSON.

**npm**: expects a lockfile (`package-lock.json` or `yarn.lock`) alongside
`package.json` in the same directory — auto-detected, not passed explicitly, matching
how `npm audit`/`npm install` themselves work.

**Python**: only exact `==` pins in `requirements.txt` are resolved as direct
dependencies. Ranges (`>=`, `~=`) and unpinned/editable-install lines are reported
separately as skipped, with a warning — not silently guessed at, since a wrong guess
would produce a vulnerability check against a version that may not actually be
installed.

### Testing against a new/unseen manifest

1. **npm**: place `package.json` and its lockfile (`package-lock.json` or
   `yarn.lock`) together in the same folder — the lockfile is auto-detected, not
   passed as a separate argument.
2. **Python**: just the `requirements.txt` file is needed — no lockfile required.
3. Run: `./cli.js /path/to/that/folder/package.json` (or `.../requirements.txt`),
   optionally with `--json-out report.json`.

No other setup is needed — the tool detects the ecosystem from the filename and
resolves everything from there. If a `.env` file with `GITHUB_TOKEN` isn't present in
the project root, GHSA queries just fall back to the unauthenticated rate limit
(60/hr) rather than failing.

## Design decisions worth knowing before a live walkthrough

- **Flat map, not a tree**, keyed by `name@version` for npm / normalized name for
  Python — the report only ever needs a flat list with parent metadata, never a
  walkable tree structure.
- **BFS over DFS** for resolution — level-order naturally separates direct (depth 0)
  from transitive dependencies, and each frontier is a natural unit for future
  parallelization.
- **npm tracks multiple installed versions per package name; Python does not.**
  npm's lockfile can show real, coexisting version conflicts (two different `zod`
  versions genuinely installed at once, since `node_modules` nesting allows it).
  Python's install model doesn't support that — one `pip install` produces exactly
  one installed copy of any given package — so the Python resolver dedupes by bare
  (PEP 503-normalized) name instead.
- **Python name normalization follows PEP 503** (lowercase + collapse `-`/`_`/`.`
  into `-`) — found necessary after a real bug where `typing-extensions` and
  `typing_extensions` were tracked as two separate packages, double-counting a real
  vulnerability in the report.
- **`recommendedUpgrade`**: rolls up all of a package's fixed versions to the single
  highest one (via `semver.rcompare`), since a later patch almost always still
  contains earlier fixes — one upgrade action instead of several to reconcile.

## Known limitations

- **npm `optionalDependencies` are not walked.** Platform-specific native binaries
  declared under that field (not `dependencies`) are never reached by the resolver.
  Found via a real discrepancy testing against a live project (512 resolved vs. 659
  total lockfile entries).
- **Python transitive resolution is best-effort, not a real SAT solver.** With no
  lockfile, edges come from live PyPI lookups of each package's declared
  `requires_dist` — this doesn't evaluate environment markers precisely or resolve
  version ranges the way `pip`'s real resolver does.
- **Fix-version selection doesn't do precise semver-range bracket matching.** When an
  advisory affects multiple major-version lines, the tool suggests the single highest
  known fix rather than computing which bracket the installed version falls into —
  matches what `pip-audit` does in practice.
- **No caching** — every run re-queries OSV/GHSA from scratch.
- **GHSA rate limits**: without a `GITHUB_TOKEN`, large manifests can hit the
  unauthenticated 60/hr limit. Individual failures are logged and skipped, not
  fatal — the scan still completes with whatever OSV data it has.

## Project structure

```
cli.js                    entrypoint
src/
  models.js
  parsers/
    npm.js                package.json + lockfile (v1/v2/v3) parsing
    python.js              requirements.txt parsing + PyPI-based resolver
  resolver.js               npm's BFS graph walker
  vulnSources/
    osv.js                  OSV.dev batch query + advisory details + dedup
    ghsa.js                 GitHub Security Advisories query
  merge.js                  cross-source advisory de-duplication
  report.js                 console + JSON output
tests/
  fixtures/                 sample manifests (npm/, python/) used for manual testing
  output/                   generated scan output (gitignored)
scripts/
  manual-test.js            npm-side manual test script
  manual-test-python.js     Python-side manual test script
```

## Testing

No automated test suite (given the take-home's time constraints) — verified
throughout development against real projects rather than only synthetic fixtures:
the npm side against a real production Next.js app (512 resolved dependencies,
including genuine multi-version conflicts), and the Python side against the
take-home's own Exercise 01 manifest plus a broader FastAPI/Django/Celery-style
`requirements.txt` (65+ resolved dependencies). See `scripts/manual-test.js` and
`scripts/manual-test-python.js` for the manual test harnesses used.
