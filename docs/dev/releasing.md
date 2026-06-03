# Cutting a release

HexGraph is distributed primarily as a source checkout (`git clone` + `just setup`), and a
tag marks each release. This is the checklist for cutting one.

## Before you tag

1. **Land everything for the release on `main`** through the normal PR + review gate, and
   make sure CI is green on `main` (offline matrix, frontend build, and the live Docker
   lane).
2. **Bump the version** in `pyproject.toml` (`project.version`) and add a dated section to
   `CHANGELOG.md`. The version is the single source of truth; nothing else hardcodes it.
3. **Re-run the full suite with the sandbox image present** (`just test-ci`) and `just demo`
   so the security-critical paths are actually exercised, not skipped.

## Building the distribution artifacts

If you build a wheel (for an archived artifact or, later, PyPI), **build the SPA first** —
this is easy to forget and produces a broken wheel if you skip it:

```bash
just ui                                  # builds the React app into src/hexgraph/web/dist
python -m build                          # or: pip wheel --no-deps -w dist .
```

`src/hexgraph/web/dist/` is gitignored and is **not** created by `just install`, so a wheel
built without `just ui` ships with no web UI (the backend serves nothing at `/`). The
frozen Finding schema, the mock-LLM fixtures, the sandbox probes, and the seccomp profile
are declared in `pyproject.toml`'s `package-data` and are bundled automatically; the SPA is
the one piece that depends on a prior build step. After building, sanity-check the wheel
actually contains `hexgraph/web/dist/index.html`.

## Tagging

```bash
git tag -a vX.Y.Z -m "HexGraph vX.Y.Z"
git push origin vX.Y.Z
```

Then cut a GitHub release from the tag and paste the `CHANGELOG.md` section into it.

## PyPI (optional, not yet enabled)

HexGraph is not published to PyPI today; the source checkout is the supported install path.
If that changes, publishing would add a release workflow gated on the tag, using a PyPI API
token stored as a repository secret — never a key in the repo.
