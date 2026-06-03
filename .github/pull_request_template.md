<!--
Thanks for the PR. The checklist below mirrors the merge gate in CONTRIBUTING.md / CLAUDE.md.
It isn't bureaucracy — each item maps to a way a change can quietly break the product.
-->

## What and why

<!-- What does this change do, and what problem does it solve? -->

## How it was verified

<!-- The commands you ran and what you observed. e.g. `just test` green; `just demo` exits 0;
     for live paths, `just test-ci` with the sandbox image built. -->

## Checklist

- [ ] Branch is named `build/<topic>`, `fix/<topic>`, or `docs/<topic>`.
- [ ] `just test` passes (and `just demo` if the core loop changed).
- [ ] If any live path changed (execution / egress / rehost / remote), `just test-ci` was run with the sandbox image built — a green offline run doesn't exercise those.
- [ ] Tests were added or updated for the change.
- [ ] Any model change ships an Alembic migration (`alembic revision --autogenerate`).
- [ ] Any UI-behavior change updates `docs/dev/ux-contract.md`.
- [ ] No invariant is broken: still loopback-only, BYOK, secrets never logged/stored, target bytes stay in the sandbox, and nothing relaxes capability outside the policy seam.
- [ ] The frozen Finding schema is untouched (new structure went in the DB envelope).
