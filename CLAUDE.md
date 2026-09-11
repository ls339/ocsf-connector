# ocsf-connector

Okta System Log → OCSF → Amazon Security Lake. Design and pinned vendor facts
live in `docs/SPEC.md` — read it before changing anything in `sources/`,
`state/`, or `sinks/`.

## Commands

```
uv sync                 # install
uv run pytest           # tests
uv run ruff check .     # lint
uv run ruff format .    # format
uv run mypy src         # types (strict)
```

## Invariants — do not break these without updating SPEC.md

1. **The cursor is the only resume state.** Never resume from a timestamp. Okta
   polling queries are ordered by persistence time and may return events out of
   order by `published`; a timestamp watermark drops events silently.
2. **A cursor is the URL to GET next; its `after` is opaque.** Only the opening
   query is built here, from a configured `since`; persist every later `next`
   URL verbatim. Never parse a cursor, never construct an `after` value. Tail's
   opening `since` comes from config, never `now()` — see SPEC §5.2.
3. **Commit the cursor only after the sink acknowledges.** `Sink.flush()`
   returning cleanly is the ack. Nothing else licenses a commit.
4. **Mapping never raises and never drops.** Unknown `eventType` degrades to a
   generic class with the source event under `unmapped`, and increments
   `unmapped_event_type_total`.
5. **All fixtures are synthetic.** No real tenant id, user, email, or IP in any
   test file, fixture, screenshot, or commit message. This is a public repo about
   security data; people will check.

## Conventions

- Python 3.12, async throughout, `from __future__ import annotations`.
- Seams are `Protocol`s in `*/base.py`. Concrete implementations sit beside them.
- Vendor behavior asserted in code needs a `docs/SPEC.md` section reference in the
  comment, and SPEC.md needs a link to the vendor doc it came from.
- Tests run against recorded fixtures via `respx`. No live API calls in CI.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
