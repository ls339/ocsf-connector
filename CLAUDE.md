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
