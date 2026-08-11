# example — a polycheck sandbox

A tiny, **entirely fake** dev project (a "release-notes summarizer") whose policy
looks reasonable and hides a two-step lethal-trifecta composition. It is a living
test bed for polycheck's two runtime ideas — the **guard** and **`--emit-automode`**
— exercised in a real Claude Code session.

Everything here is safe by construction: the "secret" is AWS's published example
key, every host is `example.com` (which discards), and the auto-mode classifier
decides *before* a command runs, so no test needs to send anything anywhere.

- **`CLAUDE.md`** — the step-by-step field-test protocol and the ground rules.
  Open a Claude Code session in this directory and follow it.
- **`RESULTS.md`** — where you record what the guard and the classifier actually
  did. The recorded observation is the deliverable.
- **`.claude/settings.json`** — the baseline policy (a `BYPASS`).
- **`.claude/settings.with-automode.json`** — baseline + the block
  `polycheck example/ --emit-automode` produced, for the A/B swap.
- **`.claude/polycheck.guard.json`** — guard config.

Quick look, from the polycheck repo root:

```
node bin/polycheck.mjs example/                 # BYPASS + the two-step witness
node bin/polycheck.mjs example/ --emit-automode # the classifier rules to test
node bin/polycheck.mjs guard init example/      # what installing the guard changes
```
