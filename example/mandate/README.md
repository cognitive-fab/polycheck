# `--mandate` — a runnable sandbox

A two-card policy for the same fake release-notes summarizer as the parent
sandbox. Nothing here is real and nothing runs: it is a policy, a declaration,
and one command.

```
node bin/polycheck.mjs example/mandate --mandate example/mandate/mandate.json
```

## What it shows

The policy is the one nearly every coding-agent repo has — read the repo, write
the source:

```json
"allow": ["Read(./**)", "Edit(./src/**)"],
"ask":   ["Edit(./config/**)"]
```

The three forbidden regions come back clean: no egress tool is granted, so no
secret and no source can leave. By the region check, there is nothing to say.

The mandate check finds something anyway, and the two cards land on **opposite
verdicts under the same policy**:

```
MANDATE  — what the task declared it would write, vs what the policy lets it reach
  ✗ summarizer-card    SURPLUS — ungated write grants reach 3 paths it did not declare
  ✓ config-card        CONFINED — every write grant crosses a gate

SURPLUS · summarizer-card  (declares: app/src/summarize.mjs)
  build the release-notes summarizer
  Write grants that fire with no gate, and what they reach beyond the declaration:

    1  Edit(./src/**)                 allow  ⟶ src/summarize.spec.mjs         oracle
    2  Edit(./src/**)                 allow  ⟶ src/summarize.test.mjs         oracle
    3  Edit(./src/**)                 allow  ⟶ src/undeclared.mjs             scope

  oracle — the file that decides whether this output passes — writable alongside the output itself
  scope — undeclared reach — permitted by the policy, not asked for by the task

  Each of these is a grant someone wrote, doing what it says. The observation
  is only that the reach is wider than the task declared — nothing here says
  what any session did with it.
     fix declare it, or narrow it. Either add these paths to "outputs", or replace
         Edit(./src/**) with a grant scoped to what the task declared
         (Edit(src/summarize.mjs)), or move it to 'ask'.
```

`summarize.test.mjs` is the file that decides whether `summarize.mjs` passes. The
policy lets the same session write both, with no one in the loop — so a green
gate on this card is not, by itself, evidence that the code works. That is a
statement about **reach**, not about anything a session did; polycheck reads a
policy, never a transcript.

`config-card` is `CONFINED` for the reason the fix line names: its writes sit
behind `ask`. Same policy, same file, different verdict — because the
declaration differs.

## Why this isn't a fourth forbidden region

The obvious version of this check is "warn when tests are writable". That fires
on every coding-agent repo on earth and gets muted the same week. The
declaration is what makes it discriminating: `src/summarize.test.mjs` is flagged
because **it was never in the grant**, not because the path has `.test.` in it.
The path shape only decides the *ranking* (`policy` > `oracle` > `scope`), never
the finding.

## Try the fix

Narrow the grant to exactly what the card declared and re-run:

```json
"allow": ["Read(./**)", "Edit(./src/summarize.mjs)"]
```

Both cards go `CONFINED`, and the run exits `0`.

## One rule this rests on

The mandate has to be authored **before and outside** the turn it constrains. If
a session can edit its own `outputs`, the comparison is self-report and worth
nothing. polycheck cannot check that — it says so every run, and its `policy`
class flags the half it *can* see: try adding `Write(./**)` to the policy and the
mandate file itself shows up in the findings.
