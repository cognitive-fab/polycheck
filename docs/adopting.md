# Adopting polycheck in your project

polycheck is just a CLI — nothing makes Claude Code run it unless your project
says so. This page is the missing piece: how to wire it in so it actually gets
used, at the right moments, in *your* repo.

There are two things you can adopt, and they activate differently:

| | how it runs | when |
|---|---|---|
| **the linter** (`polycheck .`) | a human, CI, or the agent *if told* invokes it | you choose — pre-commit, in CI, on policy changes |
| **the guard** (`polycheck guard`) | a hook that runs **itself** on every tool call | continuously, once installed |

Pick the linter for everyone (it's free and deploy-time). Add the guard only if
you want runtime enforcement and understand it is a runtime dependency — see the
caveat at the bottom.

---

## 1. Make your agent run the linter — a `CLAUDE.md` snippet

Claude Code reads `CLAUDE.md` at the start of every session, so this is how you
teach *your* project's agent that polycheck exists and when to use it. Paste into
your project's `CLAUDE.md`:

```markdown
## Least-privilege policy (polycheck)

This repo's `.claude` permission policy is checked with polycheck. Before you
change `permissions` (allow/ask/deny) or add an MCP server, run:

    npx -y @cognitive-fab/polycheck .

Keep the verdict at **PROOF**. Treat **BYPASS** or **SHELL-EQUIVALENT** as a
blocker: show me the witness and the suggested fix before proceeding. Exit 2
(**INCONCLUSIVE**) means a coverage gap, usually an unnamed MCP server — name its
tools rather than leaving it worst-case.
```

That is enough for the agent to run it and act on the verdict when it touches the
policy. You never have to remember to ask.

## 2. One-keystroke check — a slash command

Drop this at `.claude/commands/polycheck.md` in your project so `/polycheck` runs
it on demand:

```markdown
---
description: Check this repo's .claude policy for least-privilege (polycheck)
---
Run `npx -y @cognitive-fab/polycheck .` and summarize the verdict in one line.
If it is BYPASS or SHELL-EQUIVALENT, print the witness and the suggested fix and
treat it as a blocker. If it is INCONCLUSIVE, say what coverage is missing.
```

## 3. Enforce it in CI — fail the build on a bypass

polycheck exits `1` on BYPASS/SHELL-EQUIVALENT, so CI enforcement is one step.
GitHub Actions:

```yaml
name: least-privilege
on: [pull_request]
jobs:
  polycheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npx -y @cognitive-fab/polycheck .
```

Exit codes, so you can tune what fails the build: `0` proof · `1` bypassable
(incl. shell-equivalent) **or a mandate `SURPLUS`** · `2` inconclusive · `3`
usage/no-policy. To also fail on inconclusive, add `|| test $? -eq 0` logic, or
just require `0`.

### 3b. (Optional) check each task against what it declared

If your workflow gives an agent a per-task spec — a card, a ticket, a subagent
brief — that spec already names the files the task is supposed to produce. Write
those into a mandate file and polycheck will compare them against the policy:

```json
{ "id": "summarize-card", "root": "app", "outputs": ["app/src/summarize.mjs"] }
```

```
npx -y @cognitive-fab/polycheck . --mandate cards/summarize.json
```

`CONFINED` means every ungated write grant stays inside the declaration.
`SURPLUS` names the undeclared paths the policy reaches — ranked worst-first, so
a grant that reaches `.claude/settings.json` (the rules the agent is judged by) or
the test that decides whether its own output passes is reported ahead of ordinary
undeclared reach. It exits `1`, so the CI step above needs no change.

**Keep the mandate outside the agent's write grants.** The whole comparison rests
on the declaration being authored before and outside the turn it constrains;
polycheck says so every run, and flags the case where its own mandate file is
reachable.

## 4. (Optional) the runtime guard

If you want the composition gated *at runtime*, not just proved at deploy time:

```
npx polycheck guard init      # shows what it would add, then --yes to install
```

`guard init` runs the linter first and will talk you *out* of installing when the
repo is already PROOF (a static gate you wrote beats a runtime one) or has an
unrestricted shell grant (the labeler would be the only thing left in the way).

**Caveat — install it, don't `npx` it.** The guard writes a hook that points at an
absolute path to its own binary. Under a bare `npx`, that path lives in an
ephemeral cache that can vanish, leaving a broken hook. For the persistent guard,
add polycheck as a dev dependency so the path is stable:

```
npm i -D @cognitive-fab/polycheck
npx polycheck guard init      # resolves to node_modules — stable
```

`npx -y @cognitive-fab/polycheck .` is fine for the **linter** (a one-shot run);
the stability caveat only applies to the **guard** (a persistent hook).

Remove it any time with `npx polycheck guard off`. And never commit the hooks
`guard init` writes — they carry your machine's absolute path.

---

## What "good" looks like

- `CLAUDE.md` teaches the agent to run the linter when it touches the policy.
- CI fails a PR that introduces a BYPASS.
- The committed `.claude/settings.json` reads `PROOF`.
- (optional) the guard is installed from a dev dependency, gating the composition
  the linter proved — and `guard status` explains, honestly, what it does not
  cover.

See it end to end in [`../example/`](../example/) — a fake, safe sandbox you drive
from a real Claude Code session (with a model *other* than Fable 5 / Opus 5).
