# polycheck

**A least-privilege linter for Claude Code agent policies.** Point it at a repo;
it reads the `.claude` settings and MCP config and tells you — deterministically,
before any agent runs — whether your policy lets an agent get from *untrusted
input* to *credential egress* with no gate in between. Either:

- **PROOF** — every path into a forbidden region crosses a gate, or
- **WITNESS** — a concrete sequence of *allowed* tool calls that reaches
  credential egress with **zero gates crossed**.

```
npx @cognitive-fab/polycheck .
```

Zero dependencies. Offline. Deterministic. No model call, no network, no clock.
It runs on any repo in seconds and changes no behavior, so there is nothing to
integrate and nothing to trust at runtime.

> **We tried to make the gap fire against a live agent, and it didn't.** Across
> four model versions and two attack shapes, the model refused every time — and
> we published the negative result: [`experiments/FIELD-NOTES.md`](experiments/FIELD-NOTES.md).
> That's the argument for a *provable* layer, not against it: model refusal is a
> good screen and a bad control.

---

## What it's for (and what it isn't)

polycheck answers one question a human reviewer and a runtime permission prompt
both miss: **what does this agent's policy actually permit, once you account for
tool calls composing across a session?** It is a config linter in the spirit of
an IAM policy analyzer — you run it to enforce least privilege and to *know and
prove* your blast radius, not because you expect an attack today.

**It is good for:**
- **Least-privilege review** — catching over-broad grants a human wrote by
  accident: `WebFetch` is an egress channel, `Bash(npm run test:*)` is arbitrary
  code execution, an MCP `send`/`create` tool is an exfil channel.
- **Deploy-time, auditable assurance** — a deterministic proof/witness artifact
  you can put in CI and in front of a security review. "The classifier probably
  caught it" is not an audit answer; a proof is.
- **Headless / scale** — CI agents, cron jobs, subagent fleets,
  `--dangerously-skip-permissions` runs, where no human approves each call and
  the model's caution is the only backstop. polycheck is the pre-deploy gate.

**It is *not*:**
- a predictor that the model will leak (current models are good at refusing —
  see [`experiments/`](experiments/); that's *why* you want a provable layer),
- a content / prompt-injection detector (only the tool-mediated control flow is
  modeled),
- better than its labeler (a mislabeled tool is a hole the proof cannot see).

---

## Why now: it complements auto mode, it doesn't compete

Claude Code's default is moving to **auto mode** — a classifier that reviews each
shell command and, in Anthropic's testing, caught **89% of dangerous commands**
(manual approval caught 14%). polycheck is not an alternative to that number; it
covers the gap the number structurally can't:

| | auto mode (the classifier) | polycheck |
|---|---|---|
| unit of judgement | one command, in isolation | a **path** through accumulated session state |
| the compositional hazard (benign steps) | structurally invisible | **the whole design** |
| determinism | probabilistic (89%, non-deterministic) | exhaustive; same input ⇒ same verdict |
| lifecycle | runtime interception, per call | **deploy-time**, before an agent exists |
| output | allow / block | a **proof**, or a **witness** you can screenshot |
| auditable | no | yes — a proof artifact |

The lethal trifecta is a *sequence of individually-benign commands* — fetch a
page, read a file, run `curl` — so a per-action screen (rule **or** classifier)
passes each one. And there is **no per-action rule that closes it** without
breaking legitimate use: the permission model has no vocabulary for "not both, in
one session, after untrusted input." polycheck does, because it reasons over the
whole reachable state graph. See it made concrete:

```
node demo/vs-auto-mode.mjs
```

The relationship in one line: **detection for the novel command, proof for the
declared composition.** They stack.

---

## What a run looks like

**A policy that gated `curl` but not `WebFetch`** (`allow: WebFetch, Read(./**)`)
— a genuine two-step composition, and `curl` appears nowhere:

```
FORBIDDEN REGIONS
  ✗ lethal-trifecta    BYPASS — a gate-free path exists

WITNESS · lethal-trifecta  (untrusted ∧ sensitive ∧ egress)
    1  WebFetch                       allow  ⟶ +untrusted +egress  held: untrusted, egress
       └ settings: WebFetch
    2  Read(./**)                     allow  ⟶ +sensitive          held: untrusted, sensitive, egress  ← REACHED
       └ settings: Read(./**)

     fix close the 'untrusted' effect — move to ask/deny: WebFetch
```

Exit code `1`. `WebFetch` is an egress channel too (it carries data out in the
URL), so gating only `curl` left the door open — the kind of thing a human
reviewer misses. And `Bash(curl:*)` *alone* is a one-step BYPASS: `curl` reads
local files (`curl -T .env`) and posts them, so one tool is both a secret-reader
and an egress channel.

**A mediated policy** (every egress tool — `curl`, `git push`, **and
`WebFetch`** — is `ask`) → `PROOF`, exit `0`. **A coverage gap is never painted
green** (`INCONCLUSIVE`, exit `2`) — unreachable-for-lack-of-a-granted-tool is
reported as coverage, not safety. And "you granted a shell" is its own verdict
(`SHELL-EQUIVALENT`) — `Bash(npm run build:*)` runs caller-chosen code, so the
composition question is moot; that's reported separately from genuine
compositions. Every finding ends with the minimal edit that closes it.

---

## Usage

```
polycheck [path]                 check a repo (default: current directory)
polycheck . --tidy               grant hygiene: which rules are redundant or dead,
                                 with a proof of what removing them changes
polycheck . --write              apply that edit — line surgery, then re-verified
                                 from disk and rolled back if it does not match
polycheck . --verbose            expand grouped grants + every assumption (human-readable)
polycheck . --json               machine-readable output
polycheck . --md                 a fenced block ready to paste into an issue/PR
polycheck . --labels <file>      override the effect-label pack
polycheck . --regions <file>     override the forbidden-region pack
polycheck . --no-assume-defaults strict: model only explicitly-granted perms
```

By default polycheck models Claude Code's auto-allowed read-only tools (`Read`,
`Grep`) as ungated, so the common case (an egress tool but no explicit `Read`)
isn't a false pass; `--no-assume-defaults` gives the strict, explicit-only view.

### `--tidy` — read the running total you never agreed to

A permission list grows one yes-in-the-moment at a time. Nobody ever reads the
accumulated result, so it ends up a mix of rules that matter, rules another rule
already covers, and rules pinned to a session that will never recur. `--tidy`
sorts every rule into four buckets:

- **KEEP** — earning its place.
- **DEDUP** — a broader rule in the same bucket already admits it
  (`Bash(python3 -m pip install x)` under `Bash(python3:*)`), or it is listed twice.
- **PRUNE** — an exact-match rule that *cannot fire again*, and says why: a path
  that isn't on this machine, backslash-escaped parens from a mangled JSON
  round-trip, a captured `$?` echo, a hard-coded host.
- **MERGE** — several one-shots invoking the same executable that one prefix rule
  would replace. Offered, never applied: a prefix rule admits commands you have
  not run yet, so this one is a **widening** and needs your yes. And when the
  executable is an arbitrary-execution wrapper, the merge is labelled **DO NOT
  TAKE THIS ONE** — collapsing five exact `node …` commands into `Bash(node:*)`
  is a shell grant, and offering that as tidy-up is the mistake this tool exists
  to catch.

The part that makes this polycheck's job rather than a text linter's is that the
edit comes with a **proof**. The state machine is monotone and unconditional, so
the maximal reachable state is exactly the union of the available actions'
effects — which means two rulesets are effect-equivalent iff that union agrees
per gate class *and* every region verdict agrees. `--tidy` re-runs the whole
analysis over the proposed ruleset and reports the direction:

```
PROOF OF THE EDIT
  ✓ removing 7 rules is effect-preserving.
    Reachable effects are identical before and after, per gate class
    (ungated: egress, sensitive, untrusted), the shell-grant set is unchanged,
    and every region verdict is unchanged. The blast radius does not move.
```

**And it refuses to flatter you.** If deleting a subsumed line makes the *model*
smaller while the covering rule still admits the same command at runtime, the
report got better and nothing got safer — the one way a hygiene pass can
actively mislead. Those lines are flagged `⚠`, with the fix pointed at the
covering rule instead of the line.

**`--write` applies it.** Three properties make that safe enough to run without
reading the diff first:

1. **Line surgery, not reserialisation.** A settings file is *your* file — key
   order, indentation, blank lines and the `"//"` note at the top all survive,
   because the only thing that changes is that N lines are gone. A file that
   isn't in the conventional one-entry-per-line shape is **refused**, not
   guessed at, and a refusal anywhere means no file is written at all.
2. **The `⚠` rules are never applied.** They are excluded by construction:
   applying one would make the report look better while nothing got safer, which
   is the single edit this tool must not make quietly. They stay in your file,
   with the fix pointed at the covering rule.
3. **Verified from disk, then rolled back.** After writing, the repo is
   re-scanned and re-checked *from scratch* — not from the plan. If the
   behavioural signature isn't the one that was proved, every file is restored
   to its original bytes and the run exits `4`. The proof is checked against
   reality.

```
WRITE
  .claude/settings.json
    − Bash(git status:*)                              [allow] duplicate
    − Bash(cp /tmp/gone-4a91b/x.txt /tmp/gone-4a91b/y.txt)  [allow] one-shot, stale

  ⚠ held back — 1 rule whose removal would shrink the report, not the grant:
      Bash(python3 -m pip install requests -q)
      └ Bash(python3:*) still admits this command at runtime — narrow it instead.

  ✓ 2 rules removed from 1 file, effect-preserving.
```

Deliberate limits: subsumption is inferred for shell tools only
(`Bash`/`PowerShell`/`pwsh`), where a specifier is a command prefix with known
matching — `Read`/`Edit` globs are left alone, because a wrong deletion there is
silent and a cleanup you have to re-check is worthless. Staleness evidence is
machine-local. And tidy is **not** the security check: an effect-preserving edit
preserves a `BYPASS` exactly as faithfully as a `PROOF`. Without `--write` it is
a dry run and always exits `0`; `--write` exits `4` only if it refused or rolled
back, in which case nothing on disk changed.

### A declared MCP server holds you at INCONCLUSIVE — and that is deliberate

If `.mcp.json` declares a server whose tools are not named in `permissions`,
polycheck treats `mcp__<server>__*` worst-case as `[untrusted, egress]`: a
server's tool list is unknowable without running it, and Claude Code's own
prompt for an unnamed tool is polycheck's assumption rather than a rule you
wrote. It will not let an assumption carry a green verdict, so the run lands on
`INCONCLUSIVE` (exit `2`) rather than `PROOF`.

This affects any repo that declares a server, which is a large population — so
to be explicit: it is a coverage statement, not a finding against your policy,
and it is not a state you are stuck in. **Name the tools and the verdict
resolves.** Listing each server tool under `allow` / `ask` / `deny` gives the
checker real edges to reason about:

```jsonc
{
  "permissions": {
    "allow": ["mcp__notion__search"],       // returns remote content → untrusted
    "ask":   ["mcp__notion__create_page"],  // an egress verb → gate it
    "deny":  ["WebFetch", "Bash"]
  }
}
```

That policy reaches `PROOF`. If a name is misleading — a `create_*` tool that is
actually read-only — correct it in `--labels` rather than leaving it worst-case.

Exit codes: `0` proof · `1` bypassable (incl. shell-equivalent) · `2`
inconclusive · `3` usage error or no `.claude` policy at the path · `4` a
`--write` that refused or rolled back. A wrong path is an error, never a report.
CI-friendly: fail the build on `1`.

---

## The demo, and the experiments

- **`demo/showcase.mjs`** — **the demo.** `polycheck` across policies that each
  look reasonable and each hide a composition (WebFetch-as-egress, `npm run`
  arbitrary execution, an MCP send tool), then a real PROOF and an honest
  VACUOUS. Deterministic, no agent, no secret, no attacker — screen-record this.
  `node demo/showcase.mjs [your-repo]`
- **`demo/vs-auto-mode.mjs`** — the side-by-side with the 89% classifier.
- **`experiments/`** — honest tests of *does the gap get exploited live?* Across
  four model versions and two attack shapes, the model **refused every time**
  ([`experiments/FIELD-NOTES.md`](experiments/FIELD-NOTES.md)) — which is the
  argument for a provable layer, not against it. These are experiments, not a
  demo, and they are deliberately not tuned to defeat model safeguards.

---

## How it works (one file each)

- **`src/scan.mjs`** — read `.claude/settings.json`, `settings.local.json`,
  `.mcp.json`, hooks, and `defaultMode` off disk. Pure parsing; nothing runs.
- **`src/label.mjs`** — the **labeler**: map each permission rule to effect
  classes `{untrusted, sensitive, egress}`. `WebFetch` is both ingest and egress;
  `Read(./**)` is `sensitive` because its glob *covers* a secret; unrestricted
  `Bash` and arbitrary-execution wrappers (`npm run`, `make`, `python`, `bash -c`,
  `xargs`, `git -c …`) are worst-case, because a command *prefix* is not a
  security boundary; an MCP tool is `untrusted` and also `egress` when its name is
  an egress verb (`mcp__slack__send_message`). It is plain JSON
  (`data/claude-code.labels.json`) — a **named trust obligation**, inspectable
  and overridable.
- **`src/model.mjs`** — compile rules into **actions**: `allow` → ungated edge,
  `ask` / matching `PreToolUse` hook → gated edge, `deny` → no edge,
  `bypassPermissions` → every edge ungated.
- **`src/check.mjs`** — the checker. Delete the gates, BFS the reachable
  states, and for each **forbidden region** (`data/regions.json`) return the
  shortest gate-free path (a **witness**), or decide whether every path crosses a
  gate (**proof**) or a required effect has no provider at all (**vacuous**,
  reported loudly rather than as clean).
- **`src/tidy.mjs`** — the `--tidy` hygiene pass: dedup / prune / merge, plus
  `proveEdit`, which re-runs the analysis over the proposed ruleset and
  classifies the edit as effect-preserving, narrowing, or widening.
- **`src/write.mjs`** — the only part of polycheck that mutates anything:
  line-level removal that preserves formatting and comments, a refusal for any
  file shape it cannot reason about, and a verify-from-disk-then-roll-back step
  so what lands is exactly what was proved.
- **`src/report.mjs`** — render the witness/proof and, always, *what the check
  did not establish*.

Effects are monotone within a session, so a state is a subset of the effect
universe and BFS discovery order yields the shortest witness for free. The whole
check is a few hundred lines and finishes in milliseconds.

---

## What this does NOT establish

polycheck prints these every run:

- **The auto-mode classifier is not counted as a gate** — by design (see above).
- **The labeler is a trust obligation, not a proof.** It proves the policy over
  the labels; it does not prove the labels are right.
- **`ask` is a gate, but weaker than a PROOF implies** — it means a human is in
  the loop, not that they'll refuse (approval fatigue is real). Prefer `deny` for
  irreversible egress.
- **Confinement is out of scope.** Only tool-mediated actions are modeled;
  anything outside the tool interface is not.
- **Subagent taint is not propagated (v1).** `Task` spawns are a known gap —
  named, not silently cleared.
- **Modeled permissions only** — a conservative under-approximation, to keep a
  witness credible.

---

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
