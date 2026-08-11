# polycheck guard — functional specification

**Status:** draft v0.1 · **Depends on:** polycheck 0.3.1 (`src/check.mjs`, `src/label.mjs`, `data/regions.json`)
**Companion:** [`runtime-guard.technical.md`](runtime-guard.technical.md)

---

## 1. One-paragraph statement

`polycheck guard` is a Claude Code **hook** that evaluates each tool call against the
session's *accumulated* effect state rather than against the call in isolation. It
answers a question no per-call screen can: *does this call complete a forbidden
composition, given what this session has already done?* When the answer is yes, the
guard raises a gate and attaches the concrete path that got here. When the answer is
no, the guard **stands aside** — the existing permission rules and the auto-mode
classifier decide exactly as they do today.

### 1.1 The output space — a decision, not a reversal

**The guard never emits `allow`.** Its decision space is:

| output | meaning |
|---|---|
| `ask` | this call completes a forbidden region — gate it, with a witness |
| `deny` | a region configured as hard-blocked |
| **passthrough** | the guard has no objection; emit no decision and let rules + classifier resolve normally |

This is the central design constraint, and it is deliberate: **the guard reinforces
the classifier, it never overrides it.** A `PreToolUse` `allow` short-circuits the
permission system, which would make polycheck's labeler the weakest link in a stack
users believe is layered. We do not take that trade.

### 1.2 What this constraint buys

Everything downstream simplifies, and the trust story gets much stronger:

- **The guard cannot widen anything.** Adding friction is monotone. Under-labeling
  a call now causes a *missed extra gate*, not a bypass — degradation is to today's
  behaviour, which is the only acceptable failure mode for code in the critical path.
- **Fail-closed is trivial** rather than a property to defend: every failure path is
  already `ask` or passthrough.
- **It is safe to install by default**, which is worth more than any prompt-count win.

### 1.3 What it costs — stated plainly

**Prompt volume does not go down.** The earlier framing ("fewer, better prompts") is
withdrawn; only the second half survives. Approval burden is reduced by making each
decision *faster and better-informed*, not less frequent.

The one thing that keeps the increase small: **guard `ask` and a classifier prompt
for the same call resolve to one prompt, not two** — the guard supplies the reason
text on a gate the user was already going to see. So:

```
prompts(with guard) = prompts(today) ∪ {calls that complete a region}
```

A **union, not a sum**. The added prompts are exactly the region-completing calls
that would otherwise have fired silently — the set the whole project exists to
surface. That number is measured and reported (§8, A1), not assumed small.

---

## 2. Why this is a separate product from `polycheck`

The linter's trust story is *"changes no behavior, so there is nothing to integrate
and nothing to trust at runtime"* (README). The guard sits in the critical path of
every tool call and therefore forfeits that claim. It ships as a distinct, opt-in
binary with its own trust story. **`polycheck` must remain installable and runnable
without ever activating the guard.**

| | `polycheck` (linter) | `polycheck guard` |
|---|---|---|
| lifecycle | deploy time, before an agent exists | runtime, per tool call |
| input | the *policy* (what could ever happen) | the *session* (what has happened) |
| effect basis | worst-case union over all grants | actual accumulated state |
| output | PROOF / WITNESS artifact | allow / ask / deny + witness |
| in critical path | no | **yes** |
| can widen permissions | no | **no** — output is `ask`/`deny`/passthrough only |
| model call | none | **none** (preserved) |

Both halves share one label pack and one region pack. That is the point: the thing
you proved at deploy time is the thing enforced at runtime.

---

## 3. Goals

- **G1 — Add the gate that is structurally missing.** A composition of individually-
  benign calls passes every per-action screen. The guard raises a gate at the
  completing step and nowhere else. It removes no gate, ever.
- **G2 — Make the human decision cheap.** Every prompt the guard raises carries a
  numbered path: which prior calls contributed which effects, and what this call
  adds. Approval burden is attacked through *decision cost*, not prompt count — the
  user should be able to answer in one read instead of reconstructing the session.
- **G3 — Catch the compositional hazard the linter can only warn about.** A repo
  that lints `BYPASS` today gets no runtime protection. The guard makes the witness
  actionable at the moment the last step fires.
- **G4 — Extend the effect universe to irreversibility**, conditioned on provenance
  — `rm -rf build/` in a clean session vs. the same command after untrusted ingest.
- **G5 — Close the subagent-taint gap** named in the linter's limitations.
- **G6 — Stay deterministic.** No model call, no network, no clock in the decision
  path. Same ledger + same call ⇒ same decision, replayable offline.

## 4. Non-goals

- **N1** — Not a prompt-injection / content classifier. Only tool-mediated control
  flow is modeled, as in the linter.
- **N2** — Not a replacement for, or an override of, auto mode. Auto mode catches the
  *novel dangerous command*; the guard catches the *declared composition*. They stack
  strictly additively — §1.1 makes weakening the classifier structurally impossible,
  not merely discouraged.
- **N3** — Not confinement. Anything outside the tool interface is invisible.
- **N4** — Not a data-loss-prevention product. The guard reasons over effect
  classes, not over payload contents.
- **N5** — v1 does not attempt to be correct for adversarially-obfuscated shell
  (`eval "$(printf ...)"`). It fails *loud*: unparseable is worst-case, not benign.

---

## 5. Core concepts (user-facing vocabulary)

### 5.1 The session ledger
A per-session record of the **effects the session holds**, each with the call that
contributed it. Effects are monotone — once held, held for the session — matching
the linter's model exactly.

### 5.2 Effect classes
The existing three, plus one new class:

| effect | meaning |
|---|---|
| `untrusted` | session holds externally-influenceable content |
| `sensitive` | session has read secret material |
| `egress` | session has an outbound channel live |
| **`irreversible`** | **this call performs an action with no undo** — destructive delete, force-push, published send, spend, schema drop |

`irreversible` is *not* accumulated in the same sense as the others: it is a
property of the call being requested. It participates in regions as a "this call
would add it" term. (Technical spec §4.3 makes this precise.)

### 5.3 Effect basis: `capability` vs `observed`
An effect can be held on two grounds:

- **capability** — the call *could* have produced it (`Read(config/*.yaml)` could
  reach a secret). Conservative; matches the linter.
- **observed** — the call *did* produce it (the bytes returned matched a credential
  shape). Precise; requires the call to have completed.

Both are monotone and append-only; **an effect is never retracted.** The guard is
configured to evaluate regions against one basis:

- `basis: capability` — strictest. The session holds `sensitive` as soon as it reads
  a path that *could* be a secret. Default for headless/CI.
- `basis: observed` — the session holds `sensitive` only once returned bytes matched
  a credential shape. Default for interactive sessions.

Because the guard cannot emit `allow`, the basis controls **how many gates the guard
adds**, never how many it removes. `capability` adds more; `observed` adds fewer and
depends on detection patterns that can miss. Both are stated, not hidden — and both
degrade to today's behaviour, not below it.

### 5.4 Regions at runtime
The same `data/regions.json` shape, plus a runtime region pack adding:

```jsonc
{ "name": "injected-destruction", "kind": "safety",
  "requires": ["untrusted", "irreversible"],
  "gloss": "an irreversible action requested while the session holds attacker-influenceable content." }
```

Regions carry a runtime `action`: `ask` (default) or `deny`.

### 5.5 Approval scope
When a human approves a region-completing call, the guard records a **scoped
grant** — `(region, effect, providerKey)` — so the *same* channel does not re-prompt
for the rest of the session, while a *different* channel does. `providerKey` is the
tool plus a normalized target (network host, or repo remote, or `*`). Approving
`curl → api.example.com` does not silently approve `curl → attacker.example`.

---

## 6. Behaviour

### 6.1 The decision, in words
For a requested call, the guard computes the effects it would add, then for each
region asks:

1. **Would this call complete the region** (region not already satisfied; satisfied
   after)? → the region's action (`ask` by default), with a witness.
2. **Is the region already entered, and does this call exercise a required effect
   through a provider not covered by an existing scoped grant?** → `ask`, with the
   witness plus "you previously approved a different channel."
3. Otherwise → **passthrough**: the ledger is updated and no decision is emitted.
   Rules and the classifier resolve the call exactly as they do without the guard.

Passthrough is silent. There is no "polycheck reviewed 47 calls" noise.

### 6.2 What a prompt looks like

When the guard gates a call the classifier would also have prompted for, this text
*decorates* that single prompt rather than adding a second one.

```
polycheck guard · completes region 'credential-egress'

    1  Read(~/.aws/credentials)      →  +sensitive      [step 12, observed]
    2  curl -X POST https://hooks.example.com/…  →  +egress   ← THIS CALL

  the session holds readable secrets and this call opens an outbound channel.
  approving grants: egress via curl→hooks.example.com, for this session only.

  [a] approve this channel   [d] deny   [s] show full ledger
```

### 6.3 The pre-warning
A call that brings the session to **one effect short** of a region does not prompt,
but emits a one-line notice:

```
polycheck guard · this session now holds untrusted+egress. A read of a secret
path will be gated (region 'lethal-trifecta').
```

This is the property that makes the eventual prompt legible rather than surprising:
the user has already seen the state build.

### 6.4 Session lifecycle
- **New session** (`SessionStart` source `startup` / `clear`) → empty ledger.
- **Resume** (`source: resume`) → the ledger is restored; context survived, so
  effects survived. A resumed session does not launder its taint.
- **Compaction** → ledger untouched. Compaction shortens the transcript; it does
  not un-read a secret.
- **Subagent spawn** (`Task`) → child ledger seeded with the parent's held effects.
  Child effects propagate back on subagent completion.

### 6.5 Failure behaviour — fail closed
If the guard crashes, times out, cannot parse a call, or cannot read its ledger, it
returns **`ask`**, never `allow`. A broken guard degrades to today's behaviour; it
never silently widens. A guard that is *not installed* changes nothing.

---

## 7. Commands and configuration

### 7.1 CLI

```
polycheck guard init [path]     write the hook wiring into .claude/settings.json,
                                after running the linter and reporting what it found
polycheck guard status          the current session ledger: effects held, provenance,
                                which regions are one step away, scoped grants issued
polycheck guard explain <call>  dry-run a call against the current ledger; prints the
                                decision and the witness without executing anything
polycheck guard replay <log>    re-decide a recorded call log offline; deterministic,
                                used for testing and for post-incident review
polycheck guard reset           clear the current session ledger (logged, never silent)
polycheck guard off             remove the hook wiring
```

`guard init` deliberately runs the linter first: if the repo lints `PROOF`, the
guard says so and offers a minimal ledger that tracks only effects appearing in a
reachable region — the deploy-time analysis pays for the runtime cost.

### 7.2 Config (`.claude/polycheck.guard.json`)

```jsonc
{
  "basis": "observed",            // "capability" | "observed"
  "regions": "./guard-regions.json",   // defaults to the shipped runtime pack
  "labels":  "./guard-labels.json",    // defaults to the shipped runtime pack
  "onComplete": { "lethal-trifecta": "ask", "credential-egress": "ask",
                  "injected-destruction": "ask", "unrecoverable": "ask" },
  "prewarn": true,
  "scopeApprovalsByHost": true,
  "failOpen": false               // MUST be false; a true here is refused with a warning
}
```

### 7.3 Interaction with permissions and auto mode

**One rule, from which everything else follows: the guard's output is `ask`, `deny`,
or passthrough. Never `allow`.**

Consequences, all structural rather than enforced by care:

- The guard cannot soften a written `ask` or `deny` — it has no vocabulary for it.
- The guard cannot short-circuit the auto-mode classifier. A passthrough leaves the
  classifier's decision untouched; an `ask` cannot make a classifier `deny` weaker.
- The guard is not a privilege-escalation vector against the policy the linter
  analyses, so no rule-matching precision is required to *preserve* safety. (Rule
  matching is still needed to avoid *duplicating* a prompt the rules already raise —
  a UX concern, not a safety one, which is the right place for it to live.)
- A labeler bug degrades to today's behaviour in one direction and to an unnecessary
  prompt in the other. There is no third direction.

The guard therefore has no configuration that can make a session *more* permissive
than it is without the guard installed. `guard init` states this in one line, and
`guard off` is a clean revert.

---

## 8. Acceptance criteria

**A1 — Added prompt volume is measured and small.** `guard replay` over a corpus of
recorded real sessions reports: prompts today, prompts under the guard, and the
*added* set broken down as (a) region-completing calls that would have fired
silently — the intended additions — and (b) everything else, which is labeler noise
and must trend to zero. Ship both numbers. A high (b) is a defect, not a tuning
knob. Target: (b) ≤ 1 per 500 calls at M1.

**A1b — Prompts are not duplicated.** For a call the rules or classifier would
already prompt for, the guard's gate resolves to a single prompt carrying the
witness, not a second prompt. Asserted by replay against recorded sessions.

**A2 — The composition is caught.** For each linter fixture that yields `BYPASS`
(`test/fixtures/vulnerable`, `webfetch-egress`, `mcp-egress`, …), a replayed session
that walks the witness must be gated at the completing step, and only there.

**A3 — No widening, structurally.** A test asserts the guard's emitted decision is
always one of `ask`, `deny`, or passthrough (empty), over every fixture, every fault
injection, and every fuzzed input. `allow` must be unreachable from the code — not
merely unused. This replaces the earlier property test about safe `allow`s, which no
longer has a subject.

**A4 — Determinism.** Same ledger + same call ⇒ byte-identical decision record.
Replay of a log reproduces every decision exactly.

**A5 — Latency, as a marginal budget.** The guard adds **≤ 15 ms above the host's
node cold-start floor**, and pays no cost at all on calls filtered out before the
hook process spawns. An absolute p95 is not something the guard can promise: WP0
measured a 780 ms node cold start on a Windows machine with McAfee installed, 20×
the cost of spawning `git`. That floor is the host's, not the design's. Measured
marginal cost is ~5 ms. See [`WP0-findings.md`](WP0-findings.md).

**A6 — Fail-closed under fault injection.** Corrupt ledger, unwritable state dir,
malformed hook input, and forced exception each yield `ask` and a diagnostic.

---

## 9. What this does NOT establish

Printed by `guard status` and by `guard init`, in the linter's tradition:

- **The runtime labeler is a trust obligation, larger than the linter's.** The
  linter labels *rules*; the guard labels *invocations* — pipes, substitutions,
  env-var indirection. A mislabeled invocation is a gate the ledger fails to raise.
  It is **not** a hole in anything you had before: the call still faces the rules
  and the classifier. The guard is a second layer whose failure mode is "absent,"
  never "permissive."
- **`ask` is still a human.** Reducing prompt count raises the value of each
  remaining prompt; it does not make a human correct.
- **Effects entering context outside the tool interface are invisible** — a pasted
  page, a `CLAUDE.md`, an MCP resource read the guard does not observe. The ledger
  under-approximates taint by construction.
- **The guard is in the critical path.** It is code that runs on every call. Its
  own failure modes are part of your threat model now; §6.5 is why they are
  survivable, not why they are absent.
- **Scoped approvals trade safety for quiet.** A host-scoped grant means a second
  call to an approved host is not re-shown. That is a deliberate, stated trade.

---

## 10. Milestones

| | scope | exit criterion |
|---|---|---|
| **M0** | `PreToolUse` hook, ledger, `capability` basis, existing 3 effects, `Bash`/`Read`/`WebFetch`/MCP labeling, `gateKind: 'guard'` in the linter, fail-closed | A2 + A3 pass for the `vulnerable` and `webfetch-egress` fixtures |
| **M1** | `PostToolUse` evidence, `observed` basis, pre-warning, scoped approvals, `guard status`/`explain` | A1/A1b measured on a real session corpus; added-noise (b) ≤ 1 per 500 calls |
| **M2** | `irreversible` effect + `injected-destruction` region, `unrecoverable` always-ask tier | A2 extended; destructive fixtures added |
| **M3** | Subagent taint propagation, `guard replay`, `guard init` coupled to the linter verdict | G5 closed; README limitation retired |
