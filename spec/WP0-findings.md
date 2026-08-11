# WP0 findings — compat spike

**Measured:** 2026-08-10, Claude Code on Windows 11 native, node v24.12.0.
**Raw evidence:** `experiments/guard-compat/capture/hook-payloads.jsonl` (gitignored).
**Pinned into:** `src/guard/compat.mjs`.

---

## Q2 — Does `{}` pass through? **YES. Kill criterion cleared.**

21 live `PreToolUse` invocations returned `{}` (no `permissionDecision`). Every
call proceeded to its normal rules + auto-mode resolution; none were blocked,
altered, or delayed beyond the hook's own cost. **The guard's entire "reinforce,
never override" mechanism is implementable as specified.**

Also confirmed: hooks **hot-reload**. The probe began capturing without a session
restart, so `guard init` does not need to tell the user to restart.

---

## Q1 — Payload shape

Fields observed on every event: `session_id`, `transcript_path`, `cwd`,
`hook_event_name`, `tool_name`, `tool_input`.

Present on tool events raised inside a prompt turn but **absent on some earlier
records**, so all must be treated as optional: `prompt_id`, `permission_mode`,
`effort`, `tool_use_id`.

Per-event additions:
- `PostToolUse` → `tool_response`, `duration_ms`
- `PermissionRequest` → `permission_suggestions`

`tool_input` shapes: `Bash` → `{command, description}`; `Edit` →
`{file_path, old_string, new_string, replace_all}`.
`tool_response` shapes: `Bash` → `{stdout, stderr, interrupted, isImage,
noOutputExpected}` — M1's evidence pass has what it needs.

`session_id` was stable across the whole session (open question 2 partially
answered; compaction and `--resume` still untested).

---

## Three discoveries that change the design

### 1. `PermissionRequest` exists, and is the right decoration point

A `PermissionRequest` event fires when a permission decision is being sought, and
carries `permission_suggestions` (`addRules` / `behavior: allow` / `destination:
localSettings`). This is a **better** home for A1b than the spec assumed: rather
than the guard raising its own `ask` and relying on it merging with an existing
prompt, it can attach its witness to a prompt that is already happening.

**Action:** M1 should evaluate `PermissionRequest` as the witness-rendering
surface, with `PreToolUse` `ask` reserved for calls that would *not* otherwise
prompt. That is a cleaner split than one event doing both jobs.

### 2. `if` filters before the process spawns — and that is now load-bearing

Hook entries accept `if` in permission-rule syntax (`"Bash(echo WP0-ASK-TEST*)"`),
verified firing selectively. It gates whether the hook process is spawned at all.

Given the latency finding below, this is not an optimization — it is the primary
mitigation. `guard init` should emit `if` filters covering only effect-bearing
tools, so the guard never pays a spawn on a call it would pass through anyway.

### 3. `args` exec form avoids the shell

`{"command": "node", "args": ["C:\\...\\hook.mjs", "pre"]}` spawns directly with
no shell parsing. On Windows this is the difference between working and not.
**`guard init` must use the `args` form**, not a command string. Technical spec §2
shows the string form and needs updating.

---

### 4. The auto-mode classifier is configurable from settings — a whole second integration surface

The settings schema carries an `autoMode` block with `allow`, `soft_deny`,
`hard_deny`, and `environment` arrays, each accepting rule text with a `$defaults`
sentinel to inherit the built-ins. `soft_deny` is described as *destructive /
irreversible actions that user intent can clear*; `hard_deny` as *security
boundaries that user intent does not clear*.

That is a **deploy-time, declarative surface for the classifier itself** — much
closer to polycheck's existing shape than a runtime hook is. A plausible
`polycheck --emit-automode` could compile the repo's policy and label pack into
classifier rules, so the linter strengthens the 89% screen directly without any
code in the critical path.

**Not in M0 scope**, but it may be a cheaper and better-positioned product than the
guard, and it should be evaluated before M1 commits further. Recorded as technical
spec open question 6.

---

## Latency — A5 is not achievable on this machine, and not because of us

| | ms |
|---|---|
| `cmd /c exit` | 20 |
| `git --version` | 40 |
| **`node -e ""`** | **780** |
| probe end-to-end | 840 |
| **guard's own work (parse + decide + record)** | **4.7 (median)** |

Node cold start is ~780 ms here — 20× `git`, and node-specific: process spawn on
this box is otherwise fine. Defender real-time is **off**; **McAfee is installed**
and is the likely cause (`node --version`, which executes no JS, costs the same,
so it is load-time not runtime).

**Consequences:**

1. **A5 (p95 ≤ 50 ms) cannot be met by any Node hook on this machine**, guard or
   otherwise. The floor is the host's, not the design's.
2. **A5 must be restated as a marginal budget**: *the guard adds ≤ 15 ms above the
   host's node cold-start floor*. Measured marginal cost today is ~5 ms, so the
   design passes the number it actually controls.
3. **The `if` filter is the real mitigation** — no spawn, no floor, for the
   majority of calls.
4. **The daemon does not help.** A daemon still needs a client process per call,
   and a Node client pays the same 780 ms. A daemon is only worthwhile with a
   non-Node client, which would forfeit the project's zero-dependency posture.
   **Recommendation: drop the daemon from the roadmap** and rely on `if` filters
   plus an AV-exclusion note in the install docs.
5. Re-measure on a clean machine before publishing any latency claim. 780 ms is
   this machine; ~50 ms is the reference figure and it is **not** measured here.

---

## Q3 — ask rendering and A1b: **CONFIRMED**

Three findings, two from timing and one from direct observation.

### A hook `ask` genuinely gates
Timing across two runs of `echo WP0-ASK-TEST …` (the command itself costs ~180 ms):

| run | ask-hook → post-hook gap | reading |
|---|---|---|
| second | 4,106 ms | dialog raised, answered quickly |
| third | 39,390 ms | dialog raised, read carefully |

A multi-second stall around a 180 ms command is human latency. The hook's `ask`
stopped execution and waited for a person — it is a real gate, not advisory.

### `permissionDecisionReason` renders in the dialog — **observed**
The third run's multi-line marker block was displayed in the permission prompt and
confirmed read. **`PreToolUse` `ask` can carry the witness directly**, so functional
§6.2's prompt design stands as specified. `PermissionRequest` (discovery 1) remains
the better surface for *decorating a prompt that was already going to happen*, but
it is no longer required for the witness to reach the user at all.

### A1b holds — union, not sum
The rules and the hook both wanted a gate on the same call, and exactly **one**
`PermissionRequest` fired. One prompt, carrying the hook's reason.

### Event ordering, pinned
```
PreToolUse (every matching hook, in config order)   t+0
PermissionRequest                                   t+~900 ms
  … dialog, human latency …
PostToolUse (carries tool_response + duration_ms)   t+n
```

---

## Spec deltas required

| spec | change |
|---|---|
| technical §2 | install wiring → `args` exec form; add `if` filters |
| technical §2.1 | add `prompt_id`/`permission_mode`/`effort`/`tool_use_id` as optional; add `PermissionRequest` |
| technical §9 | replace the estimate with these numbers; **drop the daemon**; `if` filter becomes the mitigation |
| functional A5 | restate as a marginal budget above the host's node floor |
| functional §6.2 / M1 | evaluate `PermissionRequest` as the witness surface |
| technical §12 Q2 | `session_id` stable within a session; compaction/resume still open |
