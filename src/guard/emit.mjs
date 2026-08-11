// polycheck guard — the ONLY writer of a hook decision.
//
// The decision union is closed at `'ask' | 'deny' | null`, and `null` renders as
// `{}` — passthrough, verified in WP0 to leave the call to its normal rules +
// auto-mode resolution.
//
// There is deliberately no code path here that can produce the string 'allow'.
// That is not a style choice: the `gateKind: 'guard'` VERIFIED-gate status in
// spec/runtime-guard.technical.md §2.0 rests on the guard being unable to remove
// a gate. If this union ever widens, that status must be withdrawn in the same
// change — and test/guard.test.mjs asserts the union so the two cannot drift.

import { COMPAT } from './compat.mjs';

const ALLOWED = new Set(COMPAT.DECISIONS); // ['ask','deny']

/**
 * Render a decision to the hook's stdout payload.
 * @param {'ask'|'deny'|null} decision
 * @param {string} [reason]
 * @returns {string} JSON to write to stdout
 */
export function renderDecision(decision, reason) {
  if (decision == null) return COMPAT.PASSTHROUGH; // '{}'
  if (!ALLOWED.has(decision)) {
    // An out-of-union decision is a programming error. Fail to the safest thing
    // we are allowed to say rather than passing it through — a decision we do
    // not understand must not become silence.
    return JSON.stringify({
      hookSpecificOutput: {
        hookEventName: COMPAT.events.preToolUse,
        permissionDecision: 'ask',
        permissionDecisionReason: `polycheck guard: internal error — unknown decision '${decision}'. Gating conservatively.`,
      },
    });
  }
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: COMPAT.events.preToolUse,
      permissionDecision: decision,
      permissionDecisionReason: reason || 'polycheck guard',
    },
  });
}

// The single exit point. Always exit 0: a non-zero exit means "could not emit a
// decision at all", which the host treats as blocking, and we always can.
export function emit(decision, reason, out = process.stdout) {
  out.write(renderDecision(decision, reason));
  return 0;
}

// Fail-closed wrapper. Any throw, anywhere, becomes an 'ask' with the reason
// stated. Passthrough would also be SAFE here (the classifier still runs), but
// we choose 'ask' so a malfunctioning guard is visible rather than silently
// absent — an invisible failure is how a security tool rots.
export function failClosed(err, out = process.stdout, errOut = process.stderr) {
  try { errOut.write(`polycheck guard: ${err?.stack || err}\n`); } catch { /* ignore */ }
  return emit('ask', `polycheck guard could not evaluate this call (${String(err?.message || err).slice(0, 200)}). Gating conservatively — this is the guard failing, not a finding about your policy.`, out);
}
