// polycheck guard — witness rendering.
//
// The linter's witness is a path through the POLICY's reachable states. This one
// is a path through what the session actually did: the step that first
// contributed each required effect, then the call being requested. Same object,
// different provenance — that correspondence is what WP6 asserts.
//
// The text goes into permissionDecisionReason, which WP0 confirmed renders
// multi-line in the prompt. Keep it short enough to read at a glance under time
// pressure: a witness nobody reads is worth nothing.

import { firstContributors } from './ledger.mjs';

const MAX_TARGET = 58;
const short = (s) => {
  const t = String(s ?? '');
  return t.length <= MAX_TARGET ? t : t.slice(0, MAX_TARGET - 1) + '…';
};

/**
 * Build the prompt text for a call that completes `region`.
 *
 * @param {object} region  {name, requires, gloss}
 * @param {object} ledger
 * @param {object} call    {tool, target, effects: string[], providerKey}
 * @param {object} opts    {basis, note}
 */
export function renderWitness(region, ledger, call, opts = {}) {
  const basis = opts.basis || ledger.basis || 'capability';
  const contributedNow = new Set(call.effects || []);
  const priorEffects = region.requires.filter((e) => !contributedNow.has(e));
  const origins = firstContributors(ledger, priorEffects, basis);

  // Order the prior steps as they happened, so the path reads forward in time.
  const priorSteps = [...new Set([...origins.values()])].sort((a, b) => a.n - b.n);

  const lines = [];
  lines.push(`polycheck guard · this call completes '${region.name}'`);
  lines.push('');

  let i = 1;
  for (const st of priorSteps) {
    const adds = (st.adds?.[basis] || []).filter((e) => region.requires.includes(e));
    lines.push(`  ${i}. ${st.tool}${st.target ? `  ${short(st.target)}` : ''}`);
    lines.push(`     → +${adds.join(' +')}   [step ${st.n}]`);
    i++;
  }
  const nowAdds = region.requires.filter((e) => contributedNow.has(e));
  lines.push(`  ${i}. ${call.tool}${call.target ? `  ${short(call.target)}` : ''}`);
  lines.push(`     → +${nowAdds.join(' +')}   ← THIS CALL`);
  lines.push('');

  if (region.gloss) lines.push(`  ${region.gloss}`);
  if (opts.note) lines.push(`  note: ${opts.note}`);

  // Say what approving means, in the scope it actually has. An approval that
  // silently covers more than the user thinks is the failure mode that makes
  // "approval fatigue" a security problem rather than an annoyance.
  if (call.providerKey && !call.providerKey.endsWith('→*')) {
    lines.push(`  approving grants: ${call.providerKey}, for this session only.`);
  } else {
    lines.push('  the target could not be parsed, so approving grants nothing beyond this call.');
  }

  // Never let a witness imply more certainty than the labels carry.
  if (call.uncertain) {
    lines.push('  (one or more effects were assumed worst-case — see `polycheck guard status`.)');
  }
  return lines.join('\n');
}

/** The non-blocking heads-up for a session one effect short of a region. */
export function renderPrewarn(regions, held) {
  if (!regions.length) return null;
  const r = regions[0];
  const missing = r.requires.filter((e) => !held.has(e));
  return `polycheck guard · this session now holds ${[...held].join('+')}. `
       + `A call adding '${missing[0]}' will be gated (region '${r.name}').`;
}
