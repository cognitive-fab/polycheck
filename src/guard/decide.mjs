// polycheck guard — the decision engine.
//
// The linter BFSes the reachable state graph because it does not know which
// actions will fire. The guard knows: one call, one known held mask. So the
// runtime decision is a bitmask test over the regions, O(regions), and
// src/check.mjs stays a deploy-time engine.
//
// decision ∈ {'ask', 'deny', null}. There is deliberately no 'allow' branch
// anywhere in this file — see src/guard/emit.mjs for why that is load-bearing.

import { heldEffects, coveredByGrant } from './ledger.mjs';
import { renderWitness, renderPrewarn } from './witness.mjs';

// Effects are monotone within a session, so a state is a subset of the effect
// universe — exactly the representation src/check.mjs uses.
export function buildBits(regions) {
  const universe = [...new Set(regions.flatMap((r) => r.requires))].sort();
  const bit = {};
  universe.forEach((e, i) => { bit[e] = 1 << i; });
  const mask = (effects) => [...effects].reduce((m, e) => m | (bit[e] ?? 0), 0);
  return { universe, bit, mask };
}

const popcount = (n) => { let c = 0; while (n) { n &= n - 1; c++; } return c; };

/**
 * @param {object} args
 *  - ledger    the session ledger
 *  - labelled  result of labelCall()
 *  - regions   [{name, requires, gloss, action}]
 *  - call      {tool, target, providerKey}
 *  - policy    {alreadyGates(call) -> bool}   reporting only, never the decision
 *  - basis     'capability' | 'observed'
 * @returns {{decision, region?, reason?, prewarn?, decorates?, adds:string[]}}
 */
export function decide({ ledger, labelled, regions, call, policy = null, basis = null }) {
  const useBasis = basis || ledger.basis || 'capability';
  const { mask } = buildBits(regions);

  const adds = [...labelled.effects.keys()].sort();
  const uncertain = [...labelled.effects.values()].some((v) => v.certainty === 'worst-case');

  const held = heldEffects(ledger, useBasis);
  const H = mask(held);
  const E = mask(adds);
  const after = H | E;

  const callInfo = { ...call, effects: adds, providerKey: labelled.providerKey, uncertain };

  // Every region this call leaves us INSIDE, not just the first one that fires.
  // The regions overlap (credential-egress ⊂ lethal-trifecta), so a single call
  // can complete several at once; an approval covers the call, and therefore all
  // of them. Granting only the reported region left the others permanently
  // un-granted, which re-prompted the same channel on every subsequent call.
  const satisfiedAfter = regions
    .filter((r) => { const M = mask(r.requires); return M && (after & M) === M; })
    .map((r) => r.name);

  // A quarantined ledger cannot be reasoned over: held effects may be missing.
  // Everything effect-bearing asks, for the rest of the session (ledger I4).
  if (ledger.stickyAsk && adds.length) {
    return {
      decision: 'ask',
      adds,
      satisfiedAfter: [],
      reason: `polycheck guard · the session ledger could not be trusted (${ledger.stickyReason}),`
            + ` so accumulated state is unknown and every effect-bearing call is gated for the rest of this session.`
            + `\n  This is the guard failing safe, not a finding about your policy.`,
    };
  }

  for (const region of regions) {
    const M = mask(region.requires);
    if (!M) continue; // a region naming effects outside the universe cannot fire
    const wasIn = (H & M) === M;
    const nowIn = (after & M) === M;
    const action = region.action || 'ask';

    // (a) this call COMPLETES the region — the case a per-action screen cannot see
    if (!wasIn && nowIn) {
      return {
        decision: action,
        region,
        adds,
        satisfiedAfter,
        // Reporting only (functional A1b): whether we are decorating a prompt
        // that was already going to happen, or adding one. Never consulted
        // before this branch — a region-completing call is gated either way.
        decorates: policy ? !!policy.alreadyGates(call) : undefined,
        reason: renderWitness(region, ledger, callInfo, { basis: useBasis }),
      };
    }

    // (b) already inside the region, and this call exercises a required effect
    // through a channel no prior approval covered
    if (wasIn && (E & M) !== 0 && !coveredByGrant(ledger, region.name, labelled.providerKey)) {
      return {
        decision: action,
        region,
        adds,
        satisfiedAfter,
        decorates: policy ? !!policy.alreadyGates(call) : undefined,
        reason: renderWitness(region, ledger, callInfo, {
          basis: useBasis,
          note: 'a different channel was approved earlier in this session; this one was not.',
        }),
      };
    }
  }

  // Passthrough. The rules and the auto-mode classifier decide, exactly as they
  // would with no guard installed.
  const oneShort = regions.filter((r) => {
    const M = mask(r.requires);
    return M && popcount(M & ~after) === 1;
  });
  return {
    decision: null,
    adds,
    satisfiedAfter,
    prewarn: oneShort.length ? renderPrewarn(oneShort, new Set([...held, ...adds])) : null,
  };
}

/** Regions with a runtime action attached, from data/regions.json + config. */
export function runtimeRegions(regionsFile, config = {}) {
  const onComplete = config.onComplete || {};
  return (regionsFile.regions || []).map((r) => ({ ...r, action: onComplete[r.name] || 'ask' }));
}
