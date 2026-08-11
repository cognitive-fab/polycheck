// polycheck checker — the reachability analysis behind the linter. Exhaustive BFS
// over the reachable states of the accumulated-taint machine, via a
// gate-deletion check: DELETE the gates, then ask whether a forbidden region is
// still reachable. If it is, the shortest path is a WITNESS — a bypass nobody
// mediated. If it is not, either every path crosses a gate (a real proof) or a
// required effect has no provider at all (a VACUOUS pass — coverage, not
// mediation; absent evidence is unobserved, never reported as clean).
//
// Deterministic, finite, offline, $0. Effects are monotone (a taint, once held,
// persists within a session), so a state is a subset of the effect universe and
// BFS discovery order gives the shortest witness for free.

function effectUniverse(model) {
  const set = new Set();
  for (const r of model.regions) for (const e of r.requires) set.add(e);
  for (const a of model.actions) for (const e of a.effects) set.add(e);
  return [...set];
}

// Explore the reachable state graph under a given action list. Returns the set
// of reachable masks and a parent map for shortest-path reconstruction.
function explore(actions, bit) {
  const start = 0;
  const parent = new Map([[start, null]]);
  const depth = new Map([[start, 0]]);
  const queue = [start];
  while (queue.length) {
    const s = queue.shift();
    for (const a of actions) {
      let ns = s;
      for (const e of a.effects) ns |= bit[e];
      if (ns === s) continue; // adds nothing new from here
      if (!parent.has(ns)) {
        parent.set(ns, { prev: s, action: a });
        depth.set(ns, depth.get(s) + 1);
        queue.push(ns);
      }
    }
  }
  return { reachable: [...parent.keys()], parent, depth };
}

function reconstruct(parent, target, bit) {
  const steps = [];
  let cur = target;
  while (parent.get(cur)) {
    const { prev, action } = parent.get(cur);
    steps.push({ action, stateAfter: cur });
    cur = prev;
  }
  steps.reverse();
  // annotate each step with which effects it newly contributed
  let running = 0;
  for (const st of steps) {
    const before = running;
    for (const e of st.action.effects) running |= bit[e];
    st.added = Object.keys(bit).filter((e) => (running & bit[e]) && !(before & bit[e]));
    st.held = Object.keys(bit).filter((e) => running & bit[e]);
  }
  return steps;
}

export function modelCheck(model) {
  const universe = effectUniverse(model);
  const bit = {};
  universe.forEach((e, i) => { bit[e] = 1 << i; });

  const UNVERIFIED = new Set(['hook', 'assumed']);

  // 'guard' is polycheck's OWN PreToolUse hook, and unlike an arbitrary hook we
  // can stand behind it — but ONLY for the regions it is configured to gate. The
  // soundness argument (spec/runtime-guard.technical.md §2.0): the guard's
  // decision union is ask|deny|passthrough, so it can only ADD a gate, and it
  // gates every call that completes one of its configured regions. For any OTHER
  // region it is exactly as unverified as any other hook, so verification is a
  // per-region question, not a per-action one.
  const isUnverifiedFor = (a, region) => {
    if (UNVERIFIED.has(a.gateKind)) return true;
    if (a.gateKind === 'guard') return !(a.gateRegions || []).includes(region.name);
    return false;
  };

  const ungated = model.actions.filter((a) => a.gateKind == null);  // no gate at all
  const all = model.actions;                                        // deny already excluded upstream

  const exUngated = explore(ungated, bit);
  const exAll = explore(all, bit);

  const findSatisfying = (ex, reqMask) => {
    let best = null;
    for (const s of ex.reachable) {
      if ((s & reqMask) === reqMask) {
        if (best == null || ex.depth.get(s) < ex.depth.get(best)) best = s;
      }
    }
    return best;
  };

  const label = (a) => `${a.tool}${a.specifier != null ? `(${a.specifier})` : ''}`;
  // N2: a fix never proposes gating an edge the user did not write — neither an
  // assume-defaults injection nor a polycheck-synthesized 'assumed' gate.
  const userWritten = (a) => a.source !== 'default (auto-allowed)' && a.gateKind !== 'assumed';

  // The minimal edit that closes a region. Rank effects egress > untrusted >
  // sensitive (gate the network reach first), and only ever propose gating
  // rules the USER wrote — an assumed default may appear in a witness, never in
  // a fix.
  const PRIORITY = ['egress', 'untrusted', 'sensitive'];
  const rank = (e) => { const i = PRIORITY.indexOf(e); return i < 0 ? 99 : i; };
  const minGate = (region) => {
    const cands = region.requires
      .map((e) => ({ effect: e, providers: ungated.filter((a) => a.effects.includes(e) && userWritten(a)) }))
      .filter((c) => c.providers.length > 0)
      .sort((a, b) => rank(a.effect) - rank(b.effect));
    return cands[0] || null;
  };

  const shellGrants = [...new Set(ungated.filter((a) => a.tag === 'shell').map(label))];

  // Shell grants split by WHY they are worst-case, because the fix differs and
  // the generic advice ("narrow each to fixed arguments") is already satisfied
  // for two of the four kinds. Telling someone to do what they have already done
  // reads as "your policy is fine" — the one thing this report must never imply.
  const shellByReason = {};
  for (const a of ungated.filter((x) => x.tag === 'shell')) {
    const k = a.shellReason || 'interpreter-prefix';
    (shellByReason[k] ||= []).push({ label: label(a), scriptPath: a.scriptPath || null });
  }
  // An exact interpreter invocation is bounded in its ARGUMENTS. It is unbounded
  // in its CODE precisely when this same policy grants ungated writes to the repo.
  // polycheck does not resolve the script's imports (it reads policy, not source),
  // so this is a coupling it NAMES rather than proves.
  const writableCode = shellByReason['writable-code']?.length
    ? { grants: shellByReason['writable-code'], writers: model.ungatedWriters || [] }
    : null;

  const exploreCache = new Map();

  const results = model.regions.map((region) => {
    const reqMask = region.requires.reduce((m, e) => m | (bit[e] ?? 0), 0);

    const bypassState = findSatisfying(exUngated, reqMask);
    if (bypassState != null) {
      const witness = reconstruct(exUngated.parent, bypassState, bit);
      // A one-step path whose single action runs caller-chosen code is not a
      // composition — it's "you granted a shell". Report it as its own class.
      if (witness.length === 1 && witness[0].action.tag === 'shell') {
        return { region, status: 'SHELL-EQUIVALENT', witness, fix: { kind: 'shell', actions: shellGrants } };
      }
      const g = minGate(region);
      return {
        region, status: 'BYPASS', witness,
        fix: g ? { kind: 'gate', effect: g.effect, actions: [...new Set(g.providers.map(label))] } : null,
      };
    }

    // Not reachable ungated. Is the only thing standing in the way an UNVERIFIED
    // gate — a PreToolUse hook (logic we cannot read), an 'assumed' MCP prompt
    // polycheck synthesized, or a polycheck guard NOT configured for this region?
    // Then it is not a proof; we cannot confirm it blocks.
    // Region-dependent, so it cannot be hoisted out of the loop — but two
    // regions that admit the same action set share an exploration. Keyed on the
    // included-index signature so the BFS runs once per DISTINCT set rather than
    // once per region.
    const passable = model.actions.filter((a) => a.gateKind == null || isUnverifiedFor(a, region));
    const key = passable.map((a) => model.actions.indexOf(a)).join(',');
    let exUnverified = exploreCache.get(key);
    if (!exUnverified) { exUnverified = explore(passable, bit); exploreCache.set(key, exUnverified); }
    const unverState = findSatisfying(exUnverified, reqMask);
    if (unverState != null) {
      const witness = reconstruct(exUnverified.parent, unverState, bit);
      const kinds = [...new Set(witness.map((st) => st.action.gateKind).filter((k) => k != null && (UNVERIFIED.has(k) || k === 'guard')))];
      const unverifiedGates = [...new Set(witness.filter((st) => isUnverifiedFor(st.action, region)).map((st) => st.action.gateReason).filter(Boolean))];
      return { region, status: 'INCONCLUSIVE', reason: kinds.join('+') || 'unverified', witness, unverifiedGates };
    }

    // Every path crosses a VERIFIED gate ('ask').
    const mediatedState = findSatisfying(exAll, reqMask);
    if (mediatedState != null) {
      // A guard configured for THIS region mediates it exactly as an 'ask' does.
      const mediates = (a) => a.gateKind === 'ask' || (a.gateKind === 'guard' && (a.gateRegions || []).includes(region.name));
      const mediators = all.filter((a) => mediates(a) && a.effects.some((e) => region.requires.includes(e)));
      return { region, status: 'PROOF', mediated: true, mediators };
    }

    // Unreachable. Distinguish "you DENIED the only provider of a required
    // effect" (PROOF by denial — the strongest control) from "you never had a
    // tool for it" (a coverage gap — INCONCLUSIVE). Dropping denies made these
    // look identical; they are not.
    const missing = region.requires.filter((e) => !all.some((a) => a.effects.includes(e)));
    if (missing.length) {
      // PROOF-by-denial only when a deny SUPPRESSED a would-be edge for a missing
      // effect — not merely because a deny rule names a tool. Denying a tool the
      // user never granted closes nothing and must not earn a green verdict.
      const suppressors = (e) => (model.suppressedByDeny || []).filter((s) => s.effects.includes(e));
      const deniedEffects = missing.filter((e) => suppressors(e).length > 0);
      if (deniedEffects.length) {
        const denials = [...new Set(deniedEffects.flatMap((e) => suppressors(e).map(label)))];
        return { region, status: 'PROOF', mediated: true, reason: 'denial', denials, deniedEffects };
      }
      return { region, status: 'VACUOUS', reason: 'coverage', mediated: false, missingEffects: missing };
    }
    return { region, status: 'PROOF', mediated: false };
  });

  return { universe, results, actionCount: model.actions.length, ungatedCount: ungated.length, shellGrants, shellByReason, writableCode };
}
