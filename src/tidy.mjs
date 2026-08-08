// polycheck tidy — the grant-hygiene pass. A permission list grows one
// yes-in-the-moment at a time and nobody ever reads the running total, so it
// ends up a mixture of rules that matter, rules another rule already covers,
// and rules pinned to a session that will never recur. This module sorts every
// rule into KEEP / DEDUP / PRUNE / MERGE and — the part that makes it polycheck's
// job and not a text linter's — PROVES what the proposed edit does to the blast
// radius before anyone applies it.
//
// The proof is cheap because the underlying machine is monotone and
// unconditional: an action has no precondition, and an effect once held is held
// forever, so the maximal reachable state is exactly the UNION of the effects of
// the available actions. Two rulesets are therefore effect-equivalent iff that
// union agrees — per gate class (ungated / unverified-passable / all) — and every
// region verdict agrees. That is what `proveEdit` checks.
//
// Deliberate scope limit: coverage analysis runs on SHELL tools only
// (Bash/PowerShell/pwsh), where a specifier is a command prefix with
// well-understood matching. Path-glob subsumption (Read/Edit) is NOT inferred —
// a wrong answer there silently deletes a rule someone needs, and this pass is
// only useful if you can apply it without re-reading it. Exact duplicates are
// caught for every tool.

import { buildModel } from './model.mjs';
import { modelCheck } from './check.mjs';
import { isUnrestricted, labelEffects } from './label.mjs';
import { existsSync } from 'node:fs';

const SHELL_TOOLS = new Set(['Bash', 'PowerShell', 'pwsh']);
const UNVERIFIED = new Set(['hook', 'assumed']);

// How widely a source file applies. A rule in the shared `settings.json` covers
// everyone; `settings.local.json` is one developer's machine and is typically
// gitignored. Deleting a narrow rule because a BROADER-scoped file already
// covers it is safe. The reverse is not: dropping a shared rule because your
// own local file happens to cover it breaks the policy for everybody else.
const SCOPE = { settings: 2, 'settings.local': 1, mcp: 2 };
const scopeOf = (s) => SCOPE[s] ?? 0;

const label = (r) => `${r.tool}${r.specifier != null ? `(${r.specifier})` : ''}`;

// ---------------------------------------------------------------------------
// specifier shape + coverage

// A shell specifier is either OPEN (a prefix, `curl:*` / `Get-ChildItem *`) or
// CLOSED (an exact command string that only ever matches itself).
export function shape(specifier) {
  if (isUnrestricted(specifier)) return { prefix: '', text: '', open: true };
  const raw = String(specifier).trim();
  const m = /^([\s\S]*?)[\s:]*\*+$/.exec(raw);
  if (m) return { prefix: m[1].trim(), text: m[1].trim(), open: true };
  return { prefix: raw, text: raw, open: false };
}

// Does rule A's specifier admit every command rule B's specifier admits?
// Prefix match with a token boundary, so `grep:*` does not cover `grepfoo`.
export function covers(a, b) {
  if (a.open && a.prefix === '') return true; // unrestricted
  if (!a.open) return a.text === b.text;      // an exact rule covers only itself
  if (!b.text.startsWith(a.prefix)) return false;
  const rest = b.text.slice(a.prefix.length);
  return rest === '' || /^[\s:]/.test(rest);
}

// The executable a shell specifier invokes — the grouping key for MERGE.
function exeOf(specifier) {
  const cmd = String(specifier ?? '').trim()
    .replace(/^env\s+\w+=\S+\s+/, '').replace(/^sudo\s+/, '');
  const first = (cmd.split(/[\s:]+/)[0] || '').replace(/^["']/, '');
  return first.replace(/.*[\\/]/, '').replace(/\.exe$/i, '');
}

// ---------------------------------------------------------------------------
// staleness evidence for a CLOSED (exact-match-only) rule

// A Windows drive path or a small set of well-known POSIX roots. The negative
// lookbehind keeps `http://…` out of it — a URL scheme is not a drive letter,
// and mistaking one for a dead path would prune a perfectly live rule.
const ABS_PATH_RE = /(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s"';|&]+|(?:^|[\s"'=])(\/(?:home|Users|tmp|var|opt|etc)\/[^\s"';|&]+)/g;

function stalenessEvidence(specifier) {
  const s = String(specifier ?? '');
  const ev = [];

  // A literal path from another repo / another machine. Machine-local evidence:
  // it says the rule cannot fire HERE, not that it is wrong everywhere.
  const paths = [];
  for (const m of s.matchAll(ABS_PATH_RE)) {
    const p = (m[1] ?? m[0]).replace(/^[\s"'=]+/, '').replace(/["']+$/, '');
    if (p && !paths.includes(p)) paths.push(p);
  }
  const missing = paths.filter((p) => !existsSync(p));
  if (missing.length) ev.push({ kind: 'stale-path', detail: `references ${missing.join(', ')} — not present on this machine`, machineLocal: true });

  // Backslash-escaped shell metacharacters that a real command line does not
  // contain: the residue of a command that was JSON-encoded wrong on its way
  // into the settings file. The rule can never match anything again.
  if (/\\[()]/.test(s)) ev.push({ kind: 'escape-damage', detail: 'contains backslash-escaped parens — a mangled round-trip; cannot match a real command' });

  // Session residue: a captured exit-status echo or a hard-coded host/IP.
  if (/\$\?|\$LASTEXITCODE/.test(s)) ev.push({ kind: 'session-residue', detail: 'echoes an exit status captured from one session' });
  const ip = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(s);
  if (ip) ev.push({ kind: 'session-residue', detail: `hard-codes the host ${ip[0]}` });

  return ev;
}

// The matching primitives, exposed so the tests can pin them directly: a wrong
// answer here is a deleted rule someone needed, so they are pinned as units and
// not only through the end-to-end pass.
export const tidyInternals = { shape, covers, stalenessEvidence, exeOf };

// ---------------------------------------------------------------------------
// the equivalence proof

// The maximal reachable state under a set of actions is the union of their
// effects (monotone + unconditional), so this triple plus the region verdicts is
// a complete behavioural signature of the ruleset.
export function signature(model, check) {
  const union = (pred) => [...new Set(model.actions.filter(pred).flatMap((a) => a.effects))].sort();
  return {
    ungated: union((a) => a.gateKind == null),
    passable: union((a) => a.gateKind == null || UNVERIFIED.has(a.gateKind)),
    all: union(() => true),
    shell: [...(check.shellGrants || [])].sort(),
    regions: Object.fromEntries(check.results.map((r) => [r.region.name, r.status])),
  };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const shrank = (a, b) => b.every((x) => a.includes(x)) && b.length < a.length;

/**
 * Re-run the whole analysis over a proposed ruleset and classify the edit.
 *   effect-preserving — identical signature; the blast radius is provably unchanged
 *   narrowing         — strictly fewer reachable effects (or fewer shell grants)
 *   widening          — the edit grants something the old ruleset did not
 */
export function proveEdit(bundle, nextRules) {
  const { scan, labels, model: beforeModel, check: beforeCheck } = bundle;
  const regions = { regions: beforeModel.regions };
  const afterModel = buildModel({ ...scan, rules: nextRules }, labels, regions, { assumeDefaults: bundle.assumeDefaults !== false });
  const afterCheck = modelCheck(afterModel);

  const before = signature(beforeModel, beforeCheck);
  const after = signature(afterModel, afterCheck);

  const changed = [];
  for (const k of ['ungated', 'passable', 'all', 'shell', 'regions']) {
    if (!same(before[k], after[k])) changed.push(k);
  }

  let direction;
  if (!changed.length) direction = 'effect-preserving';
  else if (['ungated', 'passable', 'all'].some((k) => !shrank(before[k], after[k]) && !same(before[k], after[k]))) direction = 'widening';
  else direction = 'narrowing';

  return { direction, changed, before, after, afterCheck };
}

// ---------------------------------------------------------------------------
// the pass

export function tidyPolicy(bundle) {
  const rules = bundle.scan.rules.map((r, i) => ({ ...r, index: i }));
  const findings = rules.map((r) => ({
    index: r.index, raw: r.raw, tool: r.tool, specifier: r.specifier,
    decision: r.decision, source: r.source, label: label(r),
    verdict: 'KEEP', reason: null, notes: [], evidence: [], coveredBy: null,
  }));
  const by = (i) => findings.find((f) => f.index === i);

  // 1. exact duplicates — same tool, specifier and decision, listed twice.
  //    Applies to every tool; nothing is inferred.
  const firstSeen = new Map();
  for (const r of rules) {
    const key = `${r.decision} ${r.tool} ${r.specifier ?? ''}`;
    if (firstSeen.has(key)) {
      const f = by(r.index);
      f.verdict = 'DEDUP';
      f.reason = 'duplicate';
      f.coveredBy = by(firstSeen.get(key)).label;
      f.notes.push(`listed twice (also in '${by(firstSeen.get(key)).source}')`);
    } else firstSeen.set(key, r.index);
  }

  // 2. subsumption — a broader shell rule in the same bucket already admits this
  //    command. Only proposed when the covering rule lives in a file that is at
  //    least as widely-scoped, so the deletion cannot narrow the policy for
  //    anyone who does not have the covering file.
  const shellRules = rules.filter((r) => SHELL_TOOLS.has(r.tool));
  for (const victim of shellRules) {
    const f = by(victim.index);
    if (f.verdict === 'DEDUP') continue;
    const vs = shape(victim.specifier);
    for (const cand of shellRules) {
      if (cand.index === victim.index) continue;
      if (cand.tool !== victim.tool || cand.decision !== victim.decision) continue;
      const cs = shape(cand.specifier);
      if (!covers(cs, vs)) continue;
      if (covers(vs, cs) && cand.index > victim.index) continue; // mutual: keep the first
      const cf = by(cand.index);
      if (cf.verdict === 'DEDUP') continue; // do not hang a deletion off a deleted rule
      if (scopeOf(cand.source) < scopeOf(victim.source)) {
        f.notes.push(`already admitted by ${cf.label} in '${cf.source}' — but that file is not shared, so this rule still earns its place`);
        continue;
      }
      f.verdict = 'DEDUP';
      f.reason = 'subsumed';
      f.coveredBy = cf.label;
      f.notes.push(`${cf.label} (${cf.source}) already admits it`);
      break;
    }
  }

  // 3. one-shot rules — a CLOSED specifier with arguments matches only that
  //    exact command string ever again. With staleness evidence on top, it is
  //    dead weight; without, it is merely narrow (which is a virtue) and kept.
  for (const r of shellRules) {
    const f = by(r.index);
    if (f.verdict !== 'KEEP') continue;
    const s = shape(r.specifier);
    if (s.open || !/\s/.test(s.text)) continue;
    f.evidence = stalenessEvidence(r.specifier);
    if (f.evidence.length) {
      f.verdict = 'PRUNE';
      f.reason = 'one-shot, stale';
    } else {
      f.notes.push('exact-match only — fires again only for this precise command');
    }
  }

  // 4. merge candidates — several surviving one-shots that invoke the same
  //    executable with no open rule covering them. Collapsing them into one
  //    prefix rule is a real convenience and a real WIDENING; it is reported,
  //    never applied.
  const groups = new Map();
  for (const r of shellRules) {
    const f = by(r.index);
    if (f.verdict !== 'KEEP') continue;
    const s = shape(r.specifier);
    if (s.open) continue;
    const exe = exeOf(r.specifier);
    if (!exe) continue;
    const key = `${r.decision} ${r.tool} ${exe}`;
    if (!groups.has(key)) groups.set(key, { tool: r.tool, decision: r.decision, exe, members: [] });
    groups.get(key).members.push(f);
  }
  const merges = [];
  for (const g of groups.values()) {
    if (g.members.length < 2) continue;
    const sep = g.tool === 'Bash' ? ':*' : ' *';
    const spec = `${g.exe}${sep}`;
    const proposal = `${g.tool}(${spec})`;
    // What would the merged rule actually grant? For an arbitrary-execution
    // wrapper (node, npm, python, make…) the answer is "everything" — collapsing
    // five exact commands into `Bash(node:*)` is a SHELL grant, and a hygiene
    // pass that offers that without saying so is the exact mistake this tool
    // exists to catch.
    const merged = labelEffects(g.tool, spec, bundle.labels);
    const held = new Set(g.members.flatMap((m) => labelEffects(m.tool, m.specifier, bundle.labels).effects));
    const gains = [...merged.effects].filter((e) => !held.has(e)).sort();
    const shellEquivalent = merged.tag === 'shell';
    for (const m of g.members) { m.verdict = 'MERGE'; m.reason = 'mergeable'; m.mergeInto = proposal; }
    merges.push({
      tool: g.tool, decision: g.decision, exe: g.exe, proposal,
      members: g.members.map((m) => m.raw), direction: 'widening',
      shellEquivalent, gains,
    });
  }

  // 5. prove the removal set. MERGE is excluded — it widens by construction and
  //    needs a human yes, so it is never part of the proved edit.
  const removed = findings.filter((f) => f.verdict === 'DEDUP' || f.verdict === 'PRUNE');
  const removedIdx = new Set(removed.map((f) => f.index));
  const nextRules = rules.filter((r) => !removedIdx.has(r.index)).map(({ index, ...r }) => r);
  const proof = removed.length ? proveEdit(bundle, nextRules) : null;

  // 6. honesty pass. A DEDUP that NARROWS the model is not a clean win: the
  //    broad rule still admits the command at runtime, so what shrank is
  //    polycheck's picture, not the blast radius. Deleting it would make the
  //    report look better while nothing got safer — say so, loudly.
  const understates = [];
  if (proof && proof.direction === 'narrowing') {
    for (const f of removed) {
      if (f.reason !== 'subsumed') continue;
      const solo = proveEdit(bundle, rules.filter((r) => r.index !== f.index).map(({ index, ...r }) => r));
      if (solo.direction === 'narrowing') {
        f.understates = true;
        f.notes.push(`removing it SHRINKS the model but not the grant: ${f.coveredBy} still admits this command at runtime. Narrow ${f.coveredBy} instead of deleting this line.`);
        understates.push(f);
      }
    }
  }

  const counts = { total: findings.length };
  for (const v of ['KEEP', 'DEDUP', 'PRUNE', 'MERGE']) counts[v] = findings.filter((f) => f.verdict === v).length;

  return { findings, merges, removed, proof, understates, counts, nextRules };
}

// ---------------------------------------------------------------------------
// rendering

function paint(on) {
  const c = (code) => (on ? (s) => `\x1b[${code}m${s}\x1b[0m` : (s) => s);
  return { red: c('31'), green: c('32'), amber: c('33'), dim: c('2'), bold: c('1'), cyan: c('36') };
}

const trunc = (s, n = 88) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));

const VERDICT_BLURB = {
  KEEP: 'earning its place',
  DEDUP: 'another rule already admits it',
  PRUNE: 'one-shot, cannot fire again',
  MERGE: 'collapsible into one prefix rule — widens the grant',
};

export function renderTidyText(bundle, t, opts = {}) {
  const on = opts.color !== false;
  const verbose = opts.verbose === true;
  const { red, green, amber, dim, bold, cyan } = paint(on);
  const L = [];
  const { counts, proof } = t;

  L.push(bold(`polycheck ${bundle.version} — grant hygiene (--tidy)`));
  L.push(`${dim('repo:')}    ${bundle.scan.root}`);
  L.push(`${dim('rules:')}   ${counts.total}    ${dim('keep')} ${counts.KEEP}  ${dim('dedup')} ${counts.DEDUP}  ${dim('prune')} ${counts.PRUNE}  ${dim('merge')} ${counts.MERGE}`);
  L.push('');

  const section = (verdict, colour, heading) => {
    const items = t.findings.filter((f) => f.verdict === verdict);
    if (!items.length) return;
    L.push(colour(bold(heading)) + dim(`  — ${VERDICT_BLURB[verdict]}`));
    for (const f of items) {
      const flag = f.understates ? amber('  ⚠') : '';
      L.push(`    ${colour('•')} ${f.label}${flag}`);
      L.push(dim(`      ${f.source}`) + (f.mergeInto ? dim(`  →  ${f.mergeInto}`) : ''));
      for (const n of f.notes) L.push(dim(`      └ ${n}`));
      for (const e of f.evidence) L.push(dim(`      └ ${e.detail}${e.machineLocal ? ' (machine-local evidence)' : ''}`));
    }
    L.push('');
  };

  section('DEDUP', green, 'DEDUP');
  section('PRUNE', green, 'PRUNE');

  if (t.merges.length) {
    L.push(amber(bold('MERGE')) + dim('  — offered, never applied: each one grants MORE than the lines it replaces'));
    for (const m of t.merges) {
      L.push(`    ${m.shellEquivalent ? red('•') : amber('•')} ${m.proposal}  ${dim(`replaces ${m.members.length} rules in '${m.decision}'`)}`);
      if (m.shellEquivalent) {
        L.push(`      ${red(bold('DO NOT TAKE THIS ONE'))} ${dim(`— ${m.exe} runs caller-chosen code, so ${m.proposal} is a`)}`);
        L.push(dim(`      SHELL grant: it would make every forbidden region trivially reachable.`));
        L.push(dim('      Keep the exact commands, or gate the wrapper behind ask/deny.'));
      } else if (m.gains.length) {
        L.push(dim(`      grants ${m.gains.join(' + ')} that none of the lines it replaces did`));
      }
      for (const r of m.members) L.push(dim(`      └ ${r}`));
    }
    L.push(dim('  A prefix rule admits every command that starts with it, including ones you'));
    L.push(dim('  have not run yet. Take the merge for convenience, or keep the exact lines'));
    L.push(dim('  for precision — but do it knowing which of the two you chose.'));
    L.push('');
  }

  if (verbose) {
    const kept = t.findings.filter((f) => f.verdict === 'KEEP');
    if (kept.length) {
      L.push(bold('KEEP') + dim('  — earning its place'));
      for (const f of kept) {
        L.push(`    ${dim('•')} ${f.label} ${dim(f.source)}`);
        for (const n of f.notes) L.push(dim(`      └ ${n}`));
      }
      L.push('');
    }
  }

  L.push(bold('PROOF OF THE EDIT'));
  if (!proof) {
    L.push(dim('  Nothing to remove — the ruleset is already tight.'));
  } else {
    const n = t.removed.length;
    if (proof.direction === 'effect-preserving') {
      L.push(`  ${green('✓')} removing ${n} rule${n > 1 ? 's' : ''} is ${green(bold('effect-preserving'))}.`);
      L.push(dim('    Reachable effects are identical before and after, per gate class'));
      L.push(dim(`    (ungated: ${proof.before.ungated.join(', ') || '∅'}), the shell-grant set is unchanged,`));
      L.push(dim('    and every region verdict is unchanged. The blast radius does not move.'));
    } else if (proof.direction === 'narrowing') {
      L.push(`  ${amber('•')} removing ${n} rule${n > 1 ? 's' : ''} ${amber(bold('narrows the model'))} — what moved:`);
      for (const k of proof.changed) {
        const b0 = proof.before[k], a0 = proof.after[k];
        if (!Array.isArray(b0)) {
          const fmt = (v) => Object.entries(v).map(([a, x]) => `${a}=${x}`).join(', ');
          L.push(dim(`      ${k}:  ${fmt(b0)}  →  ${fmt(a0)}`));
          continue;
        }
        // These lists can run to hundreds of entries on a real policy — the
        // interesting part is the DELTA, so show that and keep the full dump
        // behind --verbose rather than flooding the terminal with one line.
        const dropped = b0.filter((x) => !a0.includes(x));
        L.push(dim(`      ${k}:  ${b0.length} → ${a0.length}`) + (dropped.length ? dim(`  (${dropped.length} gone)`) : ''));
        const show = verbose ? dropped : dropped.slice(0, 6);
        for (const d of show) L.push(dim(`        − ${trunc(d, 96)}`));
        if (dropped.length > show.length) { L.push(dim(`        … and ${dropped.length - show.length} more (--verbose)`)); }
      }
      if (t.understates.length) {
        const m = t.understates.length;
        L.push('');
        L.push(`  ${amber(bold('⚠ this is not the win it looks like.'))}`);
        L.push(dim(`    ${m} of those rule${m > 1 ? 's are' : ' is'} marked ⚠ above. Each is subsumed by a broader`));
        L.push(dim('    rule, so deleting the line does NOT revoke anything — the broad rule still'));
        L.push(dim('    admits the same command at runtime. What shrinks is polycheck\'s picture of'));
        L.push(dim('    your policy, not your exposure. Narrow the covering rule instead.'));
      }
    } else {
      L.push(`  ${red('✗')} the proposed edit ${red(bold('WIDENS'))} the policy — changed: ${proof.changed.join(', ')}. This is a bug in --tidy; do not apply it.`);
    }
    L.push('');
    L.push(dim('  Verdicts after the edit: ') + Object.entries(proof.after.regions).map(([k, v]) => `${k}=${v}`).join(dim(', ')));
  }
  L.push('');

  L.push(bold('WHAT TIDY DID NOT LOOK AT'));
  L.push(`  ${cyan('•')} ${bold('path globs are not compared.')} Subsumption is inferred for shell tools`);
  L.push('    only (Bash, PowerShell, pwsh), where a specifier is a command prefix with');
  L.push('    known matching. Read/Edit globs are left alone: a wrong deletion there is');
  L.push('    silent, and a hygiene pass is worthless if you have to re-check it.');
  L.push(`  ${cyan('•')} ${bold('tidy is not the security check.')} A tight list of grants can still be a`);
  L.push('    wide-open policy — run polycheck without --tidy for the region verdicts. An');
  L.push('    effect-preserving edit preserves a BYPASS exactly as faithfully as a PROOF.');
  L.push(`  ${cyan('•')} ${bold('staleness is machine-local.')} A rule marked stale for a missing path is`);
  L.push('    dead on THIS machine; on the machine it was written for it may still fire.');
  L.push('');

  const actionable = counts.DEDUP + counts.PRUNE;
  if (actionable) {
    L.push(bold(`verdict: ${actionable} of ${counts.total} rules can go${proof?.direction === 'effect-preserving' ? ' with no change to what the policy permits' : ''}.`));
    if (t.understates.length) {
      L.push(amber(`         ${t.understates.length} of them hide a grant rather than remove one — fix the covering rule, not the line.`));
    }
  } else {
    L.push(bold('verdict: nothing to remove.'));
  }
  if (!opts.willWrite) {
    L.push('');
    L.push(dim('Dry run — no file was written. Apply it with ') + '--write' + dim(', or take the edit as JSON with ') + '--json' + dim('.'));
  }
  return L.join('\n');
}

export function renderTidyJson(bundle, t) {
  return JSON.stringify({
    version: bundle.version,
    repo: bundle.scan.root,
    counts: t.counts,
    rules: t.findings.map((f) => ({
      rule: f.raw, tool: f.tool, specifier: f.specifier, decision: f.decision, source: f.source,
      verdict: f.verdict, reason: f.reason, coveredBy: f.coveredBy ?? null,
      mergeInto: f.mergeInto ?? null, understatesRisk: f.understates ?? false,
      notes: f.notes, evidence: f.evidence,
    })),
    merges: t.merges,
    remove: t.removed.map((f) => f.raw),
    proof: t.proof && {
      direction: t.proof.direction,
      changed: t.proof.changed,
      before: t.proof.before,
      after: t.proof.after,
    },
  }, null, 2);
}
