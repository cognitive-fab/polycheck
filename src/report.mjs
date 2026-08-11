// polycheck report renderer — the output IS the product. A witness has to read
// like a screenshot someone forwards: a concrete, provenance-anchored sequence
// of allowed tool calls that reaches credential egress with zero gates crossed.
// The proof, when it holds, has to be honest about what it did NOT cover —
// painting an unchecked thing green is the one thing a security report must not do.
//
// TONE — describe capability, not culpability. polycheck reports what a policy
// PERMITS: reach the author granted, to keep or to close. A finding is a
// description of that reach, never an accusation that anything is wrong, and
// never an alarm. Hand the decision back with the evidence; state the reach and
// let the reader weigh it. Positive framing does not mean soft substance — a
// BYPASS is still a BYPASS — it means the words assume a defender reading their
// own policy, not a suspect being charged.

const GLYPH = { BYPASS: '✗', 'SHELL-EQUIVALENT': '✗', PROOF: '✓', VACUOUS: '•', INCONCLUSIVE: '•' };

function paint(on) {
  const c = (code) => (on ? (s) => `\x1b[${code}m${s}\x1b[0m` : (s) => s);
  return { red: c('31'), green: c('32'), amber: c('33'), dim: c('2'), bold: c('1'), cyan: c('36') };
}

function effJoin(list) { return list.join(' ∧ '); }
const trunc = (s, n = 88) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));

// The executable a shell grant runs, for grouping. `Bash(python3 -c '…')` and
// `Bash(python3 *)` both key to 'python3'; `Bash(git -C /path status)` to 'git'.
function shellExe(grant) {
  const m = /^(?:Bash|PowerShell|pwsh)\(([\s\S]*)\)$/.exec(grant);
  let cmd = (m ? m[1] : grant).trim().replace(/^env\s+\w+=\S+\s+/, '').replace(/^sudo\s+/, '');
  let exe = (cmd.split(/\s+/)[0] || cmd).replace(/^["']/, '').replace(/[^\w./-].*$/, '').replace(/.*[\\/]/, '').replace(/\.exe$/i, '');
  return exe || 'shell';
}
// Group a set of tool labels by provider: shell tools by executable
// (curl, aws, python3…), everything else by tool name (WebFetch, mcp__x__y).
function providerKey(label) {
  return /^(?:Bash|PowerShell|pwsh)\(/.test(label) ? shellExe(label) : label.replace(/\(.*$/s, '');
}
function groupBy(labels, keyFn) {
  const counts = new Map();
  for (const l of labels) counts.set(keyFn(l), (counts.get(keyFn(l)) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}
const shellGroups = (grants) => groupBy(grants, shellExe);

export function renderText(bundle, opts = {}) {
  const on = opts.color !== false;
  const verbose = opts.verbose === true;
  const { red, green, amber, dim, bold, cyan } = paint(on);
  const { scan, model, check, version } = bundle;
  const L = [];
  let collapsed = false; // true if we hid detail that --verbose would show

  const srcLine = scan.sources
    .map((s) => `${s.kind}${s.exists ? (s.error ? ' ⚠' : ' ✓') : ' ✗'}`)
    .join('  ');
  L.push(bold(`polycheck ${version} — Claude Code least-privilege check`));
  L.push(`${dim('repo:')}    ${scan.root}`);
  L.push(`${dim('sources:')} ${srcLine}`);
  L.push(`${dim('mode:')}    ${scan.defaultMode || 'default'}    ${dim('actions modeled:')} ${check.actionCount} ${dim(`(ungated: ${check.ungatedCount})`)}`);
  L.push(dim('This describes what your policy permits — reach you granted, to keep or close. Not a judgment.'));
  L.push('');

  L.push(bold('FORBIDDEN REGIONS') + dim('  — effect-combinations you declared should never be reachable without a gate'));
  for (const r of check.results) {
    const g = GLYPH[r.status];
    const name = r.region.name.padEnd(18);
    if (r.status === 'BYPASS') L.push(`  ${red(g)} ${red(name)} ${red('BYPASS')} ${dim('— a gate-free path exists')}`);
    else if (r.status === 'SHELL-EQUIVALENT') L.push(`  ${red(g)} ${red(name)} ${red('SHELL-EQUIVALENT')} ${dim('— a granted tool runs arbitrary code')}`);
    else if (r.status === 'INCONCLUSIVE') L.push(`  ${amber(g)} ${amber(name)} ${amber('INCONCLUSIVE')} ${dim('— mediated only by an unverified gate')}`);
    else if (r.status === 'VACUOUS') L.push(`  ${amber(g)} ${amber(name)} ${amber('INCONCLUSIVE')} ${dim(`— no granted tool provides: ${r.missingEffects.join(', ')}`)}`);
    else if (r.reason === 'denial') L.push(`  ${green(g)} ${green(name)} ${green('PROOF')}  ${dim('— closed by a deny rule')}`);
    else if (r.mediated) L.push(`  ${green(g)} ${green(name)} ${green('PROOF')}  ${dim('— every path crosses a gate')}`);
    else L.push(`  ${green(g)} ${green(name)} ${green('PROOF')}  ${dim('— region unreachable under the modeled actions')}`);
  }
  L.push('');

  // SHELL-EQUIVALENT — reported once (the same grant makes every region trivial).
  if (check.shellGrants && check.shellGrants.length) {
    const grants = check.shellGrants;
    const groups = shellGroups(grants);
    const n = grants.length;
    L.push(red(bold('SHELL-EQUIVALENT')) + dim(`  — ${n} granted command${n > 1 ? 's' : ''} run caller-chosen code, by executable:`));
    // grouped counts, wrapped to a few per line so it stays readable
    const chips = groups.map(([exe, c]) => `${exe}${c > 1 ? dim(` ×${c}`) : ''}`);
    for (let i = 0; i < chips.length; i += 6) L.push('    ' + chips.slice(i, i + 6).join(dim('  ·  ')));
    if (verbose) { L.push(''); for (const g of grants) L.push(`    ${red('•')} ${g}`); }
    else if (grants.length > groups.length) collapsed = true;
    L.push(dim('  A command prefix is not a security boundary: npm run, node, python, bash -c'));
    L.push(dim('  all execute whatever they are handed — any one is equivalent to unrestricted'));
    L.push(dim('  Bash, so every region is reachable in a single step. If that reach is intended'));
    L.push(dim('  (a dev box, your own tooling), keep it; if not, one of the fixes below closes it.'));

    // The fix depends on WHY each grant is worst-case. "Narrow it to fixed
    // arguments" is already satisfied for the exact ones, so printing it there
    // would tell the reader their policy is fine when it is not.
    const byReason = check.shellByReason || {};
    const nPrefix = (byReason['unrestricted']?.length || 0) + (byReason['interpreter-prefix']?.length || 0);
    if (nPrefix) {
      L.push(cyan('     fix') + dim(`  ${nPrefix} open-ended: move behind 'ask'/'deny', or narrow to fixed arguments.`));
    }
    if (byReason['inline-code']?.length) {
      L.push(cyan('     fix') + dim(`  ${byReason['inline-code'].length} pass a program on the command line (-e/-c): the arguments`));
      L.push(dim('           ARE the program, so narrowing them changes nothing. Gate or delete.'));
    }
    const wc = check.writableCode;
    if (wc) {
      const scripts = [...new Set(wc.grants.map((g) => g.scriptPath).filter(Boolean))];
      L.push(cyan('     fix') + dim(`  ${wc.grants.length} already fix every argument — narrowing them is DONE and`));
      L.push(dim(`           changes nothing. They run code from this repo: ${scripts.slice(0, 3).join(', ')}${scripts.length > 3 ? `, +${scripts.length - 3}` : ''}`));
      if (wc.writers.length) {
        L.push(dim('           …and this policy grants ungated writes to it:'));
        for (const w of wc.writers.slice(0, 4)) L.push(dim(`             · ${w.raw}${w.source ? `  [${w.source}]` : ''}`));
        if (wc.writers.length > 4) L.push(dim(`             · … and ${wc.writers.length - 4} more`));
        L.push(dim('           Bounded ARGUMENTS are not bounded CODE. Close either side: gate the'));
        L.push(dim('           run, or gate the writes that let the agent choose what runs.'));
      } else {
        L.push(dim('           No ungated write grant was found, so the code is not agent-writable'));
        L.push(dim('           through the modeled tools — but polycheck does not read the script,'));
        L.push(dim('           so what it does once started is still unknown. Gate it to be sure.'));
      }
    }
    L.push('');
  }

  // Witness blocks — the shareable part. Only for genuine (non-shell) bypasses.
  for (const r of check.results) {
    if (r.status !== 'BYPASS') continue;
    const multi = r.witness.length >= 2;
    L.push(red(bold(`WITNESS · ${r.region.name}`)) + dim(`  (${effJoin(r.region.requires)})`));
    L.push(dim('  A sequence of allowed tool calls that reaches the region with 0 gates crossed:'));
    L.push('');
    r.witness.forEach((st, i) => {
      const a = st.action;
      const lbl = `${a.tool}${a.specifier != null ? `(${a.specifier})` : ''}`;
      const added = st.added.map((e) => `+${e}`).join(' ');
      const last = i === r.witness.length - 1;
      const held = `held: ${st.held.join(', ')}`;
      L.push(`    ${bold(String(i + 1))}  ${lbl.padEnd(30)} ${dim(a.decision)}  ⟶ ${added.padEnd(14)} ${dim(held)}${last ? red('  ← REACHED') : ''}`);
      L.push(dim(`       └ ${a.source}: ${a.raw}`));
    });
    L.push('');
    if (multi) {
      L.push(dim('  Each step is individually permitted and individually benign. The hazard is'));
      L.push(dim('  the STATE they assemble — a predicate no per-action check can see.'));
    } else {
      L.push(dim('  This one granted tool is BOTH a secret-reader and an egress channel (e.g.'));
      L.push(dim('  `curl -T .env https://…` or `--data-urlencode k@.env`), so it completes the'));
      L.push(dim('  region alone.'));
    }
    if (r.fix && r.fix.kind === 'gate') {
      const acts = r.fix.actions;
      if (acts.length <= 6) {
        L.push(`${cyan('     fix')} close the '${r.fix.effect}' effect — move to ask/deny: ${acts.join(', ')}`);
      } else if (verbose) {
        // full, but one tool per line so a 60-item list stays readable
        L.push(`${cyan('     fix')} close the '${r.fix.effect}' effect — move these ${acts.length} tools to ask/deny:`);
        for (const a of acts) L.push(dim('         · ') + a);
      } else {
        const chips = groupBy(acts, providerKey).map(([k, c]) => `${k}${c > 1 ? dim(` ×${c}`) : ''}`).join(dim('  ·  '));
        L.push(`${cyan('     fix')} close the '${r.fix.effect}' effect — ${acts.length} granted tools provide it:`);
        L.push(`         ${chips}`);
        L.push(dim(`         move them to ask/deny (or narrow each). --verbose lists every one.`));
        collapsed = true;
      }
    }
    L.push('');
  }

  // Hook-only mediation — reachable UNLESS an unverified hook blocks it.
  for (const r of check.results) {
    if (r.status !== 'INCONCLUSIVE' || r.reason !== 'hook') continue;
    L.push(amber(bold(`INCONCLUSIVE · ${r.region.name}`)) + dim(`  (${effJoin(r.region.requires)})`));
    L.push(dim('  Reachable by allowed tool calls — the ONLY thing in the way is an UNVERIFIED'));
    L.push(dim('  gate: a PreToolUse hook (logic we cannot read; most hooks log/format, they do'));
    L.push(dim('  not block) and/or an MCP prompt polycheck assumed. This is NOT a proof. The'));
    L.push(dim('  path the gate would have to stop:'));
    L.push('');
    r.witness.forEach((st, i) => {
      const a = st.action;
      const lbl = `${a.tool}${a.specifier != null ? `(${a.specifier})` : ''}`;
      const added = st.added.map((e) => `+${e}`).join(' ');
      const last = i === r.witness.length - 1;
      L.push(`    ${bold(String(i + 1))}  ${lbl.padEnd(30)} ${dim('gate?')}  ⟶ ${added.padEnd(14)} ${dim(`held: ${st.held.join(', ')}`)}${last ? amber('  ← REACHED') : ''}`);
    });
    if (r.unverifiedGates?.length) L.push(dim(`     ${r.unverifiedGates.join('; ')}`));
    L.push(cyan('     fix') + ` make the gate verifiable: put the tools behind an explicit 'ask'/'deny' rule (or name the MCP server's tools), rather than relying on an unverified gate.`);
    L.push('');
  }

  // Mediated proofs — name the control that carries the safety.
  for (const r of check.results) {
    if (r.status !== 'PROOF') continue;
    if (r.reason === 'denial' && r.denials?.length) {
      L.push(green(`PROOF · ${r.region.name}`) + dim(` — closed by denial: ${r.denials.join(', ')} (a deny is the strongest control)`));
    } else if (r.mediated && r.mediators?.length) {
      const gates = r.mediators.map((m) => `${m.tool}${m.specifier != null ? `(${m.specifier})` : ''} [${m.gateReason}]`);
      L.push(green(`PROOF · ${r.region.name}`) + dim(` — mediated by: ${[...new Set(gates)].join('; ')}`));

      // A PROOF carried by polycheck's own guard must never read as an
      // unconditional green. State the argument and the SCOPE of the claim, so a
      // reader can check it rather than take it: the guard is a verified gate
      // only because it cannot emit 'allow', and only for the regions it is
      // configured to gate.
      if (r.mediators.some((m) => m.gateKind === 'guard')) {
        L.push(dim(`    why this counts as a gate: polycheck guard's decision union is ask/deny/passthrough —`));
        L.push(dim(`    it can only ADD a gate, never remove one — and it gates every call completing this region.`));
        L.push(dim(`    scope: this claim covers ONLY the regions named in .claude/polycheck.guard.json.`));
        L.push(dim(`    it is a RUNTIME control: unlike an 'ask' rule, it depends on code running correctly`));
        L.push(dim(`    on every call, and on the runtime labeler recognising the call. Not a static proof.`));
      }
    }
  }
  if (check.results.some((r) => r.status === 'PROOF' && (r.mediators?.length || r.denials?.length))) L.push('');

  // Footer — what the check did NOT establish.
  L.push(bold('WHAT THIS CHECK DID NOT ESTABLISH'));
  L.push(`  ${cyan('•')} ${bold('auto-mode classifier is NOT counted as a gate.')} A probabilistic filter`);
  L.push(`    reduces frequency, not possibility. Every witness above holds`);
  L.push(`    regardless of what the classifier scores — that is the point of a static proof.`);
  L.push(`  ${cyan('•')} ${bold('the labeler is a trust obligation, not a proof.')} polycheck proves the`);
  L.push(`    policy over the labels; a mislabeled tool is a hole it cannot see.`);
  // Drop ARBITRARY-EXECUTION / WORST-CASE notes here — they just restate the
  // SHELL-EQUIVALENT section. Keep the ones that reveal blind spots (unlabeled
  // tools, MCP assumptions, commands matched as benign — those hint at gaps).
  const notes = verbose ? model.assumptions : model.assumptions.filter((a) => !/^(ARBITRARY-EXECUTION|WORST-CASE)/.test(a));
  const cap = verbose ? notes.length : 8;
  for (const a of notes.slice(0, cap)) L.push(dim(`      · ${verbose ? a : trunc(a, 128)}`));
  if (notes.length > cap) { L.push(dim(`      · … and ${notes.length - cap} more`)); collapsed = true; }
  L.push(`  ${cyan('•')} ${bold('confinement is out of scope.')} Only tool-mediated actions are`);
  L.push(`    modeled; anything the agent does outside the tool interface is not.`);
  L.push(`  ${cyan('•')} ${bold('subagent taint is not propagated (v1).')} Task/subagent spawns are a known`);
  L.push(`    gap — named, not silently cleared.`);
  L.push(`  ${cyan('•')} ${bold("'ask' is a gate, but a weaker one than a PROOF implies.")} A mediated`);
  L.push(`    verdict means a human is in the loop, not that they will refuse: approval`);
  L.push(`    fatigue is real and an injected call can be shaped to look routine. Treat a`);
  L.push(`    PROOF-by-'ask' as "a human sees it", and prefer 'deny' for irreversible egress.`);
  if (scan.warnings.length) {
    L.push('');
    for (const w of scan.warnings) L.push(amber(`  ⚠ ${w}`));
  }
  L.push('');

  const broken = check.results.filter((r) => r.status === 'BYPASS' || r.status === 'SHELL-EQUIVALENT');
  if (broken.length) {
    L.push(red(bold(`verdict: ${broken.length} region(s) reachable with no gate crossed — ${broken.map((r) => r.region.name).join(', ')}`)));
  } else if (check.results.some((r) => r.status === 'VACUOUS' || r.status === 'INCONCLUSIVE')) {
    const unver = check.results.some((r) => r.status === 'INCONCLUSIVE');
    L.push(amber(bold(`verdict: INCONCLUSIVE — ${unver ? 'a path is mediated only by an unverified gate, which polycheck cannot confirm blocks' : 'a required effect has no granted tool, so nothing was mediated'}. This is not a proof.`)));
  } else {
    L.push(green(bold('verdict: no gate-free path into any forbidden region under the modeled actions.')));
  }
  L.push('');
  if (!verbose && collapsed) {
    L.push(dim('Output was collapsed for readability. Run with ') + '--verbose' + dim(' for every grant and'));
    L.push(dim('assumption in full, or ') + '--json' + dim(' for machine-readable output.'));
  } else {
    L.push(dim('Machine-readable output: run with ') + '--json' + dim('.'));
  }
  return L.join('\n');
}

export function renderMarkdown(bundle, opts = {}) {
  const text = renderText(bundle, { color: false, verbose: opts.verbose === true });
  return '```\n' + text + '\n```\n';
}

export function renderJson(bundle) {
  const { scan, model, check, version } = bundle;
  const broken = check.results.some((r) => r.status === 'BYPASS' || r.status === 'SHELL-EQUIVALENT');
  return JSON.stringify({
    version,
    repo: scan.root,
    hasPolicy: scan.hasPolicy,
    defaultMode: scan.defaultMode || 'default',
    sources: scan.sources,
    actionCount: check.actionCount,
    ungatedCount: check.ungatedCount,
    universe: check.universe,
    shellGrants: check.shellGrants || [],
    shellByReason: check.shellByReason || {},
    writableCode: check.writableCode || null,
    regions: check.results.map((r) => ({
      name: r.region.name,
      kind: r.region.kind,
      requires: r.region.requires,
      status: r.status,
      reason: r.reason ?? null,
      mediated: r.mediated ?? null,
      missingEffects: r.missingEffects ?? null,
      unverifiedGates: r.unverifiedGates ?? null,
      denials: r.denials ?? null,
      fix: r.fix ?? null,
      mediators: (r.mediators || []).map((m) => ({ tool: m.tool, specifier: m.specifier, gateKind: m.gateKind, gateRegions: m.gateRegions || null, gateReason: m.gateReason })),
      witness: (r.witness || []).map((st, i) => ({
        step: i + 1,
        tool: st.action.tool,
        specifier: st.action.specifier,
        decision: st.action.decision,
        source: st.action.source,
        rule: st.action.raw,
        added: st.added,
        held: st.held,
      })),
    })),
    assumptions: model.assumptions,
    warnings: scan.warnings,
    verdict: broken ? 'bypass'
      : check.results.some((r) => r.status === 'VACUOUS') ? 'vacuous' : 'proof',
  }, null, 2);
}
