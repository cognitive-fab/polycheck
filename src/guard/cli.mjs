// polycheck guard — the CLI half (`polycheck guard <sub>`).
//
// `init` is deliberately not a one-liner installer. Installing a runtime control
// on a repo that is already PROOF buys nothing, and installing one on a repo
// with an unrestricted shell grant is close to theatre — the guard's labeler
// would be the only thing between the session and the region. So init runs the
// LINTER first and tells you which of those you are, then asks.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { analyze } from '../index.mjs';
import { loadLedger, stateDir } from './ledger.mjs';
import { COMPAT } from './compat.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD_BIN = resolve(HERE, '..', '..', 'bin', 'polycheck-guard.mjs');

const DEFAULT_CONFIG = {
  basis: 'capability',
  onComplete: { 'lethal-trifecta': 'ask', 'credential-egress': 'ask' },
  prewarn: true,
};

// Tools worth spawning the hook for. Everything else is filtered out before a
// process starts — the only latency mitigation that matters, since WP0 measured
// node cold start at 780 ms on one machine.
//
// This list is a SECURITY surface, not just a performance one: a tool the guard
// never runs for is a tool the guard does not gate, and src/scan.mjs now refuses
// to certify those. Anything effect-bearing in the label pack must appear here
// or the linter will (correctly) report it as unmediated.
const IF_FILTERS = ['Bash(*)', 'PowerShell(*)', 'Read(*)', 'Grep(*)', 'WebFetch', 'WebSearch', 'Task(*)'];

// MCP tools are the canonical egress channel for the trifecta, and they were
// missing entirely: `labelCall`'s MCP branch was unreachable in a real install.
// They get a matcher-scoped entry with NO `if`, rather than an `if: "mcp__*"` —
// a wildcard rule is not something we have confirmed the host's `if` parser
// accepts, and a filter that silently never matches is exactly the bug this
// whole change is fixing. A matcher regex is what polycheck already models.
const MCP_MATCHER = 'mcp__.*';

function hookEntry(sub, ifFilter) {
  const h = { type: 'command', command: 'node', args: [GUARD_BIN, sub], timeout: 10 };
  if (ifFilter) h.if = ifFilter;   // filters BEFORE the process spawns
  return h;
}

export function guardWiring() {
  return {
    SessionStart: [{ hooks: [hookEntry('session-start', null)] }],
    PreToolUse: [
      ...IF_FILTERS.map((f) => ({ matcher: '*', hooks: [hookEntry('pre', f)] })),
      { matcher: MCP_MATCHER, hooks: [hookEntry('pre', null)] },
    ],
    // The M1 evidence pass. Same coverage as pre — a call whose bytes we never
    // see cannot sharpen or clear its own taint — so it mirrors the pre filters.
    PostToolUse: [
      ...IF_FILTERS.map((f) => ({ matcher: '*', hooks: [hookEntry('post', f)] })),
      { matcher: MCP_MATCHER, hooks: [hookEntry('post', null)] },
    ],
  };
}

const isGuardHook = (h) => /polycheck[-\s]guard/i.test([h?.command, ...(h?.args || [])].filter(Boolean).join(' '));
const isGuardEntry = (e) => (e?.hooks || []).some(isGuardHook);

// APPEND to the user's hooks, never replace them. A shallow spread over event
// names looked right and silently destroyed every pre-existing PreToolUse and
// SessionStart entry — unrecoverably, since `guard off` cannot put them back.
function mergeHooks(existing, wiring) {
  const out = { ...(existing || {}) };
  for (const [event, entries] of Object.entries(wiring)) {
    const prior = Array.isArray(out[event]) ? out[event].filter((e) => !isGuardEntry(e)) : [];
    out[event] = [...prior, ...entries]; // re-installing replaces OUR entries only
  }
  return out;
}

// Distinguishes "absent" from "unparseable". Anything that WRITES the file back
// must use this: treating a broken file as an empty object destroys it.
function readJsonStrict(path) {
  if (!existsSync(path)) return { data: null, error: null };
  try { return { data: JSON.parse(readFileSync(path, 'utf8')), error: null }; }
  catch (err) { return { data: null, error: String(err.message || err) }; }
}

export function guardInit(root, { yes = false, write = null } = {}) {
  const L = [];
  const bundle = analyze(root);
  const results = bundle.check.results;

  L.push('polycheck guard · install');
  L.push('');
  L.push('  first, what the linter says about this repo:');
  for (const r of results) L.push(`    ${r.region.name.padEnd(18)} ${r.status}`);
  L.push('');

  const shell = bundle.check.shellGrants || [];
  const anyBypass = results.some((r) => r.status === 'BYPASS' || r.status === 'SHELL-EQUIVALENT');
  const allProof = results.every((r) => r.status === 'PROOF');

  if (shell.length) {
    // The honest warning. With a shell grant the guard's runtime labeler is the
    // only thing standing between the session and the region — and a labeler is
    // not a proof. Fixing the grant strictly dominates installing the guard.
    L.push(`  ⚠ ${shell.length} granted command(s) run caller-chosen code.`);
    L.push('    With an arbitrary-execution grant, the guard\'s labeler is the ONLY thing');
    L.push('    between this session and the region — and a labeler is a trust obligation,');
    L.push('    not a proof. Narrowing or gating those grants beats installing the guard.');
    L.push('    Run `polycheck . --tidy` first.');
    L.push('');
  }
  if (allProof) {
    L.push('  this policy is already PROOF: every path crosses a gate you wrote.');
    L.push('    The guard would add runtime cost and a runtime dependency for no new');
    L.push('    coverage. Installing it is reasonable only if you expect the policy to');
    L.push('    loosen. A static gate you wrote is stronger than a runtime one we run.');
    L.push('');
  }
  if (anyBypass) {
    L.push('  the guard would gate the LAST step of each witness above, with the path shown.');
    L.push('    That closes the composition at runtime. It does NOT fix the policy: the');
    L.push('    grants that make the composition possible are still there.');
    L.push('');
  }

  const cfgPath = join(root, '.claude', 'polycheck.guard.json');
  const setPath = join(root, '.claude', 'settings.json');
  L.push(`  would write:  ${cfgPath}`);
  L.push(`                ${setPath}  (hooks block only)`);
  L.push(`  ledger state: ${stateDir()}  (outside the repo, never committed)`);
  L.push('');

  if (!yes) {
    L.push('  nothing written. Re-run with --yes to install, or `polycheck guard off` to remove.');
    return { text: L.join('\n'), wrote: false, exit: 0 };
  }

  // A settings file that exists but does not parse must ABORT, not be replaced.
  // `readJsonOr(path, {})` swallowed the parse error and then wrote a
  // guard-only file over it — one trailing comma and the entire permissions
  // block was gone.
  const existing = readJsonStrict(setPath);
  if (existing.error) {
    L.push(`  ✗ REFUSED: ${setPath} exists but does not parse (${existing.error}).`);
    L.push('    Nothing was written. Fix the file, or move it aside, and re-run.');
    return { text: L.join('\n'), wrote: false, exit: 3 };
  }
  const settings = existing.data || {};
  settings.hooks = mergeHooks(settings.hooks, guardWiring());
  mkdirSync(dirname(setPath), { recursive: true });
  (write || writeFileSync)(setPath, JSON.stringify(settings, null, 2) + '\n');
  if (!existsSync(cfgPath)) (write || writeFileSync)(cfgPath, JSON.stringify(DEFAULT_CONFIG, null, 2) + '\n');

  L.push('  ✓ installed. Hooks hot-reload — no restart needed.');
  L.push('    Re-run `polycheck .` to see the regions the guard now mediates.');
  return { text: L.join('\n'), wrote: true, exit: 0 };
}

export function guardOff(root, { write = null } = {}) {
  const setPath = join(root, '.claude', 'settings.json');
  const r = readJsonStrict(setPath);
  if (r.error) return { text: `polycheck guard · REFUSED: ${setPath} does not parse (${r.error}). Nothing written.`, wrote: false, exit: 3 };
  const settings = r.data;
  if (!settings?.hooks) return { text: 'polycheck guard · nothing to remove.', wrote: false, exit: 0 };

  let removed = 0;
  for (const [event, entries] of Object.entries(settings.hooks)) {
    if (!Array.isArray(entries)) continue;
    const kept = entries.filter((e) => !(e.hooks || []).some((h) => /polycheck[-\s]guard/i.test([h.command, ...(h.args || [])].join(' '))));
    removed += entries.length - kept.length;
    if (kept.length) settings.hooks[event] = kept; else delete settings.hooks[event];
  }
  if (!Object.keys(settings.hooks).length) delete settings.hooks;
  (write || writeFileSync)(setPath, JSON.stringify(settings, null, 2) + '\n');
  return { text: `polycheck guard · removed ${removed} hook entr${removed === 1 ? 'y' : 'ies'}. The config file was left in place.`, wrote: true, exit: 0 };
}

export function guardStatus(root, sessionId) {
  const L = ['polycheck guard · status'];
  L.push('');
  if (!sessionId) {
    L.push('  no session id given. Usage: polycheck guard status <session-id>');
    L.push(`  ledgers live in ${join(stateDir(), 'sessions')}`);
    return { text: L.join('\n'), exit: 0 };
  }
  const { ledger, status, detail } = loadLedger(sessionId, root);
  L.push(`  session ${sessionId}  [${status}${detail ? ': ' + detail : ''}]`);
  L.push(`  basis: ${ledger.basis}`);
  L.push(`  held (capability): ${ledger.held.capability.join(', ') || '—'}`);
  L.push(`  held (observed):   ${ledger.held.observed.join(', ') || '—'}`);
  L.push(`  steps: ${ledger.steps.length}${ledger.truncated ? ' (truncated; effect origins preserved)' : ''}`);
  if (ledger.entered.length) L.push(`  regions entered: ${ledger.entered.map((e) => `${e.region}@${e.atStep}`).join(', ')}`);
  if (ledger.grants.length) {
    L.push('  scoped approvals:');
    for (const g of ledger.grants) {
      L.push(`    ${g.region} · ${g.effect} via ${g.providerKey}${g.pending ? '  (pending — unconfirmed, still gates)' : ''}`);
    }
  }
  L.push('');
  L.push('  WHAT THIS DOES NOT ESTABLISH');
  L.push('    · the runtime labeler is a trust obligation, larger than the linter\'s. A');
  L.push('      mislabeled invocation is a gate that never fired.');
  L.push('    · effects entering context outside the tool interface are invisible here —');
  L.push('      a pasted page, a CLAUDE.md, an unobserved MCP resource. The ledger');
  L.push('      UNDER-approximates taint by construction.');
  L.push(`    · basis '${ledger.basis}': ${ledger.basis === 'observed'
    ? 'effects are recorded only on evidence, so a missed detection means a missed gate.'
    : 'effects are recorded on capability, so some gates will fire on calls that were harmless.'}`);
  L.push('    · scoped approvals trade safety for quiet: a second call to an approved');
  L.push('      channel is not re-shown.');
  L.push(`    · the guard adds ~${COMPAT.measured.guardEntryMs} ms of its own work per call, above the host's`);
  L.push(`      node cold-start floor (measured ${COMPAT.measured.nodeColdStartMs} ms on the machine this was built on).`);
  return { text: L.join('\n'), exit: 0 };
}

export const GUARD_HELP = `polycheck guard — runtime composition gate (opt-in, separate from the linter).

The linter reasons about what a policy COULD permit. The guard reasons about what
this session HAS done, and gates the call that completes a forbidden composition.
It never emits 'allow': it can add a gate, never remove one, so it reinforces the
auto-mode classifier rather than overriding it.

Usage:
  polycheck guard init [path]      run the linter, show what the guard would add,
                                   and (with --yes) write the hook wiring
  polycheck guard init . --yes     install
  polycheck guard off [path]       remove the hook wiring
  polycheck guard status <id>      a session's held effects, provenance, approvals
  polycheck guard hook pre         (internal) the PreToolUse hook entry point
  polycheck guard hook session-start   (internal)
`;
