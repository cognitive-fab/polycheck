// polycheck mandate check — the SECOND policy surface.
//
// `.claude/settings.json` says what the agent MAY do in this repo, ever. A
// mandate says what this particular task was ASKED to produce. Those are
// different grants, and the interesting quantity is the delta:
//
//   effective = settings ∩ mandate    the authority the agent actually has here
//   surplus   = settings \ mandate    what it can reach anyway, with no gate
//
// Why this rather than a fourth forbidden region: the hazard that motivated it
// — a session that can write both an output and the check that passes that
// output — cannot be pinned down by a glob. EVERY coding-agent repo grants edit
// and run-tests, so a region over `writes-tests ∧ runs-tests` fires everywhere,
// and a finding that fires everywhere is ignored within a day. The mandate is
// the discriminator: a file is off-mandate not because it looks like a test but
// because it was never in the grant. The glob only comes back at the END, to
// RANK what the surplus reaches — writing the oracle of your own gate is a
// bigger deal than writing a README.
//
// TONE (see src/report.mjs) — this reports REACH, never conduct. polycheck
// cannot know what a session did and must never imply it. "This policy permits
// ungated writes to the file that decides whether this output passes" is the
// claim; "an agent edited a test to go green" is not, and never will be.
//
// THE INVARIANT THIS RESTS ON: the mandate must be authored BEFORE and OUTSIDE
// the turn it constrains. If a session can write its own outputs list, the
// check degrades to self-report. polycheck cannot establish that statically —
// it is stated in the report footer, not assumed. (The `policy` class below
// flags the related half: a policy whose ungated writers reach the mandate file
// or the settings that judge it.)

import { readFileSync } from 'node:fs';
import { globToRe, normPath, isUnrestricted } from './label.mjs';

// The tools that write repo files. Same set model.mjs uses for `ungatedWriters`.
const WRITERS = new Set(['Edit', 'Write', 'NotebookEdit']);

// Ranked worst-first. The order is the fix order: a policy that can rewrite the
// rules it is judged by outranks one that can rewrite the check it must pass,
// which outranks ordinary undeclared reach.
export const CLASS_RANK = ['policy', 'oracle', 'scope'];
const rankOf = (c) => { const i = CLASS_RANK.indexOf(c); return i < 0 ? 99 : i; };

export const CLASS_GLOSS = {
  policy: 'the rules this agent is judged by — a write here widens every later run',
  oracle: 'the file that decides whether this output passes — writable alongside the output itself',
  scope: 'undeclared reach — permitted by the policy, not asked for by the task',
};

// The policy surface itself. Fixed, not derived: these are the same four files
// scanRepo() reads, plus the mandate file when it lives in the repo.
const POLICY_EXEMPLARS = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.claude/polycheck.guard.json',
  '.mcp.json',
];

// Gate configuration that is not per-output — reachable regardless of what the
// mandate declared, so it is derived once rather than per output.
const FIXED_ORACLE_EXEMPLARS = [
  'package.json',
  '.github/workflows/ci.yml',
];

const FIXED_SCOPE_EXEMPLARS = ['README.md'];

// ---------------------------------------------------------------------------
// loading

function normOutputs(outputs, root) {
  // Effective declared paths, plus the root-tolerance variants. A spec written
  // by an orchestrator says `app/src/summarize.mjs` while the session runs
  // INSIDE app — comparing those strictly flags every legitimate output as
  // off-mandate, and a warning that fires on everything is the exact failure
  // this feature exists to prevent.
  const declared = [];   // every form a path may legitimately take — used for matching
  const effective = [];  // one preferred form per output — used when suggesting a grant
  const notes = [];
  const r = root != null ? normPath(root).replace(/\/+$/, '') : null;
  for (const o of outputs) {
    const p = normPath(o);
    if (r && (p === r || p.startsWith(r + '/'))) {
      const inner = p.slice(r.length + 1);
      declared.push(inner);
      effective.push(inner);
      continue;
    }
    // No declared root: keep what was written as the canonical form (a fix line
    // must suggest the path the author recognises), and add the leading-segment-
    // stripped variant as an ADDITIONAL match candidate only.
    declared.push(p);
    effective.push(p);
    if (r == null && p.includes('/')) {
      const stripped = p.slice(p.indexOf('/') + 1);
      declared.push(stripped);
      notes.push(`ROOT-TOLERANT: '${p}' also matches '${stripped}'. The mandate declares no "root", so the leading path segment is not required to line up with the scanned repo — an orchestrator's spec is usually written one directory up from where the session runs. Set "root" in the mandate for an exact comparison.`);
    }
  }
  return { declared: [...new Set(declared)], effective: [...new Set(effective)], notes };
}

function normOne(m, i) {
  if (m == null || typeof m !== 'object' || Array.isArray(m)) {
    throw new Error(`mandate ${i}: expected an object with an "outputs" array`);
  }
  if (!Array.isArray(m.outputs) || m.outputs.length === 0) {
    throw new Error(`mandate ${m.id ?? i}: "outputs" must be a non-empty array of path patterns — that array IS the grant, so an empty one declares nothing`);
  }
  for (const o of m.outputs) {
    if (typeof o !== 'string' || !o.trim()) throw new Error(`mandate ${m.id ?? i}: every entry in "outputs" must be a non-empty string`);
  }
  const { declared, effective, notes } = normOutputs(m.outputs, m.root ?? null);
  return {
    id: String(m.id ?? `mandate-${i + 1}`),
    gloss: m.gloss ? String(m.gloss) : null,
    root: m.root != null ? String(m.root) : null,
    outputs: m.outputs.map(String),
    declared,
    effective,
    notes,
  };
}

export function loadMandate(path) {
  let data;
  try {
    data = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    throw new Error(`could not read mandate ${path}: ${err.message}`);
  }
  const list = Array.isArray(data) ? data
    : Array.isArray(data?.mandates) ? data.mandates
    : [data];
  if (!list.length) throw new Error(`mandate ${path}: no mandates found`);
  return { sourcePath: path, mandates: list.map(normOne) };
}

// ---------------------------------------------------------------------------
// exemplars — concrete off-mandate paths, so a finding names a FILE rather than
// asserting an abstract glob-containment the reader cannot check.

// A path that is already a test/spec/fixture. It has no oracle of its own — it
// IS one — so deriving from it yields `summarize.test.test.mjs` and friends.
// Real specs declare these (an acceptance node routinely lists the test
// alongside the module), so without this the feature invents junk paths on the
// first real input it sees.
const IS_ORACLE_PATH = /(^|[./-])(test|tests|spec|specs|__tests__|fixtures?)([./-]|$)/i;

function oracleExemplarsFor(p) {
  // Only a concrete file has an oracle we can name. A glob or directory output
  // (`src/**`, `src/adapters/`) has no single base to derive from, so it
  // contributes nothing here — the fixed exemplars still apply.
  if (p.includes('*') || p.endsWith('/')) return [];
  if (IS_ORACLE_PATH.test(p)) return [];
  const slash = p.lastIndexOf('/');
  const dir = slash < 0 ? '' : p.slice(0, slash);
  const file = slash < 0 ? p : p.slice(slash + 1);
  const dot = file.lastIndexOf('.');
  const base = dot <= 0 ? file : file.slice(0, dot);
  const ext = dot <= 0 ? '' : file.slice(dot);
  const here = (n) => (dir ? `${dir}/${n}` : n);
  return [
    here(`${base}.test${ext}`),
    here(`${base}.spec${ext}`),
    `test/${base}.test${ext}`,
    `tests/${base}.test${ext}`,
    `__tests__/${base}.test${ext}`,
    `test/fixtures/${base}.json`,
  ];
}

function scopeExemplarsFor(p) {
  if (p.includes('*')) return [];
  // A directory output (`src/adapters/`) still has a neighbourhood: a grant that
  // covers its PARENT reaches files the card never asked for. Without this a
  // directory-declaring card derives no exemplar at all and scores CONFINED by
  // absence of evidence — the one verdict this report must never invent.
  if (p.endsWith('/')) {
    const parent = p.replace(/\/+$/, '');
    const up = parent.lastIndexOf('/');
    return [up < 0 ? 'undeclared.mjs' : `${parent.slice(0, up)}/undeclared.mjs`];
  }
  const slash = p.lastIndexOf('/');
  const dir = slash < 0 ? '' : p.slice(0, slash);
  const file = slash < 0 ? p : p.slice(slash + 1);
  const dot = file.lastIndexOf('.');
  const ext = dot <= 0 ? '' : file.slice(dot);
  // A sibling in the same directory with a different base: the plainest form of
  // "the policy reaches further than the task declared".
  return [dir ? `${dir}/undeclared${ext || '.mjs'}` : `undeclared${ext || '.mjs'}`];
}

// Where does the mandate file itself sit, relative to the scanned repo? Only a
// mandate stored INSIDE the repo is reachable by the repo's own write grants;
// one kept outside is exactly what the footer recommends and contributes no
// exemplar.
function mandatePathInRepo(sourcePath, root) {
  if (!sourcePath) return null;
  const s = normPath(String(sourcePath).replace(/\\/g, '/'));
  const r = normPath(String(root ?? '.').replace(/\\/g, '/')).replace(/\/+$/, '');
  if (!r || r === '.' || r === '') return s;
  if (s === r) return null;
  return s.startsWith(r + '/') ? s.slice(r.length + 1) : null;
}

function buildExemplars(mandate, sourcePath, root) {
  const declaredRes = mandate.declared.map((d) => { try { return globToRe(d); } catch { return null; } }).filter(Boolean);
  const isDeclared = (p) => declaredRes.some((re) => re.test(p));

  const policy = [...POLICY_EXEMPLARS];
  // A mandate stored inside the repo is itself a writable target, and a policy
  // that can rewrite the grant it is checked against has no grant at all.
  const rel = mandatePathInRepo(sourcePath, root);
  if (rel && !policy.includes(rel)) policy.push(rel);

  const oracle = [...FIXED_ORACLE_EXEMPLARS];
  const scope = [...FIXED_SCOPE_EXEMPLARS];
  for (const d of mandate.declared) {
    for (const e of oracleExemplarsFor(d)) oracle.push(e);
    for (const e of scopeExemplarsFor(d)) scope.push(e);
  }

  // Highest severity wins when a path lands in more than one bucket, and a path
  // the mandate ALREADY declared is not surplus at all.
  const out = new Map();
  for (const [cls, list] of [['policy', policy], ['oracle', oracle], ['scope', scope]]) {
    for (const p of list) {
      const n = normPath(p);
      if (!n || isDeclared(n)) continue;
      if (!out.has(n)) out.set(n, cls);
    }
  }
  return [...out.entries()].map(([path, cls]) => ({ path, cls }));
}

// ---------------------------------------------------------------------------
// the check

function reaches(specifier, path) {
  if (isUnrestricted(specifier)) return true;
  let re;
  try { re = globToRe(normPath(specifier)); } catch { return false; }
  return re.test(path) || re.test('/' + path);
}

const grantLabel = (g) => (g.tool ? `${g.tool}${g.specifier != null ? `(${g.specifier})` : ''}` : g.raw);

export function checkMandate(bundle, mandate) {
  const { scan, model, check } = bundle;
  const writers = model.ungatedWriters || [];
  const shellGrants = check.shellGrants || [];

  // Every write-capable rule in the ruleset, regardless of decision — needed to
  // tell "confined because it is gated" from "confined because nothing here can
  // write at all". Those are different verdicts and must not print the same.
  const anyWriteRule = scan.rules.some((r) => WRITERS.has(r.tool));
  const gatedWriteRules = scan.rules.filter((r) => WRITERS.has(r.tool) && r.decision !== 'allow');

  const results = mandate.mandates.map((m) => {
    const assumptions = [...m.notes];
    const exemplars = buildExemplars(m, mandate.sourcePath, scan.root);

    // bypassPermissions dominates exactly as it does for regions: no rule is
    // consulted, so every declaration is advisory.
    if (model.bypass) {
      return {
        id: m.id, gloss: m.gloss, outputs: m.outputs, root: m.root,
        status: 'SURPLUS', reason: 'bypass', witness: [], assumptions,
        fix: { kind: 'bypass' },
      };
    }

    // An ungated arbitrary-execution shell writes anywhere a file can be
    // written, so it is surplus by construction and no glob narrowing touches
    // it. Reported as its own class because the fix is the shell fix.
    const shell = shellGrants.length ? shellGrants : null;

    const hits = [];
    for (const w of writers) {
      for (const ex of exemplars) {
        if (reaches(w.specifier, ex.path)) hits.push({ grant: grantLabel(w), raw: w.raw, source: w.source ?? null, path: ex.path, cls: ex.cls });
      }
    }
    hits.sort((a, b) => rankOf(a.cls) - rankOf(b.cls) || a.path.localeCompare(b.path));

    if (hits.length || shell) {
      const worst = hits.length ? hits[0].cls : 'scope';
      return {
        id: m.id, gloss: m.gloss, outputs: m.outputs, root: m.root,
        status: 'SURPLUS', reason: shell && !hits.length ? 'shell' : 'writer',
        witness: hits, shell, assumptions,
        fix: {
          kind: shell && !hits.length ? 'shell' : 'confine',
          cls: worst,
          grants: [...new Set(hits.map((h) => h.grant))],
          declare: m.effective,
        },
      };
    }

    if (!anyWriteRule && !shell) {
      return {
        id: m.id, gloss: m.gloss, outputs: m.outputs, root: m.root,
        status: 'VACUOUS', reason: 'coverage', witness: [], assumptions, fix: null,
      };
    }

    return {
      id: m.id, gloss: m.gloss, outputs: m.outputs, root: m.root,
      status: 'CONFINED', reason: gatedWriteRules.length ? 'mediated' : 'narrow',
      witness: [], mediators: gatedWriteRules.map((r) => ({ raw: r.raw, decision: r.decision, source: r.source })),
      assumptions, fix: null,
    };
  });

  return { sourcePath: mandate.sourcePath, results };
}
