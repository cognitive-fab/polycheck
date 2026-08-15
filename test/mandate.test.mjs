// --mandate — the second policy surface. `.claude/settings.json` says what the
// agent MAY do in this repo; a mandate says what THIS task declared it would
// produce. The check is the delta: does the policy confine the agent to the
// declaration, or reach past it with no gate?
//
// The case that motivated it: a task declaring `src/summarize.mjs` whose policy
// also grants ungated writes to `src/summarize.test.mjs` — the file that decides
// whether that output passes. Not because the path looks like a test; because it
// was never in the grant.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze, loadMandate } from '../src/index.mjs';
import { renderText, renderJson } from '../src/report.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = (name) => join(HERE, 'fixtures', name);
const run = (name) => analyze(fx(name), { mandatePath: join(fx(name), 'mandate.json') });
const one = (name) => run(name).mandate.results[0];
const text = (name) => renderText(run(name), { color: false });

// An ad-hoc repo + mandate pair, for cases no fixture needs to exist for.
function pair(permissions, mandate) {
  const dir = mkdtempSync(join(tmpdir(), 'pcmnd-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ permissions }, null, 2));
  const mp = join(dir, 'mandate.json');
  writeFileSync(mp, JSON.stringify(mandate, null, 2));
  const b = analyze(dir, { mandatePath: mp });
  rmSync(dir, { recursive: true, force: true });
  return b;
}

// ---------------------------------------------------------------------------
// the verdicts

test('a grant scoped to exactly the declared output is CONFINED', () => {
  const m = one('mandate-confined');
  assert.equal(m.status, 'CONFINED');
  assert.equal(m.witness.length, 0);
});

test('THE POINT: a broader write grant reaches the oracle of its own gate', () => {
  const m = one('mandate-surplus');
  assert.equal(m.status, 'SURPLUS');
  const paths = m.witness.map((h) => h.path);
  assert.ok(paths.includes('src/summarize.test.mjs'), `expected the sibling test, got ${paths.join(', ')}`);
  const oracle = m.witness.find((h) => h.path === 'src/summarize.test.mjs');
  assert.equal(oracle.cls, 'oracle');
  assert.equal(oracle.grant, 'Edit(./src/**)');
});

test('a write grant behind ask is CONFINED, and says WHY it is confined', () => {
  const m = one('mandate-gated');
  assert.equal(m.status, 'CONFINED');
  assert.equal(m.reason, 'mediated');
  assert.ok(m.mediators.length, 'the gate that carries it must be named');
});

test('an unrestricted write grant reaches the policy that judges it — ranked first', () => {
  const m = one('mandate-policy');
  assert.equal(m.status, 'SURPLUS');
  assert.equal(m.witness[0].cls, 'policy', 'policy outranks oracle outranks scope');
  const paths = m.witness.map((h) => h.path);
  assert.ok(paths.includes('.claude/settings.json'), 'the settings file is reachable');
  assert.ok(paths.includes('mandate.json'), 'so is the mandate itself — self-report, flagged');
});

test('no write-capable grant at all is VACUOUS, not a clean bill of health', () => {
  const b = pair({ allow: ['Read(./**)'] }, { id: 'readonly-card', outputs: ['src/a.mjs'] });
  assert.equal(b.mandate.results[0].status, 'VACUOUS');
});

test('bypassPermissions dominates: no declaration constrains anything', () => {
  const b = pair({ defaultMode: 'bypassPermissions', allow: ['Edit(./src/a.mjs)'] }, { id: 'x', outputs: ['src/a.mjs'] });
  const m = b.mandate.results[0];
  assert.equal(m.status, 'SURPLUS');
  assert.equal(m.reason, 'bypass');
});

// ---------------------------------------------------------------------------
// root tolerance — the tuning that decides whether anyone keeps this switched on

test('a spec written one directory up still matches, and the report says so', () => {
  // `app/src/summarize.mjs` in the spec, a session running INSIDE app.
  // Strict comparison would flag every legitimate output as off-mandate, and a
  // check that fires on everything gets ignored within a day.
  const m = one('mandate-root');
  assert.equal(m.status, 'CONFINED');
  assert.ok(m.assumptions.some((a) => /ROOT-TOLERANT/.test(a)), 'the loosening must be stated');
  assert.match(text('mandate-root'), /ROOT-TOLERANT/);
});

test('an explicit root strips exactly, and adds no tolerance note', () => {
  const m = one('mandate-confined'); // declares root: app
  assert.deepEqual(m.assumptions, []);
});

test('with no root, the fix suggests the path the author actually wrote', () => {
  const m = one('mandate-policy'); // outputs: docs/report.md, no root
  assert.ok(m.fix.declare.includes('docs/report.md'), `got ${JSON.stringify(m.fix.declare)}`);
});

// ---------------------------------------------------------------------------
// several mandates in one file — a run is a set of cards, not a single task

test('a file of several mandates reports one verdict each', () => {
  const b = pair({ allow: ['Edit(./src/**)'] }, {
    mandates: [
      { id: 'a-card', outputs: ['src/a.mjs'] },
      { id: 'b-card', root: '.', outputs: ['src/**'] },
    ],
  });
  const [a, bb] = b.mandate.results;
  assert.equal(a.id, 'a-card');
  assert.equal(a.status, 'SURPLUS');
  assert.equal(bb.id, 'b-card');
  assert.equal(bb.status, 'CONFINED', 'declaring the whole glob confines it by definition');
});

// ---------------------------------------------------------------------------
// found by running it against a real multi-card spec set. Every
// one of these was a wrong answer on the first real input, not a hypothetical.

test('an output that IS a test derives no oracle of its own', () => {
  // Acceptance specs routinely list the test alongside the module, so this is
  // the common case, not an edge one. Deriving from `x.test.mjs` invented
  // `x.test.test.mjs` — junk paths, and noise is what gets a check muted.
  const b = pair({ allow: ['Edit(./src/**)'] }, {
    id: 'card', root: '.', outputs: ['src/summarize.mjs', 'src/summarize.test.mjs'],
  });
  const paths = b.mandate.results[0].witness.map((h) => h.path);
  assert.ok(!paths.some((p) => /\.test\.(test|spec)\./.test(p)), `derived junk: ${paths.join(', ')}`);
  assert.ok(!paths.includes('src/summarize.test.mjs'), 'a declared test is declared, not surplus');
});

test('a directory output still derives a neighbourhood — no CONFINED by absence', () => {
  // `src/adapters/` names no file to derive from, so nothing was tested against
  // and the card passed clean. Absence of evidence must never print as a pass.
  const b = pair({ allow: ['Edit(./src/**)'] }, { id: 'adapters', root: '.', outputs: ['src/adapters/'] });
  const m = b.mandate.results[0];
  assert.equal(m.status, 'SURPLUS', 'a grant over the parent reaches outside the declared directory');
  assert.ok(m.witness.some((h) => h.path === 'src/undeclared.mjs'));
});

test('a shell grant is one shared cause, not one finding per card', () => {
  // Several cards against one policy printed the same block once each. A shell
  // grant is a property of the POLICY; repeating it per declaration is exactly
  // the noise this feature exists to avoid.
  const b = pair({ allow: ['Bash(npm run:*)'] }, {
    mandates: [{ id: 'a', root: '.', outputs: ['src/a.mjs'] }, { id: 'b', root: '.', outputs: ['src/b.mjs'] }],
  });
  assert.ok(b.mandate.results.every((m) => m.status === 'SURPLUS' && m.reason === 'shell'));
  const t = renderText(b, { color: false });
  assert.equal(t.match(/^SURPLUS · /gm).length, 1, 'one shared block');
  assert.match(t, /SURPLUS · 2 mandates/);
  assert.match(t, /closing it card-by-card would be closing the wrong thing/);
});

// ---------------------------------------------------------------------------
// loading

test('a mandate with no outputs is rejected — an empty grant declares nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pcmnd-'));
  const p = join(dir, 'm.json');
  writeFileSync(p, JSON.stringify({ id: 'x', outputs: [] }));
  assert.throws(() => loadMandate(p), /non-empty array/);
  rmSync(dir, { recursive: true, force: true });
});

test('a missing mandate file fails loudly rather than checking nothing', () => {
  assert.throws(() => loadMandate(join(HERE, 'fixtures', 'nope.json')), /could not read mandate/);
});

// ---------------------------------------------------------------------------
// opt-in: a repo that does not use this must be untouched

test('with no --mandate the bundle carries null and the report is unchanged', () => {
  const plain = analyze(fx('vulnerable'));
  assert.equal(plain.mandate, null);
  const t = renderText(plain, { color: false });
  assert.doesNotMatch(t, /MANDATE/);
  assert.doesNotMatch(t, /SURPLUS/);
  assert.equal(JSON.parse(renderJson(plain)).mandate, null);
});

test('the JSON verdict reports surplus, and carries the ranked paths', () => {
  const j = JSON.parse(renderJson(run('mandate-surplus')));
  assert.equal(j.verdict, 'surplus');
  assert.equal(j.mandate.results[0].status, 'SURPLUS');
  assert.ok(j.mandate.results[0].surplus.some((s) => s.class === 'oracle'));
});

// ---------------------------------------------------------------------------
// the claim polycheck must NOT make

test('the report states reach, and never asserts what a session did', () => {
  const t = text('mandate-surplus');
  assert.match(t, /reach/i);
  // polycheck reads a policy, not a transcript. It cannot know that anything was
  // edited to turn a gate green, and the incident that motivated this feature was
  // a LEGITIMATE fixture fix — so the report must not imply otherwise.
  assert.doesNotMatch(t, /\b(disabl|sabotag|cheat|tamper|game the)/i);
  assert.doesNotMatch(t, /turn(ed)? (a|the) gate green/i);
  assert.match(t, /nothing here says[\s\S]*what any session did/i);
});

test('the report names the invariant it cannot verify', () => {
  // The whole thing rests on the mandate being authored before and outside the
  // turn it constrains. polycheck cannot establish that, so it must say so.
  assert.match(text('mandate-surplus'), /authored BEFORE and OUTSIDE/);
});
