// polycheck guard — WP5: `gateKind: 'guard'` as a VERIFIED gate.
//
// This is the only part of the guard work that changes the LINTER's verdicts, so
// it gets the most adversarial tests. The claim being made is narrow and its
// guardrails are the point:
//
//   the guard is a verified gate ONLY for the regions it is configured to gate,
//   ONLY when that configuration is readable, and ONLY when the hook really is
//   polycheck's.
//
// Each of those "only"s is a fixture below. A bug here silently paints a repo
// green, which is the single worst thing this project could do.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { renderText } from '../src/report.mjs';
import { guardInit, guardOff } from '../src/guard/cli.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const fix = (n) => join(HERE, 'fixtures', n);
const run = (n) => analyze(fix(n));
const region = (b, n) => b.check.results.find((r) => r.region.name === n);

// All four fixtures share the same permissive policy — WebFetch + Read(./**) +
// Bash(curl:*) — which on its own is a BYPASS. Only the guard wiring differs, so
// any verdict change is attributable to the guard and nothing else.
test('precondition: the shared base policy is a BYPASS without any hook', () => {
  assert.equal(region(run('vulnerable'), 'lethal-trifecta').status, 'BYPASS');
});

test('guard-verified: a configured polycheck guard turns BYPASS into PROOF', () => {
  const b = run('guard-verified');
  for (const name of ['lethal-trifecta', 'credential-egress']) {
    const r = region(b, name);
    assert.equal(r.status, 'PROOF', `${name} should be proved by the guard`);
    assert.equal(r.mediated, true);
    assert.ok(r.mediators.some((m) => m.gateKind === 'guard'), 'the guard must be named as the mediator');
  }
});

test('G-a: a guard hook with NO readable config is an ordinary unverified hook', () => {
  // The dangerous case. If the config cannot be read we do not know which
  // regions the guard gates, so we must not credit it with gating any.
  const b = run('guard-unconfigured');
  for (const name of ['lethal-trifecta', 'credential-egress']) {
    assert.equal(region(b, name).status, 'INCONCLUSIVE', `${name} must not be painted green`);
  }
});

test('G-b: a hand-written hook that is not polycheck does not inherit the verdict', () => {
  // Config present, hook present — but the hook is somebody else's script.
  const b = run('guard-lookalike');
  for (const name of ['lethal-trifecta', 'credential-egress']) {
    assert.equal(region(b, name).status, 'INCONCLUSIVE');
  }
});

test('the claim is SCOPED: a partially-configured guard proves only its own regions', () => {
  const b = run('guard-partial');
  assert.equal(region(b, 'credential-egress').status, 'PROOF', 'the configured region is proved');
  assert.equal(region(b, 'lethal-trifecta').status, 'INCONCLUSIVE', 'an unconfigured region keeps its old verdict');
});

test('a guard-mediated PROOF states its argument and its scope, never a bare green', () => {
  const text = renderText(run('guard-verified'), { color: false });
  assert.match(text, /can only ADD a gate, never remove one/, 'the soundness argument must be printed');
  assert.match(text, /scope: this claim covers ONLY the regions named/, 'the scope must be printed');
  assert.match(text, /RUNTIME control/, 'it must not read like a static proof');
});

test('the guard verdict is exposed in --json for CI', () => {
  const b = run('guard-verified');
  const r = region(b, 'lethal-trifecta');
  const kinds = r.mediators.map((m) => m.gateKind);
  assert.ok(kinds.includes('guard'));
});

test('guard init/off round-trip: install flips the verdict, off restores it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pcinit-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  cpSync(join(fix('vulnerable'), '.claude', 'settings.json'), join(dir, '.claude', 'settings.json'));

  assert.equal(region(analyze(dir), 'lethal-trifecta').status, 'BYPASS', 'before: bypassable');

  // A dry run must write nothing — installing a runtime control is a decision.
  const dry = guardInit(dir, { yes: false });
  assert.equal(dry.wrote, false);
  assert.equal(region(analyze(dir), 'lethal-trifecta').status, 'BYPASS', 'dry run changed nothing');

  const done = guardInit(dir, { yes: true });
  assert.equal(done.wrote, true);
  assert.equal(region(analyze(dir), 'lethal-trifecta').status, 'PROOF', 'after install: mediated');

  guardOff(dir);
  assert.equal(region(analyze(dir), 'lethal-trifecta').status, 'BYPASS', 'off is a clean revert');

  rmSync(dir, { recursive: true, force: true });
});

test('guard init warns rather than flatters when the repo has a shell grant', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pcinit2-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'),
    JSON.stringify({ permissions: { allow: ['Bash(npm run build:*)', 'Read(./**)'] } }, null, 2));

  const out = guardInit(dir, { yes: false });
  assert.match(out.text, /run caller-chosen code/);
  assert.match(out.text, /Narrowing or gating those grants beats installing the guard/);
  rmSync(dir, { recursive: true, force: true });
});

test('guard init says so when the repo is already PROOF, instead of selling itself', () => {
  const out = guardInit(fix('mediated'), { yes: false });
  assert.match(out.text, /already PROOF/);
  assert.match(out.text, /stronger than a runtime one we run/);
  assert.equal(out.wrote, false);
});

test('the trip-wire: emit.mjs union and the verified-gate status are coupled', () => {
  // The soundness argument in check.mjs rests entirely on the guard being unable
  // to emit 'allow'. If that union widens, this test fails and forces whoever
  // widened it to revisit the verified-gate status in the same change.
  const emit = readFileSync(join(HERE, '..', 'src', 'guard', 'emit.mjs'), 'utf8');
  const check = readFileSync(join(HERE, '..', 'src', 'check.mjs'), 'utf8');
  assert.match(emit, /DECISIONS/, 'emit must go through the closed union');
  assert.doesNotMatch(emit, /permissionDecision:\s*'allow'/, "emit must never construct an 'allow'");
  assert.match(check, /decision union is ask\|deny\|passthrough/, 'check.mjs must record why guard counts as verified');
});
