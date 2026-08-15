// The example/ sandbox is a checked-in field-test bed. These tests keep it
// HONEST as the labeler evolves: the policy must still demonstrate the two-step
// composition it claims to, and the block embedded in settings.with-automode.json
// must stay byte-identical to what `--emit-automode` produces today — otherwise
// the field test would be run against a stale artifact.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { emitAutomode } from '../src/emit-automode.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EXAMPLE = join(HERE, '..', 'example');
const MANDATE_EX = join(EXAMPLE, 'mandate');
const region = (b, n) => b.check.results.find((r) => r.region.name === n);

test('example: the baseline policy is the two-step BYPASS it advertises', () => {
  const b = analyze(EXAMPLE);
  const lethal = region(b, 'lethal-trifecta');
  assert.equal(lethal.status, 'BYPASS', 'the sandbox must actually hide a composition');
  // a genuine composition, not a shell grant — the witness has ≥2 steps and no
  // single tool is both secret-reader and egress here.
  assert.ok(lethal.witness.length >= 2, 'must be a real multi-step path, not shell-equivalent');
  assert.equal((b.check.shellGrants || []).length, 0, 'no shell grant should muddy the demo');
});

test('example: --emit-automode names the gated egress tools and the exfil hard_deny', () => {
  const { autoMode } = emitAutomode(analyze(EXAMPLE));
  const env = autoMode.environment.join('\n');
  assert.match(env, /curl/, 'environment should mirror this policy\'s gated egress');
  assert.match(autoMode.hard_deny.join('\n'), /reads a credential file and sends it/i);
  assert.match(env, /cannot enforce this; it is guidance/i, 'composition must stay labeled as advice');
});

test('example: the embedded A/B block matches what --emit-automode produces now', () => {
  // If the compiler changes, this fails and forces the sandbox variant to be
  // regenerated — never a stale block field-tested by mistake.
  const embedded = JSON.parse(readFileSync(join(EXAMPLE, '.claude', 'settings.with-automode.json'), 'utf8')).autoMode;
  const fresh = emitAutomode(analyze(EXAMPLE)).autoMode;
  assert.deepEqual(embedded, fresh, 'regenerate settings.with-automode.json: polycheck example/ --emit-automode');
});

test('example: the fake secret is credential-SHAPED so a detector fires on it', () => {
  // The observed-basis test depends on .env matching a pattern. If someone
  // "cleaned up" the fake key past recognition, that test would silently pass.
  const env = readFileSync(join(EXAMPLE, '.env'), 'utf8');
  assert.match(env, /\bAKIA[0-9A-Z]{16}\b/, 'the fixture key must match the AWS shape');
  assert.match(env, /FAKE|EXAMPLE/i, 'and must be obviously non-secret');
});

// --- example/mandate — the --mandate sandbox -------------------------------
// Its README pastes a verdict table. These keep that paste true: the whole
// point of the sandbox is that the regions are CLEAN and the finding is real
// anyway, so if the labeler ever makes it a bypass the demo has lost its claim.

test('example/mandate: no region is broken — the finding is not a bypass in disguise', () => {
  const b = analyze(MANDATE_EX, { mandatePath: join(MANDATE_EX, 'mandate.json') });
  for (const r of b.check.results) {
    assert.ok(r.status !== 'BYPASS' && r.status !== 'SHELL-EQUIVALENT',
      `${r.region.name} became ${r.status} — the sandbox must show a mandate finding on a clean policy`);
  }
});

test('example/mandate: two cards, opposite verdicts, one policy', () => {
  const b = analyze(MANDATE_EX, { mandatePath: join(MANDATE_EX, 'mandate.json') });
  const by = Object.fromEntries(b.mandate.results.map((m) => [m.id, m]));
  assert.equal(by['summarizer-card'].status, 'SURPLUS');
  assert.equal(by['config-card'].status, 'CONFINED', 'gating the writes is the fix the README tells you to try');
  // the README names this exact path as the point of the example
  const oracle = by['summarizer-card'].witness.find((h) => h.path === 'src/summarize.test.mjs');
  assert.ok(oracle, 'the test that decides whether the declared output passes');
  assert.equal(oracle.cls, 'oracle');
});

test('example/mandate: the documented fix actually confines both cards', () => {
  // The README says narrowing the grant to the declared output clears it. If
  // that stopped being true the sandbox would be teaching a fix that does not work.
  const dir = mkdtempSync(join(tmpdir(), 'pcex-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({
    permissions: { allow: ['Read(./**)', 'Edit(./src/summarize.mjs)'], ask: ['Edit(./config/**)'] },
  }));
  const b = analyze(dir, { mandatePath: join(MANDATE_EX, 'mandate.json') });
  assert.ok(b.mandate.results.every((m) => m.status === 'CONFINED'), 'both cards should clear');
  rmSync(dir, { recursive: true, force: true });
});
