// The example/ sandbox is a checked-in field-test bed. These tests keep it
// HONEST as the labeler evolves: the policy must still demonstrate the two-step
// composition it claims to, and the block embedded in settings.with-automode.json
// must stay byte-identical to what `--emit-automode` produces today — otherwise
// the field test would be run against a stale artifact.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { emitAutomode } from '../src/emit-automode.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EXAMPLE = join(HERE, '..', 'example');
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
