// The `proprietary` effect + `source-egress` region: code leaving the machine is
// a loss even when it isn't a secret. The defining property is the case the
// credential-shaped model misses — reading SOURCE (not a secret) plus egress —
// which polycheck now names deterministically.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { loadLabels, labelEffects, coversProprietary } from '../src/label.mjs';

const LABELS = loadLabels();
const eff = (tool, spec) => [...labelEffects(tool, spec, LABELS).effects].sort();
const region = (b, n) => b.check.results.find((r) => r.region.name === n);

function repo(permissions, { assumeDefaults = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'pcsrc-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ permissions }, null, 2));
  const b = analyze(dir, { assumeDefaults });
  rmSync(dir, { recursive: true, force: true });
  return b;
}

test('a Read that covers source is proprietary; one that covers only a secret is not', () => {
  assert.ok(eff('Read', './src/**').includes('proprietary'), 'src/** reads code');
  assert.ok(!eff('Read', './src/**').includes('sensitive'), 'src/** does not reach .env');
  assert.ok(eff('Read', './.env').includes('sensitive'), '.env is a secret');
  assert.ok(!eff('Read', './.env').includes('proprietary'), 'a single .env is not source');
  // an unrestricted read is BOTH
  assert.deepEqual(eff('Read', null), ['proprietary', 'sensitive']);
});

test('coversProprietary: source globs hit, non-source globs miss', () => {
  assert.ok(coversProprietary('./src/**', LABELS));
  assert.ok(coversProprietary('**/*.py', LABELS));
  assert.equal(coversProprietary('./docs/**', LABELS), null, 'docs are not source');
  assert.equal(coversProprietary('./*.md', LABELS), null);
});

test('THE POINT: source read + egress is a BYPASS even with no secret in reach', () => {
  // Read is scoped to src/ (not sensitive), so credential-egress cannot fire —
  // there is no secret provider. But the source can still leave. Without the
  // source-egress region this policy would look clean; now it does not.
  const b = repo({ allow: ['Read(./src/**)', 'WebFetch'] }, { assumeDefaults: false });
  assert.notEqual(region(b, 'credential-egress').status, 'BYPASS', 'no secret is reachable, so the credential region does not fire');
  assert.equal(region(b, 'source-egress').status, 'BYPASS', 'but the code can leave — that is the loss the others miss');
});

test('gating the egress closes source-egress too — same control, wider coverage', () => {
  const b = repo({ allow: ['Read(./src/**)'], ask: ['WebFetch', 'Bash(curl:*)'] }, { assumeDefaults: false });
  assert.equal(region(b, 'source-egress').status, 'PROOF');
});

test('a public-repo escape hatch: dropping proprietaryPaths makes code egress a non-finding', () => {
  // If your source is public, code egress is not a loss. Override the pack.
  const dir = mkdtempSync(join(tmpdir(), 'pcpub-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ permissions: { allow: ['Read(./src/**)', 'WebFetch'] } }, null, 2));
  const labelsPath = join(dir, 'public.labels.json');
  const pack = { ...LABELS, proprietaryPaths: [], proprietaryExemplars: [] };
  writeFileSync(labelsPath, JSON.stringify(pack));
  const b = analyze(dir, { labelsPath, assumeDefaults: false });
  assert.notEqual(region(b, 'source-egress').status, 'BYPASS', 'no proprietary paths ⇒ source egress is not flagged');
  rmSync(dir, { recursive: true, force: true });
});
