// --emit-automode (Q6 spike) — the compiler is EXPERIMENTAL, but its two honesty
// properties are not negotiable: it must never claim to enforce composition
// (the classifier can't), and it must reflect THIS policy, not a canned block.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { emitAutomode, renderAutomode } from '../src/emit-automode.mjs';

function repo(permissions) {
  const dir = mkdtempSync(join(tmpdir(), 'pcam-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ permissions }, null, 2));
  return dir;
}
const emit = (permissions) => { const d = repo(permissions); try { return emitAutomode(analyze(d)); } finally { rmSync(d, { recursive: true, force: true }); } };

test('the emitted block has exactly the schema keys, all arrays keep $defaults', () => {
  const { autoMode } = emit({ allow: ['Read(./**)'], ask: ['WebFetch'] });
  assert.deepEqual(Object.keys(autoMode).sort(), ['allow', 'classifyAllShell', 'environment', 'hard_deny', 'soft_deny']);
  for (const k of ['allow', 'soft_deny', 'hard_deny', 'environment']) {
    assert.equal(autoMode[k][0], '$defaults', `${k} must inherit built-ins`);
  }
  assert.equal(autoMode.classifyAllShell, false);
});

test('composition guidance is labeled as advice the classifier CANNOT enforce', () => {
  // The one line that must never overclaim. If this softens, the spike lied.
  const { autoMode } = emit({ allow: ['Read(./**)'], ask: ['WebFetch'] });
  const env = autoMode.environment.join('\n');
  assert.match(env, /cannot enforce this; it is guidance/i);
});

test('soft_deny carries arbitrary-execution wrappers (intent clears them)', () => {
  const { autoMode } = emit({ allow: ['Bash(npm run *)', 'Bash(node:*)'] });
  const soft = autoMode.soft_deny.join('\n');
  assert.match(soft, /caller-chosen code/i);
  assert.match(soft, /node|npm/);
  assert.match(soft, /deliberate run is fine/i, 'must acknowledge intended use, not accuse');
});

test('a policy with no shell grants emits no soft_deny rule beyond $defaults', () => {
  const { autoMode } = emit({ allow: ['Read(./**)'], ask: ['WebFetch'] });
  assert.deepEqual(autoMode.soft_deny, ['$defaults'], 'nothing to soft-deny ⇒ nothing invented');
});

test('the environment names THIS policy\'s gated egress tools, not a canned list', () => {
  const { autoMode } = emit({ allow: ['Read(./**)'], ask: ['WebFetch', 'Bash(curl:*)'] });
  const env = autoMode.environment.join('\n');
  assert.match(env, /WebFetch/);
  assert.match(env, /curl/);
});

test('the rendered output states it does NOT replace the guard or the proof', () => {
  const d = repo({ allow: ['Read(./**)'], ask: ['WebFetch'] });
  try {
    const text = renderAutomode(analyze(d), { color: false });
    assert.match(text, /does NOT replace the guard or the proof/i);
    assert.match(text, /probabilistic/i);
    assert.match(text, /TOP LEVEL/i, 'must warn where to place it — permissions swallows it silently');
  } finally { rmSync(d, { recursive: true, force: true }); }
});
