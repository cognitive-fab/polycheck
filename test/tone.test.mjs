// Tone — polycheck describes what a policy PERMITS, it does not accuse.
//
// The substance (a BYPASS is a BYPASS) is covered elsewhere; this file guards
// the FRAMING, which is a real product property: a defender auditing their own
// policy should read "here is the reach you granted, keep or close it", never
// "you did something wrong". These assertions are deliberately about words.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { renderText } from '../src/report.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const report = (fixture) => renderText(analyze(join(HERE, 'fixtures', fixture)), { color: false });

test('the report opens by framing findings as permitted reach, not a judgment', () => {
  const text = report('vulnerable');
  assert.match(text, /describes what your policy permits/i);
  assert.match(text, /keep or close/i);
  assert.match(text, /not a judgment/i);
});

test('a finding on your own tooling is acknowledged as possibly intended', () => {
  // The exact frustration this pass answers: your own dev tooling flagged should
  // not read as an accusation. (This lives in the shell-equivalent section.)
  const text = report('messy');
  assert.match(text, /if that reach is intended[\s\S]*keep it/i);
});

test('the dismissive "trivially" is gone from shell-equivalent output', () => {
  // "trivially reachable" reads as "your policy is obviously broken". The
  // reachability is real; the sneer is not.
  const text = report('messy'); // a fixture with shell grants
  assert.doesNotMatch(text, /trivially/i);
});

test('the MANDATE section reports reach, not conduct', () => {
  // The sharpest tone risk in the tool: this section exists because a session
  // once edited a test fixture to clear a red gate — and that edit turned out to
  // be CORRECT. polycheck reads a policy, never a transcript, so it can say what
  // the policy permits and nothing at all about what anyone did with it.
  const fixture = join(HERE, 'fixtures', 'mandate-surplus');
  const text = renderText(analyze(fixture, { mandatePath: join(fixture, 'mandate.json') }), { color: false });
  assert.match(text, /MANDATE/);
  assert.doesNotMatch(text, /\bmalicious\b/i);
  assert.doesNotMatch(text, /trivially/i);
  assert.doesNotMatch(text, /\b(disabl|sabotag|cheat|tamper)/i);
  // …and the same "keep or close" posture the rest of the report takes.
  assert.match(text, /a grant someone wrote, doing what it says/i);
});

test('region glosses describe the hazard without charging the reader', () => {
  // The words a defender sees on every guard prompt. Accurate about the
  // composition, free of "malicious" / "attacker" / "exfiltration-by-injection".
  const regions = JSON.parse(readFileSync(join(HERE, '..', 'data', 'regions.json'), 'utf8'));
  for (const r of regions.regions) {
    assert.doesNotMatch(r.gloss, /\bmalicious\b/i, `${r.name}: drop "malicious"`);
    assert.doesNotMatch(r.gloss, /exfiltration-by-injection/i, `${r.name}: drop attack jargon`);
  }
});
