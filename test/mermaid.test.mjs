// --mermaid renders a witness as a sequence diagram. It is presentation only, so
// the properties that matter are: it draws exactly the reachable compositions,
// it stays valid mermaid, and a clean policy produces no diagram (no false art).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { renderMermaid } from '../src/mermaid.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const mm = (fixture) => renderMermaid(analyze(join(HERE, 'fixtures', fixture)));

test('a bypassable policy renders one fenced sequenceDiagram per witness', () => {
  const out = mm('vulnerable');
  const blocks = out.match(/```mermaid/g) || [];
  assert.ok(blocks.length >= 1, 'at least one diagram');
  assert.match(out, /sequenceDiagram/);
  assert.match(out, /autonumber/);
  // the witness content: a step, the accumulating held set, and REACHED
  assert.match(out, /A->>A:/);
  assert.match(out, /held:/);
  assert.match(out, /A-xZ: REACHED/);
  // every opened fence is closed
  assert.equal((out.match(/```mermaid/g) || []).length, (out.match(/```/g) || []).length / 2);
});

test('the source-egress witness draws the two-step composition', () => {
  const out = mm('vulnerable');
  assert.match(out, /source-egress/);
  assert.match(out, /proprietary/);
});

test('each diagram carries the fix note — the remedy travels with the screenshot', () => {
  const out = mm('vulnerable');
  // a note inside the diagram naming the exact edit (ASCII so GitHub renders it)
  assert.match(out, /Note over A,Z: fix: gate 'egress' - move to ask\/deny: WebFetch, Bash\(curl:\*\)/);
});

test('the diagram body is pure ASCII — GitHub mermaid rejects non-ASCII', () => {
  // the "svg element not in render tree" failure. Every fenced body must be ASCII.
  const out = mm('vulnerable');
  const bodies = out.split('```mermaid').slice(1).map((s) => s.split('```')[0]);
  for (const body of bodies) {
    // eslint-disable-next-line no-control-regex
    assert.doesNotMatch(body, /[^\x00-\x7F]/, 'diagram body must be ASCII-only');
  }
});

test('a PROOF policy draws nothing — no witness, no false picture', () => {
  const out = mm('mediated');
  assert.doesNotMatch(out, /```mermaid/);
  assert.match(out, /Nothing to draw/i);
});

test('labels with mermaid-hostile characters are sanitised, not left to break the parser', () => {
  // shell specifiers carry ; # " newlines — none may reach the diagram raw.
  const out = mm('messy');
  const fences = out.split('```mermaid').slice(1).map((s) => s.split('```')[0]);
  // Newlines separate mermaid statements and are fine; the parser breaks on
  // unescaped " ; and #, so those must not survive into the diagram body.
  for (const body of fences) {
    assert.doesNotMatch(body, /["#;]/, 'diagram body must be free of parser-breaking chars');
  }
});
