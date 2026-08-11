// Why a shell grant is worst-case — and why the distinction is not cosmetic.
//
// polycheck's standard advice for a shell grant is "narrow it to fixed
// arguments". For an EXACT rule like `Bash(node bin/tool.mjs --json)` that
// advice is already satisfied, so printing it tells the reader their policy is
// fine when it is not. That is the failure mode this file guards: a report that
// is technically correct and practically misleading.
//
// The real reason an exact interpreter invocation stays unbounded is that the
// CODE it runs is writable under the same policy. polycheck names that coupling
// (it does not prove it — it reads policy, not source).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { renderText } from '../src/report.mjs';
import { loadLabels, labelEffects } from '../src/label.mjs';

const LABELS = loadLabels();
const reason = (spec) => labelEffects('Bash', spec, LABELS).shellReason;

function repo(permissions) {
  const dir = mkdtempSync(join(tmpdir(), 'pcshell-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ permissions }, null, 2));
  return dir;
}

test('shellReason: the four kinds are told apart', () => {
  assert.equal(reason('*'), 'unrestricted');
  assert.equal(reason('node:*'), 'interpreter-prefix');
  assert.equal(reason('npm run *'), 'interpreter-prefix');
  assert.equal(reason("node -e 'console.log(1)'"), 'inline-code');
  assert.equal(reason('node bin/tool.mjs . --json'), 'writable-code');
  assert.equal(reason('python3 scripts/build.py'), 'writable-code');
});

test('shellReason: an absolute path outside the repo is NOT writable-code', () => {
  // The writable-code framing claims this policy grants writes to the script.
  // For a path outside the repo that claim would be unfounded, so we must not
  // make it — the grant is still worst-case, just for the ordinary reason.
  assert.equal(reason('node /usr/local/lib/tool.mjs --json'), 'interpreter-prefix');
  assert.equal(reason('node C:\\tools\\tool.mjs'), 'interpreter-prefix');
});

test('all four kinds remain worst-case — the reason changes, the verdict does not', () => {
  for (const spec of ['*', 'node:*', "node -e 'x'", 'node bin/tool.mjs --json']) {
    const { effects, tag } = labelEffects('Bash', spec, LABELS);
    assert.equal(tag, 'shell', `${spec} must stay shell-tagged`);
    assert.deepEqual([...effects].sort(), ['egress', 'sensitive', 'untrusted']);
  }
});

test('an exact interpreter grant + an ungated write grant names BOTH sides', () => {
  const dir = repo({
    allow: ['Read(./**)', 'Edit(./src/**)', 'Bash(node bin/tool.mjs . --json)'],
    ask: ['WebFetch', 'Bash(curl:*)'],
  });
  const text = renderText(analyze(dir), { color: false });

  assert.match(text, /already fix every argument — narrowing them is DONE/);
  assert.match(text, /bin\/tool\.mjs/, 'the script must be named');
  assert.match(text, /Edit\(\.\/src\/\*\*\)/, 'the write grant that makes it bite must be named');
  assert.match(text, /Bounded ARGUMENTS are not bounded CODE/);
  rmSync(dir, { recursive: true, force: true });
});

test('with writes gated, the report says so — and still refuses to call it safe', () => {
  const dir = repo({
    allow: ['Read(./**)', 'Bash(node bin/tool.mjs . --json)'],
    ask: ['WebFetch', 'Bash(curl:*)', 'Edit(./src/**)'],
  });
  const b = analyze(dir);
  const text = renderText(b, { color: false });

  assert.equal(b.check.writableCode.writers.length, 0);
  assert.match(text, /No ungated write grant was found/);
  // The honest limit: polycheck reads policy, not source. An unknown program is
  // unknown even when nobody can edit it, so the verdict must NOT improve.
  assert.match(text, /polycheck does not read the script/);
  assert.equal(b.check.results[0].status, 'SHELL-EQUIVALENT', 'gating writes must not silently clear the verdict');
  rmSync(dir, { recursive: true, force: true });
});

test('the generic "narrow it" advice is not shown when every grant is already exact', () => {
  const dir = repo({
    allow: ['Read(./**)', 'Bash(node bin/tool.mjs . --json)'],
    ask: ['WebFetch', 'Bash(curl:*)'],
  });
  const text = renderText(analyze(dir), { color: false });
  assert.doesNotMatch(text, /open-ended: move behind/, 'no open-ended grants ⇒ no open-ended advice');
  rmSync(dir, { recursive: true, force: true });
});

test('a mixed policy gets both fixes, counted separately', () => {
  const dir = repo({
    allow: ['Read(./**)', 'Edit(./src/**)', 'Bash(npm run *)', 'Bash(node bin/tool.mjs . --json)'],
    ask: ['WebFetch', 'Bash(curl:*)'],
  });
  const b = analyze(dir);
  assert.equal(b.check.shellByReason['interpreter-prefix'].length, 1);
  assert.equal(b.check.shellByReason['writable-code'].length, 1);
  const text = renderText(b, { color: false });
  assert.match(text, /1 open-ended/);
  assert.match(text, /1 already fix every argument/);
  rmSync(dir, { recursive: true, force: true });
});
