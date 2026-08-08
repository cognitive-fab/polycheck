// polycheck vs. auto-mode — the wedge, made runnable.
//
// Starting Aug 14 2026, Claude Code's default is auto mode: a classifier that
// reviews each shell command and, in Anthropic's testing, caught 89% of
// dangerous COMMANDS. This script shows what a per-action screen — rules OR a
// classifier — structurally cannot do, and where a compositional, deploy-time
// proof lives instead. No agent, no secret, no attacker; deterministic.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'polycheck.mjs');
const FIX = join(HERE, '..', 'test', 'fixtures', 'webfetch-egress');

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const cyan = (s) => `\x1b[36m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const rule = () => console.log(dim('─'.repeat(76)));

function polyWitness(target) {
  let out;
  try { out = execFileSync('node', [BIN, target, '--color'], { encoding: 'utf8' }); }
  catch (e) { out = e.stdout || ''; }
  const lines = out.split('\n');
  const start = lines.findIndex((l) => l.includes('WITNESS · lethal-trifecta'));
  const stop = lines.findIndex((l, i) => i > start && l.includes('assemble'));
  return start >= 0 ? lines.slice(start, stop + 1).join('\n') : out;
}

console.log('');
console.log(bold('  polycheck vs. auto-mode — where a per-action screen ends'));
console.log('');
console.log('  Auto mode (default Aug 14) reviews each command with a classifier and caught');
console.log(`  ${bold('89% of dangerous commands')} in testing. Keep that number in mind. Here is a policy: `);
console.log('');
console.log(cyan('     permissions.allow: [ "WebFetch", "Read(./**)" ]'));
console.log('');

rule();
console.log(bold('  1. What a per-action screen sees — two calls, each judged alone:'));
console.log('');
console.log(`     ${green('WebFetch https://docs.example/guide')}   ${dim('→ fetching a doc. routinely approved.')}`);
console.log(`     ${green('Read ./config/.env')}                     ${dim('→ reading a local file. routinely approved.')}`);
console.log('');
console.log(`  ${dim('Each is individually reasonable and routinely approved, so a per-action screen —')}`);
console.log(`  ${dim('classifier OR an allow/deny/ask rule — waves each one through on its own.')}`);
console.log('');

rule();
console.log(bold('  2. What the two assemble into — the state no single call reveals:'));
console.log('');
console.log(polyWitness(FIX));
console.log('');

rule();
console.log(bold('  3. The part that matters:'));
console.log('');
console.log(`  ${red('There is no per-action rule that closes this without breaking legitimate use.')}`);
console.log('  You cannot write "allow WebFetch, allow reading .env, but not both in one');
console.log('  session after untrusted input." The permission model — rules and classifier');
console.log('  alike — has no vocabulary for accumulated session state. It only sees this call.');
console.log('');
console.log(`  ${bold('polycheck does')}, because it reasons over the whole reachable state graph. It is:`);
console.log(`     • ${bold('compositional')} — the hazard is a predicate over accumulated state, not a call`);
console.log(`     • ${bold('deterministic')} — same policy ⇒ same verdict; no 89%, no distribution`);
console.log(`     • ${bold('auditable')}    — a proof/witness artifact, not "the classifier probably caught it"`);
console.log(`     • ${bold('deploy-time')}  — it runs in CI, before an agent exists, as a least-privilege gate`);
console.log('');
console.log(`  ${dim('Auto mode is the runtime probabilistic screen for the novel single command.')}`);
console.log(`  ${dim('polycheck is the deploy-time proof for the declared composition. Different layers.')}`);
console.log('');
console.log(`  ${dim('The fix here is one line — gate the egress, or drop it — and polycheck flips to')}`);
console.log(`  ${dim('PROOF. The value is that it tells you WHICH line, before you ship.')}`);
console.log('');
