// polycheck showcase — the demo. Runs the static checker across a set of
// policies that each look reasonable and each hide a composition, then a genuinely
// safe one and a vacuously-safe one. Deterministic, offline, sub-second: no agent,
// no secret, no attacker. Screen-record this, or screenshot any single block.
//
//   node demo/showcase.mjs            the highlights
//   node demo/showcase.mjs <repo>     ...and finish on a real repo of your choice

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'polycheck.mjs');
const FIX = join(HERE, '..', 'test', 'fixtures');

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const cyan = (s) => `\x1b[36m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const rule = () => console.log(dim('━'.repeat(78)));

// Run polycheck and return its output. It exits non-zero on BYPASS/VACUOUS, so
// capture stdout from the thrown result. Trim the footer for a
// compact demo, but always keep the final verdict line.
function poly(target) {
  let out;
  try {
    out = execFileSync('node', [BIN, target, '--color'], { encoding: 'utf8' });
  } catch (e) {
    out = e.stdout || '';
  }
  const lines = out.split('\n');
  const cut = lines.findIndex((l) => l.includes('WHAT THIS CHECK DID NOT ESTABLISH'));
  const head = cut > 0 ? lines.slice(0, cut) : lines;
  const verdict = lines.filter((l) => l.includes('verdict:')).pop() || '';
  return head.join('\n').replace(/\n+$/, '') + '\n\n' + verdict;
}

const STORY = [
  ['vulnerable', 'Bash(curl:*) is granted. curl reads local files (curl -T .env) AND posts them — so this one tool is both a secret-reader and an egress channel, and completes the region alone. A 1-step BYPASS, with the minimal fix printed.'],
  ['webfetch-egress', 'Now a genuine composition. Someone gated Bash(curl) and believed egress was closed — but WebFetch carries data OUT in the URL too. Two individually-benign calls (WebFetch, then Read) assemble the trifecta; "curl" appears nowhere.'],
  ['npm-exec', 'Bash(npm run build:*) reads as "only the build script." But npm run executes whatever package.json says — a command prefix is not a security boundary. Its own verdict, SHELL-EQUIVALENT: not a composition, a shell grant.'],
  ['mcp-egress', 'No curl. No WebFetch. Just a Slack MCP tool + Read. mcp__slack__send_message is a first-class egress channel — and polycheck knows it.'],
  ['mediated', 'The fix: gate EVERY egress primitive (curl, wget, git push, AND WebFetch). Now the composition is provably closed — a PROOF, not a hope.'],
  ['safe', 'And honesty: when a region is unreachable only because no granted tool provides egress, it says INCONCLUSIVE — coverage, not safety. It never paints an unchecked thing green.'],
];

console.log('');
console.log(bold('  polycheck — static model-checking for Claude Code policies'));
console.log(dim('  every verdict below is deterministic, offline, and produced in milliseconds —'));
console.log(dim('  no agent, no secret, no attacker. the same check runs on any repo.'));
console.log('');

for (const [fixture, story] of STORY) {
  rule();
  console.log(cyan('▸ ') + story);
  console.log(dim(`  $ polycheck ${fixture}`));
  console.log('');
  console.log(poly(join(FIX, fixture)));
  console.log('');
}

const target = process.argv[2];
if (target) {
  rule();
  console.log(cyan('▸ ') + `And on a real repo you chose (${target}) — this is the credibility beat:`);
  console.log(dim(`  $ polycheck ${target}`));
  console.log('');
  console.log(poly(target));
  console.log('');
}

rule();
console.log(bold('  The point:'));
console.log('  A per-action check — including the Aug-14 auto-mode classifier — sees only one');
console.log('  call at a time, so it is structurally blind to these compositions. polycheck');
console.log('  proves them, or hands you the exact path that isn\'t gated. Run it on your repo:');
console.log('');
console.log(cyan('     node polycheck/bin/polycheck.mjs <path-to-any-repo>'));
console.log('');
