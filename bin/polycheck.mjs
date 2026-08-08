#!/usr/bin/env node
// polycheck CLI — point it at a repo, get a proof or a witness.
//
//   polycheck [path]            check a repo's .claude policy (default: cwd)
//   polycheck . --json          machine-readable output
//   polycheck . --md            a fenced block ready to paste into an issue
//   polycheck . --no-assume-defaults   strict: only explicitly-granted permissions
//   polycheck . --labels f.json --regions r.json   override the packs
//
// Exit codes:  0 proof · 1 a forbidden region is bypassable (incl. shell-equivalent)
//              · 2 inconclusive (a required effect has no granted tool) · 3 usage/no-policy
// Deterministic, offline, zero dependencies.

import { analyze, DEFAULT_LABELS, DEFAULT_REGIONS } from '../src/index.mjs';
import { renderText, renderMarkdown, renderJson } from '../src/report.mjs';

function parseArgs(argv) {
  const opts = { root: null, format: 'text', color: undefined, labels: DEFAULT_LABELS, regions: DEFAULT_REGIONS, assumeDefaults: true, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.format = 'json';
    else if (a === '--md' || a === '--markdown') opts.format = 'md';
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
    else if (a === '--no-color') opts.color = false;
    else if (a === '--color') opts.color = true;
    else if (a === '--assume-defaults') opts.assumeDefaults = true;
    else if (a === '--no-assume-defaults') opts.assumeDefaults = false;
    else if (a === '--labels') opts.labels = argv[++i];
    else if (a === '--regions') opts.regions = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('-')) { opts.error = `unknown flag: ${a}`; }
    else opts.root = a;
  }
  if (opts.root == null) opts.root = '.';
  return opts;
}

const HELP = `polycheck — a least-privilege linter for Claude Code agent policies.

Ingests a repo's .claude settings + MCP config and outputs a PROOF (every path
into a forbidden region crosses a gate) or a WITNESS (a concrete sequence of
allowed tool calls that reaches credential egress with zero gates crossed).

Usage:
  polycheck [path]                 check a repo (default: current directory)
  polycheck . --verbose            expand grouped grants + every assumption (human-readable)
  polycheck . --json | --md        machine output / paste-ready block
  polycheck . --no-assume-defaults strict: model only explicitly-granted permissions
  polycheck . --labels <file>      override the effect-label pack
  polycheck . --regions <file>     override the forbidden-region pack

Exit: 0 proof · 1 bypass (incl. shell-equivalent) · 2 inconclusive · 3 usage/no-policy

The hazard is a predicate over accumulated session state, so a per-action check —
including the auto-mode classifier — is structurally blind to it. $0, offline,
deterministic.`;

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(HELP + '\n'); process.exit(0); }
  if (opts.error) { process.stderr.write(opts.error + '\n\n' + HELP + '\n'); process.exit(3); }

  let bundle;
  try {
    bundle = analyze(opts.root, { labelsPath: opts.labels, regionsPath: opts.regions, assumeDefaults: opts.assumeDefaults });
  } catch (err) {
    process.stderr.write(`polycheck: ${err.message}\n`);
    process.exit(3);
  }

  // S1: a wrong path (or a repo with no .claude) is an ERROR, not a security
  // report. Never print a region table for a policy that does not exist.
  if (!bundle.scan.hasPolicy) {
    process.stderr.write(`polycheck: no .claude policy found at ${opts.root}\n`);
    process.exit(3);
  }

  const color = opts.color ?? (process.stdout.isTTY && !process.env.NO_COLOR);
  if (opts.format === 'json') process.stdout.write(renderJson(bundle) + '\n');
  else if (opts.format === 'md') process.stdout.write(renderMarkdown(bundle, { verbose: opts.verbose }));
  else process.stdout.write(renderText(bundle, { color, verbose: opts.verbose }) + '\n');

  const statuses = bundle.check.results.map((r) => r.status);
  if (statuses.includes('BYPASS') || statuses.includes('SHELL-EQUIVALENT')) process.exit(1);
  if (statuses.includes('VACUOUS') || statuses.includes('INCONCLUSIVE')) process.exit(2);
  process.exit(0);
}

main();
