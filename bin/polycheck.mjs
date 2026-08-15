#!/usr/bin/env node
// polycheck CLI — point it at a repo, get a proof or a witness.
//
//   polycheck [path]            check a repo's .claude policy (default: cwd)
//   polycheck . --tidy          grant hygiene — dedup/prune/merge, with a proof
//   polycheck . --write         apply the tidy edit, verified from disk after writing
//   polycheck . --json          machine-readable output
//   polycheck . --md            a fenced block ready to paste into an issue
//   polycheck . --no-assume-defaults   strict: only explicitly-granted permissions
//   polycheck . --mandate card.json    also check the policy against a task's declared outputs
//   polycheck . --labels f.json --regions r.json   override the packs
//
// Exit codes:  0 proof · 1 a forbidden region is bypassable (incl. shell-equivalent),
//                or a mandate reaches past what it declared
//              · 2 inconclusive (a required effect has no granted tool) · 3 usage/no-policy
// Deterministic, offline, zero dependencies.

import { analyze, tidyPolicy, DEFAULT_LABELS, DEFAULT_REGIONS } from '../src/index.mjs';
import { renderText, renderMarkdown, renderJson } from '../src/report.mjs';
import { renderMermaid } from '../src/mermaid.mjs';
import { renderTidyText, renderTidyJson } from '../src/tidy.mjs';
import { emitAutomode, renderAutomode } from '../src/emit-automode.mjs';
import { planWrite, applyWrite, renderWriteText } from '../src/write.mjs';

// `polycheck guard …` is a separate, opt-in product that shares this binary.
// It is dispatched before flag parsing so its own subcommand grammar applies.
if (process.argv[2] === 'guard') {
  const { guardInit, guardOff, guardStatus, guardReset, GUARD_HELP } = await import('../src/guard/cli.mjs');
  const sub = process.argv[3];
  const rest = process.argv.slice(4);
  const yes = rest.includes('--yes');
  const pathArg = rest.find((a) => !a.startsWith('-')) || '.';
  let out;
  if (sub === 'hook') {
    // Documented in GUARD_HELP, so it must actually work. Delegate to the hook
    // binary with stdin/stdout inherited — the host pipes JSON through it.
    const { spawnSync } = await import('node:child_process');
    const { fileURLToPath } = await import('node:url');
    const { dirname, join } = await import('node:path');
    const bin = join(dirname(fileURLToPath(import.meta.url)), 'polycheck-guard.mjs');
    const r = spawnSync(process.execPath, [bin, ...process.argv.slice(4)], { stdio: 'inherit' });
    process.exit(r.status ?? 0);
  }
  if (sub === 'init') out = guardInit(pathArg, { yes });
  else if (sub === 'off') out = guardOff(pathArg);
  else if (sub === 'status') out = guardStatus('.', rest.find((a) => !a.startsWith('-')));
  else if (sub === 'reset') out = guardReset(rest.find((a) => !a.startsWith('-')), { all: rest.includes('--all') });
  else out = { text: GUARD_HELP, exit: sub ? 3 : 0 };
  process.stdout.write(out.text + '\n');
  process.exit(out.exit ?? 0);
}

function parseArgs(argv) {
  const opts = { root: null, format: 'text', color: undefined, labels: DEFAULT_LABELS, regions: DEFAULT_REGIONS, assumeDefaults: true, verbose: false, tidy: false, write: false, mandate: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.format = 'json';
    else if (a === '--md' || a === '--markdown') opts.format = 'md';
    else if (a === '--mermaid') opts.format = 'mermaid';
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
    else if (a === '--tidy') opts.tidy = true;
    else if (a === '--emit-automode') opts.emitAutomode = true;
    else if (a === '--write') { opts.tidy = true; opts.write = true; }
    else if (a === '--no-color') opts.color = false;
    else if (a === '--color') opts.color = true;
    else if (a === '--assume-defaults') opts.assumeDefaults = true;
    else if (a === '--no-assume-defaults') opts.assumeDefaults = false;
    else if (a === '--labels') opts.labels = argv[++i];
    else if (a === '--regions') opts.regions = argv[++i];
    else if (a === '--mandate') opts.mandate = argv[++i];
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
  polycheck . --tidy               grant hygiene: which rules are redundant/dead,
                                   with a proof of what removing them changes
  polycheck . --write              apply that edit (line surgery; re-verified from
                                   disk and rolled back if it does not match)
  polycheck . --verbose            expand grouped grants + every assumption (human-readable)
  polycheck . --json | --md        machine output / paste-ready block
  polycheck . --mermaid            each witness as a mermaid sequence diagram
  polycheck . --no-assume-defaults strict: model only explicitly-granted permissions
  polycheck . --mandate <file>     also check the policy against a task's declared
                                   OUTPUTS: does it confine the agent to what the
                                   task asked for, or reach past it with no gate?
  polycheck . --labels <file>      override the effect-label pack
  polycheck . --regions <file>     override the forbidden-region pack

Exit: 0 proof · 1 bypass (incl. shell-equivalent) or mandate surplus · 2 inconclusive
      · 3 usage/no-policy
      --tidy is advisory and always exits 0 — it never gates a build.
      --write exits 4 if it refused or rolled back (nothing changed on disk).

The hazard is a predicate over accumulated session state, so a per-action check —
including the auto-mode classifier — is structurally blind to it. $0, offline,
deterministic.`;

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(HELP + '\n'); process.exit(0); }
  if (opts.error) { process.stderr.write(opts.error + '\n\n' + HELP + '\n'); process.exit(3); }

  let bundle;
  try {
    bundle = analyze(opts.root, { labelsPath: opts.labels, regionsPath: opts.regions, assumeDefaults: opts.assumeDefaults, mandatePath: opts.mandate });
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

  // --emit-automode (EXPERIMENTAL, Q6): compile the policy into auto-mode
  // classifier rules and PRINT them. Print-only by design — it never touches
  // settings, so it is zero-risk to run; you copy what you want. Exits 0.
  if (opts.emitAutomode) {
    if (opts.format === 'json') {
      process.stdout.write(JSON.stringify(emitAutomode(bundle), null, 2) + '\n');
    } else {
      process.stdout.write(renderAutomode(bundle, { color }) + '\n');
    }
    process.exit(0);
  }

  // --tidy is a hygiene pass, not the security check: it reports which grants
  // can go and PROVES what removing them does to the blast radius. It never
  // writes and never gates — a tight ruleset and a safe one are different
  // questions, so it always exits 0 and leaves the verdict to the normal run.
  if (opts.tidy) {
    const t = tidyPolicy(bundle);
    // --write applies only the proved, non-⚠ removals, then re-verifies from
    // disk and rolls back if the result is not what was proved.
    const plan = opts.write ? planWrite(bundle, t) : null;
    const result = plan ? applyWrite(bundle, plan) : null;

    if (opts.format === 'json') {
      const j = JSON.parse(renderTidyJson(bundle, t));
      if (plan) {
        j.write = {
          applied: !!result?.ok,
          reason: result?.ok ? null : result?.reason ?? null,
          files: plan.edits.map((e) => ({ path: e.path, removed: e.rules.map((f) => f.raw) })),
          heldBack: plan.excluded.map((f) => ({ rule: f.raw, coveredBy: f.coveredBy })),
          refused: plan.refusals,
        };
      }
      process.stdout.write(JSON.stringify(j, null, 2) + '\n');
    } else {
      const useColor = opts.format === 'md' ? false : color;
      let text = renderTidyText(bundle, t, { color: useColor, verbose: opts.verbose, willWrite: !!plan });
      if (plan) text += '\n' + renderWriteText(plan, result, { color: useColor });
      process.stdout.write(opts.format === 'md' ? '```\n' + text + '\n```\n' : text + '\n');
    }
    // A refused or rolled-back write is a failure the caller must see; a clean
    // dry run and a clean write are both success.
    process.exit(plan && !result?.ok && plan.targets.length ? 4 : 0);
  }

  if (opts.format === 'json') process.stdout.write(renderJson(bundle) + '\n');
  else if (opts.format === 'md') process.stdout.write(renderMarkdown(bundle, { verbose: opts.verbose }));
  else if (opts.format === 'mermaid') process.stdout.write(renderMermaid(bundle) + '\n');
  else process.stdout.write(renderText(bundle, { color, verbose: opts.verbose }) + '\n');

  const statuses = bundle.check.results.map((r) => r.status);
  // A mandate SURPLUS joins the existing CI-failing code rather than claiming a
  // fifth: an adopted `polycheck . || exit 1` step catches it with no edit.
  const mandateStatuses = (bundle.mandate?.results || []).map((m) => m.status);
  if (statuses.includes('BYPASS') || statuses.includes('SHELL-EQUIVALENT') || mandateStatuses.includes('SURPLUS')) process.exit(1);
  if (statuses.includes('VACUOUS') || statuses.includes('INCONCLUSIVE') || mandateStatuses.includes('VACUOUS')) process.exit(2);
  process.exit(0);
}

main();
