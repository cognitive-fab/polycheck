// polycheck tests — the verdicts the checker must produce, plus the
// honesty properties that make the tool trustworthy as a showcase: a witness is
// a real gate-free path, a proof names its gate, a coverage gap is never painted
// as a proof, and the run is deterministic.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/index.mjs';
import { renderText, renderJson } from '../src/report.mjs';
import { loadLabels, labelEffects } from '../src/label.mjs';
import { tidyPolicy, renderTidyText, renderTidyJson, tidyInternals } from '../src/tidy.mjs';
import { planWrite, applyWrite, writeInternals } from '../src/write.mjs';
import { mkdtempSync, mkdirSync, cpSync, existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const fix = (name) => join(HERE, 'fixtures', name);
const run = (name) => analyze(fix(name));
const region = (b, n) => b.check.results.find((r) => r.region.name === n);

test('vulnerable policy: a gate-free path to the lethal trifecta exists (BYPASS)', () => {
  const b = run('vulnerable');
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'BYPASS');
  assert.ok(r.witness.length >= 1, 'has a witness path');
  // every step of a witness is an ungated, allowed edge — that is what makes it a bypass
  for (const st of r.witness) assert.equal(st.action.gate, false, 'witness step must be ungated');
  // the final state holds all three required effects
  const held = new Set(r.witness.at(-1).held);
  for (const e of r.region.requires) assert.ok(held.has(e), `final state holds ${e}`);
});

test('vulnerable policy: credential-egress is also bypassable', () => {
  const r = region(run('vulnerable'), 'credential-egress');
  assert.equal(r.status, 'BYPASS');
  const held = new Set(r.witness.at(-1).held);
  assert.ok(held.has('sensitive') && held.has('egress'));
});

test('mediated policy: every path into each region crosses a gate (PROOF)', () => {
  const b = run('mediated');
  for (const name of ['lethal-trifecta', 'credential-egress']) {
    const r = region(b, name);
    assert.equal(r.status, 'PROOF', `${name} should be a proof`);
    assert.equal(r.mediated, true, `${name} proof must be by mediation, not coverage`);
    assert.ok(r.mediators.length > 0, `${name} must name at least one gate`);
  }
});

test('coverage-gap policy: unreachable-for-lack-of-a-tool is VACUOUS, never a PROOF', () => {
  // the 'safe' fixture can READ secrets (Read(./**)) but has no tool that opens
  // egress — the region is unreachable, but only for lack of coverage, not
  // because anything is mediated — coverage, not mediation. Never green.
  const r = region(run('safe'), 'credential-egress');
  assert.equal(r.status, 'VACUOUS');
  assert.deepEqual(r.missingEffects, ['egress']);
});

test('WebFetch is BOTH ingest and egress — gating only curl leaves a bypass (fix #1)', () => {
  // webfetch-egress DENIES curl/wget and allows WebFetch + Read(./**). If WebFetch
  // were labeled ingest-only this would be a (false) coverage-safe pass; labeling
  // it egress surfaces the real bypass.
  const b = run('webfetch-egress');
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'BYPASS');
  const wf = b.model.actions.find((a) => a.tool === 'WebFetch');
  assert.ok(wf && wf.effects.includes('egress'), 'WebFetch must carry the egress effect');
  assert.ok(r.witness.some((st) => st.action.tool === 'WebFetch'), 'the witness routes through WebFetch');
  // and curl really is absent (denied), so this is not a curl finding in disguise
  assert.ok(!r.witness.some((st) => /curl/.test(String(st.action.specifier))));
});

test('an MCP tool can be an egress channel — send/create/... verbs (fix: MCP egress)', () => {
  // mcp__slack__send_message is not curl and not WebFetch, but it carries bytes to
  // an external system. With Read(./**) it completes the trifecta.
  const b = run('mcp-egress');
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'BYPASS');
  const send = b.model.actions.find((a) => a.tool === 'mcp__slack__send_message');
  assert.ok(send && send.effects.includes('egress') && send.effects.includes('untrusted'),
    'a send-verb MCP tool is untrusted + egress');
  assert.ok(r.witness.some((st) => st.action.tool.startsWith('mcp__slack__')), 'witness routes through the MCP tool');
});

test('an MCP server with an unseen tool list is worst-case, and gated by default', () => {
  // the notion server is declared in .mcp.json but never named in permissions, so
  // it is synthesized as mcp__notion__* — worst-case effects, but 'ask' (a gate).
  const b = run('mcp-egress');
  const wild = b.model.actions.find((a) => a.tool === 'mcp__notion__*');
  assert.ok(wild, 'the undeclared server becomes a wildcard action');
  assert.equal(wild.gate, true, 'an unseen MCP server prompts by default (gate)');
  for (const e of ['untrusted', 'egress']) assert.ok(wild.effects.includes(e), `unseen server is worst-case (${e})`);
});

test('a Bash prefix is not a security boundary: npm run is SHELL-EQUIVALENT (S3)', () => {
  // Bash(npm run build:*) runs arbitrary package.json code — not a composition,
  // a shell grant. It gets its own verdict, not a WITNESS.
  const b = run('npm-exec');
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'SHELL-EQUIVALENT');
  assert.ok(b.check.shellGrants.some((s) => /npm run/.test(s)), 'the shell grant is named');
  assert.equal(r.fix.kind, 'shell');
});

test('file-capable egress: Bash(curl:*) is untrusted+sensitive+egress, a 1-step BYPASS (S2)', () => {
  // curl reads local files (curl -T .env) AND posts them, so it is a secret-reader
  // and an egress channel at once — a genuine single-tool bypass, not shell-equiv.
  const b = run('vulnerable');
  const curl = b.model.actions.find((a) => /curl/.test(String(a.specifier)));
  for (const e of ['untrusted', 'sensitive', 'egress']) assert.ok(curl.effects.includes(e), `curl grants ${e}`);
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'BYPASS');
  assert.equal(r.fix.kind, 'gate', 'a BYPASS carries a minimal-fix hint');
  assert.ok(r.fix.actions.length > 0);
});

test('bypassPermissions dominates: an unrestricted shell is SHELL-EQUIVALENT', () => {
  const b = run('mcp-bypass');
  assert.equal(b.model.bypass, true);
  const r = region(b, 'lethal-trifecta');
  assert.equal(r.status, 'SHELL-EQUIVALENT');
  assert.ok(b.check.shellGrants.length > 0, 'the shell grant is named');
});

test('S1: a repo with no .claude policy is an error, not a report', () => {
  const b = analyze(fix('does-not-exist-xyz'));
  assert.equal(b.scan.hasPolicy, false);
});

test('S7: default-allowed Read is modeled by default; --no-assume-defaults is strict', () => {
  // webfetch-noread allows WebFetch (untrusted+egress) but never lists Read.
  // With assume-defaults ON (default), the auto-allowed Read supplies sensitive
  // and the region is a real BYPASS. Strict mode loses it to a coverage gap.
  const on = region(analyze(fix('webfetch-noread')), 'credential-egress');
  assert.equal(on.status, 'BYPASS');
  const off = region(analyze(fix('webfetch-noread'), { assumeDefaults: false }), 'credential-egress');
  assert.equal(off.status, 'VACUOUS');
  assert.deepEqual(off.missingEffects, ['sensitive']);
});

test('deny removes an edge: denying the egress tool changes the verdict', () => {
  // sanity: the vulnerable fixture denies Bash(rm) but NOT Bash(curl); the bypass
  // stands. This asserts deny parsing is wired (rm is absent from the model).
  const b = run('vulnerable');
  const usesRm = b.model.actions.some((a) => /rm/.test(String(a.specifier)));
  assert.equal(usesRm, false, 'denied Bash(rm:*) must not appear as an action');
});

test('gate accounting: mediated fixture has gated actions, vulnerable has none', () => {
  assert.ok(run('mediated').model.actions.some((a) => a.gate), 'mediated has gates');
  assert.ok(run('vulnerable').model.actions.every((a) => !a.gate), 'vulnerable is all ungated');
});

test('the report always states what it did NOT establish', () => {
  const text = renderText(run('mediated'), { color: false });
  assert.match(text, /auto-mode classifier is NOT counted as a gate/);
  assert.match(text, /labeler is a trust obligation/);
  assert.match(text, /confinement is out of scope/);
});

test('A1: a region mediated only by an unverified hook is INCONCLUSIVE, never PROOF', () => {
  const r = region(run('hook-catchall'), 'lethal-trifecta');
  assert.equal(r.status, 'INCONCLUSIVE');
  assert.equal(r.reason, 'hook');
  assert.ok(r.witness.length >= 1, 'shows the path the hook would have to block');
  // and it must not read as a proof
  assert.notEqual(r.status, 'PROOF');
});

test('A2: a fix never names an assumed (default-injected) rule the user did not write', () => {
  const b = run('deny-read');
  const r = region(b, 'credential-egress');
  assert.equal(r.status, 'BYPASS');
  // sensitive is supplied by injected Grep — the fix must NOT propose gating it
  assert.ok(!r.fix.actions.some((a) => /Grep|Read/.test(a)), 'fix must not name assumed reads');
  assert.deepEqual(r.fix.actions, ['WebFetch'], 'fix names the user-written egress tool');
  // N2: the assumed edge MAY appear in the witness
  assert.ok(r.witness.some((st) => st.action.source === 'default (auto-allowed)'), 'assumed edge allowed in witness');
});

test('A2: fix ranks egress first — the curl 1-step proposes closing egress on both regions', () => {
  const b = run('vulnerable');
  for (const name of ['lethal-trifecta', 'credential-egress']) {
    assert.equal(region(b, name).fix.effect, 'egress', `${name} fix targets egress`);
  }
});

test('B1: a deny that SUPPRESSED a granted edge is PROOF-by-denial', () => {
  // deny-egress grants the egress tools then denies them — the deny closed a real
  // would-be edge, so the region is closed by denial (exit 0).
  const r = region(run('deny-egress'), 'credential-egress');
  assert.equal(r.status, 'PROOF');
  assert.equal(r.reason, 'denial');
  assert.ok(r.denials.length > 0, 'names the suppressed tools doing the work');
});

test('B1 hole: denying a NEVER-GRANTED tool closes nothing — must not PROOF', () => {
  // git status + deny curl. curl was never granted, so the deny suppressed no
  // edge. It must stay INCONCLUSIVE, never a false "closed by denial".
  const r = region(run('deny-ungranted'), 'credential-egress');
  assert.notEqual(r.status, 'PROOF');            // the key property: no false green
  assert.equal(r.status, 'VACUOUS');             // coverage gap (renders as INCONCLUSIVE)
  assert.equal(r.reason, 'coverage');
});

test('B1: the stronger control never scores worse — genuine deny and ask both PROOF', () => {
  assert.equal(region(run('deny-egress'), 'credential-egress').status, 'PROOF');
  assert.equal(region(run('mediated'), 'credential-egress').status, 'PROOF');
});

test('B2: an undeclared MCP server is an assumed gate → INCONCLUSIVE, never PROOF', () => {
  const b = run('mcp-unnamed');
  const wild = b.model.actions.find((a) => a.tool === 'mcp__notion__*');
  assert.equal(wild.gateKind, 'assumed', 'synthesized MCP gate is assumed, not a verified ask');
  const r = region(b, 'credential-egress');
  assert.equal(r.status, 'INCONCLUSIVE');
  assert.match(r.reason, /assumed/);
});

test('aws s3api labels: exfil verbs flagged, benign reads stay benign, prefix grant is worst-case', () => {
  const L = loadLabels();
  const eff = (cmd) => [...labelEffects('Bash', cmd, L).effects].sort().join('+');
  // put/upload read a local --body and ship it: egress + sensitive
  assert.equal(eff('aws s3api put-object --bucket b --body ./f'), 'egress+sensitive');
  assert.equal(eff('aws s3api upload-part --body ./f'), 'egress+sensitive');
  // get-object can pull a secret object from a bucket to disk: sensitive + untrusted
  assert.equal(eff('aws s3api get-object --bucket b out'), 'sensitive+untrusted');
  // server-side / no-data verbs are NOT exfil — must stay benign
  assert.equal(eff('aws s3api copy-object --bucket b'), '');
  assert.equal(eff('aws s3api create-multipart-upload'), '');
  assert.equal(eff('aws s3api get-bucket-website --bucket b'), '');
  assert.equal(eff('aws s3api list-buckets'), '');
  // a bare prefix grant (Bash(aws s3api:*)) permits put-object — worst-case, not benign
  assert.equal(eff('aws s3api'), 'egress+sensitive+untrusted');
});

test('deterministic: same repo ⇒ byte-identical JSON', () => {
  assert.equal(renderJson(run('vulnerable')), renderJson(run('vulnerable')));
});

test('JSON verdict matches the region statuses', () => {
  const j = JSON.parse(renderJson(run('vulnerable')));
  assert.equal(j.verdict, 'bypass');
  assert.equal(JSON.parse(renderJson(run('mediated'))).verdict, 'proof');
  assert.equal(JSON.parse(renderJson(run('safe'))).verdict, 'vacuous');
});

// --- tidy: grant hygiene -----------------------------------------------------
// The dangerous failure mode of a cleanup pass is a deletion that quietly
// changes what the policy permits, so every property below is about the EDIT
// being honest, not about the categories being pretty.

test('tidy: exact duplicates and prefix-subsumed rules are DEDUP', () => {
  const t = tidyPolicy(run('messy'));
  const v = (raw) => t.findings.find((f) => f.raw === raw);
  assert.equal(v('Bash(python3 -m pip install requests -q)').verdict, 'DEDUP');
  assert.equal(v('Bash(python3 -m pip install requests -q)').coveredBy, 'Bash(python3:*)');
  assert.equal(v('Bash(ls -la)').verdict, 'DEDUP');
  // the duplicate is flagged once; the first occurrence survives
  const gits = t.findings.filter((f) => f.raw === 'Bash(git status:*)');
  assert.deepEqual(gits.map((f) => f.verdict), ['KEEP', 'DEDUP']);
});

test('tidy: a one-shot rule is PRUNEd only with evidence it cannot fire', () => {
  const t = tidyPolicy(run('messy'));
  const v = (raw) => t.findings.find((f) => f.raw === raw);
  assert.equal(v('Bash(echo "exit=$?")').verdict, 'PRUNE');
  assert.equal(v('Bash(cp /tmp/scratch-9d3f/out.txt /home/nobody-here/dest.txt)').verdict, 'PRUNE');
  // an exact-match rule with no staleness evidence is narrow, not dead — kept
  assert.equal(v('Bash(docker ps --format json)').verdict, 'MERGE');
  for (const f of t.findings) {
    if (f.verdict === 'PRUNE') assert.ok(f.evidence.length > 0, `${f.raw} must cite evidence`);
  }
});

test('tidy: a URL scheme is not mistaken for a dead drive path', () => {
  // `http://…` starts with `p:/` — a naive absolute-path probe prunes a live rule.
  const { stalenessEvidence } = tidyInternals;
  assert.deepEqual(stalenessEvidence('curl -s http://localhost:9222/json'), []);
});

test('tidy: MERGE is offered but never part of the proved edit', () => {
  const t = tidyPolicy(run('messy'));
  assert.equal(t.merges.length, 1);
  assert.equal(t.merges[0].proposal, 'Bash(docker:*)');
  assert.equal(t.merges[0].direction, 'widening');
  // a merge widens the grant, so it needs a human yes — it is not removed
  for (const f of t.removed) assert.notEqual(f.verdict, 'MERGE');
});

test('tidy: the proposed removal never widens the policy', () => {
  for (const name of ['messy', 'vulnerable', 'mediated', 'safe', 'npm-exec']) {
    const t = tidyPolicy(run(name));
    if (!t.proof) continue;
    assert.notEqual(t.proof.direction, 'widening', `${name}: tidy must never grant more`);
  }
});

test('tidy: a dedup that shrinks the model but not the grant is flagged, not celebrated', () => {
  // Bash(python3:*) still admits `python3 -m pip install …` at runtime. Deleting
  // the narrow line makes the REPORT smaller while nothing got safer — the one
  // way a hygiene pass can actively mislead.
  const t = tidyPolicy(run('messy'));
  const f = t.findings.find((x) => x.raw === 'Bash(python3 -m pip install requests -q)');
  assert.equal(f.understates, true);
  assert.ok(t.understates.includes(f));
  assert.match(f.notes.join(' '), /still admits this command at runtime/);
});

test('tidy: an already-tight policy proposes nothing', () => {
  const t = tidyPolicy(run('mediated'));
  assert.equal(t.removed.length, 0);
  assert.equal(t.proof, null);
  assert.equal(t.counts.KEEP, t.counts.total);
});

test('tidy: an effect-preserving edit leaves every region verdict identical', () => {
  const b = run('messy');
  const t = tidyPolicy(b);
  // whatever the direction, the region verdicts must survive the edit — a
  // cleanup that turns a BYPASS into a PROOF is a cleanup that lied.
  const before = b.check.results.map((r) => r.status);
  const after = b.check.results.map((r) => t.proof.after.regions[r.region.name]);
  assert.deepEqual(after, before);
});

test('tidy: never proposes deleting a shared rule because a LOCAL rule covers it', () => {
  // settings.local.json is one machine and usually gitignored; it must not be
  // the justification for narrowing the policy everyone else runs.
  const b = run('messy');
  const t = tidyPolicy(b);
  for (const f of t.findings) {
    if (f.verdict !== 'DEDUP' || f.reason !== 'subsumed') continue;
    const cover = t.findings.find((x) => x.label === f.coveredBy && x.verdict !== 'DEDUP');
    assert.ok(cover, `${f.raw}: covering rule must survive`);
    if (f.source === 'settings') assert.notEqual(cover.source, 'settings.local');
  }
});

test('tidy: shell coverage respects token boundaries', () => {
  const { shape, covers } = tidyInternals;
  const c = (a, b) => covers(shape(a), shape(b));
  assert.ok(c('python3:*', 'python3 -m pip install x'));
  assert.ok(!c('python3:*', 'python -m json.tool'), 'python3 must not cover python');
  assert.ok(!c('grep:*', 'grepfoo bar'), 'prefix must stop at a token boundary');
  assert.ok(c('*', 'anything at all'), 'unrestricted covers everything');
  assert.ok(!c('git status', 'git status --short'), 'an exact rule covers only itself');
  assert.ok(c('git *', 'git status:*'));
});

test('tidy: deterministic — same repo ⇒ byte-identical JSON', () => {
  const a = renderTidyJson(run('messy'), tidyPolicy(run('messy')));
  const b = renderTidyJson(run('messy'), tidyPolicy(run('messy')));
  assert.equal(a, b);
});

test('PowerShell rules are reported as PowerShell, not Bash', () => {
  const labels = loadLabels();
  const { notes } = labelEffects('PowerShell', 'Get-ChildItem *', labels);
  assert.ok(notes.some((n) => n.includes('PowerShell(Get-ChildItem *)')), notes.join('|'));
  assert.ok(!notes.some((n) => n.startsWith('Bash(')), 'must not mislabel the tool');
});

// --- tidy --write: the only part of polycheck that mutates anything ----------

// Copy a fixture into a scratch dir so the write tests never touch the repo.
function scratch(name) {
  const dst = mkdtempSync(join(tmpdir(), 'polycheck-'));
  mkdirSync(join(dst, '.claude'), { recursive: true });
  for (const f of ['settings.json', 'settings.local.json']) {
    const src = join(fix(name), '.claude', f);
    if (existsSync(src)) cpSync(src, join(dst, '.claude', f));
  }
  return dst;
}

test('write: removes exactly the listed lines and leaves formatting alone', () => {
  const dir = scratch('messy');
  const before = readFileSync(join(dir, '.claude', 'settings.json'), 'utf8');
  const b = analyze(dir);
  const plan = planWrite(b, tidyPolicy(b));
  const res = applyWrite(b, plan);
  assert.equal(res.ok, true, res.reason);

  const after = readFileSync(join(dir, '.claude', 'settings.json'), 'utf8');
  JSON.parse(after); // still valid JSON, trailing comma and all
  for (const g of ['exit=$?', '/tmp/scratch-9d3f/out.txt']) assert.ok(!after.includes(g), `${g} should be gone`);
  // every surviving line is byte-identical to the line it was before
  const kept = after.split('\n');
  const orig = before.split('\n');
  for (const line of kept) {
    assert.ok(orig.includes(line) || orig.includes(line + ',') || orig.includes(line.replace(/,$/, '')),
      `line was rewritten, not preserved: ${line}`);
  }
  rmSync(dir, { recursive: true, force: true });
});

test('write: the ⚠ rules are held back, never applied', () => {
  const dir = scratch('messy');
  const b = analyze(dir);
  const t = tidyPolicy(b);
  const plan = planWrite(b, t);
  assert.ok(t.understates.length > 0, 'fixture must contain an understating dedup');
  for (const f of plan.targets) assert.notEqual(f.understates, true);
  for (const f of t.understates) assert.ok(plan.excluded.includes(f));
  applyWrite(b, plan);
  // it is still in the file afterwards
  const after = readFileSync(join(dir, '.claude', 'settings.json'), 'utf8');
  assert.ok(after.includes('Bash(python3 -m pip install requests -q)'));
  rmSync(dir, { recursive: true, force: true });
});

test('write: what lands on disk is the policy that was proved', () => {
  const dir = scratch('messy');
  const b = analyze(dir);
  const plan = planWrite(b, tidyPolicy(b));
  const res = applyWrite(b, plan);
  assert.equal(res.verified, true);
  // re-analysing the written repo from scratch reproduces the proved signature
  const after = analyze(dir);
  assert.deepEqual(
    after.check.results.map((r) => r.status),
    b.check.results.map((r) => r.status),
    'region verdicts must survive the write',
  );
  rmSync(dir, { recursive: true, force: true });
});

test('write: a file it cannot edit line-wise is refused, and nothing is written', () => {
  const dir = scratch('messy');
  const path = join(dir, '.claude', 'settings.json');
  // entries packed onto one line — valid JSON, outside what the editor will touch
  const packed = '{"permissions":{"allow":["Bash(ls:*)","Bash(ls -la)","Bash(echo \\"exit=$?\\")"]}}';
  writeFileSync(path, packed, 'utf8');
  rmSync(join(dir, '.claude', 'settings.local.json'), { force: true });

  const b = analyze(dir);
  const plan = planWrite(b, tidyPolicy(b));
  assert.ok(plan.refusals.length > 0, 'must refuse a shape it cannot reason about');
  assert.equal(plan.edits.length, 0);
  const res = applyWrite(b, plan);
  assert.equal(res.ok, false);
  assert.equal(readFileSync(path, 'utf8'), packed, 'refused file must be untouched');
  rmSync(dir, { recursive: true, force: true });
});

test('write: an edit that does not reproduce the proof is rolled back', () => {
  const dir = scratch('messy');
  const b = analyze(dir);
  const plan = planWrite(b, tidyPolicy(b));
  const originals = plan.edits.map((e) => [e.path, readFileSync(e.path, 'utf8')]);
  // sabotage the plan: the bytes about to be written no longer match the proof
  plan.edits[0].next = JSON.stringify({ permissions: { allow: ['Bash(curl:*)'] } }, null, 2);
  const res = applyWrite(b, plan);
  assert.equal(res.ok, false);
  assert.equal(res.verified, false);
  for (const [p, text] of originals) assert.equal(readFileSync(p, 'utf8'), text, 'must be restored byte-for-byte');
  rmSync(dir, { recursive: true, force: true });
});

test('write: a duplicate is removed once, keeping the first occurrence', () => {
  const { editSettingsText } = writeInternals;
  const text = '{\n  "permissions": {\n    "allow": [\n      "Bash(a:*)",\n      "Bash(b:*)",\n      "Bash(a:*)"\n    ]\n  }\n}\n';
  const r = editSettingsText(text, new Map([['allow', new Map([['Bash(a:*)', 1]])]]));
  assert.equal(r.error, undefined);
  const parsed = JSON.parse(r.text);
  assert.deepEqual(parsed.permissions.allow, ['Bash(a:*)', 'Bash(b:*)']);
});

test('write: removing the last entry leaves valid JSON, not a trailing comma', () => {
  const { editSettingsText } = writeInternals;
  const text = '{\n  "permissions": {\n    "allow": [\n      "Bash(a:*)",\n      "Bash(b:*)"\n    ],\n    "deny": [\n      "Bash(rm:*)"\n    ]\n  }\n}\n';
  const r = editSettingsText(text, new Map([['allow', new Map([['Bash(b:*)', 1]])]]));
  const parsed = JSON.parse(r.text);
  assert.deepEqual(parsed.permissions.allow, ['Bash(a:*)']);
  assert.deepEqual(parsed.permissions.deny, ['Bash(rm:*)']);
});

test('write: a rule it cannot find is an error, not a silent no-op', () => {
  const { editSettingsText } = writeInternals;
  const text = '{\n  "permissions": {\n    "allow": [\n      "Bash(a:*)"\n    ]\n  }\n}\n';
  const r = editSettingsText(text, new Map([['allow', new Map([['Bash(nope:*)', 1]])]]));
  assert.match(r.error, /could not locate/);
});

test('write: nothing to remove means nothing written', () => {
  const dir = scratch('mediated');
  const b = analyze(dir);
  const plan = planWrite(b, tidyPolicy(b));
  assert.equal(plan.edits.length, 0);
  assert.equal(applyWrite(b, plan).ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test('tidy: a MERGE that would create a shell grant says so, loudly', () => {
  // Collapsing exact `node …` commands into Bash(node:*) is arbitrary execution —
  // offering that as tidy-up without naming it would be the exact mistake
  // polycheck exists to catch.
  const t = tidyPolicy(run('mergeable-shell'));
  const m = t.merges.find((x) => x.proposal === 'Bash(node:*)');
  assert.ok(m, 'the node one-shots group');
  assert.equal(m.shellEquivalent, true);
  assert.deepEqual(m.gains, ['egress', 'sensitive', 'untrusted']);
  const text = renderTidyText(run('mergeable-shell'), t, { color: false });
  assert.match(text, /DO NOT TAKE THIS ONE/);
  // and a merge that is not an execution wrapper carries no such warning
  const benign = t.merges.find((x) => x.proposal === 'Bash(sqlite3:*)');
  assert.equal(benign.shellEquivalent, false);
  assert.equal(text.match(/DO NOT TAKE THIS ONE/g).length, 1, 'only the shell one is flagged');
});
