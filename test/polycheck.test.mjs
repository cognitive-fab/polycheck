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
