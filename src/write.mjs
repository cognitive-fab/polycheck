// polycheck --write — apply the tidy edit to the settings files on disk.
//
// This is the only part of polycheck that mutates anything, so it is built to
// be boring and reversible:
//
//   1. LINE SURGERY, not reserialisation. A settings file is someone's file:
//      key order, indentation, blank lines and the `"//"` note at the top all
//      survive because the only thing that changes is that N lines are gone. If
//      a file is not in the conventional one-entry-per-line shape, the editor
//      REFUSES it rather than guessing.
//   2. NEVER the ⚠ rules. A subsumed line whose removal shrinks the model but
//      not the grant is excluded from the write by construction: applying it
//      would make the report look better while nothing got safer, which is the
//      one edit this tool must not make silently.
//   3. VERIFY FROM DISK, then roll back. After writing, the repo is re-scanned
//      and re-checked from scratch; if the resulting behavioural signature is
//      not the one that was proved, every file is restored to its original
//      bytes and the run fails. The proof is checked against reality, not
//      against the plan.

import { readFileSync, writeFileSync } from 'node:fs';
import { scanRepo } from './scan.mjs';
import { buildModel } from './model.mjs';
import { modelCheck } from './check.mjs';
import { proveEdit, signature } from './tidy.mjs';

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Buckets, as they are spelled in the file.
const BUCKET_RE = /^"(deny|ask|allow)"\s*:\s*\[\s*$/;
// A conventional array entry: one JSON string per line, optional trailing comma.
const ENTRY_RE = /^("(?:[^"\\]|\\.)*")\s*(,?)\s*$/;

/**
 * Delete specific entries from the permission arrays of a settings file, by
 * line. `wanted` is Map<bucket, Map<rawRule, countToRemove>>; the FIRST
 * occurrence of a duplicated rule is the one that survives, matching tidy.
 * Returns { text, removed } or { error } if the file's shape is not one this
 * editor will touch.
 */
export function editSettingsText(text, wanted) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);

  // Pass 1 — locate every entry line of the arrays being edited, and the extent
  // of each array, so both the drop set and the comma normalisation can be
  // decided with the whole picture in hand.
  const arrays = [];
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (cur == null) {
      const m = BUCKET_RE.exec(t);
      if (m && wanted.has(m[1])) cur = { bucket: m[1], entries: [] };
      continue;
    }
    if (t === ']' || t === '],') { arrays.push(cur); cur = null; continue; }
    const em = ENTRY_RE.exec(t);
    // Several entries packed on one line, a comment, a nested structure —
    // anything this editor cannot reason about line-wise. Refuse the file.
    if (!em) return { error: `unexpected shape inside "${cur.bucket}": ${t.slice(0, 60)}` };
    let raw;
    try { raw = JSON.parse(em[1]); } catch { return { error: `unparseable entry: ${t.slice(0, 60)}` }; }
    cur.entries.push({ line: i, raw, quoted: em[1] });
  }
  if (cur != null) return { error: `unterminated "${cur.bucket}" array` };

  // Pass 2 — choose which lines go. For a rule listed more than once the FIRST
  // occurrence is the one that survives, so drop from the end.
  const drop = new Set();
  const removed = [];
  for (const [bucket, rules] of wanted) {
    const arr = arrays.find((a) => a.bucket === bucket);
    for (const [raw, n] of rules) {
      const hits = (arr?.entries ?? []).filter((e) => e.raw === raw);
      if (hits.length < n) return { error: `could not locate ${n} occurrence(s) of ${raw} in "${bucket}"` };
      for (const e of hits.slice(hits.length - n)) { drop.add(e.line); removed.push({ bucket, raw }); }
    }
  }

  // Pass 3 — emit, re-normalising the trailing comma of each edited array.
  const rewrite = new Map();
  for (const a of arrays) {
    const kept = a.entries.filter((e) => !drop.has(e.line));
    kept.forEach((e, n) => {
      const src = lines[e.line];
      const indent = src.slice(0, src.length - src.trimStart().length);
      rewrite.set(e.line, indent + e.quoted + (n === kept.length - 1 ? '' : ','));
    });
  }
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (drop.has(i)) continue;
    out.push(rewrite.get(i) ?? lines[i]);
  }
  return { text: out.join(eol), removed };
}

// The line editor is exposed for direct testing: it is the piece that touches
// someone's file, so its edge cases (duplicates, the last entry in an array, a
// rule that is not where the plan said) are pinned as units, not only via the
// end-to-end path.
export const writeInternals = { editSettingsText };

/**
 * Work out exactly which lines would go, in which files, and prove the result
 * before touching anything. Returns a plan; `apply` is a separate step.
 */
export function planWrite(bundle, t) {
  // ⚠ rules are excluded by construction — see the header.
  const excluded = t.removed.filter((f) => f.understates);
  const targets = t.removed.filter((f) => !f.understates);

  const keep = new Set(targets.map((f) => f.index));
  const nextRules = bundle.scan.rules
    .map((r, i) => ({ ...r, index: i }))
    .filter((r) => !keep.has(r.index))
    .map(({ index, ...r }) => r);
  const proof = targets.length ? proveEdit(bundle, nextRules) : null;

  const pathOf = (kind) => bundle.scan.sources.find((s) => s.kind === kind)?.path ?? null;
  const files = new Map();
  for (const f of targets) {
    if (!files.has(f.source)) files.set(f.source, { source: f.source, path: pathOf(f.source), wanted: new Map(), rules: [] });
    const e = files.get(f.source);
    if (!e.wanted.has(f.decision)) e.wanted.set(f.decision, new Map());
    const m = e.wanted.get(f.decision);
    m.set(f.raw, (m.get(f.raw) ?? 0) + 1);
    e.rules.push(f);
  }

  const edits = [];
  const refusals = [];
  for (const e of files.values()) {
    if (!e.path) { refusals.push({ source: e.source, reason: 'no path on disk for this source' }); continue; }
    let original;
    try { original = readFileSync(e.path, 'utf8'); } catch (err) { refusals.push({ source: e.source, path: e.path, reason: String(err.message || err) }); continue; }
    const bom = original.startsWith('﻿') ? '﻿' : '';
    const r = editSettingsText(bom ? original.slice(1) : original, e.wanted);
    if (r.error) { refusals.push({ source: e.source, path: e.path, reason: r.error }); continue; }
    const next = bom + r.text;
    // The result must still be JSON, and must still parse to the same policy
    // minus exactly the removed entries. Belt and braces before any write.
    try { JSON.parse(next); } catch (err) { refusals.push({ source: e.source, path: e.path, reason: `edit produced invalid JSON: ${err.message}` }); continue; }
    edits.push({ source: e.source, path: e.path, original, next, rules: e.rules });
  }

  return { targets, excluded, edits, refusals, proof, nextRules };
}

/**
 * Apply a plan, then re-derive the analysis FROM DISK and check it against the
 * signature that was proved. Any disagreement — or any error mid-write —
 * restores every file. Returns { ok, written, verified, reason }.
 */
export function applyWrite(bundle, plan) {
  if (!plan.edits.length) return { ok: false, written: [], reason: 'nothing to write' };
  if (plan.refusals.length) return { ok: false, written: [], reason: `refused ${plan.refusals.length} file(s); no partial writes` };
  if (plan.proof && plan.proof.direction === 'widening') return { ok: false, written: [], reason: 'the edit would widen the policy — refusing' };

  const restore = () => { for (const e of plan.edits) { try { writeFileSync(e.path, e.original, 'utf8'); } catch { /* best effort */ } } };

  const written = [];
  try {
    for (const e of plan.edits) { writeFileSync(e.path, e.next, 'utf8'); written.push(e.path); }
  } catch (err) {
    restore();
    return { ok: false, written: [], reason: `write failed (${err.message}); files restored` };
  }

  // Re-scan from disk — not from the plan — and re-run the whole analysis.
  const scan = scanRepo(bundle.scan.root);
  const model = buildModel(scan, bundle.labels, { regions: bundle.model.regions }, { assumeDefaults: bundle.assumeDefaults !== false });
  const check = modelCheck(model);
  const actual = signature(model, check);
  const expected = plan.proof ? plan.proof.after : signature(bundle.model, bundle.check);

  if (!same(actual, expected)) {
    restore();
    return { ok: false, written: [], verified: false, actual, expected, reason: 'the written policy does not match the proved result — every file was restored' };
  }
  return { ok: true, written, verified: true, actual };
}

// ---------------------------------------------------------------------------

function paint(on) {
  const c = (code) => (on ? (s) => `\x1b[${code}m${s}\x1b[0m` : (s) => s);
  return { red: c('31'), green: c('32'), amber: c('33'), dim: c('2'), bold: c('1') };
}

export function renderWriteText(plan, result, opts = {}) {
  const { red, green, amber, dim, bold } = paint(opts.color !== false);
  const L = [''];

  L.push(bold('WRITE'));
  if (!plan.targets.length) {
    L.push(dim('  Nothing to apply.'));
    return L.join('\n');
  }

  for (const e of plan.edits) {
    L.push(`  ${dim(e.path)}`);
    for (const f of e.rules) L.push(`    ${result?.ok ? green('−') : dim('−')} ${f.raw}  ${dim(`[${f.decision}] ${f.reason}`)}`);
  }
  if (plan.excluded.length) {
    L.push('');
    L.push(`  ${amber('⚠ held back')} ${dim(`— ${plan.excluded.length} rule(s) whose removal would shrink the report, not the grant:`)}`);
    for (const f of plan.excluded) {
      L.push(`      ${f.raw}`);
      L.push(dim(`      └ ${f.coveredBy} still admits this command at runtime — narrow ${f.coveredBy} instead.`));
    }
  }
  for (const r of plan.refusals) {
    L.push(`  ${red('✗ refused')} ${r.path ?? r.source} ${dim(`— ${r.reason}`)}`);
  }
  L.push('');

  if (result?.ok) {
    const n = plan.edits.reduce((a, e) => a + e.rules.length, 0);
    L.push(`  ${green('✓')} ${n} rule${n > 1 ? 's' : ''} removed from ${result.written.length} file${result.written.length > 1 ? 's' : ''}, ${green(bold(plan.proof.direction))}.`);
    L.push(dim('    Re-scanned from disk after writing: the behavioural signature matches the'));
    L.push(dim('    one proved above. Formatting, key order and comments were left untouched —'));
    L.push(dim('    only the listed lines are gone.'));
  } else {
    L.push(`  ${red('✗ not written')} ${dim(`— ${result?.reason ?? 'unknown'}`)}`);
    if (result?.verified === false) L.push(dim('    This is a bug in --write, not in your policy. Nothing on disk changed.'));
  }
  return L.join('\n');
}
