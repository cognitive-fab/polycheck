#!/usr/bin/env node
// WP0 compat probe — the one experiment M0 is blocked on.
//
// It answers three questions that the whole guard design rests on, and that no
// amount of reading can settle:
//
//   Q1  What is actually on stdin for each hook event, per tool? (field names,
//       tool_input shape, is session_id present, does SessionStart carry `source`)
//   Q2  Does emitting `{}` — no permissionDecision — cleanly PASS THROUGH to the
//       normal rules + auto-mode path? This is the guard's entire "never override
//       the classifier" mechanism. If `{}` is not a passthrough, M0 stops.
//   Q3  Does a hook `ask` on a call the rules ALREADY gate produce ONE prompt or
//       TWO? (functional A1b — the union-not-sum claim.)
//
// It decides nothing and blocks nothing. Mode comes from argv:
//
//   node dump-hook.mjs pass    → emits {}                    (Q1, Q2)
//   node dump-hook.mjs ask     → emits ask + a marker reason (Q3)
//   node dump-hook.mjs session → session-start capture       (Q1)
//
// Never throws, never exits non-zero: a probe that breaks the user's session is
// a bad probe. Every failure is written to the capture file and swallowed.

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const t0 = process.hrtime.bigint();
const HERE = dirname(fileURLToPath(import.meta.url));
const CAPTURE = join(HERE, 'capture', 'hook-payloads.jsonl');
const mode = process.argv[2] || 'pass';

function readStdin() {
  return new Promise((resolve) => {
    let buf = '';
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(buf); } };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
    setTimeout(finish, 2000).unref?.();
  });
}

function record(obj) {
  try {
    mkdirSync(dirname(CAPTURE), { recursive: true });
    appendFileSync(CAPTURE, JSON.stringify(obj) + '\n', 'utf8');
  } catch { /* a probe that fails loudly is worse than one that fails quietly */ }
}

const raw = await readStdin();

let parsed = null;
let parseError = null;
try { parsed = JSON.parse(raw); } catch (e) { parseError = String(e.message || e); }

// Structural summary — we care about the SHAPE, and dumping full payloads risks
// writing file contents / secrets into a capture file. Keys and types only, with
// small scalar values kept because they are the fields we must pin.
function shape(v, depth = 0) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return depth > 3 ? 'array' : { array: v.length, of: v.length ? shape(v[0], depth + 1) : null };
  if (typeof v === 'object') {
    if (depth > 3) return 'object';
    const out = {};
    for (const k of Object.keys(v)) out[k] = shape(v[k], depth + 1);
    return out;
  }
  if (typeof v === 'string') return v.length <= 120 ? `string:${JSON.stringify(v)}` : `string(len=${v.length})`;
  return typeof v;
}

record({
  probe: 'wp0',
  mode,
  // Wall-clock, and the host's own duration_ms on post. Together these answer
  // Q3 without a human: if a permission DIALOG appeared, there is human latency
  // between the pre hook and the post hook. If the call was resolved by rules or
  // the classifier, pre→post is sub-second.
  wallMs: Date.now(),
  hostDurationMs: parsed?.duration_ms ?? null,
  argv: process.argv.slice(2),
  cwd: process.cwd(),
  rawLength: raw.length,
  parseError,
  topLevelKeys: parsed && typeof parsed === 'object' ? Object.keys(parsed) : null,
  // the fields the technical spec §2.1 wants pinned
  pinned: parsed ? {
    session_id: parsed.session_id ?? null,
    hook_event_name: parsed.hook_event_name ?? null,
    tool_name: parsed.tool_name ?? null,
    cwd: parsed.cwd ?? null,
    source: parsed.source ?? null,
    permission_mode: parsed.permission_mode ?? null,
    transcript_path: parsed.transcript_path ? '(present)' : null,
  } : null,
  shape: parsed ? shape(parsed) : null,
  entryMicros: Number(process.hrtime.bigint() - t0) / 1000,
});

// The decision. `pass` is the one that matters: if the call proceeds to its
// normal rules/classifier resolution, Q2 is answered yes.
if (mode === 'ask') {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: [
        '>>>>>>>>>>>>>>>> WP0 PROBE — READ THIS <<<<<<<<<<<<<<<<',
        '',
        'This paragraph was written by a polycheck hook, not by Claude Code.',
        'If you can read it, then a PreToolUse hook CAN attach its own',
        'explanation to a permission prompt — which is how the guard would',
        'show you the witness path.',
        '',
        'Answer either way. The command is a harmless `echo` and the probe',
        'changes nothing on disk.',
        '',
        '>>>>>>>>>>>>>>>>>>>>>>>> END PROBE <<<<<<<<<<<<<<<<<<<<<<<',
      ].join('\n'),
    },
  }));
} else {
  process.stdout.write('{}');
}
process.exit(0);
