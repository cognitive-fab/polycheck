#!/usr/bin/env node
// Q6 field-test probe — logs what the host reports around an auto-mode decision.
// Decides nothing (emits {}), never blocks, never throws. Mirror of WP0's probe.
// Mode from argv: "req" (PermissionRequest) | "deny" (PermissionDenied).

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CAPTURE = join(HERE, 'capture', 'automode-decisions.jsonl');
const mode = process.argv[2] || 'req';

function read() {
  return new Promise((resolve) => {
    let b = ''; let done = false;
    const fin = () => { if (!done) { done = true; resolve(b); } };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { b += c; });
    process.stdin.on('end', fin);
    process.stdin.on('error', fin);
    setTimeout(fin, 2000).unref?.();
  });
}

const raw = await read();
let p = null; try { p = JSON.parse(raw); } catch { /* keep raw */ }

// Shape only — keys and small scalars — so we never write a command's file
// contents or a secret into the capture log.
function shape(v, d = 0) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return { array: v.length };
  if (typeof v === 'object') { const o = {}; for (const k of Object.keys(v)) o[k] = d > 3 ? typeof v[k] : shape(v[k], d + 1); return o; }
  if (typeof v === 'string') return v.length <= 100 ? `str:${JSON.stringify(v)}` : `str(len=${v.length})`;
  return typeof v;
}

try {
  mkdirSync(dirname(CAPTURE), { recursive: true });
  appendFileSync(CAPTURE, JSON.stringify({
    mode,
    event: p?.hook_event_name ?? null,
    tool: p?.tool_name ?? null,
    permission_mode: p?.permission_mode ?? null,
    topLevelKeys: p && typeof p === 'object' ? Object.keys(p) : null,
    shape: p ? shape(p) : null,
  }) + '\n', 'utf8');
} catch { /* a probe that fails is quieter than one that breaks the session */ }

process.stdout.write('{}');
process.exit(0);
