#!/usr/bin/env node
// polycheck guard — hook entry point.
//
// Thin by design: read stdin, hand off, emit. Everything that can throw is
// inside one try/catch that fails closed to 'ask' (spec functional §6.5), so a
// broken guard degrades to today's behaviour and never to a wider one.

import { emit, failClosed } from '../src/guard/emit.mjs';
import { evaluatePre, evaluatePost, evaluateSessionStart } from '../src/guard/run.mjs';

function readStdin(timeoutMs = 3000) {
  return new Promise((resolve) => {
    let buf = '';
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(buf); } };
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
    const t = setTimeout(finish, timeoutMs);
    if (typeof t.unref === 'function') t.unref();
  });
}

const sub = process.argv[2];

try {
  const raw = await readStdin();
  const payload = JSON.parse(raw || '{}');

  if (sub === 'session-start') {
    evaluateSessionStart(payload);
    process.stdout.write('{}');       // never a decision
  } else if (sub === 'pre') {
    const r = evaluatePre(payload);
    if (r.prewarn) process.stderr.write(r.prewarn + '\n'); // non-blocking notice
    emit(r.decision, r.reason);
  } else if (sub === 'post') {
    evaluatePost(payload);
    process.stdout.write('{}');       // evidence pass — never a decision
  } else {
    // An unrecognised subcommand is a wiring bug. Say so and stand aside rather
    // than gating every call in the session on our own mistake.
    process.stderr.write(`polycheck guard: unknown subcommand '${sub}'\n`);
    process.stdout.write('{}');
  }
  process.exit(0);
} catch (err) {
  failClosed(err);
  process.exit(0);
}
