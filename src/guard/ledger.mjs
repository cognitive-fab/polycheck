// polycheck guard — the session effect ledger.
//
// The linter takes the worst case over everything a policy COULD grant. The
// guard knows what the session actually did, so it tracks the real accumulated
// effect set. Same monotone model as src/check.mjs: an effect, once held, is
// held for the rest of the session, so a state is a subset of the effect
// universe and "does this call complete a forbidden region" is a mask test.
//
// Invariants this file exists to hold (spec/runtime-guard.technical.md §3.3):
//   I1  append-only. `steps` only grows; `held.capability` and `held.observed`
//       only grow. NOTHING is ever retracted — `observed` is a second monotone
//       set, not a correction of the first.
//   I2  persist before the decision is emitted. A crash between deciding and
//       recording must not lose taint, so the write is atomic (temp + rename).
//   I3  a missing ledger is an EMPTY ledger, never an error. Empty means more
//       gates, not fewer.
//   I4  a corrupt or digest-mismatched ledger is quarantined, never repaired,
//       and the session continues in sticky-ask.
//
// No clock in the decision path: `wallMs` is recorded for forensics only and is
// never read by decide(). Determinism (functional A4) depends on that.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, unlinkSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

export const LEDGER_VERSION = 1;

// Where session state lives. NEVER inside the repo: a ledger under .claude/
// would be committed, shared, and trusted across machines.
export function stateDir(env = process.env) {
  if (env.POLYCHECK_STATE_DIR) return env.POLYCHECK_STATE_DIR;
  if (process.platform === 'win32') {
    return join(env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'polycheck');
  }
  return join(env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'polycheck');
}

// A session id arrives from an untrusted-ish payload and becomes a filename.
// Anything outside the safe set is hashed rather than rejected: a session we
// cannot name is still a session we must track.
function safeId(sessionId) {
  const s = String(sessionId ?? '');
  return /^[A-Za-z0-9._-]{1,128}$/.test(s) ? s : 'h' + createHash('sha256').update(s).digest('hex').slice(0, 32);
}

export function ledgerPath(sessionId, env = process.env) {
  return join(stateDir(env), 'sessions', `${safeId(sessionId)}.json`);
}

// The digest covers everything except itself. Tamper-EVIDENT, not tamper-proof:
// an attacker with local write access has already won at a lower layer, and the
// threat model says so rather than pretending otherwise.
function digestOf(led) {
  const { digest, ...rest } = led;
  return 'sha256:' + createHash('sha256').update(JSON.stringify(rest)).digest('hex');
}

export function emptyLedger(sessionId, cwd, opts = {}) {
  return {
    v: LEDGER_VERSION,
    sessionId: String(sessionId ?? ''),
    cwd: cwd ?? null,
    parent: opts.parent ?? null,
    basis: opts.basis ?? 'capability',
    steps: [],
    held: { capability: [], observed: [] },
    entered: [],
    grants: [],
    stickyAsk: opts.stickyAsk ?? false,
    stickyReason: opts.stickyReason ?? null,
  };
}

// Shape validation is deliberately strict: a ledger we cannot fully understand
// is quarantined (I4), because a half-read ledger under-reports held effects and
// under-reporting is exactly the failure that lets a region complete unseen.
function looksLikeLedger(o) {
  return !!o && o.v === LEDGER_VERSION
    && Array.isArray(o.steps) && Array.isArray(o.entered) && Array.isArray(o.grants)
    && !!o.held && Array.isArray(o.held.capability) && Array.isArray(o.held.observed);
}

/**
 * Load a session's ledger.
 * @returns {{ledger: object, status: 'fresh'|'loaded'|'quarantined', detail?: string}}
 */
export function loadLedger(sessionId, cwd, env = process.env) {
  const path = ledgerPath(sessionId, env);
  if (!existsSync(path)) return { ledger: emptyLedger(sessionId, cwd), status: 'fresh' }; // I3

  let parsed = null;
  let detail = null;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    detail = `unparseable: ${String(err.message || err)}`;
  }

  if (parsed && !detail) {
    if (!looksLikeLedger(parsed)) detail = 'shape not recognised';
    else if (parsed.digest !== digestOf(parsed)) detail = 'digest mismatch — ledger was modified out of band';
  }

  if (detail) {
    // I4: quarantine, do not repair. The replacement ledger is empty AND sticky:
    // every region-relevant call asks for the rest of the session, with the
    // reason stated. An empty ledger alone would silently launder held taint.
    try {
      renameSync(path, path + '.quarantined');
    } catch { /* best effort; the sticky flag is what carries the safety */ }
    return {
      ledger: emptyLedger(sessionId, cwd, { stickyAsk: true, stickyReason: detail }),
      status: 'quarantined',
      detail,
    };
  }

  return { ledger: parsed, status: 'loaded' };
}

// Atomic write (I2). The temp file is created in the same directory so the
// rename is a same-filesystem operation and therefore atomic.
export function saveLedger(ledger, env = process.env) {
  const path = ledgerPath(ledger.sessionId, env);
  const dir = join(stateDir(env), 'sessions');
  mkdirSync(dir, { recursive: true });

  const out = { ...ledger };
  delete out.digest;
  out.digest = digestOf(out);

  const tmp = join(dir, `.${safeId(ledger.sessionId)}.${process.pid}.tmp`);
  writeFileSync(tmp, JSON.stringify(out), { encoding: 'utf8', mode: 0o600 });
  try {
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
  return path;
}

// Default cap. Head-truncation, but never at the cost of a witness: the first
// step that contributed each held effect is what a witness points at, so those
// steps are pinned and only the rest are dropped.
export const DEFAULT_STEP_CAP = 2000;

export function truncateSteps(ledger, cap = DEFAULT_STEP_CAP) {
  if (ledger.steps.length <= cap) return ledger;

  const pinned = new Set();
  const firstFor = new Map(); // effect -> step index
  ledger.steps.forEach((st, i) => {
    for (const basis of ['capability', 'observed']) {
      for (const e of st.adds?.[basis] || []) {
        if (!firstFor.has(basis + ':' + e)) { firstFor.set(basis + ':' + e, i); pinned.add(i); }
      }
    }
  });

  const keep = [];
  // Walk backwards keeping the most recent steps, then add the pinned origins.
  const recentStart = Math.max(0, ledger.steps.length - cap + pinned.size);
  for (let i = 0; i < ledger.steps.length; i++) {
    if (i >= recentStart || pinned.has(i)) keep.push(ledger.steps[i]);
  }
  ledger.steps = keep;
  ledger.truncated = true;
  return ledger;
}

/**
 * Append a decided step and fold its effects into the held sets.
 * Monotone by construction (I1): effects are unioned, never removed.
 *
 * @param {object} ledger
 * @param {object} step  {tool, target, providerKey, adds:{capability:[],observed:[]}, decision, why, region?}
 */
export function appendStep(ledger, step, { cap = DEFAULT_STEP_CAP, now = null } = {}) {
  const n = (ledger.steps.at(-1)?.n ?? 0) + 1;
  const rec = { n, ...step };
  if (now != null) rec.wallMs = now; // forensics only; never read by decide()
  ledger.steps.push(rec);

  for (const basis of ['capability', 'observed']) {
    const cur = new Set(ledger.held[basis]);
    for (const e of step.adds?.[basis] || []) cur.add(e);
    ledger.held[basis] = [...cur].sort();
  }

  truncateSteps(ledger, cap);
  return rec;
}

// Record that a region was entered, and the scoped grant an approval implies.
export function enterRegion(ledger, regionName, atStep) {
  if (!ledger.entered.some((e) => e.region === regionName)) {
    ledger.entered.push({ region: regionName, atStep });
  }
}

export function addGrant(ledger, { region, effect, providerKey, atStep }) {
  // A '*' providerKey is never issued from an approval — an unparseable target
  // must not become a wildcard grant (technical §4.4).
  if (!providerKey || providerKey.endsWith('→*')) return null;
  const g = { region, effect, providerKey, atStep };
  if (!ledger.grants.some((x) => x.region === g.region && x.effect === g.effect && x.providerKey === g.providerKey)) {
    ledger.grants.push(g);
  }
  return g;
}

export function coveredByGrant(ledger, regionName, providerKey) {
  return ledger.grants.some((g) => g.region === regionName && g.providerKey === providerKey);
}

// The held set on the configured basis, as a Set of effect names.
export function heldEffects(ledger, basis = ledger.basis) {
  return new Set(ledger.held[basis === 'observed' ? 'observed' : 'capability']);
}

// The step that first contributed each effect — what a witness points at.
export function firstContributors(ledger, effects, basis = ledger.basis) {
  const want = new Set(effects);
  const out = new Map();
  for (const st of ledger.steps) {
    for (const e of st.adds?.[basis === 'observed' ? 'observed' : 'capability'] || []) {
      if (want.has(e) && !out.has(e)) out.set(e, st);
    }
  }
  return out;
}

export const ledgerInternals = { digestOf, safeId, looksLikeLedger, tmpdir };
