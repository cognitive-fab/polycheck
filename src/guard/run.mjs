// polycheck guard — the hook run loop, kept separate from bin/ so it is
// testable without spawning a process.
//
// Ordering matters and is spec'd (technical §3.3 I2): decide, PERSIST, then
// emit. A crash between deciding and persisting must not lose taint, so the
// ledger write happens before the decision reaches the host.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { COMPAT, field } from './compat.mjs';
import { loadLedger, saveLedger, appendStep, enterRegion, addGrant, emptyLedger } from './ledger.mjs';
import { labelCall, loadRuntimeLabels } from './runtime-label.mjs';
import { decide, runtimeRegions } from './decide.mjs';
import { loadPolicy } from './policy.mjs';
import { loadLabels } from '../label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REGIONS_FILE = join(HERE, '..', '..', 'data', 'regions.json');

export function loadGuardConfig(cwd) {
  try {
    return JSON.parse(readFileSync(join(cwd, '.claude', 'polycheck.guard.json'), 'utf8'));
  } catch {
    return {}; // absent config is the default config, not an error
  }
}

/**
 * Evaluate one PreToolUse payload. Pure except for the ledger write, which is
 * injected so tests can run entirely in memory.
 *
 * @returns {{decision, reason, adds, prewarn, region, ledger}}
 */
export function evaluatePre(payload, deps = {}) {
  const cwd = field(payload, 'cwd') || process.cwd();
  const sessionId = field(payload, 'session_id', { required: true });
  const toolName = field(payload, 'tool_name', { required: true });
  const toolInput = field(payload, 'tool_input') || {};

  const labels = deps.labels || loadLabels();
  const rt = deps.rt || loadRuntimeLabels();
  const config = deps.config || loadGuardConfig(cwd);
  const regionsFile = deps.regionsFile || JSON.parse(readFileSync(REGIONS_FILE, 'utf8'));
  const regions = runtimeRegions(regionsFile, config);
  const basis = config.basis === 'observed' ? 'observed' : 'capability'; // M0: capability only in practice

  const loaded = deps.ledger
    ? { ledger: deps.ledger, status: 'loaded' }
    : loadLedger(sessionId, cwd, deps.env);
  const ledger = loaded.ledger;
  if (loaded.status === 'fresh') ledger.basis = basis;

  const labelled = labelCall(toolName, toolInput, labels, { rt, cwd });
  const policy = deps.policy || loadPolicy(cwd);

  const call = {
    tool: toolName,
    command: toolInput.command,
    target: labelled.target?.host || labelled.target?.path || labelled.target?.mcp || null,
  };

  const result = decide({ ledger, labelled, regions, call, policy, basis });

  // Persist BEFORE emitting (I2). The step is recorded whatever the decision —
  // a gated call still contributed the knowledge that it was attempted.
  const step = appendStep(ledger, {
    tool: toolName,
    target: call.target,
    providerKey: labelled.providerKey,
    adds: {
      // M0 is capability-basis: an effect the call COULD produce is recorded as
      // held. `observed` waits for the PostToolUse evidence pass (M1).
      capability: result.adds,
      observed: [],
    },
    decision: result.decision,
    why: result.region?.name || (result.decision ? 'sticky-ask' : 'no region completed'),
    ruleIds: [...labelled.effects.values()].map((v) => v.ruleId),
    parseOk: labelled.parse.ok,
  });

  if (result.region) {
    // Enter and grant for EVERY region this call leaves us inside, not just the
    // one reported. The regions overlap (credential-egress ⊂ lethal-trifecta),
    // so one call can complete several; the human approved the call, so the
    // approval covers all of them. Granting only the reported region left the
    // others permanently un-granted and re-prompted the same channel forever.
    for (const name of result.satisfiedAfter || [result.region.name]) {
      enterRegion(ledger, name, step.n);
      const region = regions.find((r) => r.name === name);
      for (const e of region?.requires || []) {
        if (result.adds.includes(e)) {
          addGrant(ledger, { region: name, effect: e, providerKey: labelled.providerKey, atStep: step.n });
        }
      }
    }
    // Stated limitation: the guard never learns the human's ANSWER — the host
    // does not call back — so the grant is issued optimistically at the moment
    // of gating. A denied call therefore still suppresses a re-prompt for that
    // same channel. M1 revisits this once PostToolUse reveals whether it ran.
  }

  if (!deps.ledger) saveLedger(ledger, deps.env);

  return { ...result, ledger, labelled, step };
}

export function evaluateSessionStart(payload, deps = {}) {
  const cwd = field(payload, 'cwd') || process.cwd();
  const sessionId = field(payload, 'session_id', { required: true });
  const source = field(payload, 'source');

  // A resumed session did not un-read its secrets: context survived, so the
  // ledger survives with it. Only a genuinely new session starts empty.
  if (source === 'resume') {
    const { ledger } = loadLedger(sessionId, cwd, deps.env);
    if (!deps.ledger) saveLedger(ledger, deps.env);
    return { action: 'resumed', held: ledger.held };
  }
  const fresh = emptyLedger(sessionId, cwd, { basis: (deps.config || loadGuardConfig(cwd)).basis || 'capability' });
  if (!deps.ledger) saveLedger(fresh, deps.env);
  return { action: 'fresh', held: fresh.held };
}

export const runInternals = { REGIONS_FILE, COMPAT };
