// polycheck scanner — read a repo's Claude Code policy surface off disk and
// normalise it into rules + hooks + MCP servers. No execution, no network, no
// clock: a policy is read as data, never run. Everything here is
// pure parsing; the security judgement happens later, in the checker.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// Claude Code permission-rule grammar: `Tool` or `Tool(specifier)`. MCP tools
// carry their whole dotted name as the tool (`mcp__server__tool`), optionally
// with a specifier. Anything else is passed through verbatim as an opaque rule.
const RULE_RE = /^([A-Za-z_][A-Za-z0-9_]*)(?:\((.*)\))?$/s;

export function parseRule(entry, decision, source) {
  const raw = String(entry).trim();
  const m = RULE_RE.exec(raw);
  if (!m) return { tool: raw, specifier: null, decision, source, raw, malformed: true };
  return { tool: m[1], specifier: m[2] ?? null, decision, source, raw };
}

// JSONC-tolerant read: Claude Code settings are strict JSON, but we defensively
// strip a leading BOM and never throw on a missing file — a repo with no
// settings.local.json is the common case, not an error.
function readJson(path) {
  if (!existsSync(path)) return { exists: false, path, data: null };
  try {
    const text = readFileSync(path, 'utf8').replace(/^﻿/, '');
    return { exists: true, path, data: JSON.parse(text) };
  } catch (err) {
    return { exists: true, path, data: null, error: String(err.message || err) };
  }
}

// The three permission buckets Claude Code recognises. `ask` and `deny` are
// gates in our model; `allow` is an ungated edge. Order matters only for
// provenance — the checker treats deny as strictly removing, ask as gating.
const BUCKETS = [
  ['deny', 'deny'],
  ['ask', 'ask'],
  ['allow', 'allow'],
];

// Is this hook entry polycheck's OWN guard, and is it configured? Recognising it
// lets check.mjs treat it as a VERIFIED gate rather than the unverified default
// — see spec/runtime-guard.technical.md §2.0 for why that is sound (the guard's
// decision union is ask|deny|passthrough, so it can only ADD a gate).
//
// Two guardrails, both deliberate:
//   G-a  the claim is scoped to the regions the guard is CONFIGURED to gate. No
//        readable config ⇒ not a guard ⇒ ordinary unverified hook.
//   G-b  recognition is on the command shape. A hand-written hook that merely
//        resembles polycheck's does not inherit the verdict — but neither does a
//        real guard whose config we cannot read, which is the safe direction.
//
// Returns the region-name array it gates, or null.
const GUARD_CMD = /polycheck[-\s]guard(\.mjs)?\b/i;

function guardHookOf(entry, guardConfig) {
  if (!guardConfig) return null;                    // G-a: unconfigured ⇒ not a gate
  if (entry?.matcher != null && entry.matcher !== '*' && entry.matcher !== '') {
    // A guard wired to only some tools does not gate the others; refusing to
    // reason about the partial case is safer than modelling it wrong.
    return null;
  }
  for (const h of entry?.hooks || []) {
    const text = [h?.command, ...(h?.args || [])].filter(Boolean).join(' ');
    if (GUARD_CMD.test(text)) return guardConfig.regions;
  }
  return null;
}

// The guard's config, if present and readable. `onComplete` names the regions it
// gates; absent means the default set, which we cannot know here, so an absent
// or malformed file yields null and the hook stays unverified (G-a).
function readGuardConfig(root) {
  const r = readJson(join(root, '.claude', 'polycheck.guard.json'));
  if (!r.exists || !r.data) return null;
  const oc = r.data.onComplete;
  if (!oc || typeof oc !== 'object') return null;
  const regions = Object.keys(oc).filter((k) => oc[k] === 'ask' || oc[k] === 'deny');
  return regions.length ? { regions, path: r.path } : null;
}

export function scanRepo(root) {
  const sources = [];
  const rules = [];
  const hooks = [];
  const mcpServers = [];
  const warnings = [];

  const settingsFiles = [
    ['settings', join(root, '.claude', 'settings.json')],
    ['settings.local', join(root, '.claude', 'settings.local.json')],
  ];

  let defaultMode = null;
  let sawAnySettings = false;
  // Read once, before the settings loop: the guard config is repo-level, not
  // per-settings-file.
  const guardConfig = readGuardConfig(root);

  for (const [kind, path] of settingsFiles) {
    const r = readJson(path);
    sources.push({ kind, path, exists: r.exists, error: r.error || null });
    if (r.error) warnings.push(`${path}: ${r.error}`);
    if (!r.exists || !r.data) continue;
    sawAnySettings = true;
    const s = r.data;

    if (s.permissions && typeof s.permissions === 'object') {
      for (const [bucket, decision] of BUCKETS) {
        const arr = s.permissions[bucket];
        if (Array.isArray(arr)) {
          for (const entry of arr) rules.push(parseRule(entry, decision, kind));
        }
      }
      // defaultMode: `bypassPermissions` (or the --dangerously-skip flag baked
      // into settings) makes EVERY tool allow with no gate — the strongest
      // possible finding. First non-null wins (settings before local here, but
      // local overrides in real precedence — we record both and flag it).
      if (s.permissions.defaultMode && defaultMode == null) defaultMode = s.permissions.defaultMode;
    }
    // Top-level defaultMode is also accepted by some versions.
    if (s.defaultMode && defaultMode == null) defaultMode = s.defaultMode;

    // Hooks. A PreToolUse hook is a gate by declaration — we cannot read its
    // logic, so we record its matcher and treat matched tools as
    // gated, loudly noting the contents are unverified.
    if (s.hooks && typeof s.hooks === 'object') {
      for (const [event, entries] of Object.entries(s.hooks)) {
        if (!Array.isArray(entries)) continue;
        for (const e of entries) {
          const guard = guardHookOf(e, guardConfig);
          hooks.push({ event, matcher: e?.matcher ?? '*', source: kind, kind: guard ? 'guard' : 'hook', guardRegions: guard || null });
        }
      }
    }

    // MCP servers may also be declared inline in settings (enabledMcpjsonServers
    // / mcpServers); collect names so the catalogue is complete.
    collectMcp(s.mcpServers, kind, mcpServers);
  }

  // Project-level .mcp.json — the usual home of MCP server declarations.
  const mcp = readJson(join(root, '.mcp.json'));
  sources.push({ kind: 'mcp', path: mcp.path, exists: mcp.exists, error: mcp.error || null });
  if (mcp.error) warnings.push(`${mcp.path}: ${mcp.error}`);
  if (mcp.exists && mcp.data) collectMcp(mcp.data.mcpServers, 'mcp', mcpServers);

  const hasPolicy = sawAnySettings || (mcp.exists && !!mcp.data);
  if (!hasPolicy) {
    warnings.push('no .claude/settings.json or settings.local.json found — nothing to check. Point polycheck at a repo that has a .claude directory.');
  }

  return { root, sources, rules, hooks, mcpServers, defaultMode, warnings, hasPolicy };
}

function collectMcp(obj, source, out) {
  if (!obj || typeof obj !== 'object') return;
  for (const name of Object.keys(obj)) {
    if (out.some((m) => m.name === name)) continue;
    // Tool list is unknowable without running the server; null = unknown.
    out.push({ name, tools: null, source });
  }
}
