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
          hooks.push({ event, matcher: e?.matcher ?? '*', source: kind });
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
