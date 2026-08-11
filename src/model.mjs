// polycheck model builder — turn a scanned policy + a label pack into the set of
// ACTIONS a session can take, each tagged with the effects it grants and whether
// it crosses a gate. This is the bridge from "what the config says" to "what a
// state machine can do" — compiling a policy into an explorable state machine.
//
// Decisions map to edge semantics:
//   allow  → an UNGATED edge (fires silently, no human in the loop)
//   ask    → a GATED edge   (a human sees it before it fires)
//   deny   → NO edge        (removed; can never fire)
//   hook   → GATED edge     (a PreToolUse hook matches the tool — treated as a
//            gate by declaration; its logic is unverified)
// bypassPermissions (defaultMode) collapses every edge to ungated allow.

import { labelEffects, isUnrestricted } from './label.mjs';

function hookMatches(matcher, tool) {
  const m = String(matcher ?? '').trim();
  if (m === '' || m === '*') return true;
  if (m === tool) return true;
  try { if (new RegExp(m).test(tool)) return true; } catch { /* not a regex */ }
  return false;
}

// Does a deny rule shadow an allow/ask on the same tool? Approximate: a deny
// with an unrestricted specifier, or the exact same specifier, removes the edge.
// A narrower deny leaves the broader allow standing (and is noted). Rule-
// specificity resolution is declared approximate in the report.
function denyShadows(deny, tool, specifier) {
  if (deny.tool !== tool) return false;
  if (isUnrestricted(deny.specifier)) return true;
  return String(deny.specifier) === String(specifier);
}

export function buildModel(scan, labels, regions, opts = {}) {
  const assumeDefaults = opts.assumeDefaults !== false; // default ON
  const bypass = scan.defaultMode === 'bypassPermissions';
  const denies = scan.rules.filter((r) => r.decision === 'deny');
  const hooks = scan.hooks || [];

  const actions = [];
  const assumptions = [];
  const seen = new Set();
  // A deny only did WORK if it removed an edge that would otherwise be live —
  // an allow/ask rule or an assumed default. Denying a tool nobody granted
  // suppresses nothing, so it must not earn a PROOF. We record the suppressions
  // here as they happen; PROOF-by-denial traces to one of these, never to a bare
  // deny rule.
  const suppressedByDeny = [];

  const addAction = ({ tool, specifier, decision, source, raw, assumed }) => {
    // deny shadowing (skip in bypass mode — bypass ignores the ruleset)
    if (!bypass && decision !== 'deny') {
      const shadow = denies.find((d) => denyShadows(d, tool, specifier));
      if (shadow) {
        const supp = labelEffects(tool, specifier, labels).effects;
        if (supp.size) suppressedByDeny.push({ tool, specifier, effects: [...supp], denyRaw: shadow.raw });
        return; // this edge was live-but-for the deny; it is genuinely closed
      }
    }
    const { effects, notes, tag, shellReason, scriptPath } = labelEffects(tool, specifier, labels);
    for (const n of notes) if (!assumptions.includes(n)) assumptions.push(n);
    // A tool with no exfil-relevant effect is not worth an edge in this model,
    // but keep unlabeled/benign notes (already pushed above).
    if (effects.size === 0) return;

    // gateKind distinguishes a VERIFIED gate ('ask' = a human is shown the call)
    // from UNVERIFIED ones we cannot stand behind: 'hook' (a PreToolUse hook
    // matches, but we cannot read its logic — most hooks log/format, they do not
    // block) and 'assumed' (a gate polycheck synthesized, e.g. an undeclared MCP
    // server we assume prompts — not a rule anyone wrote). null = ungated.
    let gateKind, gateReason, gateRegions = null;
    if (assumed) {
      gateKind = 'assumed';
      gateReason = `assumed prompt — synthesized by polycheck, not a written rule`;
    } else {
      gateKind = decision === 'ask' ? 'ask' : null;
      gateReason = gateKind === 'ask' ? `permission 'ask'` : null;
      if (!bypass && gateKind !== 'ask') {
        const matching = hooks.filter((hk) => hk.event === 'PreToolUse' && hookMatches(hk.matcher, tool));
        // polycheck's OWN guard is a VERIFIED gate, but only for the regions it
        // is configured to gate — see spec/runtime-guard.technical.md §2.0. The
        // soundness argument is that its decision union is ask|deny|passthrough,
        // so it can only ADD a gate, never remove one. If that union ever widens
        // to include 'allow', this must be withdrawn in the same change.
        const g = matching.find((hk) => hk.kind === 'guard' && hk.guardRegions?.length);
        if (g) {
          gateKind = 'guard';
          gateRegions = g.guardRegions;
          gateReason = `polycheck guard (gates: ${g.guardRegions.join(', ')})`;
        } else if (matching.length) {
          const h = matching[0];
          gateKind = 'hook';
          gateReason = `PreToolUse hook (matcher '${h.matcher}', logic unverified)`;
        }
      }
    }
    if (bypass) { gateKind = null; gateReason = null; }
    const gate = gateKind != null;

    const id = `${tool}${specifier != null ? `(${specifier})` : ''}::${[...effects].sort().join('+')}::${gateKind}`;
    if (seen.has(id)) return;
    seen.add(id);
    actions.push({
      tool, specifier, decision, source, raw: raw ?? id,
      effects: [...effects], gate, gateKind, gateReason, gateRegions, tag: tag ?? null,
      shellReason: shellReason ?? null, scriptPath: scriptPath ?? null,
    });
  };

  if (bypass) {
    assumptions.push(`DOMINATING: permissions.defaultMode = 'bypassPermissions' — every tool fires ungated, no prompts, no hooks. The ruleset below is inert. This is the strongest possible finding.`);
    // Every labelled built-in becomes an ungated allow; worst-case for Bash.
    for (const tool of Object.keys(labels.tools || {})) {
      const spec = labels.tools[tool]?.classify === 'bash' ? '*' : (labels.tools[tool]?.sensitiveWhenPathMatches ? '*' : null);
      addAction({ tool, specifier: spec, decision: 'allow', source: 'defaultMode', raw: `${tool} (bypassPermissions)` });
    }
    for (const srv of scan.mcpServers || []) {
      addAction({ tool: `mcp__${srv.name}__*`, specifier: null, decision: 'allow', source: 'defaultMode', raw: `mcp__${srv.name}__* (bypassPermissions)` });
    }
  } else {
    // Explicit rules (allow/ask). deny rules are consumed as shadows above.
    for (const r of scan.rules) {
      if (r.decision === 'deny') continue;
      addAction(r);
    }
    // Claude Code auto-allows some read-only tools (labels.defaultUngated) with
    // no prompt, so most policies never list Read even though the agent can read
    // any file. With --assume-defaults (the default) we model those as ungated
    // edges — otherwise the common case (an egress tool but no explicit Read)
    // scores a false VACUOUS. --no-assume-defaults gives the strict, explicitly-
    // granted-only view. A default is NOT injected when the tool is explicitly
    // gated (deny/ask).
    const defaults = labels.defaultUngated || [];
    if (assumeDefaults && defaults.length) {
      for (const tool of defaults) {
        if (!labels.tools?.[tool]) continue; // only inject tools we can label
        // Skip only when explicitly ASKED (it is gated, not ungated). A DENIED
        // default still flows through addAction so the deny is recorded as having
        // suppressed a real would-be edge (PROOF-by-denial needs that evidence).
        const asked = scan.rules.some((r) => r.tool === tool && r.decision === 'ask');
        if (asked) continue;
        addAction({ tool, specifier: null, decision: 'allow', source: 'default (auto-allowed)', raw: `${tool} (Claude Code default-allow)` });
      }
      assumptions.push(`ASSUMING DEFAULTS: Claude Code auto-allows read-only tools (${defaults.join(', ')}) without a prompt, so they are modeled as ungated. Pass --no-assume-defaults for a strict, explicitly-granted-only view.`);
    } else if (defaults.length) {
      assumptions.push(`STRICT MODE (--no-assume-defaults): only explicitly-granted permissions are modeled. Claude Code auto-allows read-only tools (${defaults.join(', ')}) without a prompt, so a real session may be less safe than this shows.`);
    }
    // Unknown MCP servers contribute an untrusted-ingest edge (assumption).
    for (const srv of scan.mcpServers || []) {
      const anyRule = scan.rules.some((r) => r.tool.startsWith(`mcp__${srv.name}__`));
      if (!anyRule) {
        // The server is declared but no rule names its tools; Claude Code would
        // prompt, but that gating is OUR assumption, not a written rule — mark it
        // 'assumed' so it can never be the sole mediator of a green PROOF.
        addAction({ tool: `mcp__${srv.name}__*`, specifier: null, source: srv.source, raw: `mcp__${srv.name}__* (declared, tools unknown)`, assumed: true });
      }
    }
  }

  // Rules that can WRITE repo code without crossing a gate. Edit/Write carry no
  // exfil effect so they never become actions — but they are exactly what makes
  // an exact interpreter invocation unbounded, so the checker needs them.
  // Exact-interpreter grants are deliberately excluded from this set: including
  // them would be circular (they are the thing being explained).
  const WRITERS = new Set(["Edit", "Write", "NotebookEdit"]);
  const ungatedWriters = bypass
    ? [{ raw: "everything (bypassPermissions)" }]
    : scan.rules
        .filter((r) => r.decision === "allow" && WRITERS.has(r.tool)
          && !scan.rules.some((d) => d.decision !== "allow" && d.tool === r.tool && String(d.specifier) === String(r.specifier)))
        .map((r) => ({ tool: r.tool, specifier: r.specifier, raw: r.raw, source: r.source }));

  return { actions, assumptions, regions: regions.regions, bypass, suppressedByDeny, ungatedWriters };
}
