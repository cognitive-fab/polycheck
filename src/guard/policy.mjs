// polycheck guard — written-policy awareness.
//
// In the pre-decision draft this file was load-bearing for SAFETY: the guard
// could emit 'allow', so mis-matching a written `ask`/`deny` would have let it
// soften a rule the user wrote. That failure mode no longer exists — the guard's
// output union has no 'allow' — so all this file does now is answer "was this
// call already going to prompt?", which feeds:
//
//   - functional A1b's metric (added prompts vs decorated ones), and
//   - the prompt copy.
//
// It never feeds the decision. A region-completing call is gated regardless of
// what the rules say (src/guard/decide.mjs, branch (a) runs first).
//
// Requirement R1: an undecidable match answers YES (assume already gated). The
// worst case is that the guard UNDER-reports its own added-prompt count — a
// conservative direction for a self-measurement.

import { scanRepo } from '../scan.mjs';
import { normaliseBash } from '../label.mjs';

// Claude Code matches a Bash specifier as a command PREFIX. We reimplement only
// enough of that to answer the reporting question; polycheck's own report is
// explicit that rule-specificity resolution is approximate.
function specifierMatches(tool, specifier, call) {
  if (specifier == null) return true; // bare `Bash` covers every command
  const spec = String(specifier);
  if (spec === '*' || spec === ':*') return true;

  if (tool === 'Bash' || tool === 'PowerShell' || tool === 'pwsh') {
    const prefix = normaliseBash(spec).replace(/\s*\*$/, '').trim();
    if (!prefix) return true;
    const cmd = String(call.command ?? '').trim();
    return cmd === prefix || cmd.startsWith(prefix + ' ') || cmd.startsWith(prefix);
  }
  // Path-shaped specifiers (Read/Edit globs): deliberately NOT matched here. A
  // wrong answer only skews the metric, and guessing at glob semantics would
  // skew it in an unpredictable direction. Undecidable ⇒ yes (R1).
  return true;
}

export function loadPolicy(cwd) {
  let scan = null;
  try { scan = scanRepo(cwd); } catch { scan = null; }
  const rules = (scan?.rules || []).filter((r) => r.decision === 'ask' || r.decision === 'deny');

  return {
    scan,
    /**
     * Would a written rule already raise a prompt (or block) for this call?
     * Undecidable ⇒ true (R1).
     */
    alreadyGates(call) {
      if (!scan) return true; // no policy read ⇒ cannot tell ⇒ assume gated
      const tool = call.tool;
      for (const r of rules) {
        if (r.tool !== tool) continue;
        if (specifierMatches(tool, r.specifier, call)) return true;
      }
      // Nothing matched. If the tool is not named anywhere in the ruleset at
      // all, the classifier may still prompt — but for the metric, "no written
      // rule gates this" is the honest answer.
      return false;
    },
  };
}

export const policyInternals = { specifierMatches };
