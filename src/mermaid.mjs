// polycheck --mermaid — the witness as a picture. A witness is already a
// SEQUENCE ("step 1 → step 2 → REACHED"), so a mermaid sequenceDiagram is its
// natural shape: each allowed call is a self-action on the session, annotated
// with the effect it adds and the running held set, and the composition
// completes with a crossed arrow into the forbidden region. This is presentation
// only — it makes no claim the text report does not already make; it just makes
// the accumulated-state hazard legible at a glance (and screenshot-able).

// Mermaid note/message text is line-oriented and chokes on a few characters.
// Keep labels short and strip what breaks the parser; the full rule is still in
// --json / --verbose.
function clean(s, n = 58) {
  const t = String(s ?? '').replace(/[\n\r;#]+/g, ' ').replace(/"/g, "'").trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

const label = (a) => clean(`${a.tool}${a.specifier != null ? `(${a.specifier})` : ''}`);

function witnessDiagram(r) {
  const L = ['```mermaid', 'sequenceDiagram', '  autonumber',
    '  participant A as Agent session',
    `  participant Z as ⛔ ${clean(r.region.name, 32)}`,
    '  Note over A: session start · held: (nothing)'];

  for (const st of r.witness) {
    const a = st.action;
    // In a real bypass every step is an ungated allow; an INCONCLUSIVE witness
    // walks the path an UNVERIFIED gate would have to stop.
    const dec = a.decision || (a.gate ? 'gate?' : 'allow');
    const added = st.added.length ? '+' + st.added.join(' +') : '(no new effect)';
    L.push(`  A->>A: ${label(a)}  [${dec}]`);
    L.push(`  Note over A: ${added} · held: ${st.held.join(', ') || 'none'}`);
  }

  const req = r.region.requires.join(' ∧ ');
  const how = r.status === 'INCONCLUSIVE'
    ? 'only an UNVERIFIED gate stands in the way — not a proof'
    : r.status === 'SHELL-EQUIVALENT'
      ? 'one granted tool runs arbitrary code — a shell'
      : '0 gates crossed';
  L.push(`  A-xZ: REACHED · ${clean(req, 48)} · ${how}`);
  L.push('```');
  return L.join('\n');
}

/**
 * Render every witness in the bundle as a fenced mermaid sequence diagram,
 * ready to paste into an issue / PR / README (GitHub renders mermaid natively).
 */
export function renderMermaid(bundle) {
  const { check, version, scan } = bundle;
  const drawable = check.results.filter((r) => r.witness && r.witness.length);
  const L = [`### polycheck ${version} · ${scan.root}`, ''];

  if (!drawable.length) {
    L.push('_Nothing to draw: every path into a forbidden region crosses a gate '
      + '(**PROOF**), or a required effect has no granted provider (a coverage gap). '
      + 'A witness only exists when a composition is reachable._');
    return L.join('\n') + '\n';
  }

  for (const r of drawable) {
    L.push(`**${r.status} · ${r.region.name}**  (${r.region.requires.join(' ∧ ')})`, '');
    L.push(witnessDiagram(r), '');
  }
  return L.join('\n');
}

export const mermaidInternals = { clean, witnessDiagram };
