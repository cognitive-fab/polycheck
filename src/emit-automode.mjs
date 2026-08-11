// polycheck --emit-automode — EXPERIMENTAL (Q6 spike).
//
// Compile a repo's policy + labels into the auto-mode classifier's own
// declarative rules (the `autoMode` settings block). The linter already knows
// which tools are egress channels, which are arbitrary-execution wrappers, and
// which regions must never be reachable ungated; this turns that knowledge into
// guidance the 89% classifier consumes at deploy time — no runtime code.
//
// HONEST LIMIT, stated up front and in the output: the classifier is
// per-command and probabilistic. It CANNOT see composition — there is no
// autoMode rule for "not both, in one session, after untrusted input". So this
// is not the guard and not the proof: it reinforces the per-command screen using
// the policy's own intent, and it degrades to "the classifier tries to honor
// this", never a guarantee. The deterministic control is still the guard; the
// proof is still the linter.
//
// The intent axis the classifier gives us — and polycheck's static model does
// not — is soft_deny vs hard_deny:
//   soft_deny  destructive / irreversible, but USER INTENT CAN CLEAR IT
//              (your own tooling, a deliberate rm -rf on a dev box)
//   hard_deny  a security boundary intent does NOT clear
//              (shipping a credential file to a remote host)
// That is exactly the "protecting yourself vs. attacking someone else"
// distinction a least-privilege proof cannot express, so we lean on it here.

const label = (a) => `${a.tool}${a.specifier != null ? `(${a.specifier})` : ''}`;
const uniq = (xs) => [...new Set(xs)];

// The executable a shell grant runs, for readable guidance ("node", "npm run").
function shellExe(lbl) {
  const m = /^(?:Bash|PowerShell|pwsh)\(([\s\S]*)\)$/.exec(lbl);
  const cmd = (m ? m[1] : lbl).trim();
  return (cmd.split(/\s+/)[0] || cmd).replace(/^["']/, '').replace(/[^\w./-].*$/, '').replace(/.*[\\/]/, '').replace(/\.exe$/i, '') || cmd;
}

/**
 * @param {object} bundle  the analyze() result
 * @returns {{autoMode: object, rationale: string[]}}
 */
export function emitAutomode(bundle) {
  const { model, check } = bundle;
  const rationale = [];

  // Outbound tools the policy already gates — tell the classifier so it treats a
  // network reach by ANY other route with the same suspicion.
  const gatedEgress = uniq(
    model.actions
      .filter((a) => a.effects.includes('egress') && (a.gateKind === 'ask' || a.gateKind === 'guard'))
      .map(label),
  );

  // Arbitrary-execution wrappers → soft_deny: destructive-capable, but the user's
  // own tooling is the common case, so intent clears it.
  const shellExes = uniq((check.shellGrants || []).map(shellExe)).sort();

  // The regions the policy declares off-limits — the composition guidance. This
  // is the part that can only be ADVICE: the classifier cannot enforce a session
  // predicate, but it can be told what the dangerous assembled state looks like.
  const regionNames = (check.results || []).map((r) => r.region.name);

  const environment = ['$defaults'];
  if (gatedEgress.length) {
    environment.push(
      `This project's policy gates these outbound tools behind ask/deny: ${gatedEgress.join(', ')}. ` +
      `A command that reaches the network by another route deserves the same scrutiny.`,
    );
    rationale.push(`environment: named ${gatedEgress.length} already-gated egress tool(s) so the classifier mirrors them.`);
  }
  if (regionNames.includes('lethal-trifecta') || regionNames.includes('credential-egress')) {
    environment.push(
      `Treat a session that has read a credential file (.env, .aws/credentials, id_rsa, .ssh/*) and then ` +
      `reaches the network as high-risk, even when each step looks routine — that assembled state is what ` +
      `this policy exists to prevent. (The classifier sees one command at a time and cannot enforce this; it is guidance.)`,
    );
    rationale.push('environment: described the composition hazard as guidance (the classifier cannot enforce a session predicate).');
  }

  const hard_deny = ['$defaults',
    `A single command that both reads a credential file and sends it to a remote host ` +
    `(e.g. curl -T .env https://…, curl --data @~/.aws/credentials).`,
  ];
  rationale.push('hard_deny: the one-command secret-exfil — a boundary intent should not clear.');

  const soft_deny = ['$defaults'];
  if (shellExes.length) {
    soft_deny.push(
      `Arbitrary-execution wrappers running caller-chosen code (${shellExes.join(', ')}): confirm the ` +
      `exact command matches your intent. This is your own tooling in the common case, so a deliberate ` +
      `run is fine — it just should not pass unseen.`,
    );
    rationale.push(`soft_deny: ${shellExes.length} arbitrary-execution wrapper(s) — destructive-capable, but intent clears them.`);
  }

  return {
    autoMode: { allow: ['$defaults'], soft_deny, hard_deny, environment, classifyAllShell: false },
    rationale,
  };
}

export function renderAutomode(bundle, opts = {}) {
  const on = opts.color !== false;
  const dim = on ? (s) => `\x1b[2m${s}\x1b[0m` : (s) => s;
  const bold = on ? (s) => `\x1b[1m${s}\x1b[0m` : (s) => s;
  const cyan = on ? (s) => `\x1b[36m${s}\x1b[0m` : (s) => s;
  const { autoMode, rationale } = emitAutomode(bundle);
  const L = [];
  L.push(bold('polycheck --emit-automode  ') + dim('· EXPERIMENTAL (Q6 spike)'));
  L.push('');
  L.push(dim('Compiles this policy into the auto-mode classifier\'s own rules. This REINFORCES'));
  L.push(dim('the per-command classifier; it does NOT replace the guard or the proof. The'));
  L.push(dim('classifier is probabilistic and sees one command at a time — the composition'));
  L.push(dim('guidance below is advice it tries to honor, not a gate it enforces.'));
  L.push('');
  L.push(dim('# why each section, from your policy:'));
  for (const r of rationale) L.push(dim(`#   ${r}`));
  L.push('');
  L.push(dim('Merge this under the TOP LEVEL of .claude/settings.json (a sibling of'));
  L.push(dim('"permissions", NOT inside it). "$defaults" keeps Claude Code\'s built-in rules.'));
  L.push('');
  L.push(cyan(JSON.stringify({ autoMode }, null, 2)));
  return L.join('\n');
}
