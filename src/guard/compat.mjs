// polycheck guard — host compatibility surface.
//
// Everything the guard knows about Claude Code's hook I/O lives here, pinned to
// what WP0 actually OBSERVED on a live host rather than to documentation. The
// rest of src/guard/ imports these names and never reads a raw payload field
// directly, so a host change is a one-file diff plus a failing compat test.
//
// Measured on: Claude Code (Windows 11, native), 2026-08-10.
// Raw evidence: experiments/guard-compat/capture/hook-payloads.jsonl
// Findings write-up: spec/WP0-findings.md

export const COMPAT = {
  observedOn: '2026-08-10',
  platform: 'win32',

  // ---------------------------------------------------------------------------
  // The passthrough contract — the single fact the whole design rests on.
  // Emitting `{}` (no permissionDecision) lets the call proceed to its normal
  // rules + auto-mode resolution. VERIFIED: 21 PreToolUse invocations returning
  // `{}`, zero blocked, zero altered.
  // ---------------------------------------------------------------------------
  PASSTHROUGH: '{}',

  // The guard's decision union. 'allow' is deliberately absent — see
  // spec/runtime-guard.functional.md §1.1. Widening this invalidates the
  // `gateKind: 'guard'` verified-gate argument in spec §2.0.
  DECISIONS: Object.freeze(['ask', 'deny']),

  // VERIFIED: an 'ask' from a PreToolUse hook stops execution and waits for a
  // human (4.1 s and 39.4 s stalls around ~180 ms commands), and the
  // permissionDecisionReason string — multi-line — is DISPLAYED in the prompt.
  // The witness therefore reaches the user through this field; no other channel
  // is required.
  askIsBlocking: true,
  reasonRendersInPrompt: true,

  // Event ordering, observed:
  //   PreToolUse (every matching hook, in config order)  t+0
  //   PermissionRequest                                  t+~900 ms
  //     … dialog, human latency …
  //   PostToolUse (tool_response + duration_ms)          t+n
  // A1b: rules AND hook both wanting a gate produced exactly ONE
  // PermissionRequest — one prompt, carrying the hook's reason. Union, not sum.

  // ---------------------------------------------------------------------------
  // Events. Names verified as delivered; `matcher` and the `if` filter both work.
  // ---------------------------------------------------------------------------
  events: {
    preToolUse: 'PreToolUse',
    postToolUse: 'PostToolUse',
    sessionStart: 'SessionStart',
    // OBSERVED, not in the original spec: fires when a permission decision is
    // being sought, and carries `permission_suggestions`. This is the natural
    // decoration point for A1b (attach a witness to a prompt that is ALREADY
    // happening) rather than raising a second gate. M1 should evaluate it.
    permissionRequest: 'PermissionRequest',
  },

  // ---------------------------------------------------------------------------
  // Payload fields. `common` is present on every event observed; `perEvent` adds
  // to it. Anything not listed here was not observed and must not be relied on.
  // ---------------------------------------------------------------------------
  fields: {
    common: ['session_id', 'transcript_path', 'cwd', 'hook_event_name', 'tool_name', 'tool_input'],
    // Present on tool events raised inside a prompt turn; ABSENT on the earliest
    // PreToolUse records captured, so treat every one of these as optional.
    sometimes: ['prompt_id', 'permission_mode', 'effort', 'tool_use_id'],
    perEvent: {
      PostToolUse: ['tool_response', 'duration_ms'],
      PermissionRequest: ['permission_suggestions'],
    },
  },

  // tool_input shapes, per tool, as observed. The runtime labeler (WP2) reads
  // ONLY through these accessors.
  toolInput: {
    Bash: ['command', 'description'],
    Edit: ['file_path', 'old_string', 'new_string', 'replace_all'],
  },

  // tool_response shapes, for the M1 evidence pass.
  toolResponse: {
    Bash: ['stdout', 'stderr', 'interrupted', 'isImage', 'noOutputExpected'],
    Edit: ['filePath', 'oldString', 'newString', 'originalFile', 'structuredPatch', 'userModified', 'replaceAll'],
  },

  // ---------------------------------------------------------------------------
  // Install shape. `args` (exec form) spawns the executable directly with no
  // shell, so Windows backslash paths never reach a parser — `guard init` MUST
  // use this form rather than a single `command` string.
  //
  // `if` takes permission-rule syntax and filters BEFORE the hook process is
  // spawned. Given the measured node cold start (see below) this is not a
  // nicety: it is the primary latency mitigation. VERIFIED firing selectively.
  // ---------------------------------------------------------------------------
  install: { form: 'args', supportsIf: true, supportsTimeout: true, hotReload: true },

  // ---------------------------------------------------------------------------
  // Latency, measured. The guard's own work is ~5 ms; the host's node cold start
  // dominates by two orders of magnitude on this machine.
  // ---------------------------------------------------------------------------
  measured: {
    nodeColdStartMs: 780,      // `node -e ""`, mean of 8. McAfee + Defender present.
    guardEntryMs: 4.7,         // median in-process cost to parse + decide + record
    referenceColdStartMs: 50,  // typical clean machine; NOT measured here
  },
};

// A field the host did not send is a compat drift, not a runtime surprise: the
// guard reads through these so a missing field is caught in one place.
export function field(payload, name, { required = false } = {}) {
  const v = payload?.[name];
  if (v === undefined && required) {
    const err = new Error(`compat: required hook field '${name}' absent (host drift?)`);
    err.compatDrift = name;
    throw err; // callers fail closed to 'ask'
  }
  return v;
}
