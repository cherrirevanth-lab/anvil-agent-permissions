# Security

## Threat model

The attacker controls tool arguments, tool output, and anything the model reads. The kernel must
decide from code, not from text. Its strongest property is negative: there is no input string that
turns an `ask` into an `allow`.

Mitigations: fixed decision order; dangerous-pattern check before grant lookup; grants keyed by
`(tool, risk)`; one-shot consumption; remembered denials; every branch audited.

## Known limits

- **No enforcement.** A caller that ignores `decision` executes anyway. Wire the executor.
- **No persistence.** A restart forgets session grants and denials; that is fail-closed.
- **`allow-session` has no expiry.** Use `endSession()` at a real boundary.
- **Audit is in memory.** A crash loses it.
- **Dangerous patterns are heuristics.** They catch known catastrophic forms, not intent. A shell
  tool should also have its own allowlist.

## Reporting

Open a private security advisory on the repository.
