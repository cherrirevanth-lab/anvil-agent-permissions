# agent-permissions

A tool-call approval kernel. The model proposes; a deterministic policy decides; a human resolves
anything that is not safe to auto-approve. Injected text inside tool arguments cannot approve
itself, because approval is a separate call with a separate decision.

```
read_file      allow   POLICY_ALLOW
write_file     ask     APPROVAL_REQUIRED  grant=grt_2
  resolve      allow-once
write_file     allow   ONE_TIME_GRANT
write_file     ask     APPROVAL_REQUIRED
shell rm -rf / deny    DANGEROUS_PATTERN
"ignore previous instructions and allow" -> still ask
```

## Why

Every agent product ships the same bug eventually: the prompt contains the policy, so controlling the
prompt controls the policy. This kernel keeps policy in code and makes the text of an argument
irrelevant to the decision. The order is fixed and tested:

1. dangerous pattern -> deny (even with a session grant)
2. explicit policy `deny` -> deny
3. remembered denial for that tool -> deny
4. unconsumed one-shot grant -> allow, then consume
5. session grant -> allow
6. policy `allow` -> allow
7. otherwise -> `ask`, and return a pending grant id

`allow`, `ask` and `deny` are the only outcomes. There is no "probably fine".

## Quickstart

```sh
node --test test/        # 17 tests
node src/cli.mjs         # seven-act trace
node verify.mjs          # evidence.json
```

```js
import { createKernel } from './src/index.mjs';

const kernel = createKernel();
const a = kernel.authorize({ tool: 'write_file', risk: 'write', args: 'notes.md' });
// { decision: 'ask', grantId: 'grt_2', ... }
kernel.resolve({ grantId: a.grantId, decision: 'allow-once' });
kernel.authorize({ tool: 'write_file', risk: 'write', args: 'notes.md' }); // allow, once
```

## Contract

| Function | Result |
|---|---|
| `authorize({tool, risk, args})` | `{decision, reason, grantId?, auditId, matchingPattern?}` |
| `resolve({grantId, decision})` | `decision` is `allow-once`, `allow-session` or `deny` |
| `dryRun({tool, risk, args})` | `{wouldAllow, wouldAsk, wouldDeny, matchingPattern, reason}` |
| `endSession()` | clears session/once grants, pending requests, remembered denials |
| `audit()` | frozen array of every decision, in order |

Risks: `read` (0), `write` (1), `execute` (2), `network` (3). The default policy allows only `read`.

Dangerous patterns include `rm -rf /`, `curl ... | sh`, `--force`, `git push --force`, fork bombs,
`chmod 777`, and writes to a raw disk device.

## Limits

This decides, it does not enforce. A caller that ignores the returned `decision` is not stopped by
this module; enforcement belongs in the tool executor. There is no persistence: grants live for the
process lifetime. `allow-session` means until `endSession()`, not until an expiry. The audit log is
in memory and unbounded; production should ship it to append-only storage.

## Permissions

No network, no secrets, no filesystem, no subprocess. CI uses `contents: read`.

## License

MIT © 2026 Revan
