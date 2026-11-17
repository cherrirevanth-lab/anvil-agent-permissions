# Rebuild contract — agent-permissions

A valid reconstruction passes `test/agent-permissions.test.mjs` (17 tests) and obeys the decision
order below. The test file is the oracle.

## 1. Files

```
08-agent-permissions/
├─ package.json             ESM, no dependencies
├─ src/index.mjs            RISK, DANGEROUS_PATTERNS, createKernel
├─ src/cli.mjs              seven-act trace, exits 0 on success
├─ test/agent-permissions.test.mjs
├─ verify.mjs               tests + trace -> evidence.json
├─ permission-manifest.json
├─ .github/workflows/ci.yml
└─ README.md / SPEC.md / SECURITY.md / LICENSE / .gitignore
```

## 2. Decision algorithm

`authorize({tool, risk, args})`:

1. non-empty string tool, else `deny/INVALID_TOOL`
2. risk resolves to a name and level, else `deny/INVALID_RISK`
3. any `DANGEROUS_PATTERNS` matches `tool + "\n" + args` -> `deny/DANGEROUS_PATTERN`
4. policy[risk] === 'deny' -> `deny/POLICY_DENY`
5. tool in deniedTools -> `deny/DENIED_TOOL`
6. matching one-shot grant -> `allow/ONE_TIME_GRANT`, delete the grant
7. matching session grant -> `allow/SESSION_GRANT`
8. policy[risk] === 'allow' -> `allow/POLICY_ALLOW`
9. else create `{grantId:'grt_<seq>', status:'pending', tool, risk}` -> `ask/APPROVAL_REQUIRED`

`resolve`: invalid decision -> `INVALID_DECISION`; unknown grant -> `UNKNOWN_GRANT`; non-pending ->
`ALREADY_RESOLVED`; otherwise set status, register once/session, or remember the tool denial.

Every branch appends exactly one frozen audit entry. Audit ids are `aud_<seq>`.

## 3. Invariants -> tests

| # | Invariant | Test |
|---|---|---|
| P1 | Read is allowed with no human | `default policy allows reads` |
| P2 | Write returns a pending grant | `a write asks...` |
| P3 | One-shot permits exactly one identical call | `allow-once permits exactly one...` |
| P4 | One-shot does not cross risk levels | `does not leak to a different risk level` |
| P5 | Session grant persists | `allow-session permits repeated...` |
| P6 | Deny is remembered | `a session deny is remembered` |
| P7 | Dangerous pattern beats a session grant | `dangerous pattern is denied even with...` |
| P8 | Injection cannot elevate | `injected instructions... cannot elevate` |
| P9 | Unknown risk denied | `an unknown risk is denied` |
| P10 | Policy deny wins | `a policy deny wins over everything` |
| P11 | dryRun is side-effect free | `dryRun reports... without mutating state` |
| P12 | Audit is frozen/append-only | `the audit log is frozen...` |
| P13 | endSession clears grants | `endSession clears session grants` |
| P14 | Tools are independent | `two different tools stay independent` |
| P15 | Tool-name pattern is checked | `dangerous pattern in the tool name` |
| P16 | Invalid resolution is refused | `resolve refuses...` |
| P17 | Risk table is ordered | `risk table is numeric...` |

## 4. Boundaries

Decision only, no enforcement. No persistence, no expiry, no rate limiting. A production host must
wrap the executor: call `authorize`, refuse unless `allow`, then execute. Treat the audit array as a
telemetry buffer, not a compliance record.

## 5. Rebuild checklist

- [ ] 17 tests pass.
- [ ] `node src/cli.mjs` prints `KERNEL ok=true`, exit 0.
- [ ] `node verify.mjs` -> `ok: true`.
- [ ] Injected "ignore previous instructions" yields `ask`, never `allow`.
