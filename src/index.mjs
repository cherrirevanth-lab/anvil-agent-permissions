// SPDX-License-Identifier: MIT
/**
 * agent-permissions — a tool-call approval kernel.
 *
 * Every tool call is decided by the kernel, not by the text of the call. The
 * order is fixed: dangerous pattern, then hard policy deny, then remembered
 * denial, then an explicit one-shot or session grant, then the configured
 * policy. An approval is a separate call (`resolve`) with its own decision, so
 * injected instructions inside `args` have no path to `allow`.
 */
export const RISK = Object.freeze({
  read: 0,
  write: 1,
  execute: 2,
  network: 3,
});

export const DANGEROUS_PATTERNS = Object.freeze([
  /rm\s+-rf\s+\//i,
  /curl[^|]*\|\s*(sh|bash)/i,
  /--force\b/i,
  /git\s+push\s+--force/i,
  /:\(\)\s*\{/,
  /chmod\s+777/i,
  />\s*\/dev\/sd/i,
]);

const DEFAULT_POLICY = Object.freeze({ read: 'allow', write: 'ask', execute: 'ask', network: 'ask' });
const POLICY_VALUES = new Set(['allow', 'ask', 'deny']);

export function createKernel({ policy = DEFAULT_POLICY, now = () => Date.now() } = {}) {
  if (typeof now !== 'function') throw new TypeError('now must be a function');
  if (policy === null || typeof policy !== 'object') throw new TypeError('policy must be an object');

  const effectivePolicy = { ...DEFAULT_POLICY };
  for (const [name, value] of Object.entries(policy)) {
    if (!Object.hasOwn(RISK, name)) throw new TypeError(`unknown policy risk: ${name}`);
    if (!POLICY_VALUES.has(value)) throw new TypeError(`invalid policy value for ${name}: ${value}`);
    effectivePolicy[name] = value;
  }

  const grants = new Map();
  const pendingByTool = new Map();
  const onceGrants = new Map();
  const sessionGrants = new Map();
  const deniedTools = new Set();
  const auditLog = [];
  let seq = 0;

  const callKey = (tool, riskName) => `${tool}\u0000${riskName}`;

  function normalizeRisk(risk) {
    if (typeof risk === 'string') {
      const name = risk.toLowerCase();
      return Object.hasOwn(RISK, name) ? { name, level: RISK[name] } : null;
    }
    if (typeof risk === 'number' && Number.isInteger(risk)) {
      for (const [name, level] of Object.entries(RISK)) {
        if (level === risk) return { name, level };
      }
    }
    return null;
  }

  function matchingPattern(tool, args) {
    const haystack = `${tool}\n${args === undefined || args === null ? '' : String(args)}`;
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(haystack)) return pattern;
    }
    return null;
  }

  function audit(entry) {
    const record = Object.freeze({ auditId: `aud_${++seq}`, at: now(), ...entry });
    auditLog.push(record);
    return record;
  }

  function authorize({ tool, risk, args = '' } = {}) {
    if (typeof tool !== 'string' || tool.trim().length === 0) {
      const entry = audit({ tool: null, risk: null, decision: 'deny', reason: 'INVALID_TOOL', grantId: null });
      return { decision: 'deny', reason: 'INVALID_TOOL', auditId: entry.auditId };
    }
    const normalized = normalizeRisk(risk);
    if (!normalized) {
      const entry = audit({ tool, risk: null, decision: 'deny', reason: 'INVALID_RISK', grantId: null });
      return { decision: 'deny', reason: 'INVALID_RISK', auditId: entry.auditId };
    }

    const pattern = matchingPattern(tool, args);
    if (pattern) {
      const entry = audit({
        tool,
        risk: normalized.name,
        decision: 'deny',
        reason: 'DANGEROUS_PATTERN',
        grantId: null,
        pattern: pattern.source,
      });
      return { decision: 'deny', reason: 'DANGEROUS_PATTERN', auditId: entry.auditId, matchingPattern: pattern.source };
    }

    if (effectivePolicy[normalized.name] === 'deny') {
      const entry = audit({ tool, risk: normalized.name, decision: 'deny', reason: 'POLICY_DENY', grantId: null });
      return { decision: 'deny', reason: 'POLICY_DENY', auditId: entry.auditId };
    }

    if (deniedTools.has(tool)) {
      const entry = audit({ tool, risk: normalized.name, decision: 'deny', reason: 'DENIED_TOOL', grantId: null });
      return { decision: 'deny', reason: 'DENIED_TOOL', auditId: entry.auditId };
    }

    const key = callKey(tool, normalized.name);
    const once = onceGrants.get(key);
    if (once) {
      onceGrants.delete(key);
      once.status = 'consumed';
      const entry = audit({
        tool,
        risk: normalized.name,
        decision: 'allow',
        reason: 'ONE_TIME_GRANT',
        grantId: once.grantId,
      });
      return { decision: 'allow', reason: 'ONE_TIME_GRANT', grantId: once.grantId, auditId: entry.auditId };
    }

    const session = sessionGrants.get(key);
    if (session) {
      const entry = audit({
        tool,
        risk: normalized.name,
        decision: 'allow',
        reason: 'SESSION_GRANT',
        grantId: session.grantId,
      });
      return { decision: 'allow', reason: 'SESSION_GRANT', grantId: session.grantId, auditId: entry.auditId };
    }

    if (effectivePolicy[normalized.name] === 'allow') {
      const entry = audit({ tool, risk: normalized.name, decision: 'allow', reason: 'POLICY_ALLOW', grantId: null });
      return { decision: 'allow', reason: 'POLICY_ALLOW', auditId: entry.auditId };
    }

    const grant = {
      grantId: `grt_${++seq}`,
      status: 'pending',
      tool,
      risk: normalized.name,
      createdAt: now(),
    };
    grants.set(grant.grantId, grant);
    pendingByTool.set(key, grant);
    const entry = audit({
      tool,
      risk: normalized.name,
      decision: 'ask',
      reason: 'APPROVAL_REQUIRED',
      grantId: grant.grantId,
    });
    return { decision: 'ask', reason: 'APPROVAL_REQUIRED', grantId: grant.grantId, auditId: entry.auditId };
  }

  function resolve({ grantId, decision } = {}) {
    if (decision !== 'allow-once' && decision !== 'allow-session' && decision !== 'deny') {
      return { ok: false, code: 'INVALID_DECISION' };
    }
    const grant = grants.get(grantId);
    if (!grant) return { ok: false, code: 'UNKNOWN_GRANT' };
    if (grant.status !== 'pending') return { ok: false, code: 'ALREADY_RESOLVED' };

    const key = callKey(grant.tool, grant.risk);
    if (decision === 'allow-once') {
      grant.status = 'allowed-once';
      onceGrants.set(key, grant);
    } else if (decision === 'allow-session') {
      grant.status = 'allowed-session';
      sessionGrants.set(key, grant);
    } else {
      grant.status = 'denied';
      deniedTools.add(grant.tool);
    }
    pendingByTool.delete(key);

    const entry = audit({
      tool: grant.tool,
      risk: grant.risk,
      decision,
      reason: decision === 'deny' ? 'DENIED_BY_APPROVER' : 'APPROVED_BY_APPROVER',
      grantId: grant.grantId,
    });
    return { ok: true, grantId: grant.grantId, decision, status: grant.status, auditId: entry.auditId };
  }

  function dryRun({ tool, risk, args = '' } = {}) {
    if (typeof tool !== 'string' || tool.trim().length === 0) {
      return { wouldAllow: false, wouldAsk: false, wouldDeny: true, matchingPattern: null, reason: 'INVALID_TOOL' };
    }
    const normalized = normalizeRisk(risk);
    if (!normalized) {
      return { wouldAllow: false, wouldAsk: false, wouldDeny: true, matchingPattern: null, reason: 'INVALID_RISK' };
    }
    const pattern = matchingPattern(tool, args);
    if (pattern) {
      return {
        wouldAllow: false,
        wouldAsk: false,
        wouldDeny: true,
        matchingPattern: pattern.source,
        reason: 'DANGEROUS_PATTERN',
      };
    }
    if (effectivePolicy[normalized.name] === 'deny') {
      return { wouldAllow: false, wouldAsk: false, wouldDeny: true, matchingPattern: null, reason: 'POLICY_DENY' };
    }
    if (deniedTools.has(tool)) {
      return { wouldAllow: false, wouldAsk: false, wouldDeny: true, matchingPattern: null, reason: 'DENIED_TOOL' };
    }
    const key = callKey(tool, normalized.name);
    if (onceGrants.has(key) || sessionGrants.has(key) || effectivePolicy[normalized.name] === 'allow') {
      return { wouldAllow: true, wouldAsk: false, wouldDeny: false, matchingPattern: null, reason: 'ALLOW' };
    }
    return { wouldAllow: false, wouldAsk: true, wouldDeny: false, matchingPattern: null, reason: 'APPROVAL_REQUIRED' };
  }

  function endSession() {
    const cleared = {
      session: sessionGrants.size,
      once: onceGrants.size,
      pending: pendingByTool.size,
      denied: deniedTools.size,
    };
    for (const grant of pendingByTool.values()) grant.status = 'cancelled';
    sessionGrants.clear();
    onceGrants.clear();
    pendingByTool.clear();
    deniedTools.clear();
    return { ok: true, cleared };
  }

  function auditTrail() {
    return Object.freeze(auditLog.slice());
  }

  return { authorize, resolve, dryRun, endSession, audit: auditTrail };
}
