"""Pure analysis of a snapshot. No AWS calls happen here, so it is fully testable offline."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import asdict, dataclass

from . import rules as R

_ARN_ALL = re.compile(r"arn:[^:]*:[^:]*:[^:]*:[^:]*:\*")
_SERVICE_WILDCARD = re.compile(r"([A-Za-z0-9-]+):\*")
_AWS_MANAGED = re.compile(r"arn:aws[a-z-]*:iam::aws:policy/(?:.*/)?([^/]+)$")


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    agent: str
    subject: str
    role_arn: str
    policy: str
    evidence: list
    remediation: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _downgrade(severity: str) -> str:
    idx = R.SEVERITIES.index(severity)
    return R.SEVERITIES[max(idx - 1, 0)]


def severity_at_least(severity: str, threshold: str) -> bool:
    return R.SEVERITIES.index(severity) >= R.SEVERITIES.index(threshold)


def match_actions(patterns: list, targets: list) -> list:
    """Return the targets that any IAM action pattern covers (case-insensitive)."""
    hits = []
    lowered = [str(p).lower() for p in patterns]
    for target in targets:
        t = target.lower()
        if any(fnmatch.fnmatchcase(t, p) for p in lowered):
            hits.append(target)
    return hits


def is_broad_resource(statement: dict) -> bool:
    """True when the statement applies to all resources, or all resources of a service."""
    if "NotResource" in statement:
        return True
    for res in _as_list(statement.get("Resource")):
        if res == "*" or _ARN_ALL.fullmatch(str(res)):
            return True
    return False


def _make(rule_id: str, ctx: dict, evidence: list, conditional: bool, severity: str = "") -> Finding:
    default_sev, title, remediation = R.RULES[rule_id]
    sev = severity or default_sev
    note = ""
    if conditional:
        sev = _downgrade(sev)
        note = "Statement has a Condition, which agentleash does not evaluate. Severity lowered one level; review manually."
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=title,
        agent=ctx["agent"],
        subject=ctx["subject"],
        role_arn=ctx["role_arn"],
        policy=ctx["policy"],
        evidence=evidence,
        remediation=remediation,
        note=note,
    )


def analyze_policy_document(document, ctx: dict) -> list:
    """Check one identity policy document. ctx carries agent, subject, role_arn, policy."""
    findings = []
    if not isinstance(document, dict):
        return findings

    for stmt in _as_list(document.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        if not is_broad_resource(stmt):
            continue
        conditional = bool(stmt.get("Condition"))

        if "NotAction" in stmt:
            excluded = [str(a) for a in _as_list(stmt.get("NotAction"))]
            findings.append(_make("AGT007", ctx, ["NotAction: " + ", ".join(excluded)], conditional))
            continue

        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        if any(a in ("*", "*:*") for a in actions):
            findings.append(_make("AGT001", ctx, ["Action: *", "Resource: *"], conditional))
            continue

        wildcards = [a for a in actions if _SERVICE_WILDCARD.fullmatch(a)]
        specific = [a for a in actions if a not in wildcards]

        for wc in wildcards:
            service = wc.split(":", 1)[0].lower()
            sev = "high" if service in R.SENSITIVE_SERVICES else "medium"
            findings.append(_make("AGT002", ctx, [wc], conditional, severity=sev))

        privesc = match_actions(specific, R.PRIVESC_ACTIONS)
        if privesc:
            findings.append(_make("AGT003", ctx, privesc, conditional))

        data = match_actions(specific, R.DATA_READ_ACTIONS)
        if data:
            findings.append(_make("AGT004", ctx, data, conditional))

        destructive = match_actions(specific, R.DESTRUCTIVE_ACTIONS)
        if destructive:
            findings.append(_make("AGT005", ctx, destructive, conditional))

        invoke = match_actions(specific, R.MODEL_INVOKE_ACTIONS)
        if invoke:
            findings.append(_make("AGT006", ctx, invoke, conditional))

    return findings


def _principal_is_wildcard(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(v == "*" for value in principal.values() for v in _as_list(value))
    return False


def _condition_keys(condition) -> set:
    keys = set()
    if isinstance(condition, dict):
        for block in condition.values():
            if isinstance(block, dict):
                keys.update(k.lower() for k in block)
    return keys


def analyze_trust_policy(document, ctx: dict) -> list:
    findings = []
    if not isinstance(document, dict):
        return findings
    ctx = dict(ctx, policy="trust policy")

    for stmt in _as_list(document.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        condition = stmt.get("Condition")

        if _principal_is_wildcard(principal):
            findings.append(_make("AGT009", ctx, ["Principal: *"], bool(condition)))
            continue

        services = []
        if isinstance(principal, dict):
            services = [str(s).lower() for s in _as_list(principal.get("Service"))]
        matched = sorted(R.AGENT_SERVICE_PRINCIPALS & set(services))
        if matched:
            keys = _condition_keys(condition)
            if not ({"aws:sourceaccount", "aws:sourcearn"} & keys):
                findings.append(
                    _make("AGT010", ctx, ["Service: %s with no aws:SourceAccount / aws:SourceArn" % matched[0]], False)
                )
    return findings


def analyze_role(role, ctx: dict, check_trust: bool) -> list:
    findings = []
    if not isinstance(role, dict):
        return findings
    ctx = dict(ctx, role_arn=role.get("arn", ""))

    for pol in role.get("attached_policies") or []:
        arn = pol.get("arn", "")
        name = pol.get("name", "") or arn.rsplit("/", 1)[-1]
        managed = _AWS_MANAGED.match(arn)
        if managed:
            base = managed.group(1)
            sev = R.BROAD_MANAGED_POLICIES.get(base)
            if sev is None and base.endswith("FullAccess"):
                sev = "high"
            if sev:
                findings.append(_make("AGT008", dict(ctx, policy=name), [arn], False, severity=sev))
                continue
        findings.extend(analyze_policy_document(pol.get("document"), dict(ctx, policy=name)))

    for pol in role.get("inline_policies") or []:
        name = pol.get("name", "inline")
        findings.extend(analyze_policy_document(pol.get("document"), dict(ctx, policy=name + " (inline)")))

    if check_trust:
        findings.extend(analyze_trust_policy(role.get("trust_policy"), dict(ctx, policy="trust policy")))
    return findings


CLASSIC = "bedrock-classic"

ROLE_LABELS = {
    "agentcore-runtime": "runtime execution role",
    "agentcore-harness": "harness execution role",
    "agentcore-gateway": "gateway role",
    "agentcore-code-interpreter": "code interpreter execution role",
}


def display_name(agent: dict) -> str:
    name = agent.get("agent_name") or agent.get("agent_id") or "unknown-agent"
    kind = agent.get("kind")
    return "%s (%s)" % (name, kind) if kind else name


def analyze_agent(agent: dict) -> list:
    kind = agent.get("kind") or CLASSIC
    role_label = ROLE_LABELS.get(kind, "agent role")
    base = {"agent": display_name(agent), "subject": role_label, "role_arn": "", "policy": ""}
    findings = analyze_role(agent.get("role"), base, check_trust=True)
    posture = dict(base, subject=kind, policy="-")

    if kind == CLASSIC and not agent.get("guardrail"):
        findings.append(_make("AGT011", posture, ["guardrailConfiguration is empty"], False))

    if kind == "agentcore-gateway" and str(agent.get("authorizer_type") or "").upper() == "NONE":
        findings.append(_make("AGT013", posture, ["authorizerType: NONE"], False))

    if (kind == "agentcore-code-interpreter" and agent.get("role")
            and str(agent.get("network_mode") or "").upper() == "PUBLIC"):
        findings.append(_make("AGT015", posture, ["networkMode: PUBLIC", "executionRoleArn is set"], False))

    for tool in agent.get("tools") or agent.get("action_groups") or []:
        tname = tool.get("name", "unnamed")
        signature = str(tool.get("signature") or tool.get("type") or "").lower()
        if signature in ("amazon.codeinterpreter", "agentcore_code_interpreter") and tool.get("state", "ENABLED") == "ENABLED":
            findings.append(_make("AGT012", dict(base, subject="tool '%s'" % tname, policy="-"),
                                  [tool.get("signature") or tool.get("type")], False))
        lambda_role = tool.get("lambda_role")
        if lambda_role:
            ctx = dict(base, subject="tool role (tool '%s')" % tname)
            findings.extend(analyze_role(lambda_role, ctx, check_trust=False))
    return findings


def analyze_snapshot(snapshot: dict) -> list:
    findings = []
    for agent in snapshot.get("agents") or []:
        findings.extend(analyze_agent(agent))
    findings.sort(key=lambda f: (-R.SEVERITIES.index(f.severity), f.agent, f.rule_id))
    return findings
