"""Text and JSON output."""

from __future__ import annotations

import json
from collections import Counter, OrderedDict

from . import rules as R
from .analyzer import display_name


def to_json(snapshot: dict, findings: list) -> str:
    counts = Counter(f.severity for f in findings)
    return json.dumps(
        {
            "account_id": snapshot.get("account_id"),
            "region": snapshot.get("region"),
            "agents_scanned": len(snapshot.get("agents") or []),
            "summary": {sev: counts.get(sev, 0) for sev in reversed(R.SEVERITIES)},
            "findings": [f.to_dict() for f in findings],
            "collection_errors": snapshot.get("errors") or [],
        },
        indent=2,
    )


def to_text(snapshot: dict, findings: list) -> str:
    lines = []
    agents = snapshot.get("agents") or []
    lines.append("agentleash report")
    lines.append("account: %s   region: %s   agents scanned: %d"
                 % (snapshot.get("account_id") or "-", snapshot.get("region") or "-", len(agents)))
    counts = Counter(f.severity for f in findings)
    lines.append("findings: " + "  ".join("%s=%d" % (s, counts.get(s, 0)) for s in reversed(R.SEVERITIES)))
    lines.append("")

    by_agent = OrderedDict()
    for f in findings:
        by_agent.setdefault(f.agent, []).append(f)

    flagged = set(by_agent)
    for agent in agents:
        name = display_name(agent)
        if name not in flagged:
            lines.append("[ok] %s: no findings" % name)
    if len(flagged) < len(agents):
        lines.append("")

    for agent, items in by_agent.items():
        lines.append("== %s ==" % agent)
        for f in items:
            lines.append("  [%s] %s %s" % (f.severity.upper(), f.rule_id, f.title))
            lines.append("      where:    %s / %s" % (f.subject, f.policy))
            if f.role_arn:
                lines.append("      role:     %s" % f.role_arn)
            lines.append("      evidence: %s" % ", ".join(f.evidence))
            lines.append("      fix:      %s" % f.remediation)
            if f.note:
                lines.append("      note:     %s" % f.note)
        lines.append("")

    errors = snapshot.get("errors") or []
    if errors:
        lines.append("collection errors (results may be incomplete):")
        lines.extend("  - %s" % e for e in errors)
    return "\n".join(lines).rstrip() + "\n"
