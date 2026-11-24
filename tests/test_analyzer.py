import json
import os

from agentleash.analyzer import (
    analyze_policy_document,
    analyze_snapshot,
    analyze_trust_policy,
    is_broad_resource,
    match_actions,
    severity_at_least,
)
from agentleash.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "examples", "sample_snapshot.json")
CTX = {"agent": "a", "subject": "agent role", "role_arn": "arn:aws:iam::1:role/r", "policy": "p"}


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def test_match_actions_expands_wildcards_case_insensitively():
    assert match_actions(["s3:Get*"], ["s3:GetObject", "s3:DeleteObject"]) == ["s3:GetObject"]
    assert match_actions(["IAM:passrole"], ["iam:PassRole"]) == ["iam:PassRole"]
    assert match_actions(["ec2:Describe*"], ["iam:PassRole"]) == []


def test_broad_resource_detection():
    assert is_broad_resource({"Resource": "*"})
    assert is_broad_resource({"Resource": ["arn:aws:s3:::*"]})
    assert is_broad_resource({"NotResource": "arn:aws:s3:::x"})
    assert not is_broad_resource({"Resource": "arn:aws:s3:::bucket/*"})
    assert not is_broad_resource({})


def test_admin_statement_is_single_critical_finding():
    findings = analyze_policy_document(_doc({"Effect": "Allow", "Action": "*", "Resource": "*"}), CTX)
    assert _ids(findings) == ["AGT001"]
    assert findings[0].severity == "critical"


def test_scoped_statement_has_no_findings():
    doc = _doc({"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole"],
                "Resource": "arn:aws:s3:::bucket/key"})
    assert analyze_policy_document(doc, CTX) == []


def test_deny_statements_are_ignored():
    assert analyze_policy_document(_doc({"Effect": "Deny", "Action": "*", "Resource": "*"}), CTX) == []


def test_service_wildcard_severity_depends_on_service():
    findings = analyze_policy_document(
        _doc({"Effect": "Allow", "Action": ["iam:*", "polly:*"], "Resource": "*"}), CTX)
    by_evidence = {f.evidence[0]: f.severity for f in findings}
    assert by_evidence == {"iam:*": "high", "polly:*": "medium"}


def test_privesc_data_destructive_and_model_invoke():
    doc = _doc({
        "Effect": "Allow",
        "Action": ["iam:Pass*", "secretsmanager:GetSecretValue", "cloudtrail:StopLogging", "bedrock:InvokeModel"],
        "Resource": "*",
    })
    assert _ids(analyze_policy_document(doc, CTX)) == ["AGT003", "AGT004", "AGT005", "AGT006"]


def test_condition_lowers_severity_and_adds_note():
    doc = _doc({"Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}})
    finding = analyze_policy_document(doc, CTX)[0]
    assert finding.severity == "high"
    assert "Condition" in finding.note


def test_notaction_allow_is_flagged():
    doc = _doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert _ids(analyze_policy_document(doc, CTX)) == ["AGT007"]


def test_statement_as_single_object_and_bad_input():
    doc = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    assert _ids(analyze_policy_document(doc, CTX)) == ["AGT001"]
    assert analyze_policy_document(None, CTX) == []
    assert analyze_policy_document("not a policy", CTX) == []


def test_trust_policy_checks():
    open_trust = _doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
    assert _ids(analyze_trust_policy(open_trust, CTX)) == ["AGT009"]

    no_condition = _doc({"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
                         "Action": "sts:AssumeRole"})
    assert _ids(analyze_trust_policy(no_condition, CTX)) == ["AGT010"]

    protected = _doc({"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
                      "Action": "sts:AssumeRole",
                      "Condition": {"StringEquals": {"aws:SourceAccount": "1"}}})
    assert analyze_trust_policy(protected, CTX) == []


def test_sample_snapshot_end_to_end():
    with open(SAMPLE, encoding="utf-8") as fh:
        findings = analyze_snapshot(json.load(fh))

    by_agent = {}
    for f in findings:
        by_agent.setdefault(f.agent, []).append(f.rule_id)

    assert sorted(by_agent["support-bot"]) == ["AGT008", "AGT010", "AGT011", "AGT012"]
    assert sorted(by_agent["billing-agent"]) == ["AGT002", "AGT003", "AGT004"]
    assert "faq-agent" not in by_agent

    # tool-role findings are attributed to the tool, not the agent role
    assert all("InvoiceLookup" in f.subject for f in findings if f.agent == "billing-agent")
    # sorted most severe first
    assert findings[0].severity == "critical"


def test_severity_threshold():
    assert severity_at_least("critical", "high")
    assert not severity_at_least("medium", "high")


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["analyze", SAMPLE]) == 1
    out = capsys.readouterr().out
    assert "support-bot" in out and "[ok] faq-agent" in out

    assert main(["analyze", SAMPLE, "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["agents_scanned"] == 3
    assert payload["summary"]["critical"] >= 1

    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"agents": []}))
    assert main(["analyze", str(clean)]) == 0

    assert main(["analyze", str(tmp_path / "missing.json")]) == 2
