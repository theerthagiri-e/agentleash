"""Collector wiring, checked against the real AWS service models with botocore's Stubber.

The Stubber validates every request parameter and response field against the
service model, so a wrong operation or field name fails here without AWS access.
"""

import datetime
import json

import boto3
import pytest
from botocore.stub import Stubber

from agentleash.analyzer import analyze_snapshot
from agentleash.collector import Collector

NOW = datetime.datetime(2026, 1, 1)
ACCT = "111122223333"
REGION = "us-east-1"


def _role_arn(name):
    return "arn:aws:iam::%s:role/%s" % (ACCT, name)


class StubSession:
    """Hands out one stubbed client per service."""

    def __init__(self):
        real = boto3.Session(region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
        self.clients = {s: real.client(s) for s in
                        ("bedrock-agentcore-control", "bedrock-agent", "lambda", "iam", "sts")}
        self.stubs = {s: Stubber(c) for s, c in self.clients.items()}

    def client(self, name, region_name=None):
        return self.clients[name]

    def activate(self):
        for stub in self.stubs.values():
            stub.activate()

    def assert_done(self):
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()


def _stub_role(iam, name, trust, inline=None, attached=None):
    iam.add_response("get_role", {"Role": {
        "Path": "/", "RoleName": name, "RoleId": "AROAEXAMPLEEXAMPLE01", "Arn": _role_arn(name),
        "CreateDate": NOW, "AssumeRolePolicyDocument": json.dumps(trust)}}, {"RoleName": name})
    inline = inline or {}
    iam.add_response("list_role_policies", {"PolicyNames": list(inline)}, {"RoleName": name})
    for pol_name, doc in inline.items():
        iam.add_response("get_role_policy",
                         {"RoleName": name, "PolicyName": pol_name, "PolicyDocument": json.dumps(doc)},
                         {"RoleName": name, "PolicyName": pol_name})
    attached = attached or []
    iam.add_response("list_attached_role_policies",
                     {"AttachedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in attached]},
                     {"RoleName": name})
    for arn in attached:
        iam.add_response("get_policy", {"Policy": {"Arn": arn, "DefaultVersionId": "v1"}}, {"PolicyArn": arn})
        iam.add_response("get_policy_version",
                         {"PolicyVersion": {"VersionId": "v1", "Document": json.dumps(
                             {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})}},
                         {"PolicyArn": arn, "VersionId": "v1"})


def _trust(service, condition=None):
    stmt = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


AC = "bedrock-agentcore.amazonaws.com"


@pytest.fixture
def session():
    return StubSession()


def test_agentcore_collection_and_findings(session):
    ac, iam, lam = session.stubs["bedrock-agentcore-control"], session.stubs["iam"], session.stubs["lambda"]
    lambda_arn = "arn:aws:lambda:%s:%s:function:tool-fn" % (REGION, ACCT)

    # runtime
    ac.add_response("list_agent_runtimes", {"agentRuntimes": [{
        "agentRuntimeArn": "arn:aws:bedrock-agentcore:%s:%s:runtime/rt-1" % (REGION, ACCT),
        "agentRuntimeId": "rt-1", "agentRuntimeVersion": "1", "agentRuntimeName": "rt",
        "description": "d", "lastUpdatedAt": NOW, "status": "READY"}]}, {})
    ac.add_response("get_agent_runtime", {
        "agentRuntimeArn": "arn:aws:bedrock-agentcore:%s:%s:runtime/rt-1" % (REGION, ACCT),
        "agentRuntimeName": "rt", "agentRuntimeId": "rt-1", "agentRuntimeVersion": "1",
        "createdAt": NOW, "lastUpdatedAt": NOW, "roleArn": _role_arn("rt-role"),
        "networkConfiguration": {"networkMode": "PUBLIC"}, "status": "READY",
        "lifecycleConfiguration": {}}, {"agentRuntimeId": "rt-1"})
    _stub_role(iam, "rt-role", _trust(AC), attached=["arn:aws:iam::aws:policy/AdministratorAccess"])

    # harness
    ac.add_response("list_harnesses", {"harnesses": [{
        "harnessId": "h-1", "harnessName": "hn", "arn": "arn:aws:bedrock-agentcore:%s:%s:harness/h-1" % (REGION, ACCT),
        "status": "READY", "createdAt": NOW, "updatedAt": NOW}]}, {})
    ac.add_response("get_harness", {"harness": {
        "harnessId": "h-1", "harnessName": "hn", "arn": "arn:aws:bedrock-agentcore:%s:%s:harness/h-1" % (REGION, ACCT),
        "status": "READY", "executionRoleArn": _role_arn("h-role"), "createdAt": NOW, "updatedAt": NOW,
        "model": {"bedrockModelConfig": {"modelId": "example.model-v1"}}, "systemPrompt": [], "skills": [],
        "allowedTools": [], "truncation": {"strategy": "none"}, "environment": {"agentCoreRuntimeEnvironment": {"agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/rt-1", "agentRuntimeName": "rt", "agentRuntimeId": "rt-1", "lifecycleConfiguration": {}, "networkConfiguration": {"networkMode": "PUBLIC"}}},
        "tools": [{"type": "agentcore_code_interpreter", "name": "code"}]}}, {"harnessId": "h-1"})
    _stub_role(iam, "h-role", _trust(AC, {"StringEquals": {"aws:SourceAccount": ACCT}}),
               inline={"scoped": {"Version": "2012-10-17", "Statement": [
                   {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}})

    # gateway with a lambda target
    ac.add_response("list_gateways", {"items": [{
        "gatewayId": "gw-abcdefghij", "name": "gw", "status": "READY", "createdAt": NOW, "updatedAt": NOW,
        "authorizerType": "NONE", "protocolType": "MCP"}]}, {})
    ac.add_response("get_gateway", {
        "gatewayArn": "arn:aws:bedrock-agentcore:%s:%s:gateway/gw-abcdefghij" % (REGION, ACCT),
        "gatewayId": "gw-abcdefghij", "createdAt": NOW, "updatedAt": NOW, "status": "READY", "name": "gw",
        "roleArn": _role_arn("gw-role"), "protocolType": "MCP", "authorizerType": "NONE"},
        {"gatewayIdentifier": "gw-abcdefghij"})
    _stub_role(iam, "gw-role", _trust(AC, {"StringEquals": {"aws:SourceAccount": ACCT}}))
    ac.add_response("list_gateway_targets", {"items": [{
        "targetId": "TARGET0001", "name": "tool", "status": "READY", "createdAt": NOW, "updatedAt": NOW}]},
        {"gatewayIdentifier": "gw-abcdefghij"})
    ac.add_response("get_gateway_target", {
        "gatewayArn": "arn:aws:bedrock-agentcore:%s:%s:gateway/gw-abcdefghij" % (REGION, ACCT),
        "targetId": "TARGET0001", "createdAt": NOW, "updatedAt": NOW, "status": "READY", "name": "tool",
        "targetConfiguration": {"mcp": {"lambda": {"lambdaArn": lambda_arn, "toolSchema": {"inlinePayload": [
            {"name": "t", "description": "d", "inputSchema": {"type": "object"}}]}}}},
        "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]},
        {"gatewayIdentifier": "gw-abcdefghij", "targetId": "TARGET0001"})
    lam.add_response("get_function_configuration", {"FunctionName": "tool-fn", "Role": _role_arn("fn-role")},
                     {"FunctionName": lambda_arn})
    _stub_role(iam, "fn-role", _trust("lambda.amazonaws.com"),
               inline={"bad": {"Version": "2012-10-17", "Statement": [
                   {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}})

    # custom code interpreter
    ac.add_response("list_code_interpreters", {"codeInterpreterSummaries": [{
        "codeInterpreterId": "ci_x-abcdefghij",
        "codeInterpreterArn": "arn:aws:bedrock-agentcore:%s:%s:code-interpreter-custom/ci_x-abcdefghij" % (REGION, ACCT),
        "name": "ci_x", "status": "READY", "createdAt": NOW, "lastUpdatedAt": NOW}]}, {"type": "CUSTOM"})
    ac.add_response("get_code_interpreter", {
        "codeInterpreterId": "ci_x-abcdefghij",
        "codeInterpreterArn": "arn:aws:bedrock-agentcore:%s:%s:code-interpreter-custom/ci_x-abcdefghij" % (REGION, ACCT),
        "name": "ci_x", "executionRoleArn": _role_arn("ci-role"),
        "networkConfiguration": {"networkMode": "PUBLIC"}, "status": "READY", "createdAt": NOW, "lastUpdatedAt": NOW},
        {"codeInterpreterId": "ci_x-abcdefghij"})
    _stub_role(iam, "ci-role", _trust(AC, {"StringEquals": {"aws:SourceAccount": ACCT}}))

    session.activate()
    collector = Collector(session, REGION)
    agents = collector.collect_agentcore()
    session.assert_done()
    assert collector.errors == []
    assert [a["kind"] for a in agents] == ["agentcore-runtime", "agentcore-harness",
                                           "agentcore-gateway", "agentcore-code-interpreter"]

    found = {}
    for f in analyze_snapshot({"agents": agents}):
        found.setdefault(f.agent, []).append(f.rule_id)
    assert sorted(found["rt (agentcore-runtime)"]) == ["AGT008", "AGT010"]
    assert found["hn (agentcore-harness)"] == ["AGT012"]
    assert sorted(found["gw (agentcore-gateway)"]) == ["AGT003", "AGT013"]
    assert found["ci_x (agentcore-code-interpreter)"] == ["AGT015"]


def test_classic_collection(session):
    bedrock, iam = session.stubs["bedrock-agent"], session.stubs["iam"]
    bedrock.add_response("list_agents", {"agentSummaries": [{
        "agentId": "AGENT00001", "agentName": "old", "agentStatus": "PREPARED", "updatedAt": NOW}]}, {})
    bedrock.add_response("get_agent", {"agent": {
        "agentId": "AGENT00001", "agentName": "old",
        "agentArn": "arn:aws:bedrock:%s:%s:agent/AGENT00001" % (REGION, ACCT), "agentVersion": "DRAFT",
        "agentStatus": "PREPARED", "idleSessionTTLInSeconds": 600,
        "agentResourceRoleArn": _role_arn("old-role"), "createdAt": NOW, "updatedAt": NOW}},
        {"agentId": "AGENT00001"})
    _stub_role(iam, "old-role", _trust("bedrock.amazonaws.com"))
    bedrock.add_response("list_agent_action_groups", {"actionGroupSummaries": [{
        "actionGroupId": "AG00000001", "actionGroupName": "code", "actionGroupState": "ENABLED", "updatedAt": NOW}]},
        {"agentId": "AGENT00001", "agentVersion": "DRAFT"})
    bedrock.add_response("get_agent_action_group", {"agentActionGroup": {
        "agentId": "AGENT00001", "agentVersion": "DRAFT", "actionGroupId": "AG00000001", "actionGroupName": "code",
        "actionGroupState": "ENABLED", "parentActionSignature": "AMAZON.CodeInterpreter",
        "createdAt": NOW, "updatedAt": NOW}},
        {"agentId": "AGENT00001", "agentVersion": "DRAFT", "actionGroupId": "AG00000001"})

    session.activate()
    collector = Collector(session, REGION)
    agents = collector.collect_classic()
    session.assert_done()
    assert collector.errors == []
    ids = sorted(f.rule_id for f in analyze_snapshot({"agents": agents}))
    assert ids == ["AGT010", "AGT011", "AGT012"]


def test_service_failure_is_recorded_not_raised(session):
    session.stubs["bedrock-agent"].add_client_error("list_agents", "AccessDeniedException", "closed to new customers")
    session.activate()
    collector = Collector(session, REGION)
    assert collector.collect_classic() == []
    assert "bedrock agents classic" in collector.errors[0]
