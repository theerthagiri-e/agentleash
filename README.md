# agentleash

Find AI agents on AWS that hold more permissions than they need.

An AI agent acts on whatever text reaches it. If a prompt injection steers the
agent, the attacker gets everything the agent's IAM role allows. `agentleash`
finds your agents, follows each one to the IAM roles behind it (its own role
and the role of every Lambda tool it can call), and reports the permissions an
attacker could abuse.

It is read-only. It makes only `List*` and `Get*` calls.

## What it scans

**Amazon Bedrock AgentCore**

- Runtimes and their execution roles
- Harnesses, their execution roles and enabled tools
- Gateways: authorizer type, gateway role, and the role of each Lambda target
- Custom code interpreters: execution role and network mode

**Amazon Bedrock Agents Classic**

- Agents, guardrails, action groups, and the role of each Lambda action group

Agents Classic is in maintenance mode and closed to new customers. If you still
run it, scan before you migrate: an over-permissioned role copied to AgentCore
is still over-permissioned.

## Install

```
pip install .
```

Use a recent `boto3`; older versions do not know every AgentCore operation.

## Use

```
agentleash scan --region us-east-1
agentleash scan --region us-east-1 --target agentcore
agentleash scan --region us-east-1 --profile audit --format json --output report.json
```

Save what was collected and analyze it later, with no AWS access:

```
agentleash scan --region us-east-1 --save-snapshot snapshot.json
agentleash analyze snapshot.json
```

Try it without an AWS account:

```
agentleash analyze examples/sample_snapshot.json
```

Exit status is `1` when any finding is at or above `--fail-on` (default
`high`), `0` otherwise, and `2` on error, so it can gate a CI pipeline.

## What it checks

| Rule | Severity | Finding |
| --- | --- | --- |
| AGT001 | critical | Role allows every action on every resource |
| AGT002 | high / medium | Role allows a whole service on all resources |
| AGT003 | critical | Role can escalate its own privileges (`iam:PassRole`, `sts:AssumeRole`, `lambda:UpdateFunctionCode`, ...) |
| AGT004 | high | Role can read secrets, parameters, objects, keys or tables account-wide |
| AGT005 | high | Role can destroy resources or disable logging account-wide |
| AGT006 | medium | Role can invoke any foundation model |
| AGT007 | high | Policy uses `Allow` with `NotAction` |
| AGT008 | critical / high | Broad AWS managed policy attached (`AdministratorAccess`, `*FullAccess`, ...) |
| AGT009 | critical | Trust policy lets any principal assume the role |
| AGT010 | medium | Trust policy has no `aws:SourceAccount` / `aws:SourceArn` condition |
| AGT011 | medium | Classic agent has no guardrail attached |
| AGT012 | low | Code interpreter is enabled |
| AGT013 | critical | Gateway accepts unauthenticated requests (`authorizerType: NONE`) |
| AGT015 | medium | Code interpreter has an execution role and public network access |

Rules AGT001 to AGT008 apply to each agent's own role and to the role of each
Lambda tool. Findings on a tool's role are labelled with the tool name.

## Permissions the scanner needs

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:ListHarnesses",
        "bedrock-agentcore:GetHarness",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:ListGatewayTargets",
        "bedrock-agentcore:GetGatewayTarget",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:GetCodeInterpreter",
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "bedrock:ListAgentActionGroups",
        "bedrock:GetAgentActionGroup",
        "lambda:GetFunctionConfiguration",
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

If a service or call is unavailable, the scan continues and lists it under
"collection errors".

## Test lab

`lab/lab.py` creates a small set of deliberately misconfigured AgentCore
resources in an account you own, and removes them again.

```
python3 lab/lab.py up --region us-east-1
agentleash scan --region us-east-1 --target agentcore
python3 lab/lab.py down --region us-east-1
```

Expected findings:

- `leashlab-gateway`: AGT010, AGT002 and AGT004 on the gateway role; AGT003 and AGT002 on the tool role
- `leashlab_ci`: AGT008 and AGT015
- `leashlab-clean-gateway`: none

The lab is for testing only. Nothing in it is invoked. Run `down` when finished.

## Limits

- It reads policies; it does not simulate them. `Deny` statements, permission
  boundaries, service control policies and resource policies are not
  evaluated, so a finding can be blocked elsewhere. Statements with a
  `Condition` are reported one severity level lower, with a note.
- Only statements that apply to all resources (`*`, or every resource of a
  service) are flagged. A dangerous action scoped to named resources is not
  reported.
- Gateway targets other than Lambda (OpenAPI, MCP servers, API Gateway,
  connectors) are listed but their downstream permissions are not analyzed.
- AgentCore policy engines, memory, browsers and identity providers are not
  analyzed yet.
- For Agents Classic it reads the `DRAFT` version of each agent.
- One region per run.

## Roadmap

- AgentCore policy engine and gateway rule analysis
- Agents running outside AgentCore (ECS, EKS, Lambda)
- Multi-region and multi-account scans
- SARIF output for code-scanning dashboards

## Develop

```
pip install -e ".[dev]"
pytest
```

The collector tests run against the AWS service models with botocore's
Stubber, so wrong operation or field names fail without AWS access.

## License

MIT
