"""Read-only collection of AI agents on AWS and the IAM roles behind them.

Covers Amazon Bedrock AgentCore (runtimes, harnesses, gateways and their Lambda
targets, custom code interpreters) and Amazon Bedrock Agents Classic.

Produces a plain-dict snapshot that analyzer.analyze_snapshot() consumes.
Only List*/Get* calls are made.
"""

from __future__ import annotations


def _role_name_from_arn(arn: str) -> str:
    return arn.split(":role/", 1)[-1].rsplit("/", 1)[-1]


class Collector:
    def __init__(self, session, region: str):
        self.region = region
        self.session = session
        self.lambda_ = session.client("lambda", region_name=region)
        self.iam = session.client("iam")
        self.sts = session.client("sts")
        self._roles = {}
        self.errors = []

    def _note(self, where: str, exc: Exception) -> None:
        self.errors.append("%s: %s" % (where, exc))

    # ---------- IAM ----------

    def get_role(self, role_arn: str):
        if not role_arn:
            return None
        if role_arn in self._roles:
            return self._roles[role_arn]
        name = _role_name_from_arn(role_arn)
        role = {"arn": role_arn, "name": name, "trust_policy": None,
                "inline_policies": [], "attached_policies": [], "permissions_boundary": None}
        try:
            raw = self.iam.get_role(RoleName=name)["Role"]
            role["trust_policy"] = raw.get("AssumeRolePolicyDocument")
            role["permissions_boundary"] = (raw.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")

            for page in self.iam.get_paginator("list_role_policies").paginate(RoleName=name):
                for pol_name in page.get("PolicyNames", []):
                    doc = self.iam.get_role_policy(RoleName=name, PolicyName=pol_name)["PolicyDocument"]
                    role["inline_policies"].append({"name": pol_name, "document": doc})

            for page in self.iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                for att in page.get("AttachedPolicies", []):
                    entry = {"name": att["PolicyName"], "arn": att["PolicyArn"], "document": None}
                    try:
                        version = self.iam.get_policy(PolicyArn=att["PolicyArn"])["Policy"]["DefaultVersionId"]
                        entry["document"] = self.iam.get_policy_version(
                            PolicyArn=att["PolicyArn"], VersionId=version
                        )["PolicyVersion"]["Document"]
                    except Exception as exc:  # noqa: BLE001 - record and keep going
                        self._note("policy %s" % att["PolicyArn"], exc)
                    role["attached_policies"].append(entry)
        except Exception as exc:  # noqa: BLE001
            self._note("role %s" % role_arn, exc)
        self._roles[role_arn] = role
        return role

    def _lambda_role(self, lambda_arn: str):
        cfg = self.lambda_.get_function_configuration(FunctionName=lambda_arn)
        return self.get_role(cfg.get("Role", ""))

    @staticmethod
    def _entry(kind: str, agent_id, name, arn=None, status=None) -> dict:
        return {"kind": kind, "agent_id": agent_id, "agent_name": name, "agent_arn": arn,
                "status": status, "role": None, "tools": []}

    # ---------- Bedrock AgentCore ----------

    def collect_agentcore(self) -> list:
        ac = self.session.client("bedrock-agentcore-control", region_name=self.region)
        agents = []
        for label, fn in (("runtimes", self._runtimes), ("harnesses", self._harnesses),
                          ("gateways", self._gateways), ("code interpreters", self._code_interpreters)):
            try:
                agents.extend(fn(ac))
            except Exception as exc:  # noqa: BLE001
                self._note("agentcore %s" % label, exc)
        return agents

    def _runtimes(self, ac) -> list:
        out = []
        for page in ac.get_paginator("list_agent_runtimes").paginate():
            for item in page.get("agentRuntimes", []):
                entry = self._entry("agentcore-runtime", item["agentRuntimeId"], item.get("agentRuntimeName"),
                                    item.get("agentRuntimeArn"), item.get("status"))
                try:
                    detail = ac.get_agent_runtime(agentRuntimeId=item["agentRuntimeId"])
                    entry["role"] = self.get_role(detail.get("roleArn", ""))
                    entry["network_mode"] = (detail.get("networkConfiguration") or {}).get("networkMode")
                    entry["jwt_authorizer"] = bool((detail.get("authorizerConfiguration") or {}).get("customJWTAuthorizer"))
                except Exception as exc:  # noqa: BLE001
                    self._note("runtime %s" % item["agentRuntimeId"], exc)
                out.append(entry)
        return out

    def _harnesses(self, ac) -> list:
        out = []
        for page in ac.get_paginator("list_harnesses").paginate():
            for item in page.get("harnesses", []):
                entry = self._entry("agentcore-harness", item["harnessId"], item.get("harnessName"),
                                    item.get("arn"), item.get("status"))
                try:
                    detail = ac.get_harness(harnessId=item["harnessId"])["harness"]
                    entry["role"] = self.get_role(detail.get("executionRoleArn", ""))
                    entry["tools"] = [{"name": t.get("name") or t.get("type"), "type": t.get("type")}
                                      for t in detail.get("tools") or []]
                except Exception as exc:  # noqa: BLE001
                    self._note("harness %s" % item["harnessId"], exc)
                out.append(entry)
        return out

    def _gateways(self, ac) -> list:
        out = []
        for page in ac.get_paginator("list_gateways").paginate():
            for item in page.get("items", []):
                gid = item["gatewayId"]
                entry = self._entry("agentcore-gateway", gid, item.get("name"), None, item.get("status"))
                entry["authorizer_type"] = item.get("authorizerType")
                try:
                    detail = ac.get_gateway(gatewayIdentifier=gid)
                    entry["agent_arn"] = detail.get("gatewayArn")
                    entry["authorizer_type"] = detail.get("authorizerType") or entry["authorizer_type"]
                    entry["role"] = self.get_role(detail.get("roleArn", ""))
                except Exception as exc:  # noqa: BLE001
                    self._note("gateway %s" % gid, exc)
                entry["tools"] = self._gateway_targets(ac, gid)
                out.append(entry)
        return out

    def _gateway_targets(self, ac, gid: str) -> list:
        tools = []
        try:
            for page in ac.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gid):
                for item in page.get("items", []):
                    tool = {"name": item.get("name"), "type": item.get("targetType"),
                            "lambda_arn": None, "lambda_role": None, "credential_types": []}
                    try:
                        detail = ac.get_gateway_target(gatewayIdentifier=gid, targetId=item["targetId"])
                        tool["credential_types"] = [c.get("credentialProviderType")
                                                    for c in detail.get("credentialProviderConfigurations") or []]
                        mcp = (detail.get("targetConfiguration") or {}).get("mcp") or {}
                        lambda_arn = (mcp.get("lambda") or {}).get("lambdaArn")
                        if lambda_arn:
                            tool["type"] = tool["type"] or "lambda"
                            tool["lambda_arn"] = lambda_arn
                            tool["lambda_role"] = self._lambda_role(lambda_arn)
                    except Exception as exc:  # noqa: BLE001
                        self._note("gateway target %s" % item.get("name"), exc)
                    tools.append(tool)
        except Exception as exc:  # noqa: BLE001
            self._note("targets for gateway %s" % gid, exc)
        return tools

    def _code_interpreters(self, ac) -> list:
        out = []
        for page in ac.get_paginator("list_code_interpreters").paginate(type="CUSTOM"):
            for item in page.get("codeInterpreterSummaries", []):
                cid = item["codeInterpreterId"]
                entry = self._entry("agentcore-code-interpreter", cid, item.get("name"),
                                    item.get("codeInterpreterArn"), item.get("status"))
                try:
                    detail = ac.get_code_interpreter(codeInterpreterId=cid)
                    entry["role"] = self.get_role(detail.get("executionRoleArn", ""))
                    entry["network_mode"] = (detail.get("networkConfiguration") or {}).get("networkMode")
                except Exception as exc:  # noqa: BLE001
                    self._note("code interpreter %s" % cid, exc)
                out.append(entry)
        return out

    # ---------- Bedrock Agents Classic ----------

    def collect_classic(self) -> list:
        agents = []
        try:
            bedrock = self.session.client("bedrock-agent", region_name=self.region)
            for page in bedrock.get_paginator("list_agents").paginate():
                for summary in page.get("agentSummaries", []):
                    agent_id = summary["agentId"]
                    entry = self._entry("bedrock-classic", agent_id, summary.get("agentName"),
                                        None, summary.get("agentStatus"))
                    entry["guardrail"] = None
                    try:
                        detail = bedrock.get_agent(agentId=agent_id)["agent"]
                        entry["agent_arn"] = detail.get("agentArn")
                        guard = detail.get("guardrailConfiguration") or {}
                        if guard.get("guardrailIdentifier"):
                            entry["guardrail"] = {"id": guard["guardrailIdentifier"],
                                                  "version": guard.get("guardrailVersion")}
                        entry["role"] = self.get_role(detail.get("agentResourceRoleArn", ""))
                    except Exception as exc:  # noqa: BLE001
                        self._note("agent %s" % agent_id, exc)
                    entry["tools"] = self._action_groups(bedrock, agent_id)
                    agents.append(entry)
        except Exception as exc:  # noqa: BLE001
            self._note("bedrock agents classic", exc)
        return agents

    def _action_groups(self, bedrock, agent_id: str) -> list:
        groups = []
        try:
            paginator = bedrock.get_paginator("list_agent_action_groups")
            for page in paginator.paginate(agentId=agent_id, agentVersion="DRAFT"):
                for summary in page.get("actionGroupSummaries", []):
                    group = {"name": summary.get("actionGroupName"), "state": summary.get("actionGroupState"),
                             "signature": None, "lambda_arn": None, "lambda_role": None}
                    try:
                        detail = bedrock.get_agent_action_group(
                            agentId=agent_id, agentVersion="DRAFT", actionGroupId=summary["actionGroupId"]
                        )["agentActionGroup"]
                        group["signature"] = detail.get("parentActionSignature")
                        executor = detail.get("actionGroupExecutor") or {}
                        if executor.get("lambda"):
                            group["lambda_arn"] = executor["lambda"]
                            group["lambda_role"] = self._lambda_role(executor["lambda"])
                    except Exception as exc:  # noqa: BLE001
                        self._note("action group %s" % summary.get("actionGroupName"), exc)
                    groups.append(group)
        except Exception as exc:  # noqa: BLE001
            self._note("action groups for agent %s" % agent_id, exc)
        return groups

    # ---------- entry point ----------

    def collect(self, target: str = "all") -> dict:
        account = None
        try:
            account = self.sts.get_caller_identity()["Account"]
        except Exception as exc:  # noqa: BLE001
            self._note("sts", exc)

        agents = []
        if target in ("all", "agentcore"):
            agents.extend(self.collect_agentcore())
        if target in ("all", "classic"):
            agents.extend(self.collect_classic())
        return {"account_id": account, "region": self.region, "agents": agents, "errors": self.errors}


def collect(region: str, profile=None, target: str = "all") -> dict:
    import boto3  # imported here so `analyze` works without AWS libraries configured

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    region = region or session.region_name
    if not region:
        raise ValueError("No region given. Pass --region or set AWS_REGION.")
    return Collector(session, region).collect(target)
