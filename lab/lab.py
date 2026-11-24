#!/usr/bin/env python3
"""agentleash test lab for Amazon Bedrock AgentCore.

Creates a few deliberately misconfigured resources so the scanner has something
to find, and removes them again. FOR TESTING ONLY, in an account you own.

    python3 lab/lab.py up   --region us-east-1
    python3 lab/lab.py down --region us-east-1

Nothing here is invoked, so cost should be negligible, but run `down` when done.
"""

import argparse
import io
import json
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

AC_SERVICE = "bedrock-agentcore.amazonaws.com"
GATEWAY, CLEAN_GATEWAY, TARGET = "leashlab-gateway", "leashlab-clean-gateway", "leashlab-tool"
INTERPRETER, FUNCTION = "leashlab_ci", "leashlab-tool"
ROLE_GATEWAY, ROLE_CLEAN, ROLE_TOOL, ROLE_CI = (
    "leashlab-gateway-role", "leashlab-clean-role", "leashlab-tool-role", "leashlab-ci-role")
CI_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
TAGS = {"project": "agentleash-lab"}


def trust(service, account=None):
    stmt = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
    if account:
        stmt["Condition"] = {"StringEquals": {"aws:SourceAccount": account}}
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def gateway_kwargs(name, role_arn):
    return {"name": name, "roleArn": role_arn, "protocolType": "MCP", "authorizerType": "AWS_IAM",
            "description": "agentleash lab - testing only", "tags": TAGS}


def target_kwargs(gateway_id, lambda_arn):
    return {
        "gatewayIdentifier": gateway_id,
        "name": TARGET,
        "description": "agentleash lab - stub tool",
        "targetConfiguration": {"mcp": {"lambda": {
            "lambdaArn": lambda_arn,
            "toolSchema": {"inlinePayload": [{
                "name": "lookup_invoice",
                "description": "Look up an invoice by id",
                "inputSchema": {"type": "object",
                                "properties": {"invoice_id": {"type": "string"}},
                                "required": ["invoice_id"]},
            }]},
        }}},
        "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
    }


def interpreter_kwargs(role_arn):
    return {"name": INTERPRETER, "description": "agentleash lab - testing only",
            "executionRoleArn": role_arn, "networkConfiguration": {"networkMode": "PUBLIC"}, "tags": TAGS}


def lambda_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'status': 'lab stub'}\n")
    return buf.getvalue()


def ensure_role(iam, name, trust_doc, inline=None, managed=None):
    try:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_doc,
                              Description="agentleash lab - testing only")["Role"]["Arn"]
        print("created role", name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName="lab", PolicyDocument=inline)
    if managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=managed)
    return arn


def wait_gateway(ac, gateway_id):
    for _ in range(60):
        status = ac.get_gateway(gatewayIdentifier=gateway_id)["status"]
        if status == "READY":
            return
        if status == "FAILED":
            raise RuntimeError("gateway %s failed to create" % gateway_id)
        time.sleep(5)
    raise RuntimeError("gateway %s not ready after 5 minutes" % gateway_id)


def find_gateways(ac):
    found = {}
    for page in ac.get_paginator("list_gateways").paginate():
        for item in page.get("items", []):
            if item.get("name") in (GATEWAY, CLEAN_GATEWAY):
                found[item["name"]] = item["gatewayId"]
    return found


def up(session, region):
    iam, lam = session.client("iam"), session.client("lambda", region_name=region)
    ac = session.client("bedrock-agentcore-control", region_name=region)
    account = session.client("sts").get_caller_identity()["Account"]
    fn_arn = "arn:aws:lambda:%s:%s:function:%s" % (region, account, FUNCTION)

    tool_role = ensure_role(iam, ROLE_TOOL, trust("lambda.amazonaws.com"),
                            inline=policy(allow(["iam:PassRole", "dynamodb:*"])))
    gateway_role = ensure_role(iam, ROLE_GATEWAY, trust(AC_SERVICE),  # no condition on purpose
                               inline=policy(allow(["s3:*", "secretsmanager:GetSecretValue"]),
                                             allow("lambda:InvokeFunction", fn_arn)))
    clean_role = ensure_role(iam, ROLE_CLEAN, trust(AC_SERVICE, account),
                             inline=policy(allow("lambda:InvokeFunction", fn_arn)))
    ci_role = ensure_role(iam, ROLE_CI, trust(AC_SERVICE, account), managed=CI_MANAGED_POLICY)

    print("waiting for the new roles to become usable...")
    time.sleep(15)

    for attempt in range(6):
        try:
            lam.create_function(FunctionName=FUNCTION, Runtime="python3.12", Handler="index.handler",
                                Role=tool_role, Code={"ZipFile": lambda_zip()}, Timeout=5, Tags=TAGS)
            print("created function", FUNCTION)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceConflictException":
                break
            if code == "InvalidParameterValueException" and attempt < 5:
                time.sleep(10)
                continue
            raise

    existing = find_gateways(ac)
    for name, role_arn in ((GATEWAY, gateway_role), (CLEAN_GATEWAY, clean_role)):
        if name not in existing:
            existing[name] = ac.create_gateway(**gateway_kwargs(name, role_arn))["gatewayId"]
            print("created gateway", name)
    for gateway_id in existing.values():
        wait_gateway(ac, gateway_id)

    gid = existing[GATEWAY]
    targets = [t.get("name") for page in ac.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gid)
               for t in page.get("items", [])]
    if TARGET not in targets:
        ac.create_gateway_target(**target_kwargs(gid, fn_arn))
        print("created gateway target", TARGET)

    names = [c.get("name") for page in ac.get_paginator("list_code_interpreters").paginate(type="CUSTOM")
             for c in page.get("codeInterpreterSummaries", [])]
    if INTERPRETER not in names:
        ac.create_code_interpreter(**interpreter_kwargs(ci_role))
        print("created code interpreter", INTERPRETER)

    print("\nLab is up. Now run:  python3 -m agentleash.cli scan --region %s --target agentcore" % region)
    print("When finished:      python3 lab/lab.py down --region %s" % region)


def _ignore_missing(fn, **kwargs):
    try:
        fn(**kwargs)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "NoSuchEntity", "NoSuchEntityException"):
            return False
        raise


def down(session, region):
    iam, lam = session.client("iam"), session.client("lambda", region_name=region)
    ac = session.client("bedrock-agentcore-control", region_name=region)

    for name, gid in find_gateways(ac).items():
        for page in ac.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gid):
            for target in page.get("items", []):
                _ignore_missing(ac.delete_gateway_target, gatewayIdentifier=gid, targetId=target["targetId"])
        for _ in range(30):  # targets delete asynchronously
            left = [t for page in ac.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gid)
                    for t in page.get("items", [])]
            if not left:
                break
            time.sleep(5)
        _ignore_missing(ac.delete_gateway, gatewayIdentifier=gid)
        print("deleted gateway", name)

    for page in ac.get_paginator("list_code_interpreters").paginate(type="CUSTOM"):
        for item in page.get("codeInterpreterSummaries", []):
            if item.get("name") == INTERPRETER:
                _ignore_missing(ac.delete_code_interpreter, codeInterpreterId=item["codeInterpreterId"])
                print("deleted code interpreter", INTERPRETER)

    if _ignore_missing(lam.delete_function, FunctionName=FUNCTION):
        print("deleted function", FUNCTION)

    for role in (ROLE_GATEWAY, ROLE_CLEAN, ROLE_TOOL, ROLE_CI):
        _ignore_missing(iam.delete_role_policy, RoleName=role, PolicyName="lab")
        _ignore_missing(iam.detach_role_policy, RoleName=role, PolicyArn=CI_MANAGED_POLICY)
        if _ignore_missing(iam.delete_role, RoleName=role):
            print("deleted role", role)
    print("\nLab removed.")


def main():
    parser = argparse.ArgumentParser(description="agentleash AgentCore test lab")
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    (up if args.action == "up" else down)(session, args.region)


if __name__ == "__main__":
    main()
