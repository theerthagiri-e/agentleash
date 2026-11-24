"""Rule metadata and the action lists the analyzer matches against.

IAM action names are matched case-insensitively, with IAM-style wildcards
(``*`` and ``?``) in the policy expanded against these lists.
"""

from __future__ import annotations

SEVERITIES = ["low", "medium", "high", "critical"]

# rule_id -> (default severity, title, remediation)
RULES = {
    "AGT001": (
        "critical",
        "Role allows every action on every resource",
        "Replace the wildcard with the specific actions and resource ARNs the agent's tools call.",
    ),
    "AGT002": (
        "high",
        "Role allows a whole service on all resources",
        "List the individual actions the agent needs and scope them to named resources.",
    ),
    "AGT003": (
        "critical",
        "Role can escalate its own privileges",
        "Remove these actions, or scope them to one named role or function. "
        "An agent steered by prompt injection can use them to become an administrator.",
    ),
    "AGT004": (
        "high",
        "Role can read sensitive data across the whole account",
        "Scope read access to the specific buckets, secrets, parameters, keys or tables the agent uses.",
    ),
    "AGT005": (
        "high",
        "Role can destroy resources or disable logging across the account",
        "Remove destructive actions, or scope them to named resources and require human confirmation.",
    ),
    "AGT006": (
        "medium",
        "Role can invoke any foundation model",
        "Scope bedrock:InvokeModel to the model ARNs the agent is configured to use.",
    ),
    "AGT007": (
        "high",
        "Policy uses Allow with NotAction",
        "Rewrite as an explicit Action list. Allow + NotAction grants everything except the listed actions.",
    ),
    "AGT008": (
        "high",
        "Broad AWS managed policy attached",
        "Detach the managed policy and attach a customer policy limited to what the agent needs.",
    ),
    "AGT009": (
        "critical",
        "Trust policy lets any principal assume the role",
        "Restrict the Principal to the specific service or account, with a condition.",
    ),
    "AGT010": (
        "medium",
        "Trust policy has no confused-deputy protection",
        "Add aws:SourceAccount and aws:SourceArn conditions to the Bedrock / AgentCore trust statement.",
    ),
    "AGT011": (
        "medium",
        "Classic agent has no guardrail attached",
        "Attach a Bedrock guardrail so prompt-attack and sensitive-data filters apply to this agent.",
    ),
    "AGT012": (
        "low",
        "Code interpreter is enabled",
        "Confirm the agent needs code execution. Combined with a broad role it widens what an injected prompt can do.",
    ),
    "AGT013": (
        "critical",
        "Gateway accepts unauthenticated requests",
        "Set the gateway authorizer to AWS_IAM or CUSTOM_JWT. With NONE, anyone who has the URL can call its tools.",
    ),
    "AGT015": (
        "medium",
        "Code interpreter has a role and public network access",
        "Use SANDBOX or VPC network mode, or remove the execution role. Code steered by an injected prompt "
        "can send the role's credentials or data to the internet.",
    ),
}

AGENT_SERVICE_PRINCIPALS = {"bedrock.amazonaws.com", "bedrock-agentcore.amazonaws.com"}

# Services where a service-level wildcard on all resources is rated high.
SENSITIVE_SERVICES = {
    "iam", "sts", "organizations", "kms", "secretsmanager", "ssm", "s3",
    "dynamodb", "rds", "rds-data", "ec2", "lambda", "bedrock", "cloudtrail",
    "logs", "cloudformation", "ecs", "eks", "ecr", "glue", "redshift", "sns", "sqs",
}

PRIVESC_ACTIONS = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:CreateRole",
    "iam:CreateUser",
    "sts:AssumeRole",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:CreateFunction",
    "lambda:AddPermission",
    "cloudformation:CreateStack",
    "ec2:RunInstances",
    "glue:UpdateDevEndpoint",
    "ssm:SendCommand",
]

DATA_READ_ACTIONS = [
    "s3:GetObject",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "dynamodb:Scan",
    "dynamodb:Query",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "rds-data:ExecuteStatement",
    "ecr:GetAuthorizationToken",
]

DESTRUCTIVE_ACTIONS = [
    "s3:DeleteObject",
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "dynamodb:DeleteTable",
    "rds:DeleteDBInstance",
    "rds:DeleteDBCluster",
    "ec2:TerminateInstances",
    "lambda:DeleteFunction",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "logs:DeleteLogGroup",
    "guardduty:DeleteDetector",
]

MODEL_INVOKE_ACTIONS = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
]

# AWS managed policies flagged by ARN suffix: name -> severity
BROAD_MANAGED_POLICIES = {
    "AdministratorAccess": "critical",
    "PowerUserAccess": "high",
    "IAMFullAccess": "critical",
}
