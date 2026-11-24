"""The lab's create calls must be valid against the AWS service model."""

import importlib.util
import os

import boto3
from botocore.validate import validate_parameters

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("lab", os.path.join(HERE, "..", "lab", "lab.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

ROLE = "arn:aws:iam::111122223333:role/x"


def _model():
    session = boto3.Session(region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
    return session.client("bedrock-agentcore-control").meta.service_model


def test_lab_requests_match_service_model():
    model = _model()
    calls = {
        "CreateGateway": lab.gateway_kwargs(lab.GATEWAY, ROLE),
        "CreateGatewayTarget": lab.target_kwargs("leashlab-gateway-abcdefghij",
                                                 "arn:aws:lambda:us-east-1:111122223333:function:f"),
        "CreateCodeInterpreter": lab.interpreter_kwargs(ROLE),
    }
    for operation, kwargs in calls.items():
        validate_parameters(kwargs, model.operation_model(operation).input_shape)
