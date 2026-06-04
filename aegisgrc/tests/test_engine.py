import pytest
from aegisgrc.engine.parser import CustomHclParser
from aegisgrc.engine.scorer import ComplianceScorer
from aegisgrc.engine.opa import OPAPolicyClient


def test_custom_hcl_parser_empty():
    assert CustomHclParser.parse_manifest("") == []


def test_custom_hcl_parser_valid():
    sample_hcl = """
    resource "aws_s3_bucket" "secure" {
      bucket = "my-secure-bucket"
      server_side_encryption_configuration = "AES256"
    }
    """
    resources = CustomHclParser.parse_manifest(sample_hcl)
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_s3_bucket"
    assert resources[0]["name"] == "secure"
    assert resources[0]["attributes"]["bucket"] == "my-secure-bucket"
    assert resources[0]["attributes"]["server_side_encryption_configuration"] == "AES256"


def test_compliance_scorer_all_secure():
    metrics = ComplianceScorer.calculate_metrics([], 4)
    assert metrics["compliance_score"] == 100
    assert metrics["risk_rating"] == "LOW"


def test_compliance_scorer_violations():
    findings = [
        "SOC2 CC6.3 Violation: Bucket open static access.",
        "SOC2 CC6.4 Violation: Port 22 open globally"
    ]
    metrics = ComplianceScorer.calculate_metrics(findings, 2)
    # Score should be reduced due to 2 violations
    assert metrics["compliance_score"] < 100
    assert metrics["critical_count"] == 2
    assert metrics["risk_rating"] == "HIGH"


def test_opa_internal_mocked_fallback_rules():
    client = OPAPolicyClient()
    resources = [
        {
            "type": "aws_s3_bucket",
            "name": "unencrypted",
            "attributes": {}
        }
    ]
    res = client._evaluate_internally_mocked_fallback(resources)
    assert res["ok"] is False
    assert len(res["findings"]) == 1
    assert "encryption" in res["findings"][0]
