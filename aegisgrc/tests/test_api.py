from fastapi.testclient import TestClient
from aegisgrc.api.main import app
from aegisgrc.core.config import settings

client = TestClient(app)


def test_health_endpoint():
    response = client.get(f"{settings.API_V1_STR}/health")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "healthy"
    assert "regulatory_alignment" in json_data


def test_unauthorized_scan():
    # If settings is forced to production behavior
    old_env = settings.ENVIRONMENT
    settings.ENVIRONMENT = "production"
    try:
        response = client.post(
            f"{settings.API_V1_STR}/scans/evaluate",
            json={"hcl_content": "resource 'aws' 'test' {}"}
        )
        assert response.status_code == 401
    finally:
         settings.ENVIRONMENT = old_env


def test_authorized_scan_success():
    payload = {
        "hcl_content": """
        resource "aws_s3_bucket" "approved" {
          bucket = "aegis-approved-logs"
          server_side_encryption_configuration = "AES256"
        }
        """
    }
    
    headers = {"X-AEGIS-KEY": "dev-authorized"}
    response = client.post(
        f"{settings.API_V1_STR}/scans/evaluate",
        json=payload,
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "compliance_score" in data
    assert data["critical_count"] == 0
    assert data["compliance_score"] == 100
