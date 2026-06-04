import hashlib
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from aegisgrc.api.schemas.scan import ScanPayload, EvaluationResultSchema
from aegisgrc.api.dependencies import get_api_key
from aegisgrc.db.session import get_db
from aegisgrc.db.models import ScanReport
from aegisgrc.engine.parser import CustomHclParser
from aegisgrc.engine.opa import OPAPolicyClient
from aegisgrc.engine.scorer import ComplianceScorer
from aegisgrc.engine.ai_evidence import GeminiEvidenceBuilder
from aegisgrc.core.logging import logger

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/evaluate", response_model=EvaluationResultSchema)
def evaluate_infrastructure_manifest(
    payload: ScanPayload,
    api_key: str = Depends(get_api_key),
    db: Session = Depends(get_db)
):
    """Parses incoming HCL manifests, executes Rego policy queries, and returns AI-enriched audit findings."""
    logger.info(f"Triggering on-demand policy-as-code assessment scan. Client role: {api_key}")
    
    # 1. Parse Terraform files to structured lists of dictionaries
    try:
        parsed_resources = CustomHclParser.parse_manifest(payload.hcl_content)
    except Exception as e:
        logger.error(f"HCL lexical parsing anomaly: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to compile Terraform manifest: {str(e)}")
        
    # 2. Evaluate against Rego Rules using OPA Policy Client
    opa_client = OPAPolicyClient()
    policy_path = "policies/soc2/cc6_1.rego"
    
    opa_res = opa_client.evaluate_resources(parsed_resources, policy_path)
    
    # 3. Score overall compliance based on severity levels
    findings_list = opa_res.get("findings", [])
    metrics = ComplianceScorer.calculate_metrics(findings_list, len(parsed_resources))
    
    # 4. Integrate Gemini models to generate interactive guidelines
    ai_builder = GeminiEvidenceBuilder()
    enriched = ai_builder.enrich_findings_schema(findings_list)
    
    # 5. Lock in state ledger with secure sha256 checksum
    payload_hash = hashlib.sha256(payload.hcl_content.encode("utf-8")).hexdigest()
    
    try:
        report = ScanReport(
            compliance_score=metrics["compliance_score"],
            total_findings=len(findings_list),
            sha256_hash=payload_hash,
            findings=enriched
        )
        db.add(report)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Metadata persistence error inside core SQLite index: {e}")

    return {
        "compliance_score": metrics["compliance_score"],
        "critical_count": metrics["critical_count"],
        "warning_count": metrics["warning_count"],
        "info_count": metrics["info_count"],
        "risk_rating": metrics["risk_rating"],
        "findings_count": len(findings_list),
        "execution_state": opa_res.get("compiler_state", "SIGNED_COMPLIANT"),
        "enriched_findings": enriched
    }
