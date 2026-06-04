from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class ScanPayload(BaseModel):
    hcl_content: str = Field(..., description="Raw infrastructure Terraform/HCL manifest content for parsing")
    environment: Optional[str] = Field("sandbox", description="Target environment boundary tag")


class ReprehensiveRemediation(BaseModel):
    finding: str
    diagnostics: str
    reremed_plan: str
    tsc_mapping: str


class EvaluationResultSchema(BaseModel):
    compliance_score: int
    critical_count: int
    warning_count: int
    info_count: int
    risk_rating: str
    findings_count: int
    execution_state: str
    enriched_findings: List[Dict[str, Any]]
