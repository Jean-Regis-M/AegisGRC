export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  resource: string;
  resourceType: string;
  finding: string;
  severity: Severity;
  controlId: string;
  framework: "SOC2" | "ISO27001" | "NIST_CSF";
  ruleName: string;
  likelihood: number; // 1-5
  impact: number; // 1-5
  exposure: number; // 1-5
  riskScore: number; // likelihood * impact * exposure
  remediation: string;
  whyItHappened: string;
  evidenceText?: string;
  status: "FAIL" | "PASS";
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  sha256: string;
  totalResources: number;
  violationsCount: number;
  complianceScore: number; // 0-100
  findings: Finding[];
  rawCode: string;
}

export interface DriftAlert {
  id: string;
  resource: string;
  resourceType: string;
  detectedAt: string;
  parameterChanged: string;
  expectedValue: string;
  actualValue: string;
  severity: Severity;
  remediated: boolean;
  userTriaged: boolean;
}

export interface AuditTrailLog {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  details: string;
  status: "success" | "warning" | "alert";
}

export interface CompactHistoryItem {
  timestamp: string;
  complianceScore: number;
  violationsCount: number;
}
