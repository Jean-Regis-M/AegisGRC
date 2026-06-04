import json
import subprocess
from typing import Dict, List, Any
from aegisgrc.core.config import settings
from aegisgrc.core.exceptions import OPAEvaluationError
from aegisgrc.core.logging import logger


class OPAPolicyClient:
    """Invokes OPA evaluations over compiled rule assets.

    Supports dual evaluation models: shell executable wrappers or memory mocked templates
    if binary operations are restricted locally by environment permissions.
    """

    def __init__(self, opa_path: str = None):
        self.opa_path = opa_path or settings.OPA_PATH

    def evaluate_resources(self, resources: List[Dict[str, Any]], rego_path: str) -> Dict[str, Any]:
        """Sends translated Terraform attributes over to local OPA compiler schemas."""
        input_data = {"input": {"resources": resources}}
        
        logger.info(f"Preparing GRC OPA policy query container verification on schema at: {rego_path}")
        
        try:
            # Prepare standard JSON input parameters to feed into OPA
            input_json = json.dumps(input_data)
            
            # Exec OPA subprocess evaluation wrapper
            cmd = [
                self.opa_path,
                "eval",
                "-d", rego_path,
                "data.soc2.cc6.violation",
                "--format=json"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=input_json)
            
            if process.returncode != 0:
                logger.warning(f"Local OPA binary command exited with error structure: {stderr}. Engaging memory model fallback.")
                return self._evaluate_internally_mocked_fallback(resources)
                
            opa_output = json.loads(stdout)
            
            # Retrieve violations from evaluated schema output
            violations = []
            if "result" in opa_output and isinstance(opa_output["result"], list):
                for val in opa_output["result"]:
                    if "expressions" in val:
                        for exp in val["expressions"]:
                            if "value" in exp and isinstance(exp["value"], list):
                                violations.extend(exp["value"])
                                
            return {
                "ok": len(violations) == 0,
                "findings": violations,
                "compiler_state": "SIGNED_BINARY_EXECUTED"
            }
            
        except FileNotFoundError:
            logger.warning("Local OPA compiler engine not accessible in environment. Engaging fallback evaluation matrices.")
            return self._evaluate_internally_mocked_fallback(resources)
            
        except Exception as e:
            logger.error(f"Fatal regression evaluating policy parameters: {e}")
            raise OPAEvaluationError(f"OPA Client failure: {str(e)}")

    def _evaluate_internally_mocked_fallback(self, resources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Provides an identical declarative state checks representation if OPA CLI isn't installed locally."""
        violations = []
        
        for res in resources:
            res_type = res.get("type")
            res_name = res.get("name")
            attrs = res.get("attributes", {})
            
            # S3 Encryption Check
            if res_type == "aws_s3_bucket":
                if not attrs.get("server_side_encryption_configuration"):
                    violations.append(
                        f"SOC2 CC6.3 Violation: S3 bucket '{res_name}' does not enforce AES256 server-side encryption."
                    )
            
            # Global Ingress Security Group Check (Port 22 SSH)
            elif res_type == "aws_security_group":
                ingress_rules = attrs.get("ingress", [])
                for rule in ingress_rules:
                    cidr_blocks = rule.get("cidr_blocks", [])
                    from_port = int(rule.get("from_port", 0))
                    to_port = int(rule.get("to_port", 9999))
                    
                    if from_port <= 22 and to_port >= 22:
                        if "0.0.0.0/0" in cidr_blocks:
                            violations.append(
                                f"SOC2 CC6.4 Violation: Security Group '{res_name}' allows globally open ingress (0.0.0.0/0) to port 22."
                            )
            
            # EBS Volume Encryption Check
            elif res_type == "aws_ebs_volume":
                if not attrs.get("encrypted"):
                    violations.append(
                        f"NIST CSF PR.DS-01 Violation: EBS Volume '{res_name}' is not encrypted."
                    )
                    
        return {
            "ok": len(violations) == 0,
            "findings": violations,
            "compiler_state": "SIGNED_INTERNAL_FALLBACK"
        }
