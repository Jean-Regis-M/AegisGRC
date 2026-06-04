from typing import Dict, List, Any
from aegisgrc.core.config import settings
from aegisgrc.core.logging import logger

try:
    # Google GenAI modern SDK is imported if available in environment
    from google import genai
    from google.genai import types
except ImportError:
    genai = None


class GeminiEvidenceBuilder:
    """Uses Gemini API models to enrich findings with formal GRC evidence checklists and mitigation paths."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.client = None
        if genai and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                logger.info("Initializing Google GenAI Client wrapper on python background stack.")
            except Exception as e:
                logger.warning(f"Failed to bootstrap authentic python genai context: {e}")

    def enrich_findings_schema(self, findings: List[str]) -> List[Dict[str, Any]]:
        enriched = []
        for finding in findings:
            diagnostics = self._generate_ai_diagnostics(finding)
            evidence = self._generate_ai_evidence(finding)
            
            enriched.append({
                "finding": finding,
                "diagnostics": diagnostics,
                "remediation_plan": evidence.get("plan", ""),
                "tsc_mapping": evidence.get("tsc_mapping", "SOC2 Trust Services criteria compliance gap")
            })
        return enriched

    def _generate_ai_diagnostics(self, finding: str) -> str:
        """Asks Gemini model to evaluate standard risk profile coordinates."""
        if not self.client:
            return "Standard high-fidelity GRC template applied: Root access must be strictly constrained to authorized administrators."
            
        try:
            prompt = (
                f"You are a Senior GRC SOC2 Lead Compliance Auditor. Examine this vulnerability: '{finding}'. "
                f"Provide a brief, single-sentence high-impact forensic diagnostic detailing why this boundary breach "
                f"jeopardizes organizational integrity. Keep it formal, sleek, professional."
            )
            response = self.client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            logger.warning(f"High load fallback on Gemini API diagnostics generation: {str(e)}")
            return "Aegis Audit warning: Failure exposes resources to malicious vector compromises."

    def _generate_ai_evidence(self, finding: str) -> Dict[str, str]:
        """Provides technical mitigation roadmap mapped against trust boundaries."""
        if not self.client:
            return {
                "plan": "Configure AES256 SSE-S3 encryption using AWS Key Management Service (KMS). Restrict port 22 access strictly to trusted company CIDR blocks.",
                "tsc_mapping": "SOC2 CC6.3 Alignment: Static Media Cryptography Verification"
            }
            
        try:
            prompt = (
                f"As a veteran policy auditor mapping rules to compliance constraints, read this issue: '{finding}'. "
                f"Output a JSON object with keys 'plan' (concise technical remediation steps under 60 words) "
                f"and 'tsc_mapping' (specific SOC2 CC reference and alignment statement). Let the JSON be raw, no markdown wrappers."
            )
            response = self.client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            
            text = response.text.strip()
            # Safety cleaning if model uses code blocks
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("\n", 1)[0].strip()
                if text.startswith("json"):
                    text = text[4:].strip()
                    
            import json
            data = json.loads(text)
            return {
                "plan": data.get("plan", "Remediate immediately."),
                "tsc_mapping": data.get("tsc_mapping", "SOC2 Alignment Control")
            }
        except Exception as e:
            logger.warning(f"High load fallback on AI evidence generation: {str(e)}")
            return {
                "plan": "Review configuration files immediately, enforce kms parameters, and restrict access boundaries inside ingress configurations.",
                "tsc_mapping": "Regulatory Standard Protection Control"
            }
