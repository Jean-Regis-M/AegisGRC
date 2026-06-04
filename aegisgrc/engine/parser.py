import re
from typing import Dict, List, Any
from aegisgrc.core.exceptions import HCLParsingError


class ASTHclParser:
    """Provides a regex-driven intermediate AST parsing engine representation of Terraform manifests.

    This maps raw string tokens to structured dictionary schemas.
    """
    
    @staticmethod
    def parse_manifest(hcl_content: str) -> List[Dict[str, Any]]:
        if not hcl_content.strip():
            return []
            
        resources: List[Dict[str, Any]] = []
        
        # Regex to capture standard 'resource "type" "name" { body }' blocks
        resource_pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{'
        )
        
        lines = hcl_content.splitlines()
        current_idx = 0
        
        while current_idx < len(lines):
            line = lines[current_idx].strip()
            match = resource_pattern.match(line) or resource_pattern.search(line)
            
            if match:
                res_type = match.group(1)
                res_name = match.group(2)
                
                # Extract simple attribute brackets
                bracket_count = 1
                body_lines: List[str] = []
                current_idx += 1
                
                while current_idx < len(lines) and bracket_count > 0:
                    body_line = lines[current_idx]
                    bracket_count += body_line.count("{") - body_line.count("}")
                    if bracket_count >= 0:
                        body_lines.append(body_line)
                    current_idx += 1
                
                # Simple parser key-value mapper inside the body extraction
                attributes = ASTHclParser._parse_attributes(body_lines)
                
                resources.append({
                    "type": res_type,
                    "name": res_name,
                    "attributes": attributes
                })
            else:
                current_idx += 1
                
        return resources

    @staticmethod
    def _parse_attributes(body_lines: List[str]) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {}
        kv_regex = re.compile(r'^\s*([a-zA-Z0-9_\-]+)\s*=\s*(.+)$')
        
        # Ingress block collector for security groups
        ingress_rules: List[Dict[str, Any]] = []
        in_ingress_block = False
        ingress_lines: List[str] = []
        
        for raw_line in body_lines:
            line = raw_line.strip()
            
            if line.startswith("ingress {") or line.startswith("ingress_rules {"):
                in_ingress_block = True
                ingress_lines = []
                continue
                
            if in_ingress_block:
                if line.endswith("}") or line == "}":
                    in_ingress_block = False
                    sub_attrs = ASTHclParser._parse_attributes(ingress_lines)
                    ingress_rules.append(sub_attrs)
                else:
                    ingress_lines.append(raw_line)
                continue
                
            match = kv_regex.match(line)
            if match:
                key = match.group(1)
                val = match.group(2).strip().strip('"').strip("'")
                
                # Type sanitization helpers
                if val.lower() == "true":
                    attrs[key] = True
                elif val.lower() == "false":
                    attrs[key] = False
                elif val.startswith("[") and val.endswith("]"):
                    # Quick list parser
                    item_str = val[1:-1].strip()
                    attrs[key] = [item.strip().strip('"') for item in item_str.split(",") if item]
                else:
                    attrs[key] = val
                    
        if ingress_rules:
            attrs["ingress"] = ingress_rules
            
        return attrs
CustomHclParser = ASTHclParser
