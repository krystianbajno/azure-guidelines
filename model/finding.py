import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Finding:
    id: str
    category: str
    subcategory: str
    source: str
    name: str
    description: str
    effects: List[str]
    version: str
    severity: str

    criticality: str = ""
    rationale: str = ""
    notes: List[str] = field(default_factory=list)
    last_modified: str = ""
    mitre: List[str] = field(default_factory=list)
    remediation: str = ""
    product: str = ""
    reference: str = ""

def parse_findings(yaml_data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []


    for top_key, top_value in yaml_data.items():
        if isinstance(top_value, dict) and 'categories' in top_value:
            source = top_value.get('title', top_key)

            for category_dict in top_value.get('categories', []):
                category_name = category_dict.get('name', '')

                for subcategory_dict in category_dict.get('subcategories', []):
                    subcat_name = subcategory_dict.get('name', '')
                    subcat_id = subcategory_dict.get('id', '')

                    for policy in subcategory_dict.get('policies', []):
                        f = Finding(
                            id=subcat_id,
                            category=category_name,
                            subcategory=subcat_name,
                            source=source,
                            name=policy.get('name', ''),
                            description=policy.get('description', ''),
                            effects=policy.get('effects', []),
                            version=policy.get('version', ''),
                            severity=policy.get('severity', '')
                        )

                        f.criticality = policy.get('criticality', '')
                        f.rationale = policy.get('rationale', '')
                        f.notes = policy.get('notes', [])
                        f.last_modified = policy.get('last_modified', '')
                        f.mitre = policy.get('mitre', [])
                        f.remediation = policy.get('remediation', '')
                        f.product = policy.get('product', '')
                        f.reference = policy.get("reference", "")

                        findings.append(f)
    
    return findings


def parse_findings_final(yaml_data: Any) -> List[Finding]:
    findings: List[Finding] = []

    if isinstance(yaml_data, list):
        for item in yaml_data:
            f = Finding(
                id=item.get("id", ""),
                category=item.get("category", ""),
                subcategory=item.get("subcategory", ""),
                source=item.get("source", ""),
                name=item.get("name", ""),
                description=item.get("description", ""),
                effects=item.get("effects", []),
                version=item.get("version", ""),
                severity=item.get("severity", "")
            )

            f.criticality = item.get("criticality", "")
            f.rationale = item.get("rationale", "")
            f.notes = item.get("notes", [])
            f.last_modified = item.get("last_modified", "")
            f.mitre = item.get("mitre", [])
            f.remediation = item.get("remediation", "")
            f.product = item.get("product", "")
            f.reference = item.get("reference", "")

            findings.append(f)

    return findings
