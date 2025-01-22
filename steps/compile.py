import yaml
from model.finding import parse_findings

def compile():
    findings = []

    finding_sources = [
        "target/azure-security-benchmark.yml",
        "target/cis-azure-2.0.0.yml",
        "target/nist-sp.yml",
        "target/scuba/aad.yml",
        "target/scuba/defender.yml",
        "target/scuba/exo.yml",
        "target/scuba/powerbi.yml",
        "target/scuba/powerplatform.yml",
        "target/scuba/removedpolicies.yml",
        "target/scuba/sharepoint.yml",
        "target/scuba/teams.yml",
    ]

    for source in finding_sources:
        with open(source, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        source_findings = parse_findings(data)
        findings.extend(source_findings)

    print("+ Mapped findings")

    SEVERITY_ORDER = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Informational": 5
    }

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9999), f.name))

    dict_findings = [vars(f) for f in findings]

    outfile = "target/compiled/output.yml"

    with open(outfile, "w", encoding="utf-8") as out_file:
        yaml.safe_dump(dict_findings, out_file, sort_keys=False)

    print(f"+ Written compiled YAML to {outfile}")

if __name__ == "__main__":
    compile()
