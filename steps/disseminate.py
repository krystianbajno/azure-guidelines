#!/usr/bin/env python3

import csv
import json
import yaml
from datetime import datetime
from typing import List
from jinja2 import Template, Environment, FileSystemLoader

from model.finding import parse_findings_final, Finding

SEVERITY_ORDER = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Informational": 5
}


class FindingReportService:
    @staticmethod
    def generate_csv_report(findings: List[Finding], filename: str) -> None:
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "ID",
                "Category",
                "Subcategory",
                "Source",
                "Name",
                "Severity",
                "Version",
                "Effects",
                "Description",
            ])

            for f in findings:
                writer.writerow([
                    f.id,
                    f.category,
                    f.subcategory,
                    f.source,
                    f.name,
                    f.severity,
                    f.version,
                    "; ".join(f.effects or []),
                    f.description or ""
                ])

        print(f"[+] CSV report saved to {filename}")

    @staticmethod
    def generate_json_report(findings: List[Finding], filename: str) -> None:
        data = [vars(f) for f in findings]

        data = FindingReportService._convert_sets_to_lists(data)

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        print(f"[+] JSON report saved to {filename}")

    @staticmethod
    def _convert_sets_to_lists(obj):
        if isinstance(obj, dict):
            return {k: FindingReportService._convert_sets_to_lists(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [FindingReportService._convert_sets_to_lists(e) for e in obj]
        elif isinstance(obj, set):
            return list(obj)
        else:
            return obj

    @staticmethod
    def generate_html_report(findings: List[Finding], filename: str) -> None:
        env = Environment(
            loader=FileSystemLoader("views"),
            autoescape=True
        )

        def extract_url_if_markdown(value: str) -> str:
            import re
            match = re.search(r"\((http[s]?:\/\/[^\)]+)\)", value)
            return match.group(1) if match else value

        env = Environment(
            loader=FileSystemLoader("views"),
            autoescape=True
        )

        def md_link_text(value: str) -> str:
            import re

            """
            If `value` is in the form:
            [some text here](some_url)
            then return "some text here". Otherwise, return `value` as is.
            """
            pattern = r'^\[([^\]]+)\]\([^\)]+\)$'
            match = re.match(pattern, value)
            if match:
                return match.group(1)  # The text within square brackets
            return value

        env.filters["md_link_text"] = md_link_text

        env.filters["extract_url_if_markdown"] = extract_url_if_markdown

        template = env.get_template("finding_report_template.html")

        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rendered_html = template.render(findings=findings, date=date_str)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(rendered_html)

        print(f"[+] HTML report saved to {filename}")


def disseminate():
    source = "target/compiled/output.yml"
    
    all_findings = []

    with open(source, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    findings = parse_findings_final(data)
    all_findings.extend(findings)

    print(f"[+] Total findings loaded: {len(all_findings)}")

    FindingReportService.generate_csv_report(all_findings, "target/report/findings_report.csv")
    print(f"CSV written: {len(all_findings)}")

    FindingReportService.generate_json_report(all_findings, "target/report/findings_report.json")
    print(f"JSON written: {len(all_findings)}")

    FindingReportService.generate_html_report(all_findings, "target/report/findings_report.html")
    print(f"HTML written: {len(all_findings)}")

if __name__ == "__main__":
    disseminate()
