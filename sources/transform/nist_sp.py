#!/usr/bin/env python3
# https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/refs/heads/main/articles/governance/policy/samples/nist-sp-800-53-r5.m

import sys
import re
import yaml

def estimate_severity(effects):
    effects_lc = [e.lower().strip() for e in effects]
    if any("deny" in e for e in effects_lc):
        return "High"
    elif any("audit" in e for e in effects_lc) or any("auditifnotexists" in e for e in effects_lc):
        return "Medium"
    else:
        return "Low"

def parse_effects(effects_cell):
    splitted = re.split(r",|\n", effects_cell)
    return [s.strip() for s in splitted if s.strip()]

def parse_markdown_table(table_text):
    rows = table_text.strip().split("\n")
    data_rows = rows[2:]  

    findings = []

    for line in data_rows:
        line = line.strip()
        if not line.startswith("|"):
            break

        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 5:
            continue

        name = cells[1]
        description = cells[2]
        effects = parse_effects(cells[3])
        version = cells[4]
        severity = estimate_severity(effects)

        findings.append({
            "name": name,
            "reference": name,
            "description": description,
            "effects": effects,
            "version": version,
            "severity": severity
        })

    return findings

def parse_document(md_text):
    lines = md_text.split("\n")

    result = {
        "nistSP80053Rev5": {
            "title": "NIST SP 800-53 Rev. 5 Regulatory Compliance",
            "categories": []
        }
    }

    categories = []
    current_category = None
    current_subcategory = None

    table_buffer = []
    in_table = False

    def flush_table():
        nonlocal table_buffer
        if not table_buffer:
            return []

        table_text = "\n".join(table_buffer)
        policies = parse_markdown_table(table_text)
        table_buffer = []
        return policies

    re_category = re.compile(r"^##\s+(.*)")
    re_subcategory = re.compile(r"^###\s+(.*)")
    re_id_line = re.compile(r"^\*\*ID\*\*:\s*(.+)$")
    re_ownership_line = re.compile(r"^\*\*Ownership\*\*:\s*(.+)$")

    for line in lines:
        line_stripped = line.strip()

        cat_match = re_category.match(line_stripped)
        if cat_match:
            if in_table and current_subcategory:
                found_policies = flush_table()
                current_subcategory["policies"].extend(found_policies)
                in_table = False

            if current_subcategory and current_category:
                current_category["subcategories"].append(current_subcategory)
                current_subcategory = None

            if current_category:
                categories.append(current_category)
                current_category = None

            category_name = cat_match.group(1).strip()
            current_category = {
                "name": category_name,
                "subcategories": []
            }
            continue

        subcat_match = re_subcategory.match(line_stripped)
        if subcat_match:
            if in_table and current_subcategory:
                found_policies = flush_table()
                current_subcategory["policies"].extend(found_policies)
                in_table = False

            if current_subcategory and current_category:
                current_category["subcategories"].append(current_subcategory)

            subcategory_name = subcat_match.group(1).strip()
            current_subcategory = {
                "name": subcategory_name,
                "id": "",
                "ownership": "",
                "policies": []
            }
            continue

        id_match = re_id_line.match(line_stripped)
        if id_match and current_subcategory:
            current_subcategory["id"] = id_match.group(1).strip()
            continue

        own_match = re_ownership_line.match(line_stripped)
        if own_match and current_subcategory:
            current_subcategory["ownership"] = own_match.group(1).strip()
            continue

        if line_stripped.startswith("|Name"):
            if in_table and current_subcategory:
                found_policies = flush_table()
                current_subcategory["policies"].extend(found_policies)

            in_table = True
            table_buffer = [line]
            continue
        elif in_table:
            if not line_stripped or line_stripped.startswith("##") or line_stripped.startswith("###"):
                found_policies = flush_table()
                if current_subcategory:
                    current_subcategory["policies"].extend(found_policies)
                in_table = False
            else:
                table_buffer.append(line)

    if in_table and current_subcategory:
        found_policies = flush_table()
        current_subcategory["policies"].extend(found_policies)
    if current_subcategory and current_category:
        current_category["subcategories"].append(current_subcategory)
    if current_category:
        categories.append(current_category)

    result["nistSP80053Rev5"]["categories"] = categories
    return result

def parse():
    input_file = "./sources/dataset/nist-sp.md"
    output_file = "./target/nist-sp.yml"

    with open(input_file, "r", encoding="utf-8") as f:
        md_text = f.read()

    parsed_data = parse_document(md_text)

    with open(output_file, "w", encoding="utf-8") as f_out:
        yaml.safe_dump(parsed_data, f_out, sort_keys=False, allow_unicode=True)

    print(f"+ Results written to: {output_file}")


if __name__ == "__main__":
    parse()
