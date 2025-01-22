#!/usr/bin/env python3
# https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/governance/policy/samples/cis-azure-2-0-0.md

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
    # Skip the first two lines (header and dashes)
    data_rows = rows[2:]

    findings = []
    for line in data_rows:
        line = line.strip()
        if not line.startswith("|"):
            break  # table presumably ends
        cells = [c.strip() for c in line.split("|")]
        # Typically cells[0] == '' if table starts with '|', so real columns start at cells[1].
        if len(cells) < 5:
            continue
        name = cells[1]
        description = cells[2]
        raw_effects = cells[3]
        version = cells[4]
        # Parse effects
        effects = parse_effects(raw_effects)
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
        "cisAzureFoundationsBenchmark": {
            "title": "CIS Microsoft Azure Foundations Benchmark 2.0.0",
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
        table_buffer = []
        return parse_markdown_table(table_text)

    re_category = re.compile(r"^##\s+(\S.*)$")

    re_subcategory = re.compile(r"^###\s+(.*)$")

    re_id = re.compile(r"^\*\*ID\*\*:\s*(.+)$")

    re_ownership = re.compile(r"^\*\*Ownership\*\*:\s*(.+)$")

    for line in lines:
        line_stripped = line.strip()

        match_cat = re_category.match(line_stripped)
        if match_cat:
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

            category_title = match_cat.group(1).strip()
            current_category = {
                "name": category_title,
                "subcategories": []
            }
            continue

        match_subcat = re_subcategory.match(line_stripped)
        if match_subcat:
            if in_table and current_subcategory:
                found_policies = flush_table()
                current_subcategory["policies"].extend(found_policies)
                in_table = False

            if current_subcategory and current_category:
                current_category["subcategories"].append(current_subcategory)

            subcat_title = match_subcat.group(1).strip()
            current_subcategory = {
                "name": subcat_title,
                "id": "",
                "ownership": "",
                "policies": []
            }
            continue

        match_id = re_id.match(line_stripped)
        if match_id and current_subcategory:
            current_subcategory["id"] = match_id.group(1).strip()
            continue

        match_owner = re_ownership.match(line_stripped)
        if match_owner and current_subcategory:
            current_subcategory["ownership"] = match_owner.group(1).strip()
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

    result["cisAzureFoundationsBenchmark"]["categories"] = categories
    return result


def parse():
    input_file =  "./sources/dataset/cis-azure-2-0-0.md"
    output_file = "./target/cis-azure-2.0.0.yml"

    with open(input_file, "r", encoding="utf-8") as f:
        md_text = f.read()

    parsed_data = parse_document(md_text)

    with open(output_file, "w", encoding="utf-8") as f_out:
        yaml.safe_dump(parsed_data, f_out, sort_keys=False, allow_unicode=True)

    print(f"+ Parsed results written to: {output_file}")


if __name__ == "__main__":
    parse()
