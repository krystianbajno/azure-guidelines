import os
import re
import yaml
from typing import Dict, Any, List

def map_criticality_to_severity(criticality: str) -> str:
    crit_lower = criticality.strip().lower()
    if crit_lower == "shall":
        return "High"
    elif crit_lower == "should":
        return "Medium"
    else:
        return "Low"

def parse_markdown_nested(md_text: str, fallback_title: str = "") -> Dict[str, Any]:
    """
    Parse the entire Markdown into a *nested* structure:

    cisaM365Baseline:
      title: ...
      categories:
        - name: "1. Legacy Authentication"
          subcategories:
            - name: "Policies"
              id: "Category1"
              ownership: "Shared"
              policies:
                - id: ...
                  name: ...
                  severity: ...
                  description: ...
                  remediation: ...
                  ...

    The function is based on your original parse_markdown_flat, but
    reorganizes the output in a nested format.
    """

    lines = md_text.split("\n")
    total_lines = len(lines)

    # Grab top-level title from the first "# Some Title"
    found_title = None
    for line in lines:
        if line.startswith("# "):
            found_title = line.lstrip("# ").strip()
            break

    # We will keep the category -> list of policy dicts in an interim data structure
    # Example: category_buckets = {
    #    "1. Legacy Authentication": [ { policy1 }, { policy2 } ],
    #    "2. Risk Based Policies":   [ { policy3 }, ... ]
    # }
    category_buckets: Dict[str, List[Dict[str, Any]]] = {}

    # We'll store the intermediate policy data in a dict keyed by ID
    policy_map: Dict[str, Dict[str, Any]] = {}

    # Regexes to identify things
    re_category = re.compile(r"^##\s+(\d+\.\s+.*)$")  # e.g. "## 1. Legacy Authentication"
    re_subcategory = re.compile(r"^###\s+(.*)$")      # We'll only use this to detect Implementation
    re_policy_header = re.compile(r"^####\s+(MS\.[A-Za-z0-9]+\.\d+\.\dv\d+)\s*(.*)$")
    re_instructions_header = re.compile(r"^####\s+(MS\.[A-Za-z0-9]+\.\d+\.\dv\d+)\s+Instructions\s*$")

    re_comment_criticality = re.compile(r"^<!--\s*Policy:\s*(MS\.[A-Za-z0-9]+\.\d+\.\dv\d+);\s*Criticality:\s*(\S+)\s*-->")
    re_rationale = re.compile(r"^-\s*_Rationale:_\s*(.*)", re.IGNORECASE)
    re_last_modified = re.compile(r"^-\s*_Last modified:_\s*(.*)", re.IGNORECASE)
    re_note = re.compile(r"^-\s*_Note:_\s*(.*)", re.IGNORECASE)
    re_mitre_header = re.compile(r"^-\s*_MITRE ATT&CK TTP Mapping:_", re.IGNORECASE)
    re_mitre_item = re.compile(r"^\s*-?\s*\[(T\d+.*?)\]", re.IGNORECASE)

    current_category = ""
    in_implementation_section = False
    current_instructions_policy_id = None

    # instructions_map[policy_id] -> list of lines for the remediation
    instructions_map: Dict[str, List[str]] = {}

    def get_or_create_policy(pid: str) -> Dict[str, Any]:
        if pid not in policy_map:
            policy_map[pid] = {
                "id": pid,
                "category": current_category,
                "title": "",
                "description": "",
                "criticality": "",
                "severity": "",
                "rationale": "",
                "notes": [],
                "last_modified": "",
                "mitre": [],
                "remediation": "",
                "product": ""
            }
        return policy_map[pid]

    i = 0
    while i < total_lines:
        line = lines[i]
        stripped = line.strip()

        # Detect "## X. Something" => new category
        cat_match = re_category.match(stripped)
        if cat_match:
            current_category = cat_match.group(1).strip()  # e.g. "1. Legacy Authentication"
            if current_category not in category_buckets:
                category_buckets[current_category] = []
            in_implementation_section = False
            current_instructions_policy_id = None
            i += 1
            continue

        # If we see "### Implementation" (or any ### that starts with "Implementation")
        if stripped.startswith("### "):
            subcat_title = stripped.lstrip("# ").strip().lower()  # e.g. "Implementation"
            if subcat_title.startswith("implementation"):
                in_implementation_section = True
                current_instructions_policy_id = None
            else:
                in_implementation_section = False
                current_instructions_policy_id = None
            i += 1
            continue

        # If we are in the Implementation block, watch for new headings or instructions
        if in_implementation_section:
            # If we see a new "##", it means Implementation ended
            if stripped.startswith("## "):
                in_implementation_section = False
                current_instructions_policy_id = None
                i += 1
                continue

            # If we see "#### MS.xxx Instructions"
            instr_match = re_instructions_header.match(stripped)
            if instr_match:
                current_instructions_policy_id = instr_match.group(1)
                instructions_map.setdefault(current_instructions_policy_id, [])
                i += 1
                continue
            else:
                # Otherwise, add lines to current policy's instructions
                if current_instructions_policy_id:
                    instructions_map[current_instructions_policy_id].append(line)
                i += 1
                continue

        # Detect a new policy: "#### MS.AAD.x.xvY SomeTitle"
        pol_match = re_policy_header.match(stripped)
        if pol_match:
            pid = pol_match.group(1).strip()
            ptitle = pol_match.group(2).strip()
            pol = get_or_create_policy(pid)
            pol["title"] = ptitle
            pol["category"] = current_category  # update category if changed
            i += 1
            continue

        # If there's a comment specifying criticality: <!--Policy: MS.AAD.x.x; Criticality: SHALL -->
        crit_match = re_comment_criticality.match(stripped)
        if crit_match:
            pid = crit_match.group(1).strip()
            crit = crit_match.group(2).strip()
            pol = get_or_create_policy(pid)
            pol["criticality"] = crit
            pol["severity"] = map_criticality_to_severity(crit)
            i += 1
            continue

        # Rationale, last modified, note, MITRE items
        rationale_match = re_rationale.match(stripped)
        if rationale_match:
            last_pid = list(policy_map.keys())[-1] if policy_map else None
            if last_pid:
                policy_map[last_pid]["rationale"] = rationale_match.group(1).strip()
            i += 1
            continue

        last_mod_match = re_last_modified.match(stripped)
        if last_mod_match:
            last_pid = list(policy_map.keys())[-1] if policy_map else None
            if last_pid:
                policy_map[last_pid]["last_modified"] = last_mod_match.group(1).strip()
            i += 1
            continue

        note_match = re_note.match(stripped)
        if note_match:
            last_pid = list(policy_map.keys())[-1] if policy_map else None
            if last_pid:
                policy_map[last_pid]["notes"].append(note_match.group(1).strip())
            i += 1
            continue

        if re_mitre_header.match(stripped):
            # read subsequent lines that match MITRE items
            j = i + 1
            while j < total_lines:
                mline = lines[j].strip()
                mj = re_mitre_item.match(mline)
                if mj:
                    last_pid = list(policy_map.keys())[-1] if policy_map else None
                    if last_pid:
                        policy_map[last_pid]["mitre"].append(mj.group(1).strip())
                    j += 1
                else:
                    break
            i = j
            continue

        # Otherwise, treat non-empty lines as part of the last policy's description
        if stripped:
            last_pid = list(policy_map.keys())[-1] if policy_map else None
            if last_pid:
                desc = policy_map[last_pid]["description"]
                if desc:
                    policy_map[last_pid]["description"] = desc + "\n" + stripped
                else:
                    policy_map[last_pid]["description"] = stripped

        i += 1

    # Merge instructions into each policy's 'remediation'
    for pid, lines_list in instructions_map.items():
        if pid in policy_map:
            policy_map[pid]["remediation"] = "\n".join(lines_list).strip()

    # Now place each policy into the correct category bucket
    for pid, pol in policy_map.items():
        cat_name = pol["category"]
        if not cat_name:
            cat_name = "Uncategorized"
        if cat_name not in category_buckets:
            category_buckets[cat_name] = []
        category_buckets[cat_name].append(pol)

    # Finally, build the nested structure:
    categories_data = []
    for cat_name, policies in category_buckets.items():
        # Sort policies by ID or whatever you prefer
        policies.sort(key=lambda x: x["id"].lower())
        # Transform each policy dict to the final shape you want
        policy_items = []
        for p in policies:
            title = p["description"].split(".")[0]
            policy_items.append({
                "id": p["id"],
                "name": title,
                "severity": p["severity"],
                "description": p["description"].strip(),
                "remediation": p["remediation"].strip(),
                "rationale": p["rationale"],
                "notes": p["notes"],
                "last_modified": p["last_modified"],
                "mitre": p["mitre"],
                "product": p["product"]
            })

        category_entry = {
            "name": cat_name,
            "subcategories": [
                {
                    "name": "Policies",
                    "id": f"Category_{cat_name.replace(' ', '_')}",
                    "ownership": "Shared",
                    "policies": policy_items
                }
            ]
        }
        categories_data.append(category_entry)

    # Sort categories by their name if you wish
    categories_data.sort(key=lambda x: x["name"].lower())

    # Wrap in top-level key
    nested_result = {
        "cisaM365Baseline": {
            "title": found_title if found_title else fallback_title,
            "categories": categories_data
        }
    }

    return nested_result

def parse_all_scuba_markdowns(source_dir: str) -> None:
    """
    Parse each .md file under source_dir and write out a separate .yml file
    with a nested categories→subcategories→policies structure.
    """
    output_dir = "./target/scuba"
    os.makedirs(output_dir, exist_ok=True)

    for root, dirs, files in os.walk(source_dir):
        for filename in files:
            if filename.lower().endswith(".md"):
                path = os.path.join(root, filename)
                with open(path, "r", encoding="utf-8") as f:
                    md_text = f.read()

                fallback_title = os.path.splitext(filename)[0]
                baseline_data = parse_markdown_nested(md_text, fallback_title)

                out_filename = os.path.splitext(filename)[0] + ".yml"
                out_path = os.path.join(output_dir, out_filename)

                with open(out_path, "w", encoding="utf-8") as out:
                    yaml.safe_dump(baseline_data, out, sort_keys=False, allow_unicode=True)

                print(f"[+] Wrote nested baseline: {baseline_data['cisaM365Baseline']['title']} → {out_path}")

def parse():
    input_dir = "./sources/dataset/scuba"
    parse_all_scuba_markdowns(input_dir)

if __name__ == "__main__":
    parse()
