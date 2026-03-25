import json
import shutil
from pathlib import Path

import yaml

# Paths
ROOT_DIR = Path(__file__).parent.parent
RULES_JSON_PATH = ROOT_DIR / "docs" / "rules.json"
DOCS_RULES_DIR = ROOT_DIR / "docs" / "rules"
MKDOCS_YML_PATH = ROOT_DIR / "mkdocs.yml"

# Markdown Template
MD_TEMPLATE = """# {name} ({id})

**Dimension**: {dimension}
**Severity**: {severity}
**Scope**: {scope}

## Description
{impact}

**Rationale:**
{rationale}

## Remediation / Fix
{fix}
"""

def clean_rules_dir():
    """Delete all files in docs/rules/ except overview.md"""
    print("Cleaning docs/rules/...")
    for item in DOCS_RULES_DIR.iterdir():
        if item.is_file() and item.name != "overview.md":
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)

def generate_docs():
    """Parse rules.json and write individual rule markdown files."""
    print("Loading rules.json...")
    with open(RULES_JSON_PATH, encoding="utf-8") as f:
        content = f.read().strip()
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Fallback for slightly malformed JSON (like trailing commas)
        import re
        content = re.sub(r",\s*]", "]", content)
        content = re.sub(r",\s*}", "}", content)
        data = json.loads(content)

    if isinstance(data, dict) and "flat" in data:
        rules = data["flat"]
    elif isinstance(data, list):
        rules = data
    else:
        # Handle cases where it might be wrapped in a single-item list by previous logic
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict) and "flat" in data[0]:
            rules = data[0]["flat"]
        else:
            raise ValueError("Unexpected rules.json format")

    # Dictionary to keep track of the navigation structure
    # nav_tree = {"Universal": {dimension: [(Rule Name, path)]}, "Dialects": {dialect: {dimension: [(Rule Name, path)]}}}
    nav_tree = {
        "Universal": {},
        "Dialects": {}
    }

    print(f"Generating markdown for {len(rules)} rules...")

    for rule in rules:
        r_id = rule["id"]
        r_name = rule["name"]
        r_dim = rule.get("dimension", "unknown").capitalize()
        r_sev = rule.get("severity", "unknown").capitalize()
        r_impact = rule.get("impact", "TBD").strip()
        r_rationale = rule.get("rationale", "TBD").strip()
        r_fix = rule.get("fix", "TBD").strip()
        dialects = rule.get("dialects", [])

        # Clean "TBD"
        if r_impact == "TBD":
            r_impact = "Documentation for this rule's impact is pending."
        if r_rationale == "TBD":
            r_rationale = "Documentation for this rule's rationale is pending."
        if r_fix == "TBD":
            r_fix = "No automated or manual fix guidance is currently available for this rule."

        if not dialects:
            # Universal
            scope = "Universal (All Dialects)"
            content = MD_TEMPLATE.format(
                name=r_name, id=r_id, dimension=r_dim, severity=r_sev,
                scope=scope, impact=r_impact, rationale=r_rationale, fix=r_fix
            )
            # Create folder
            dim_lower = r_dim.lower()
            folder_path = DOCS_RULES_DIR / "universal" / dim_lower
            folder_path.mkdir(parents=True, exist_ok=True)

            file_name = f"{r_id}.md"
            file_path = folder_path / file_name
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Nav
            if dim_lower not in nav_tree["Universal"]:
                nav_tree["Universal"][dim_lower] = []
            nav_tree["Universal"][dim_lower].append({f"{r_name} ({r_id})": f"rules/universal/{dim_lower}/{file_name}"})

        else:
            # Dialect specific
            for dialect in dialects:
                dialect_str = str(dialect).lower()
                scope = f"Dialect Specific ({dialect_str.capitalize()})"
                content = MD_TEMPLATE.format(
                    name=r_name, id=r_id, dimension=r_dim, severity=r_sev,
                    scope=scope, impact=r_impact, rationale=r_rationale, fix=r_fix
                )

                dim_lower = r_dim.lower()
                folder_path = DOCS_RULES_DIR / "dialects" / dialect_str / dim_lower
                folder_path.mkdir(parents=True, exist_ok=True)

                file_name = f"{r_id}.md"
                file_path = folder_path / file_name
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

                # Nav
                if dialect_str not in nav_tree["Dialects"]:
                    nav_tree["Dialects"][dialect_str] = {}
                if dim_lower not in nav_tree["Dialects"][dialect_str]:
                    nav_tree["Dialects"][dialect_str][dim_lower] = []

                nav_tree["Dialects"][dialect_str][dim_lower].append({f"{r_name} ({r_id})": f"rules/dialects/{dialect_str}/{dim_lower}/{file_name}"})

    return nav_tree


def sort_nav(nav_tree):
    # Sort Universal
    univ = nav_tree["Universal"]
    sorted_univ_list = []
    for dim in sorted(univ.keys()):
        # sort rules by name
        sorted_rules = sorted(univ[dim], key=lambda x: list(x.keys())[0])
        sorted_univ_list.append({dim.capitalize(): sorted_rules})

    # Sort Dialects
    dialects = nav_tree["Dialects"]
    sorted_dialects_list = []
    for dialect_name in sorted(dialects.keys()):
        dim_dict = dialects[dialect_name]
        sorted_dims_list = []
        for dim in sorted(dim_dict.keys()):
            sorted_rules = sorted(dim_dict[dim], key=lambda x: list(x.keys())[0])
            sorted_dims_list.append({dim.capitalize(): sorted_rules})
        sorted_dialects_list.append({dialect_name.capitalize(): sorted_dims_list})

    return sorted_univ_list, sorted_dialects_list


def update_mkdocs(sorted_univ, sorted_dialects):
    print("Updating mkdocs.yml navigation...")

    with open(MKDOCS_YML_PATH, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Build the Rules Explorer nav structure
    rules_explorer = [
        {"Overview": "rules/overview.md"},
        {"Universal": sorted_univ},
        {"Dialects": sorted_dialects}
    ]

    # Find where to replace in nav
    nav = config.get("nav", [])
    for item in nav:
        if "Rules Explorer" in item:
            item["Rules Explorer"] = rules_explorer
            break

    # Write back preserving order as much as possible if we used a standard yaml loader
    # However yaml.safe_dump doesn't preserve comments. To be completely flawless,
    # let's just use yaml.dump but with Custom options
    with open(MKDOCS_YML_PATH, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, sort_keys=False, default_flow_style=False)

    print("Success!")

if __name__ == "__main__":
    clean_rules_dir()
    nav_tree = generate_docs()
    sorted_u, sorted_d = sort_nav(nav_tree)
    update_mkdocs(sorted_u, sorted_d)
