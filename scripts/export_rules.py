import json
import os
import sys
from pathlib import Path

# Add src to sys.path to allow importing slowql
src_path = str(Path(__file__).parent.parent / "src")
sys.path.insert(0, src_path)

try:
    from slowql.rules.catalog import get_all_rules
except ImportError as e:
    print(f"Error: Could not import slowql. Make sure you are running this from the project root. {e}")
    sys.exit(1)

def export_rules():
    rules = get_all_rules()
    flat_rules = []
    grouped_rules = {}

    for rule in rules:
        metadata = rule.metadata
        data = metadata.to_dict()
        flat_rules.append(data)
        
        dimension = data["dimension"]
        if dimension not in grouped_rules:
            grouped_rules[dimension] = []
        grouped_rules[dimension].append(data)

    output_data = {
        "flat": flat_rules,
        "grouped": grouped_rules
    }

    output_path = Path(__file__).parent.parent / "docs" / "rules.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"Exported {len(flat_rules)} rules to {output_path}")


if __name__ == "__main__":
    export_rules()
