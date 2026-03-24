import shutil
from pathlib import Path
from export_rules import export_rules
from export_docs import export_docs

def sync():
    root_path = Path(__file__).parent.parent
    docs_path = root_path / "docs"
    site_data_path = root_path / "rules-site" / "src" / "data"

    
    # 1. Export rules to docs/rules.json
    print("--- Exporting Rules ---")
    export_rules()
    
    # 2. Export general docs to docs/docs.json
    print("\n--- Exporting Documentation ---")
    export_docs()
    
    # 3. Copy to React site
    print("\n--- Syncing Data to Rules Site ---")
    site_data_path.mkdir(parents=True, exist_ok=True)
    
    shutil.copy2(docs_path / "rules.json", site_data_path / "rules.json")
    shutil.copy2(docs_path / "docs.json", site_data_path / "docs.json")
    
    print(f"Successfully synced data to {site_data_path}")

if __name__ == "__main__":
    sync()
