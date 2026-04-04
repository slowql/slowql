import json
from pathlib import Path

import yaml


def parse_nav(nav, base_docs_path):
    pages = []

    def traverse(item, parent_title=None):
        if isinstance(item, str):
            # This is a leaf node (markdown file)
            path = base_docs_path / item
            if path.exists():
                with open(path) as f:
                    content = f.read()
                return {
                    "title": item.split("/")[-1].replace(".md", "").replace("-", " ").title(),
                    "path": item,
                    "content": content
                }
            return None

        if isinstance(item, dict):
            title = list(item.keys())[0]
            value = item[title]

            if isinstance(value, str):
                # Simple title: path mapping
                page = traverse(value)
                if page:
                    page["title"] = title
                    return page
            else:
                # Nested structure
                children = []
                for child in value:
                    res = traverse(child, title)
                    if res:
                        children.append(res)
                return {
                    "title": title,
                    "children": children
                }
        return None

    for entry in nav:
        res = traverse(entry)
        if res:
            pages.append(res)

    return pages

def export_docs():
    root_path = Path(__file__).parent.parent
    mkdocs_file = root_path / "mkdocs.yml"
    docs_path = root_path / "docs"

    with open(mkdocs_file) as f:
        config = yaml.safe_load(f)

    nav = config.get("nav", [])
    pages = parse_nav(nav, docs_path)

    output_path = docs_path / "docs.json"
    with open(output_path, "w") as f:
        json.dump(pages, f, indent=2)

    print(f"Exported documentation to {output_path}")

if __name__ == "__main__":
    export_docs()
