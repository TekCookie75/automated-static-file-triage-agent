#!/usr/bin/env python3
"""
Step 4 — PE Import Analysis
Read-only. Parses the import directory and cross-references against
the suspicious imports reference file.

Usage: python 04_imports.py <sample_path> <suspicious_imports_md_path>
Output: JSON to stdout
"""

import json
import re
import sys


def parse_suspicious_imports(md_path: str) -> dict:
    """
    Parse references/suspicious_imports.md and return a dict:
      { "FunctionName": "Category Name", ... }
    Extracts all second-column values from markdown table rows.
    """
    suspicious = {}
    current_category = "Unknown"

    try:
        with open(md_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {}

    for line in lines:
        # Detect category headings (## Category Name)
        heading = re.match(r"^##\s+(.+)", line.strip())
        if heading:
            current_category = heading.group(1).strip()
            continue

        # Match table rows: | FunctionName | Notes |
        # Skip header rows (contain "Function" or dashes)
        cols = [c.strip() for c in line.strip().split("|") if c.strip()]
        if len(cols) >= 1:
            name = cols[0]
            if name and name not in ("Function", "---", "Field") and not name.startswith("---"):
                suspicious[name] = current_category

    return suspicious


def analyze_imports(sample_path: str, suspicious_md_path: str) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed. Run: pip install pefile"}

    suspicious_map = parse_suspicious_imports(suspicious_md_path)

    try:
        pe = pefile.PE(sample_path)
    except Exception as e:
        return {"error": f"Failed to parse PE: {e}"}

    all_imports     = []
    suspicious_hits = []
    dll_summary     = {}

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = dll_entry.dll.decode(errors="replace")
            dll_summary[dll_name] = 0

            for imp in dll_entry.imports:
                fname = (imp.name.decode(errors="replace")
                         if imp.name else f"ordinal_{imp.ordinal}")
                dll_summary[dll_name] += 1

                entry = {
                    "dll":      dll_name,
                    "function": fname,
                    "ordinal":  imp.ordinal,
                }

                if fname in suspicious_map:
                    entry["suspicious"] = True
                    entry["category"]   = suspicious_map[fname]
                    suspicious_hits.append(entry)
                else:
                    entry["suspicious"] = False
                    entry["category"]   = None

                all_imports.append(entry)

    pe.close()

    return {
        "total_imports":         len(all_imports),
        "suspicious_hit_count":  len(suspicious_hits),
        "dll_summary":           dll_summary,
        "suspicious_imports":    suspicious_hits,
        "all_imports":           all_imports,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python 04_imports.py <sample_path> <suspicious_imports_md_path>",
              file=sys.stderr)
        sys.exit(1)

    result = analyze_imports(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
