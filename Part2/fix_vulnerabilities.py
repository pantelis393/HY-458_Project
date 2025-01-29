import sqlite3
import yaml
import os

DATABASE = "semgrep_results.db"
FIXES_YAML = "fixes.yaml"


def load_fixes():
    """
    Parse 'fixes.yaml' and return a dict of { check_id: fix_snippet }
    We'll also store a 'suggestion' if we can't do line-based replacement.
    """
    with open(FIXES_YAML, "r") as f:
        data = yaml.safe_load(f)

    # We expect data to look like: { "rules": [ { "id": "...", "fix": "...", ... }, ... ] }
    rules = data.get("rules", [])
    fix_map = {}
    for rule in rules:
        cid = rule.get("id")
        fix_text = rule.get("fix", "")
        fix_map[cid] = fix_text
    return fix_map


def get_vulnerability_by_id(vuln_id):
    """
    Return one row from semgrep_results by ID,
    or None if not found.
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT id, scan_name, file_path, line_start, check_id, message
        FROM semgrep_results
        WHERE id=?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    # row structure: (id, scan_name, file_path, line_start, check_id, message)
    return {
        "id": row[0],
        "scan_name": row[1],
        "file_path": row[2],
        "line_start": row[3],
        "check_id": row[4],
        "message": row[5],
    }


def list_vulnerabilities_for_case(case_name):
    """
    Return all vulnerabilities for a given case_name as a list of dicts.
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, line_start, check_id, message
        FROM semgrep_results
        WHERE scan_name=?
    """, (case_name,))
    rows = c.fetchall()
    conn.close()
    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "file_path": row[1],
            "line_start": row[2],
            "check_id": row[3],
            "message": row[4],
        })
    return results


def apply_fix_to_file(file_path, line_num, fix_snippet):
    """
    Attempt to replace the vulnerable line at 'line_num' with the 'fix_snippet'.
    This is very naive: we simply replace the entire line with fix_snippet.
    If fix_snippet is multiline, we place them all in place of that line.

    If we can't find that line, we skip.
    """
    if not os.path.isfile(file_path):
        return "File not found. Could not fix automatically."

    with open(file_path, "r") as f:
        lines = f.readlines()

    idx = line_num - 1  # 1-based line_start => 0-based index
    if idx < 0 or idx >= len(lines):
        return "Line out of range. Could not fix automatically."

    # Replace that line with fix_snippet
    fix_lines = fix_snippet.strip().split("\n")
    fix_lines = [l + "\n" for l in fix_lines]  # add newlines
    lines[idx:idx + 1] = fix_lines  # splice in fix lines at index

    with open(file_path, "w") as f:
        f.writelines(lines)

    return "OK"


def apply_fix_suggestion(file_path, line_num, suggestion_text):
    """
    Insert a TODO comment near that line to suggest a fix.
    """
    if not os.path.isfile(file_path):
        return "File not found. Suggestion only."

    with open(file_path, "r") as f:
        lines = f.readlines()

    idx = line_num - 1
    if idx < 0 or idx >= len(lines):
        return "Line out of range. Suggestion only."

    lines.insert(idx + 1, f"# TODO: {suggestion_text}\n")

    with open(file_path, "w") as f:
        f.writelines(lines)

    return "SUGGESTED"


def fix_single_vulnerability(vuln_id):
    """
    Fix one vulnerability by ID:
      - read from DB
      - find fix snippet in fixes.yaml for that check_id
      - attempt line replacement. If not found or if check_id has no fix snippet, add suggestion
    Return a dict with { "status": "OK"/"SUGGESTED"/"ERROR", "details": ... }
    """
    vuln = get_vulnerability_by_id(vuln_id)
    if not vuln:
        return {"status": "ERROR", "details": "No vulnerability found with that ID."}

    fix_map = load_fixes()
    fix_snippet = fix_map.get(vuln["check_id"], "")
    if not fix_snippet.strip():
        # No known fix => suggestion
        apply_fix_suggestion(vuln["file_path"], vuln["line_start"], "No auto-fix available. " + vuln["message"])
        return {"status": "SUGGESTED", "details": "No direct fix snippet. Inserted suggestion."}

    # Try line-based fix
    result = apply_fix_to_file(vuln["file_path"], vuln["line_start"], fix_snippet)
    if result == "OK":
        return {"status": "OK", "details": "Auto-fix applied."}
    else:
        # If line-based fix fails => suggestion
        apply_fix_suggestion(vuln["file_path"], vuln["line_start"], vuln["message"])
        return {"status": "SUGGESTED", "details": result}


def fix_all_in_case(case_name):
    """
    Fix all vulnerabilities in the DB for this case_name, one by one.
    Return a summary dict of how many fixed, how many suggested, etc.
    """
    vulns = list_vulnerabilities_for_case(case_name)
    if not vulns:
        return {"fixed": 0, "suggested": 0, "error_count": 0}

    fix_map = load_fixes()
    fixed_count = 0
    suggested_count = 0
    error_count = 0

    for v in vulns:
        check_id = v["check_id"]
        fix_snippet = fix_map.get(check_id, "")
        if not fix_snippet.strip():
            # suggestion
            apply_fix_suggestion(v["file_path"], v["line_start"], "No auto-fix for check_id: " + check_id)
            suggested_count += 1
            continue
        # attempt line-based fix
        result = apply_fix_to_file(v["file_path"], v["line_start"], fix_snippet)
        if result == "OK":
            fixed_count += 1
        else:
            # fallback to suggestion
            apply_fix_suggestion(v["file_path"], v["line_start"], f"Could not fix: {result}")
            suggested_count += 1

    return {
        "fixed": fixed_count,
        "suggested": suggested_count,
        "error_count": error_count
    }


if __name__ == "__main__":
    # Optional: a small CLI usage
    import sys

    if len(sys.argv) == 2:
        # fix a single vulnerability ID
        vid = int(sys.argv[1])
        r = fix_single_vulnerability(vid)
        print(r)
    elif len(sys.argv) == 3 and sys.argv[1] == "--case":
        # fix all in a case
        c = sys.argv[2]
        r = fix_all_in_case(c)
        print(r)
    else:
        print("Usage:")
        print("  python fix_vulnerabilities.py <vuln_id>")
        print("  python fix_vulnerabilities.py --case <case_name>")
