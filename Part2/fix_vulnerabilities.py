import sqlite3
import yaml
import os
import subprocess
import logging

DATABASE = "semgrep_results.db"
FIXES_YAML = "fixes.yaml"
RUN_SEMGREP_SCRIPT = "runSemGrepWithDB.py"

logging.basicConfig(level=logging.INFO)


def load_fixes():
    """Load fix snippets from fixes.yaml."""
    with open(FIXES_YAML, "r") as f:
        data = yaml.safe_load(f)
    fix_map = {}
    for rule in data.get("rules", []):
        cid = rule.get("id")
        fix_snippet = rule.get("fix", "")
        if cid and fix_snippet:
            fix_map[cid] = fix_snippet
    return fix_map


def get_vulnerability_by_id(vuln_id):
    """Return DB row for a single vulnerability ID."""
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
    return {
        "id": row[0],
        "scan_name": row[1],
        "file_path": row[2],
        "line_start": row[3],
        "check_id": row[4],
        "message": row[5],
    }


def apply_fix_to_file(file_path, line_num, fix_snippet):
    """Naively replace line_num in file_path with fix_snippet."""
    if not os.path.isfile(file_path):
        return "File not found. Could not fix automatically."

    with open(file_path, "r") as f:
        lines = f.readlines()

    idx = line_num - 1
    if idx < 0 or idx >= len(lines):
        return "Line out of range. Could not fix automatically."

    lines[idx:idx+1] = [l + "\n" for l in fix_snippet.strip().split("\n")]
    
    with open(file_path, "w") as f:
        f.writelines(lines)

    return "OK"


def run_semgrep_again(case_name):
    """Re-run Semgrep on '.' for the given case_name, removing old lines that vanish."""
    logging.info(f"Re-running Semgrep for case: {case_name}")
    cmd = ["python", RUN_SEMGREP_SCRIPT, "--db", DATABASE, "--rules", "rules.yaml", "--target", "."]
    subprocess.run(cmd, check=True)
    logging.info("Completed new Semgrep scan.")


def fix_single_vulnerability(vuln_id):
    """Fix one vulnerability, re-run Semgrep, remove old lines from DB."""
    vuln = get_vulnerability_by_id(vuln_id)
    if not vuln:
        return {"status": "ERROR", "details": "No vulnerability found with that ID."}

    fix_map = load_fixes()
    snippet = fix_map.get(vuln["check_id"], "")
    if not snippet.strip():
        return {"status": "SUGGESTED", "details": "No direct fix snippet."}

    result = apply_fix_to_file(vuln["file_path"], vuln["line_start"], snippet)
    if result != "OK":
        return {"status": "SUGGESTED", "details": result}

    # If fix was "OK", re-scan the code and remove old lines from DB
    run_semgrep_again(vuln["scan_name"])
    return {"status": "OK", "details": "Fix applied and re-scan done."}


def fix_all_in_case(case_name):
    """
    Fix all vulnerabilities in this case. 
    We fix each ID in turn, then after the last fix, do a final re-scan once.
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM semgrep_results WHERE scan_name=?", (case_name,))
    vuln_ids = [r[0] for r in c.fetchall()]
    conn.close()

    fixed_count = 0
    suggested_count = 0

    for vid in vuln_ids:
        row_result = fix_single_vulnerability(vid)
        if row_result["status"] == "OK":
            fixed_count += 1
        elif row_result["status"] == "SUGGESTED":
            suggested_count += 1

    # After all are attempted, do one final re-scan to remove leftover lines
    run_semgrep_again(case_name)

    return {"fixed": fixed_count, "suggested": suggested_count}


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        vid = int(sys.argv[1])
        print(fix_single_vulnerability(vid))
    elif len(sys.argv) == 3 and sys.argv[1] == "--case":
        c_name = sys.argv[2]
        print(fix_all_in_case(c_name))
    else:
        print("Usage:")
        print("  python fix_vulnerabilities.py <vuln_id>")
        print("  python fix_vulnerabilities.py --case <case_name>")
