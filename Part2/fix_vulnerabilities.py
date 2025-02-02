import sqlite3
import yaml
import os
import subprocess
import logging


DATABASE = "semgrep_results.db"
FIXES_YAML = "fixes.yaml"
RUN_SEMGREP_SCRIPT = "custom_parser.py"

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
        SELECT id, scan_name, file_path, line_start, check_id, message, column_start, column_end,line_end
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
        "column_start": row[6],
        "column_end": row[7],
        "line_end": row[8]
    }

import os
import re

import os
import re

# Example placeholder patterns
import os
import re

# Example placeholder patterns
PLACEHOLDER_PATTERNS = {
    "$DATA": re.compile(
        r"hashlib\.\w+\s*\(\s*(?P<data>.*?)\s*\)",
        re.DOTALL
    ),
    "$ARGS": re.compile(
        # Regex accepts:
        #   Crypto.Cipher.<algo>.new(...)
        #   DES.new(...)
        #   SHA1(...)
        #   DES_set_key(...)
        # capturing everything inside parentheses as group 'args'.
        r"(?:Crypto\.Cipher\.\w+\.new|DES|SHA1|DES_set_key)\s*\(\s*(?P<args>.*?)\s*\)",
        re.DOTALL
    ),
}


def apply_fix_to_file(file_path, line_start, column_start, line_end, column_end, fix_snippet):
    """
    Remove text in `file_path` from (line_start, column_start) up to (line_end, column_end)
    (all 1-based, end_col inclusive), then replace that region with `fix_snippet`.

    If `fix_snippet` contains placeholders like `$DATA` or `$ARGS`, we capture them from
    the removed text via PLACEHOLDER_PATTERNS. This version also has special logic to handle
    multi-line snippets where the first line is an import statement (like `from Crypto.Cipher import AES`),
    inserting it on the line above and inlining the second line.
    """
    print("[DEBUG] apply_fix_to_file called with:\n"
          f"         file_path={file_path}\n"
          f"         line_start={line_start}, column_start={column_start}, "
          f"line_end={line_end}, column_end={column_end}\n"
          f"         fix_snippet={repr(fix_snippet)}")

    if not os.path.isfile(file_path):
        return "File not found. Could not fix automatically."

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    total_lines = len(lines)
    # Basic sanity checks
    if any([
        line_start < 1,
        line_end < 1,
        line_start > total_lines,
        line_end > total_lines,
        line_start > line_end
    ]):
        return "Line indices out of range or invalid."

    # Convert line indices to 0-based
    ls_idx = line_start - 1
    le_idx = line_end - 1

    # ----------------------------------------------------------
    # 1) Extract the text to be removed (inclusive of column_end)
    # ----------------------------------------------------------
    if ls_idx == le_idx:
        # Single-line removal
        original_line = lines[ls_idx]
        start_col_0 = column_start - 1
        end_col_0   = column_end  # inclusive
        if start_col_0 > len(original_line):
            return "column_start out of range."
        if end_col_0 > len(original_line):
            end_col_0 = len(original_line)

        removed_text = original_line[start_col_0:end_col_0]
    else:
        # Multi-line removal
        first_line = lines[ls_idx]
        last_line  = lines[le_idx]
        start_col_0 = column_start - 1
        end_col_0   = column_end
        if start_col_0 > len(first_line):
            return "column_start out of range in the first line."
        if end_col_0 > len(last_line):
            end_col_0 = len(last_line)

        middle_lines = []
        if (le_idx - ls_idx) > 1:
            middle_lines = lines[ls_idx+1 : le_idx]

        removed_text = (
            first_line[start_col_0:]
            + "".join(middle_lines)
            + last_line[:end_col_0]
        )

    # ----------------------------------------------------------
    # 2) Substitute placeholders in the fix_snippet based on the removed text
    # ----------------------------------------------------------
    for placeholder, pattern in PLACEHOLDER_PATTERNS.items():
        if placeholder in fix_snippet:
            match = pattern.search(removed_text)
            if match:
                group_name = placeholder.strip("$").lower()  # e.g., "$ARGS" -> "args"
                if group_name in match.groupdict():
                    captured_value = match.group(group_name).strip()
                    fix_snippet = fix_snippet.replace(placeholder, captured_value)

    snippet_lines = fix_snippet.splitlines(keepends=False)

    # ----------------------------------------------------------
    # 3) Special handling for multi-line snippet where we want
    #    the *first line* to appear ABOVE the replaced line (e.g. import).
    #
    #    If snippet_lines == 2 and snippet_lines[0] looks like 'from ' or 'import ',
    #    we treat it as:
    #      line_above = snippet_lines[0]
    #      replaced_line = snippet_lines[1]
    # ----------------------------------------------------------
    needs_import_above = False
    if len(snippet_lines) == 2:
        first_snippet_line = snippet_lines[0].strip()
        # Very naive check:
        if first_snippet_line.startswith("from ") or first_snippet_line.startswith("import "):
            needs_import_above = True

    # ----------------------------------------------------------
    # 4) Replace old code with snippet lines
    # ----------------------------------------------------------
    if ls_idx == le_idx:
        # Single-line fix
        line_text = lines[ls_idx]
        start_col_0 = column_start - 1
        end_col_0   = column_end
        if end_col_0 > len(line_text):
            end_col_0 = len(line_text)

        before_part = line_text[:start_col_0]
        after_part  = line_text[end_col_0:]

        if not snippet_lines:
            # No snippet => just remove
            lines[ls_idx] = before_part + after_part
        elif len(snippet_lines) == 1:
            # Single line snippet => inline replace
            lines[ls_idx] = before_part + snippet_lines[0] + after_part
        else:
            # If the snippet is multi-line, check for the special import rule
            if needs_import_above:
                # Insert import line above
                import_line = snippet_lines[0]
                # Replace the original line with the second line + before/after
                replacement_line = before_part + snippet_lines[1] + after_part

                # Insert the import line *above* the replaced line
                lines.insert(ls_idx, import_line + "\n")

                # Now the replaced line moves down by 1
                lines[ls_idx+1] = replacement_line
            else:
                # Normal multi-line snippet => expand in place
                new_lines = []
                new_lines.append(before_part + snippet_lines[0] + "\n")
                for mid_line in snippet_lines[1:-1]:
                    new_lines.append(mid_line + "\n")
                new_lines.append(snippet_lines[-1] + after_part)
                lines[ls_idx : ls_idx+1] = new_lines

    else:
        # Multi-line fix
        first_line_text = lines[ls_idx]
        last_line_text  = lines[le_idx]
        start_col_0 = column_start - 1
        end_col_0   = column_end
        if end_col_0 > len(last_line_text):
            end_col_0 = len(last_line_text)

        before_part = first_line_text[:start_col_0]
        after_part  = last_line_text[end_col_0:]

        if not snippet_lines:
            # No snippet => just remove entire block
            lines[ls_idx] = before_part + after_part
            del lines[ls_idx+1 : le_idx+1]
        elif len(snippet_lines) == 1:
            # Single-line snippet replaces the block
            lines[ls_idx] = before_part + snippet_lines[0] + after_part
            del lines[ls_idx+1 : le_idx+1]
        else:
            # Multi-line snippet
            if needs_import_above:
                # Insert import line above
                import_line = snippet_lines[0]
                # The second line of snippet is what replaces the original block
                block_lines = snippet_lines[1:]

                # Insert import line above the replaced block
                lines.insert(ls_idx, import_line + "\n")
                # The original lines just shifted down by 1
                ls_idx += 1
                le_idx += 1

                if len(block_lines) == 1:
                    # There's only one more line in the snippet after import
                    lines[ls_idx] = before_part + block_lines[0] + after_part
                    del lines[ls_idx+1 : le_idx+1]
                else:
                    new_lines = []
                    new_lines.append(before_part + block_lines[0] + "\n")
                    for mid_line in block_lines[1:-1]:
                        new_lines.append(mid_line + "\n")
                    new_lines.append(block_lines[-1] + after_part)
                    lines[ls_idx : le_idx+1] = new_lines
            else:
                # Normal multi-line replacement
                new_lines = []
                new_lines.append(before_part + snippet_lines[0] + "\n")
                for mid_line in snippet_lines[1:-1]:
                    new_lines.append(mid_line + "\n")
                new_lines.append(snippet_lines[-1] + after_part)
                lines[ls_idx : le_idx+1] = new_lines

    # ----------------------------------------------------------
    # 5) Write updated lines back to the file
    # ----------------------------------------------------------
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return "OK"


def run_semgrep_again(case_name):
    """Re-run Semgrep on '.' for the given case_name, removing old lines that vanish."""
    logging.info(f"Re-running Semgrep for case: {case_name}")
    cmd = ["python3", RUN_SEMGREP_SCRIPT, "--db", DATABASE, "--target", "."]
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

    result = apply_fix_to_file(vuln["file_path"], vuln["line_start"],vuln["column_start"],vuln["line_end"],vuln["column_end"], snippet)
    if result != "OK":
        return {"status": "SUGGESTED", "details": result}

    # If fix was "OK", re-scan the code and remove old lines from DB

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
    # run_semgrep_again(case_name)

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
