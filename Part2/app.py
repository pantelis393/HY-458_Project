import os
import sqlite3
import subprocess
import csv
import json
import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file, Response
)
from io import BytesIO, StringIO

# If you have fix_vulnerabilities.py for auto-fix logic, import it:
import fix_vulnerabilities

app = Flask(__name__)
app.secret_key = "some_secure_secret_key"

DATABASE = "semgrep_results.db"
RUN_SEMGREP_SCRIPT = "runSemGrepWithDB.py"


###############################################################################
#                         Database / Table Setup                              #
###############################################################################

def get_connection():
    return sqlite3.connect(DATABASE)

def create_main_table():
    """
    Ensure 'semgrep_results' table exists.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS semgrep_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_name TEXT,
                scan_date TEXT,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                column_start INTEGER,
                column_end INTEGER,
                check_id TEXT,
                message TEXT,
                severity TEXT
            )
        """)
        conn.commit()


###############################################################################
#                          Case / Scan Helpers                                #
###############################################################################

def ensure_case_row_exists(case_name):
    """
    Insert an empty row if this case_name has 0 rows,
    so a 0-vulnerability case is still visible in the UI.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM semgrep_results WHERE scan_name=? LIMIT 1", (case_name,))
        row = c.fetchone()
        if not row:
            c.execute("""
                INSERT INTO semgrep_results (scan_name, scan_date)
                VALUES (?, NULL)
            """, (case_name,))
        conn.commit()

def list_cases():
    """
    Return a list of dicts describing each case with aggregated counts & last_scan time.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 
                scan_name,
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(severity)='info' THEN 1 ELSE 0 END) AS info_count,
                SUM(CASE WHEN LOWER(severity)='warning' THEN 1 ELSE 0 END) AS warning_count,
                SUM(CASE WHEN LOWER(severity)='error' THEN 1 ELSE 0 END) AS error_count,
                MAX(scan_date) AS last_scan
            FROM semgrep_results
            GROUP BY scan_name
            ORDER BY scan_name
        """)
        rows = c.fetchall()

    results = []
    for row in rows:
        scan_name, total, info, warning, error, last_scan = row
        results.append({
            "scan_name": scan_name,
            "total": int(total or 0),
            "info": int(info or 0),
            "warning": int(warning or 0),
            "error": int(error or 0),
            "last_scan": last_scan or ""
        })
    return results

def create_case(case_name):
    """
    Create a minimal row so the case is recognized with no vulnerabilities.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO semgrep_results (scan_name, scan_date)
            VALUES (?, NULL)
        """, (case_name,))
        conn.commit()

def delete_case(case_name):
    """
    Remove all vulnerabilities for a given case_name from DB.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM semgrep_results WHERE scan_name=?", (case_name,))
        conn.commit()

def get_case_results(case_name):
    """
    Return:
      rows -> (vuln_id, file_path, line_start, message, severity)
      stats -> {total, info, warning, error}
      lang_counts -> for the chart
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, file_path, line_start, message, severity
            FROM semgrep_results
            WHERE scan_name=?
        """, (case_name,))
        fetched_rows = c.fetchall()

        c.execute("""
            SELECT
              COUNT(*),
              SUM(CASE WHEN LOWER(severity)='info' THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(severity)='warning' THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(severity)='error' THEN 1 ELSE 0 END)
            FROM semgrep_results
            WHERE scan_name=?
        """, (case_name,))
        stat_row = c.fetchone()

    stats = {
        "total": int(stat_row[0] or 0),
        "info": int(stat_row[1] or 0),
        "warning": int(stat_row[2] or 0),
        "error": int(stat_row[3] or 0),
    }

    lang_counts = {"python": 0, "java": 0, "c": 0, "other": 0}
    row_list = []
    for (vid, fpath, line, msg, sev) in fetched_rows:
        low_fpath = (fpath or "").lower()
        if low_fpath.endswith(".py"):
            lang_counts["python"] += 1
        elif low_fpath.endswith(".java"):
            lang_counts["java"] += 1
        elif low_fpath.endswith(".c"):
            lang_counts["c"] += 1
        elif fpath and fpath.strip():
            lang_counts["other"] += 1

        row_list.append((vid, fpath, line, msg, sev))

    return row_list, stats, lang_counts


###############################################################################
#                     DB MGMT: Clear / Import / Export (DB + CSV)             #
###############################################################################

def clear_database():
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM semgrep_results")
        conn.commit()

def export_database():
    with open(DATABASE, "rb") as f:
        return BytesIO(f.read())

def import_database(file_stream):
    with open(DATABASE, "wb") as f:
        f.write(file_stream.read())

@app.route("/clear_db", methods=["POST"])
def do_clear_db():
    clear_database()
    flash("Database cleared (all rows removed).", "success")
    return redirect(url_for("index"))

@app.route("/export_db", methods=["GET"])
def do_export_db():
    mem = export_database()
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="semgrep_results.db")

@app.route("/import_db", methods=["POST"])
def do_import_db():
    f = request.files.get("dbfile")
    if not f or f.filename == "":
        flash("No .db file provided.", "error")
        return redirect(url_for("index"))
    import_database(f)
    flash("Database imported successfully.", "success")
    return redirect(url_for("index"))

#######################################
# NEW: Export to CSV route
#######################################
@app.route("/export_csv", methods=["GET"])
def export_csv():
    """
    Exports all rows from semgrep_results as a CSV file.
    Columns: id, scan_name, scan_date, file_path, line_start, line_end, check_id, message, severity
    """
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        "id", "scan_name", "scan_date",
        "file_path", "line_start", "line_end",
        "check_id", "message", "severity"
    ])

    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, scan_name, scan_date,
                   file_path, line_start, line_end,
                   check_id, message, severity
            FROM semgrep_results
            ORDER BY id
        """)
        rows = c.fetchall()

    for row in rows:
        writer.writerow(row)

    # Convert to a response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":"attachment;filename=semgrep_results.csv"}
    )


###############################################################################
#             SEMGREP SCAN + REMOVE OLD + SKIP DUPLICATES                     #
###############################################################################

def run_semgrep_script(scan_name, target):
    cmd = [
        "python", RUN_SEMGREP_SCRIPT,
        "--db", DATABASE,
        "--rules", "rules.yaml",
        "--target", target
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    proc.communicate(input=f"{scan_name}\n")
    proc.wait()

def remove_old_and_skip_duplicates(case_name):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, line_start, check_id, scan_date
        FROM semgrep_results
        WHERE scan_name=?
    """, (case_name,))
    rows = c.fetchall()
    if not rows:
        conn.close()
        return

    row_info = {}
    latest_date = None
    for (rid, fpath, line, cid, sdate) in rows:
        row_info[rid] = {
            "file_path": fpath,
            "line_start": line,
            "check_id": cid,
            "scan_date": sdate
        }
        if sdate and (not latest_date or sdate > latest_date):
            latest_date = sdate

    if not latest_date:
        conn.close()
        return

    from collections import defaultdict
    sig_map = defaultdict(list)
    for rid, info in row_info.items():
        sig = (info["file_path"], info["line_start"], info["check_id"])
        sig_map[sig].append(rid)

    new_signatures = set()
    for rid, info in row_info.items():
        if info["scan_date"] == latest_date:
            new_signatures.add((info["file_path"], info["line_start"], info["check_id"]))

    to_remove = []
    for sig, rid_list in sig_map.items():
        if sig not in new_signatures:
            # remove old ones not found in new scan
            to_remove.extend(rid_list)
        else:
            # keep one row with new date
            new_rows = []
            old_rows = []
            for rid in rid_list:
                if row_info[rid]["scan_date"] == latest_date:
                    new_rows.append(rid)
                else:
                    old_rows.append(rid)
            to_remove.extend(old_rows)
            if len(new_rows) > 1:
                new_rows.sort()
                keep = new_rows[0]
                remove = new_rows[1:]
                to_remove.extend(remove)

    if to_remove:
        id_str = ",".join(str(x) for x in to_remove)
        c.execute(f"DELETE FROM semgrep_results WHERE id IN ({id_str})")
        conn.commit()
    conn.close()


###############################################################################
#                             FLASK ROUTES                                    #
###############################################################################

@app.route("/")
def index():
    cases = list_cases()
    return render_template("index.html", cases=cases)

@app.route("/create_case", methods=["POST"])
def handle_create_case():
    name = request.form.get("case_name", "").strip()
    if not name:
        flash("Case name cannot be empty!", "error")
        return redirect(url_for("index"))
    create_case(name)
    flash(f"Case '{name}' created (empty).", "success")
    return redirect(url_for("index"))

@app.route("/delete_case", methods=["POST"])
def handle_delete_case():
    name = request.form.get("case_name", "").strip()
    if name:
        delete_case(name)
        flash(f"Case '{name}' deleted.", "success")
    return redirect(url_for("index"))

@app.route("/load_case/<case_name>")
def load_case(case_name):
    rows, stats, lang_counts = get_case_results(case_name)
    low_count = stats["info"]
    med_count = stats["warning"]
    high_count = stats["error"]
    languages = list(lang_counts.keys())
    lang_values = list(lang_counts.values())

    return render_template(
        "case.html",
        case_name=case_name,
        rows=rows,
        stats=stats,
        low_count=low_count,
        med_count=med_count,
        high_count=high_count,
        languages=languages,
        lang_values=lang_values
    )

@app.route("/rescan_case", methods=["POST"])
def rescan_case():
    case_name = request.form.get("case_name", "").strip()
    target = request.form.get("target", ".").strip()
    if not case_name:
        flash("No case name specified for re-scan!", "error")
        return redirect(url_for("index"))

    run_semgrep_script(case_name, target)
    remove_old_and_skip_duplicates(case_name)
    ensure_case_row_exists(case_name)

    flash(f"Re-scan completed for '{case_name}'.", "success")
    return redirect(url_for("load_case", case_name=case_name))

@app.route("/scan_new_directory", methods=["POST"])
def scan_new_directory():
    new_case_name = request.form.get("new_case_name", "").strip()
    file_list = request.files.getlist("new_target_path")
    if not new_case_name:
        flash("Please provide a case name.", "error")
        return redirect(url_for("index"))
    if not file_list or len(file_list) == 0:
        flash("Please select a directory to scan.", "error")
        return redirect(url_for("index"))

    relative_paths = [f.filename for f in file_list if f.filename]
    if not relative_paths:
        flash("No valid files found in that directory selection.", "error")
        return redirect(url_for("index"))

    def common_prefix(a, b):
        import os
        pa = a.split(os.sep)
        pb = b.split(os.sep)
        i = 0
        while i < len(pa) and i < len(pb) and pa[i] == pb[i]:
            i += 1
        return os.sep.join(pa[:i])

    common_anc = relative_paths[0]
    for rp in relative_paths[1:]:
        common_anc = common_prefix(common_anc, rp)
        if not common_anc:
            break

    if not common_anc:
        common_anc = "."

    run_semgrep_script(new_case_name, common_anc)
    remove_old_and_skip_duplicates(new_case_name)
    ensure_case_row_exists(new_case_name)

    flash(f"Scanned directory '{common_anc}' into case '{new_case_name}'.", "success")
    return redirect(url_for("index"))

###############################################################################
# FIX SINGLE or ALL VULNERABILITIES
###############################################################################
@app.route("/fix_vulnerability", methods=["POST"])
def fix_vulnerability():
    vuln_id = request.form.get("vuln_id", "")
    case_name = request.form.get("case_name", "")
    if not vuln_id.isdigit():
        flash("Invalid vulnerability ID.", "error")
        return redirect(url_for("load_case", case_name=case_name))

    vid = int(vuln_id)
    result = fix_vulnerabilities.fix_single_vulnerability(vid)
    if result["status"] == "OK":
        flash(f"Auto-fix applied for vulnerability {vid}.", "success")
    elif result["status"] == "SUGGESTED":
        flash(f"Inserted suggestion for vulnerability {vid}.", "warning")
    else:
        flash(f"Fix error: {result['details']}", "error")

    return redirect(url_for("load_case", case_name=case_name))

@app.route("/fix_all/<case_name>", methods=["POST"])
def fix_all(case_name):
    summary = fix_vulnerabilities.fix_all_in_case(case_name)
    fcount = summary["fixed"]
    scount = summary["suggested"]
    flash(f"Fix All in '{case_name}': {fcount} auto-fixed, {scount} suggestions.", "info")
    return redirect(url_for("load_case", case_name=case_name))

###############################################################################
# MAIN
###############################################################################
if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        open(DATABASE, 'w').close()
    create_main_table()
    app.run(debug=True)
