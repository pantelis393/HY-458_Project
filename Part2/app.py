import os
import shutil
import sqlite3
import subprocess
import json
import datetime
import tempfile
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file
)
from io import BytesIO

from fix_vulnerabilities import fix_single_vulnerability, fix_all_in_case

app = Flask(__name__)
app.secret_key = "some_secure_secret_key"
DATABASE = "semgrep_results.db"
RUN_SEMGREP_SCRIPT = "runSemGrepWithDB.py"


def get_connection():
    return sqlite3.connect(DATABASE)


def create_main_table():
    """
    Create the main table if it doesn't exist.
    Also try to add the 'scan_directory' column so we can store the original
    directory used for each case.
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
                /* 'scan_directory' is added below if missing */
            )
        """)
        conn.commit()

    # Attempt to add 'scan_directory' if it doesn't exist
    try:
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("ALTER TABLE semgrep_results ADD COLUMN scan_directory TEXT")
            conn.commit()
    except:
        # If this column already exists, ignore the error
        pass


def ensure_case_row_exists(case_name):
    """
    Insert an empty row if none exist for this case,
    so that 0-vulnerability cases still appear in the DB.
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
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO semgrep_results (scan_name, scan_date)
            VALUES (?, NULL)
        """, (case_name,))
        conn.commit()


def delete_case(case_name):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT scan_directory FROM semgrep_results WHERE scan_name=?", (case_name,))
        path = c.fetchone()
        shutil.rmtree(path[0])
        c.execute("DELETE FROM semgrep_results WHERE scan_name=?", (case_name,))
        conn.commit()


def get_case_results(case_name):
    """
    Returns a list of vulnerabilities (plus ID),
    along with stats (info/warning/error),
    plus language counts.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 
                id,
                file_path,
                line_start,
                message,
                severity
            FROM semgrep_results
            WHERE scan_name=?
        """, (case_name,))
        rows = c.fetchall()

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
    for (vuln_id, fpath, line, msg, sev) in rows:
        lower_fpath = (fpath or "").lower()
        if lower_fpath.endswith(".py"):
            lang_counts["python"] += 1
        elif lower_fpath.endswith(".java"):
            lang_counts["java"] += 1
        elif lower_fpath.endswith(".c"):
            lang_counts["c"] += 1
        elif fpath and fpath.strip():
            lang_counts["other"] += 1
        row_list.append((vuln_id, fpath, line, msg, sev))

    return row_list, stats, lang_counts


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


########################################
# RUN THE EXTERNAL SCRIPT
########################################
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
    # Provide the scan_name to the external script via stdin
    proc.communicate(input=f"{scan_name}\n")
    proc.wait()


def remove_old_and_skip_duplicates(scan_name):
    """
    Remove older duplicates from the DB, keeping only the newest
    if they share (file_path, line_start, check_id).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, line_start, check_id, scan_date
        FROM semgrep_results
        WHERE scan_name=?
    """, (scan_name,))
    rows = c.fetchall()
    if not rows:
        conn.close()
        return

    row_info = {}
    latest_date = None

    for r in rows:
        rid, fpath, line, cid, sdate = r
        row_info[rid] = {
            "file_path": fpath or "",
            "line_start": line or 0,
            "check_id": cid or "",
            "scan_date": sdate
        }
        if sdate and (not latest_date or sdate > latest_date):
            latest_date = sdate

    if not latest_date:
        conn.close()
        return

    # signature => [list_of_ids]
    sig_map = {}
    for rid, info in row_info.items():
        sig = (info["file_path"], info["line_start"], info["check_id"])
        sig_map.setdefault(sig, []).append(rid)

    new_sigs = set()
    for rid, info in row_info.items():
        if info["scan_date"] == latest_date:
            new_sigs.add((info["file_path"], info["line_start"], info["check_id"]))

    to_remove = []
    for sig, rid_list in sig_map.items():
        if sig not in new_sigs:
            to_remove.extend(rid_list)
        else:
            new_date_rows = []
            old_date_rows = []
            for r in rid_list:
                if row_info[r]["scan_date"] == latest_date:
                    new_date_rows.append(r)
                else:
                    old_date_rows.append(r)
            to_remove.extend(old_date_rows)
            if len(new_date_rows) > 1:
                new_date_rows.sort()
                keep = new_date_rows[0]
                remove = new_date_rows[1:]
                to_remove.extend(remove)

    if to_remove:
        ids_str = ",".join(str(x) for x in to_remove)
        c.execute(f"DELETE FROM semgrep_results WHERE id IN ({ids_str})")
        conn.commit()

    conn.close()


##########################################
# HELPER: Retrieve the stored scan directory
##########################################
def get_scan_directory(case_name):
    """
    Return the first non-null scan_directory for this scan_name, if any.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT scan_directory
            FROM semgrep_results
            WHERE scan_name=?
              AND scan_directory IS NOT NULL
            LIMIT 1
        """, (case_name,))
        row = c.fetchone()
        return row[0] if row else None


##########################################
# FLASK ROUTES
##########################################
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
    """
    Re-scan the originally stored directory (scan_directory) for this case,
    so that we're not hardcoding "." or losing the original path.
    """
    case_name = request.form.get("case_name", "").strip()
    if not case_name:
        flash("Missing case_name in form!", "error")
        return redirect(url_for("index"))

    # Retrieve the stored directory
    target_dir = get_scan_directory(case_name)
    if not target_dir:
        flash(f"No directory stored for case '{case_name}'. Can't re-scan!", "error")
        return redirect(url_for("index"))

    # Re-scan using the original directory
    run_semgrep_script(case_name, target_dir)
    remove_old_and_skip_duplicates(case_name)
    ensure_case_row_exists(case_name)

    flash(f"Re-scan completed for '{case_name}' using '{target_dir}'.", "success")
    return redirect(url_for("load_case", case_name=case_name))

def find_root_directory(paths):
    if not paths:
        return ""
    common = os.path.dirname(os.path.commonprefix([p.split(os.sep) for p in paths]))
    return common if common else "."


# Find deepest common directory from relative paths
def find_common_directory(paths):
    if not paths:
        print("No relative paths?")
        return ""
    split_paths = [p.split(os.sep) for p in paths]
    common = os.path.commonprefix(split_paths)
    return os.sep.join(common[:-1]) if len(common) > 0 else ""


@app.route("/scan_new_directory", methods=["POST"])
def scan_new_directory():
    """
    1) Create a case directory using the provided case name,
    2) Save all uploaded files into this directory while preserving their structure,
    3) Use the absolute path of this directory for the scan.
    """
    new_case_name = request.form.get("new_case_name", "").strip()
    file_list = request.files.getlist("new_target_path")

    if not new_case_name:
        flash("Please provide a case name.", "error")
        return redirect(url_for("index"))
    if not file_list or len(file_list) == 0:
        flash("Please select a directory to scan.", "error")
        return redirect(url_for("index"))

    # Create a directory for the new case
    upload_folder = app.config.get('UPLOAD_FOLDER', os.getcwd())  # Ensure UPLOAD_FOLDER is configured in your app
    case_dir = os.path.join(upload_folder, new_case_name)

    try:
        os.makedirs(case_dir, exist_ok=True)
    except OSError:
        flash("Failed to create case directory.", "error")
        return redirect(url_for("index"))

    # Save uploaded files preserving their relative paths
    for file in file_list:
        if file.filename:
            # Prevent path traversal attacks and ensure safe path
            safe_filename = os.path.join(case_dir, file.filename)
            safe_dir = os.path.dirname(safe_filename)

            # Ensure the directory exists
            os.makedirs(safe_dir, exist_ok=True)

            # Save the file
            file.save(safe_filename)

    # Now use the absolute path of the case directory for scanning
    abs_dir = os.path.abspath(case_dir)

    # Ensure the case row is present
    ensure_case_row_exists(new_case_name)

    # Run Semgrep on that directory
    run_semgrep_script(new_case_name, abs_dir)
    remove_old_and_skip_duplicates(new_case_name)

    # Store the directory used in the DB for re-scans (only if scan_directory is still NULL)
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE semgrep_results
               SET scan_directory=?
             WHERE scan_name=?
               AND (scan_directory IS NULL OR scan_directory='')
        """, (abs_dir, new_case_name))
        conn.commit()

    flash(f"Scanned directory '{abs_dir}' into case '{new_case_name}'.", "success")
    return redirect(url_for("index"))


@app.route("/clear_db", methods=["POST"])
def do_clear_db():
    clear_database()
    flash("Database cleared.", "success")
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


##########################################
# FIXING VULNERABILITIES ROUTES (Optional)
##########################################
@app.route("/fix_vulnerability", methods=["POST"])
def fix_vulnerability():
    vuln_id = request.form.get("vuln_id")
    case_name = request.form.get("case_name")
    if not vuln_id or not case_name:
        flash("Missing vulnerability ID or case name.", "error")
        return redirect(url_for("index"))

    result = fix_single_vulnerability(int(vuln_id))
    remove_old_and_skip_duplicates(case_name)
    ensure_case_row_exists(case_name)

    flash(f"Fix single vulnerability result: {result}", "info")
    return redirect(url_for("load_case", case_name=case_name))


@app.route("/fix_all_vulnerabilities", methods=["POST"])
def fix_all_vulnerabilities():
    case_name = request.form.get("case_name")
    if not case_name:
        flash("Missing case name.", "error")
        return redirect(url_for("index"))

    result = fix_all_in_case(case_name)
    remove_old_and_skip_duplicates(case_name)
    ensure_case_row_exists(case_name)

    flash(f"Fix all vulnerabilities result: {result}", "info")
    return redirect(url_for("load_case", case_name=case_name))


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        open(DATABASE, "w").close()
    create_main_table()
    app.run(debug=True)
