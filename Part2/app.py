from flask import Flask, render_template, request
import sqlite3
import os

app = Flask(__name__)

########################################################
#               HELPER FUNCTIONS / DATABASE            #
########################################################

def get_scans(db_file="semgrep_results.db"):
    """
    Returns all scans (scan_name, scan_date) and how many vulnerabilities in each.
    Ordered by date descending.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_name, scan_date, COUNT(*) as vuln_count
        FROM semgrep_results
        GROUP BY scan_name, scan_date
        ORDER BY scan_date DESC
    """)
    scans = cursor.fetchall()
    conn.close()
    return scans  # (scan_name, scan_date, vuln_count)


def get_unique_root_folders(scan_name, scan_date, db_file="semgrep_results.db"):
    """
    Returns top-level folders for a given scan (based on file paths).
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT file_path
        FROM semgrep_results
        WHERE scan_name = ? AND scan_date = ?
    """, (scan_name, scan_date))
    all_paths = [row[0] for row in cursor.fetchall()]
    conn.close()

    # Extract the first path component as the "root folder"
    root_folders = set()
    for path in all_paths:
        parts = path.split(os.sep)
        if parts:
            root_folders.add(parts[0])
    return sorted(root_folders)


def get_files_in_folder(scan_name, scan_date, folder, db_file="semgrep_results.db"):
    """
    Returns all file paths in 'folder' for the chosen scan.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Use a LIKE pattern that matches the folder as the leading path.
    query_pattern = folder + "%"
    cursor.execute("""
        SELECT DISTINCT file_path
        FROM semgrep_results
        WHERE scan_name = ?
          AND scan_date = ?
          AND file_path LIKE ?
    """, (scan_name, scan_date, query_pattern))
    files = [row[0] for row in cursor.fetchall()]
    conn.close()
    return sorted(files)


def get_results_by_file(scan_name, scan_date, file_path, db_file="semgrep_results.db"):
    """
    Returns a list of vulnerabilities for the given file in the chosen scan.
    Also maps severity to a user-friendly string (Low, Medium, High).
    """
    severity_mapping = {
        "info": "Low",
        "warning": "Medium",
        "error": "High"
    }

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_path, line_start, message, severity
        FROM semgrep_results
        WHERE scan_name = ?
          AND scan_date = ?
          AND file_path = ?
        ORDER BY severity DESC, line_start
    """, (scan_name, scan_date, file_path))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for (fp, line_start, message, severity) in rows:
        mapped_sev = severity_mapping.get(severity.lower(), severity)
        results.append((fp, line_start, message, mapped_sev))
    return results


def get_total_vulns_for_scan(scan_name, scan_date, db_file="semgrep_results.db"):
    """
    Return how many vulnerabilities are in a given scan.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*)
        FROM semgrep_results
        WHERE scan_name = ?
          AND scan_date = ?
    """, (scan_name, scan_date))
    count = cursor.fetchone()[0]
    conn.close()
    return count


########################################################
#                     FLASK ROUTES                     #
########################################################

@app.route("/")
def index():
    """
    Index page: List all scans with total vulnerability counts.
    Display the total number of scans at the top.
    """
    scans = get_scans()
    total_scans = len(scans)
    return render_template("index.html", scans=scans, total_scans=total_scans)


@app.route("/scan")
def scan():
    """
    Show top-level folders for the chosen scan, and total vulnerabilities.
    """
    scan_name = request.args.get("scan_name")
    scan_date = request.args.get("scan_date")

    root_folders = get_unique_root_folders(scan_name, scan_date)
    total_vulns = get_total_vulns_for_scan(scan_name, scan_date)

    return render_template("scan.html",
                           scan_name=scan_name,
                           scan_date=scan_date,
                           root_folders=root_folders,
                           total_vulns=total_vulns)


@app.route("/results")
def results():
    """
    Show all files within a particular folder for the chosen scan.
    """
    scan_name = request.args.get("scan_name")
    scan_date = request.args.get("scan_date")
    folder = request.args.get("folder")

    files = get_files_in_folder(scan_name, scan_date, folder)
    return render_template("results.html",
                           scan_name=scan_name,
                           scan_date=scan_date,
                           folder=folder,
                           files=files)


@app.route("/details")
def details():
    """
    Show vulnerabilities for a particular file (line, message, severity).
    """
    scan_name = request.args.get("scan_name")
    scan_date = request.args.get("scan_date")
    file_path = request.args.get("file_path")

    results = get_results_by_file(scan_name, scan_date, file_path)
    return render_template("details.html",
                           scan_name=scan_name,
                           scan_date=scan_date,
                           file_path=file_path,
                           results=results)


##########################################
# OPTIONAL: Debug route to view raw data #
##########################################
@app.route("/debug_db")
def debug_db():
    """
    Debug route: Shows all rows of the table.
    NOTE: Use carefully; it's not production safe.
    """
    conn = sqlite3.connect("semgrep_results.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM semgrep_results")
    rows = cursor.fetchall()
    conn.close()
    return f"<pre>{rows}</pre>"


if __name__ == "__main__":
    app.run(debug=True)
