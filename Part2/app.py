from flask import Flask, render_template, request
import sqlite3
import os

app = Flask(__name__)

def get_unique_root_folders():
    """
    Get a list of unique root folders from the file paths in the database.
    """
    conn = sqlite3.connect("semgrep_results.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT file_path FROM semgrep_results")
    file_paths = [row[0] for row in cursor.fetchall()]
    conn.close()
    root_folders = {os.path.dirname(path).split(os.sep)[0] for path in file_paths}
    return sorted(root_folders)

def get_files_in_folder(folder):
    """
    Get a list of files within a specific root folder.
    """
    conn = sqlite3.connect("semgrep_results.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT file_path FROM semgrep_results WHERE file_path LIKE ?", (f"{folder}%",))
    files = [row[0] for row in cursor.fetchall()]
    conn.close()
    return files

def get_results_by_file(file_path):
    """
    Get Semgrep results for a specific file path from the database.
    Map severities to 'Low', 'Medium', and 'High' for user-friendly display.
    """
    severity_mapping = {
        "info": "Low",
        "warning": "Medium",
        "error": "High"
    }
    conn = sqlite3.connect("semgrep_results.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_path, line_start, message, severity 
        FROM semgrep_results 
        WHERE file_path = ?
        ORDER BY severity DESC, line_start
    """, (file_path,))
    results = cursor.fetchall()
    conn.close()
    # Apply severity mapping
    results = [(row[0], row[1], row[2], severity_mapping.get(row[3].lower(), row[3])) for row in results]
    return results

@app.route("/")
def index():
    root_folders = get_unique_root_folders()
    return render_template("index.html", root_folders=root_folders)

@app.route("/results", methods=["GET"])
def results():
    folder = request.args.get("folder")
    files = get_files_in_folder(folder)
    return render_template("results.html", folder=folder, files=files)

@app.route("/details", methods=["GET"])
def details():
    file_path = request.args.get("file_path")
    results = get_results_by_file(file_path)
    return render_template("details.html", file_path=file_path, results=results)

if __name__ == "__main__":
    app.run(debug=True)
