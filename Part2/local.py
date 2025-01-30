#!/usr/bin/env python3
"""
A local Tkinter GUI to scan code with Semgrep, store results in an SQLite DB,
and optionally fix vulnerabilities. Runs on Linux, Windows, or macOS (where
Python + Tkinter + Semgrep are installed).

Usage:
  python local_semgrep_gui.py

Dependencies:
  - Python 3.x
  - Tkinter (usually included by default on Windows; on Linux, install via:
      sudo apt-get install python3-tk
  - semgrep (pip install semgrep)
  - sqlite3 (standard library)
  - PyYAML (optional) if you want to store raw semgrep results as YAML
"""

import os
import sqlite3
import subprocess
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# ----------------------------------------------------------------------
# DATABASE / SCAN LOGIC
# ----------------------------------------------------------------------

DB_FILE = "semgrep_results.db"

def get_connection():
    return sqlite3.connect(DB_FILE)

def create_main_table():
    """
    Creates the main table if it doesn't exist for storing semgrep results.
    Also attempts to add a 'scan_directory' column if it isn't present yet.
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
                check_id TEXT,
                message TEXT,
                severity TEXT,
                scan_directory TEXT
            )
        """)
        conn.commit()

def create_database(reset=False):
    """
    If reset=True, drop the table and recreate. Otherwise, just create if absent.
    """
    if reset and os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    create_main_table()

def save_to_database(findings, scan_name, scan_date, scan_directory):
    """
    Insert results from semgrep into the DB, skipping duplicates.
    A duplicate is considered anything with the same:
      - scan_name
      - file_path
      - line_start
      - check_id
    """
    conn = get_connection()
    c = conn.cursor()
    for f in findings:
        file_path = f.get("path")
        start_line = f.get("start", {}).get("line")
        end_line = f.get("end", {}).get("line")
        check_id = f.get("check_id")
        message = f.get("extra", {}).get("message")
        severity = f.get("extra", {}).get("severity")

        # Skip duplicates
        c.execute("""
            SELECT 1 FROM semgrep_results
             WHERE scan_name=?
               AND file_path=?
               AND line_start=?
               AND check_id=?
            LIMIT 1
        """, (scan_name, file_path, start_line, check_id))
        existing = c.fetchone()
        if existing:
            continue

        c.execute("""
            INSERT INTO semgrep_results (
                scan_name, scan_date, file_path, line_start, line_end,
                check_id, message, severity, scan_directory
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_name, scan_date, file_path, start_line, end_line,
              check_id, message, severity, scan_directory))

    conn.commit()
    conn.close()

def remove_old_and_skip_duplicates(scan_name):
    """
    OPTIONAL: If you want to remove older duplicates in the database, keep only
    the latest scan_date for each unique (file_path, line_start, check_id).
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

    # Group them
    from collections import defaultdict
    sig_map = defaultdict(list)
    # track each row's date
    row_info = {}
    for (rid, fpath, lstart, cid, sdate) in rows:
        sig_map[(fpath, lstart, cid)].append(rid)
        row_info[rid] = sdate

    # For each signature, keep only the row(s) with the newest date, remove older
    # If multiple with the exact same date, keep 1, remove the rest
    to_remove = []
    for sig, rid_list in sig_map.items():
        # find the max date
        max_date = None
        for row_id in rid_list:
            dt = row_info[row_id]
            if dt and (not max_date or dt > max_date):
                max_date = dt
        # collect all that are older or not the first in the newest group
        newest_ids = [r for r in rid_list if row_info[r] == max_date]
        if len(newest_ids) > 1:
            # sort them so we keep the smallest ID, remove the rest
            newest_ids.sort()
            to_keep = newest_ids[0]
            to_remove.extend(newest_ids[1:])
        # remove all that are older date
        older_ids = [r for r in rid_list if row_info[r] != max_date]
        to_remove.extend(older_ids)

    if to_remove:
        qmarks = ",".join(str(x) for x in to_remove)
        c.execute(f"DELETE FROM semgrep_results WHERE id IN ({qmarks})")
        conn.commit()

    conn.close()

def run_semgrep(scan_name, target_folder):
    """
    Actually run semgrep on target_folder using 'rules.yaml'. You must have
    semgrep installed. This function returns a list of findings (dictionaries).
    """
    # Customize if you have a different rules file
    RULES_FILE = "rules.yaml"
    if not os.path.exists(RULES_FILE):
        messagebox.showerror("Error", f"Rules file '{RULES_FILE}' not found.")
        return []

    try:
        # call semgrep CLI, output JSON
        proc = subprocess.run(
            ["semgrep", "--config", RULES_FILE, target_folder, "--json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(proc.stdout)
        return data.get("results", [])
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error running semgrep", e.stderr)
        return []

# ----------------------------------------------------------------------
# VULNERABILITY FIXING LOGIC
# ----------------------------------------------------------------------

def load_fix_snippets():
    """
    Hardcode or load from a 'fixes.yaml' file any fix snippets if you want them.
    For demonstration, we put a few examples in a dictionary:
    """
    return {
        "detect-md5": "hashlib.sha256($DATA)",
        "detect-sha1": "hashlib.sha256($DATA)",
        # ...
    }

def fix_single_vulnerability(vuln_id):
    """
    Example fix logic: Replaces the line in the file with something from a snippet.
    Real code would parse the snippet, maybe do AST transformations, etc.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, scan_name, file_path, line_start, check_id, message
          FROM semgrep_results
         WHERE id=?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {"status": "ERROR", "details": f"No vulnerability with ID {vuln_id}"}

    _, scan_name, file_path, line_start, check_id, message = row
    if not os.path.isfile(file_path):
        return {"status": "ERROR", "details": f"File not found: {file_path}"}

    # pretend we have a snippet
    fix_snippets = load_fix_snippets()
    snippet = fix_snippets.get(check_id, "")
    if not snippet:
        return {"status": "SUGGESTED", "details": "No snippet available."}

    # naive line-based fix:
    with open(file_path, "r") as f:
        lines = f.readlines()

    idx = line_start - 1
    if idx < 0 or idx >= len(lines):
        return {"status": "ERROR", "details": "Line out of range."}

    # For demonstration, just replace that entire line with snippet
    lines[idx] = "# FIX APPLIED: " + snippet + "\n"

    with open(file_path, "w") as f:
        f.writelines(lines)

    # success
    # Optionally re-run semgrep or remove the old row from DB
    return {"status": "OK", "details": "Fix applied."}

def fix_all_in_case(case_name):
    """
    Fix everything in the DB for this case. We do a simple loop calling fix_single_vulnerability.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM semgrep_results WHERE scan_name=?", (case_name,))
    vuln_ids = [r[0] for r in c.fetchall()]
    conn.close()

    results = []
    for vid in vuln_ids:
        r = fix_single_vulnerability(vid)
        results.append((vid, r))

    return results

# ----------------------------------------------------------------------
# TKINTER GUI
# ----------------------------------------------------------------------

class LocalSemgrepGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Local Semgrep GUI")
        self.geometry("900x600")

        # Case name
        frm_top = tk.Frame(self)
        frm_top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        tk.Label(frm_top, text="Case Name:").pack(side=tk.LEFT)
        self.entry_case = tk.Entry(frm_top, width=20)
        self.entry_case.pack(side=tk.LEFT, padx=5)

        tk.Button(frm_top, text="Scan Folder", command=self.scan_folder).pack(side=tk.LEFT, padx=5)
        tk.Button(frm_top, text="Load Vulns for Case", command=self.load_vulnerabilities).pack(side=tk.LEFT, padx=5)
        tk.Button(frm_top, text="Fix All in Case", command=self.fix_all_in_case).pack(side=tk.LEFT, padx=5)

        # Treeview for vulnerabilities
        frm_tree = tk.Frame(self)
        frm_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

        columns = ("ID", "File Path", "Line", "Check ID", "Severity")
        self.tree = ttk.Treeview(frm_tree, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100 if col=="ID" else 200)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(frm_tree, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Bottom frame: fix single vulnerability
        frm_bottom = tk.Frame(self)
        frm_bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        tk.Button(frm_bottom, text="Fix Selected Vulnerability", command=self.fix_selected_vuln).pack(side=tk.LEFT)

        # On start, create DB if not exist
        create_main_table()

    def scan_folder(self):
        """
        1) Asks user for a folder on local machine
        2) Runs semgrep, saves results to DB
        3) Remove older duplicates
        """
        case_name = self.entry_case.get().strip()
        if not case_name:
            messagebox.showerror("Error", "Please enter a Case Name first.")
            return

        folder = filedialog.askdirectory()
        if not folder:
            return  # user canceled

        # 1) Run semgrep
        findings = run_semgrep(case_name, folder)
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 2) Save to DB
        save_to_database(findings, case_name, scan_date, folder)

        # 3) Optionally remove older duplicates
        remove_old_and_skip_duplicates(case_name)

        # 4) confirm
        messagebox.showinfo("Scan Complete", f"Scanned folder:\n{folder}\nFound {len(findings)} items.")
        self.load_vulnerabilities()

    def load_vulnerabilities(self):
        """
        Load vulnerabilities from DB for the typed Case Name.
        """
        case_name = self.entry_case.get().strip()
        if not case_name:
            messagebox.showerror("Error", "Please enter a Case Name.")
            return

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, file_path, line_start, check_id, severity
              FROM semgrep_results
             WHERE scan_name=?
        """, (case_name,))
        rows = c.fetchall()
        conn.close()

        # Clear current tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new rows
        for row in rows:
            rid, fpath, lstart, cid, sev = row
            self.tree.insert("", tk.END, values=(rid, fpath, lstart, cid, sev))

    def fix_selected_vuln(self):
        """
        Get currently selected row's ID, call fix_single_vulnerability on it.
        Then reload.
        """
        selection = self.tree.selection()
        if not selection:
            messagebox.showerror("Error", "No row selected.")
            return

        item_id = selection[0]
        vals = self.tree.item(item_id, "values")
        vuln_id = vals[0]  # the ID is in the first column

        try:
            vuln_id_int = int(vuln_id)
        except:
            messagebox.showerror("Error", f"Invalid ID: {vuln_id}")
            return

        result = fix_single_vulnerability(vuln_id_int)
        if result["status"] == "OK":
            messagebox.showinfo("Fix Result", f"Fixed ID {vuln_id_int} successfully.")
            # optionally re-run semgrep or remove the row from DB
            # for demonstration, let's just remove the row from the DB:
            self.remove_vuln_db(vuln_id_int)
            self.load_vulnerabilities()
        else:
            messagebox.showinfo("Fix Result", f"Status: {result['status']}\n{result['details']}")

    def remove_vuln_db(self, vuln_id_int):
        conn = get_connection()
        c = conn.cursor()
        c.execute("DELETE FROM semgrep_results WHERE id=?", (vuln_id_int,))
        conn.commit()
        conn.close()

    def fix_all_in_case(self):
        """
        Fix all vulnerabilities for the typed case name.
        Then refresh the table.
        """
        case_name = self.entry_case.get().strip()
        if not case_name:
            messagebox.showerror("Error", "Please enter a Case Name.")
            return

        results = fix_all_in_case(case_name)
        # results is a list of (vuln_id, fix_result_dict)
        # For demonstration, let's remove them all from DB if fix status is 'OK'
        conn = get_connection()
        c = conn.cursor()
        removed_count = 0
        for (vid, res) in results:
            if res["status"] == "OK":
                c.execute("DELETE FROM semgrep_results WHERE id=?", (vid,))
                removed_count += 1
        conn.commit()
        conn.close()

        messagebox.showinfo("Fix All", f"Fixed {removed_count} vulnerabilities in case '{case_name}'!")
        self.load_vulnerabilities()

# ----------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------

if __name__ == "__main__":
    app = LocalSemgrepGUI()
    app.mainloop()
