import subprocess
import json
import yaml
import argparse
import sqlite3
import os
import logging
from collections import defaultdict
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)


def create_database(db_file="semgrep_results.db", reset=False):
    """
    Create or recreate the SQLite database and table for Semgrep results.
    If 'reset' is True, the existing table (if any) is dropped.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    if reset:
        cursor.execute("DROP TABLE IF EXISTS semgrep_results")
        logging.info("Database reset: Table dropped.")

    # Create the table for Semgrep results (with scan_name and scan_date)
    cursor.execute("""
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

    # Create indexes for better query performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON semgrep_results(file_path)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON semgrep_results(severity)")

    conn.commit()
    conn.close()


def save_to_database(findings, db_file, scan_name, scan_date):
    """
    Save Semgrep findings into the SQLite database with a given scan name and date.

    Args:
        findings (list): List of Semgrep findings (dicts).
        db_file (str): Path to the SQLite database file.
        scan_name (str): User-specified name for this scan.
        scan_date (str): Timestamp for when this scan occurred.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    for finding in findings:
        cursor.execute("""
            INSERT INTO semgrep_results (
                scan_name,
                scan_date,
                file_path,
                line_start,
                line_end,
                column_start,
                column_end,
                check_id,
                message,
                severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_name,
            scan_date,
            finding.get("path"),
            finding.get("start", {}).get("line"),
            finding.get("end", {}).get("line"),
            finding.get("start", {}).get("col"),
            finding.get("end", {}).get("col"),
            finding.get("check_id"),
            finding.get("extra", {}).get("message"),
            finding.get("extra", {}).get("severity")
        ))

    conn.commit()
    conn.close()


def gather_all_files(target_path):
    """
    Recursively collect all files under a target directory (or return
    the file itself if target_path is a single file).

    Args:
        target_path (str): Path to the file or directory.

    Returns:
        list: A list of absolute file paths.
    """
    all_files = []
    target_path = os.path.abspath(target_path)

    if os.path.isfile(target_path):
        # If it's a single file, just return it
        all_files.append(target_path)
    else:
        # Recursively walk the directory and add all files
        for root, dirs, files in os.walk(target_path):
            for fname in files:
                full_path = os.path.join(root, fname)
                all_files.append(os.path.abspath(full_path))

    return all_files


def run_semgrep(rule_file: str, target: str) -> list:
    """
    Run Semgrep on a target file/directory with a specific rule file.
    """
    if not os.path.exists(rule_file):
        logging.error(f"Rule file not found: {rule_file}")
        exit(1)

    try:
        # Run Semgrep and capture JSON output
        result = subprocess.run(
            ["semgrep", "--config", rule_file, target, "--json"],
            capture_output=True,
            text=True,
            check=True
        )

        findings = json.loads(result.stdout)

        # Save the raw Semgrep output as a YAML file for reference
        with open("semgrep_results.yaml", "w") as f:
            yaml.dump(findings, f, default_flow_style=False)

        return findings.get("results", [])
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Semgrep: {e.stderr}")
        return []


def display_findings(findings: list, all_scanned_files: list):
    """
    Display findings in a readable format and list all scanned files.

    Args:
        findings (list): List of Semgrep findings.
        all_scanned_files (list): The full list of files that were scanned.
    """
    all_scanned_files = set(all_scanned_files)
    file_stats = defaultdict(lambda: {"total": 0, "vulnerable": 0})
    vulnerable_files = set()

    # Populate total files scanned per "language" (basic guess by extension)
    for file_path in all_scanned_files:
        language = get_language_from_extension(file_path)
        file_stats[language]["total"] += 1

    # Print each finding
    for finding in findings:
        file_path = finding.get('path', 'Unknown file')
        line = finding.get('start', {}).get('line', 'Unknown line')
        message = finding.get('extra', {}).get('message', 'No specific message found.')
        logging.info(f"- File: {file_path}, Line: {line}\n  Message: {message}")
        vulnerable_files.add(file_path)

    # Count vulnerable files per language
    for file_path in vulnerable_files:
        language = get_language_from_extension(file_path)
        file_stats[language]["vulnerable"] += 1

    # Print scan statistics
    logging.info("\nScan Statistics:\n")
    for lang, stats in file_stats.items():
        logging.info(f"- {lang}: {stats['vulnerable']} vulnerable files out of {stats['total']} scanned")

    # Categorize and print all scanned files by language
    categorized_files = defaultdict(list)
    for file_path in all_scanned_files:
        language = get_language_from_extension(file_path)
        categorized_files[language].append(file_path)

    logging.info("\nScanned Files by Category:\n")
    for lang, files in categorized_files.items():
        logging.info(f"{lang} Files:")
        for file_path in files:
            marker = " (vulnerable)" if file_path in vulnerable_files else ""
            logging.info(f"  - {file_path}{marker}")


def get_language_from_extension(file_path):
    """
    Determine the programming language based on file extension.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: The guessed programming language.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.py':
        return 'Python'
    elif ext == '.java':
        return 'Java'
    elif ext in ['.c', '.h']:
        return 'C'
    else:
        return 'Unknown'


if __name__ == "__main__":
    # Define default rule file and target
    default_rule_file = "rules.yaml"
    default_target = "Vulnerable_Code"

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run Semgrep with specified rules and target.')
    parser.add_argument('--rules', help='Path to the Semgrep rule file (YAML).')
    parser.add_argument('--target', help='Path to the target file or directory to scan.')
    parser.add_argument('--db', help='Path to the SQLite database file.', default="semgrep_results.db")
    parser.add_argument('--reset-db', help='Reset the database by dropping and recreating the table.', action='store_true')

    args = parser.parse_args()

    rule_file = args.rules if args.rules else default_rule_file
    target = args.target if args.target else default_target
    db_file = args.db
    reset_db = args.reset_db

    # Create/reset the database if needed
    create_database(db_file, reset=reset_db)

    # Prompt the user for a scan name
    scan_name = input("Enter a name for this scan: ").strip()
    if not scan_name:
        scan_name = "Unnamed_Scan"

    # Generate a timestamp for this scan
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Gather all files in the target
    all_files = gather_all_files(target)

    # Run Semgrep
    findings = run_semgrep(rule_file, target)

    # Display results in the console
    display_findings(findings, all_files)

    # Save findings to the database with the given name/date
    save_to_database(findings, db_file, scan_name, scan_date)
    logging.info(f"Results saved to database: {db_file} (scan: '{scan_name}', date: {scan_date})")
