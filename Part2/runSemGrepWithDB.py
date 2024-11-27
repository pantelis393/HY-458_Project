import subprocess
import json
import yaml
import argparse
import sqlite3


def create_database(db_file="semgrep_results.db", reset=False):
    """
    Create the SQLite database and table if they don't exist.
    Optionally, reset the database by deleting all existing entries.

    Args:
        db_file (str): Path to the SQLite database file.
        reset (bool): If True, delete all existing entries in the table.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Create the table for Semgrep results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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

    # Reset the table if the flag is set
    if reset:
        cursor.execute("DELETE FROM semgrep_results")
        print("Database reset: All existing entries deleted.")

    conn.commit()
    conn.close()


def save_to_database(findings, db_file="semgrep_results.db"):
    """
    Save Semgrep findings into the SQLite database.

    Args:
        findings (list): List of Semgrep findings.
        db_file (str): Path to the SQLite database file.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    for finding in findings:
        cursor.execute("""
            INSERT INTO semgrep_results (
                file_path, line_start, line_end, column_start, column_end, 
                check_id, message, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
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


def run_semgrep(rule_file: str, target: str) -> list:
    """
    Run Semgrep on a target file/directory with a specific rule file.

    Args:
        rule_file (str): Path to the Semgrep rule file (YAML). If None, use default hardcoded rules.
        target (str): Path to the target file or directory to scan.

    Returns:
        list: Parsed findings from Semgrep in JSON format.
    """
    try:
        if rule_file:
            # Execute Semgrep with the provided rule file
            result = subprocess.run(
                ["semgrep", "--config", rule_file, target, "--json"],
                capture_output=True,
                text=True,
                check=True
            )
        else:
            # Use hardcoded default rules
            default_rule_content = """
rules:
  - id: example-rule
    patterns:
      - pattern: $X == $X
    message: "Possible redundant comparison"
    severity: INFO
            """
            # Execute Semgrep with rules from stdin
            result = subprocess.run(
                ["semgrep", "--config", "-", target, "--json"],
                input=default_rule_content,
                capture_output=True,
                text=True,
                check=True
            )
        # Parse JSON output
        findings = json.loads(result.stdout)

        # Save the raw Semgrep output as a YAML file
        with open("semgrep_results.yaml", "w") as f:
            yaml.dump(findings, f, default_flow_style=False)

        return findings.get("results", [])
    except subprocess.CalledProcessError as e:
        print(f"Error running Semgrep: {e.stderr}")
        return []


def display_findings(findings: list):
    """
    Display findings in a readable format.

    Args:
        findings (list): List of Semgrep findings.
    """
    if not findings:
        print("No vulnerabilities found!")
        return

    print("\nVulnerabilities Detected:\n")
    for finding in findings:
        file_path = finding.get('path', 'Unknown file')
        line = finding.get('start', {}).get('line', 'Unknown line')
        message = finding.get('extra', {}).get('message', 'No specific message found.')
        print(f"- File: {file_path}, Line: {line}")
        print(f"  Message: {message}")


if __name__ == "__main__":
    # Define default rule file and target file/directory
    default_rule_file = "rules.yaml"
    default_target = "../Part2"
    default_reset_db = False

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run Semgrep with specified rules and target.')
    parser.add_argument('--rules', help='Path to the Semgrep rule file (YAML).')
    parser.add_argument('--target', help='Path to the target file or directory to scan.')
    parser.add_argument('--db', help='Path to the SQLite database file.', default="semgrep_results.db")
    parser.add_argument('--reset-db', help='Reset the database by deleting all existing entries.', action='store_true', default=default_reset_db)

    args = parser.parse_args()

    rule_file = args.rules if args.rules else default_rule_file
    target = args.target if args.target else default_target
    db_file = args.db
    reset_db = args.reset_db

    # Create the database and optionally reset it
    create_database(db_file, reset=reset_db)

    # Run Semgrep and display results
    findings = run_semgrep(rule_file, target)
    display_findings(findings)

    # Save findings to the database
    save_to_database(findings, db_file)
    print(f"Results saved to database: {db_file}")
