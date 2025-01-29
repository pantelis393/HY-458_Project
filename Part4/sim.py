import os
import json
import sqlite3
from collections import defaultdict

DB_PATH = "../Part2/semgrep_results.db"  # Adjust if needed

class CryptoAgilitySimulator:
    def __init__(self):
        self.cryptosystems = {}  # Loaded from config
        self.stats = {
            "vulnerable_files": defaultdict(int),
            "fixed_files": 0,
            "pending_manual_fixes": 0
        }

    def load_config(self, config_file):
        """
        Load vulnerabilities and their replacements from a JSON config file
        keyed by rule ID. Example:
        {
          "detect-md5": {
            "algorithm": "MD5",
            "status": "vulnerable",
            "replacement": "SHA-256"
          },
          "detect-sha1": {
            "algorithm": "SHA1",
            "status": "vulnerable",
            "replacement": "SHA-256"
          },
          ...
        }
        """
        try:
            with open(config_file, "r") as f:
                self.cryptosystems = json.load(f)
            print(f"Loaded vulnerability configurations from '{config_file}'")
        except FileNotFoundError:
            print(f"Error: Config file '{config_file}' not found.")
            self.cryptosystems = {}

    def scan_target_folder(self, target):
        """
        OPTIONAL: Runs Semgrep on the target folder and saves the findings
        in the 'semgrep_results' table with a user-provided scan_name.
        """
        print(f"Scanning target folder: {target}")
        os.system(f"python3 runSemGrepWithDB.py --target {target}")
        print("Scan completed. Findings saved to the database.")

    def retrieve_findings(self, scan_name):
        """
        Query the semgrep_results table for rows matching the scan_name.
        For each row:
          - We look up the rule ID in self.cryptosystems to get the
            'algorithm', 'status', and 'replacement'.
          - We store them in a list of dictionaries (findings).
        """
        findings = []
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT file_path, check_id
                FROM semgrep_results
                WHERE scan_name = ?
            """, (scan_name,))

            rows = cursor.fetchall()
            for (file_path, rule_id) in rows:
                # Look up details in the config by rule_id
                config_entry = self.cryptosystems.get(rule_id, {})
                algorithm = config_entry.get("algorithm", None)
                status = config_entry.get("status", None)
                replacement = config_entry.get("replacement", None)

                # We'll store one "algorithm" per finding
                # If the rule isn't in the config, algorithm might be None
                findings.append({
                    "file": file_path,
                    "rule_id": rule_id,
                    "algorithm": algorithm,      # e.g., "MD5"
                    "status": status,            # e.g., "vulnerable" or "secure"
                    "replacement": replacement   # e.g., "SHA-256"
                })

        except sqlite3.OperationalError as e:
            print(f"Error retrieving findings: {e}")
        finally:
            conn.close()

        return findings

    def assess_vulnerabilities(self, findings):
        """
        Go through each finding. If 'status' == "vulnerable", mark it
        and record the file extension stats.
        Returns a list of vulnerable files for further processing.
        """
        vulnerable_files = []
        for finding in findings:
            if finding["status"] == "vulnerable":
                # Mark it as vulnerable
                file_ext = os.path.splitext(finding["file"])[1].lower()
                self.stats["vulnerable_files"][file_ext] += 1

                vulnerable_files.append(finding)

        return vulnerable_files

    def fix_vulnerabilities(self, vulnerable_files):
        """
        For each vulnerable finding:
          - If there's a 'replacement', we increment 'fixed_files'.
          - Otherwise, increment 'pending_manual_fixes'.
        """
        for finding in vulnerable_files:
            if finding["replacement"]:
                # We can "fix" it automatically
                self.stats["fixed_files"] += 1
                # You could store the new algorithm name in finding["algorithm"] if you like
                finding["algorithm"] = finding["replacement"]
            else:
                # No replacement => manual fix needed
                self.stats["pending_manual_fixes"] += 1

    def generate_report(self):
        """
        Dump a JSON report about how many were vulnerable, how many fixed, etc.
        """
        report = {
            "total_vulnerable_files": sum(self.stats["vulnerable_files"].values()),
            "vulnerable_files_by_extension": dict(self.stats["vulnerable_files"]),
            "fixed_files": self.stats["fixed_files"],
            "pending_manual_fixes": self.stats["pending_manual_fixes"],
        }
        with open("crypto_agility_report.json", "w") as f:
            json.dump(report, f, indent=4)
        print("Report saved as 'crypto_agility_report.json'.")

    def display_stats(self):
        """
        Print a summary to the console.
        """
        print("--- Crypto Agility Simulator Stats ---")
        total_vuln = sum(self.stats["vulnerable_files"].values())
        print(f"Total vulnerable files: {total_vuln}")
        print("Vulnerable files by extension:")
        for ext, count in self.stats["vulnerable_files"].items():
            print(f"  {ext}: {count}")
        print(f"Files fixed: {self.stats['fixed_files']}")
        print(f"Pending manual fixes: {self.stats['pending_manual_fixes']}")

if __name__ == "__main__":
    simulator = CryptoAgilitySimulator()

    # 1. Load your config with rule->algorithm mappings
    simulator.load_config("vulnerabilities_config.json")

    # 2. [Optional] Run Semgrep if you have not saved results yet
    # simulator.scan_target_folder("./some_target")

    # 3. Ask user for the scan name
    scan_name_input = input("Enter the scan name you used: ")

    # 4. Retrieve the findings from the DB
    findings = simulator.retrieve_findings(scan_name_input)
    print(f"Found {len(findings)} findings for scan '{scan_name_input}'.")

    # 5. Assess vulnerabilities
    print("Assessing vulnerabilities...")
    vulnerable_files = simulator.assess_vulnerabilities(findings)

    # 6. Fix vulnerabilities if there's a 'replacement'
    print("Fixing vulnerabilities...")
    simulator.fix_vulnerabilities(vulnerable_files)

    # 7. Generate and display the report
    print("Generating report...")
    simulator.generate_report()

    print("Displaying stats...")
    simulator.display_stats()
