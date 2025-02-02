#!/usr/bin/env python3
"""
Directory Vulnerability Scanner with Hardcoded Rules

This script:
  - Uses embedded Semgrep‑style rules (with wildcards, metavariables,
    pattern-inside, and pattern-where-python conditions) hardcoded into the script.
  - Recursively scans a target directory (or single file) for vulnerabilities.
  - Produces a detailed report (file, line, rule id, severity, message).
  - Prints a scan summary by language along with a list of vulnerable filenames per language.
  - Optionally saves results to an SQLite database if --db is provided.
  - Optionally can run an external Semgrep scan (via --external) instead of the internal engine.

Usage examples:
  # Use the internal scanning engine (embedded rules):
  python3 custom_parser.py --target /path/to/your/code

  # Use external Semgrep with your own rules file:
  python3 custom_parser.py --target /path/to/your/code --rules /path/to/semgrep_rules.yaml --external

  # Save results into a database (and reset the table if desired):
  python3 custom_parser.py --target /path/to/your/code --db vuln_results.db --reset-db
"""

import os
import re
import sys
import argparse
import sqlite3
import logging
import yaml
import json
import subprocess
from collections import defaultdict
from datetime import datetime

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# --- Database Functions ---
def create_database(db_file, reset=False):
    """Create (or reset) the SQLite database and table for scan results."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    if reset:
        cursor.execute("DROP TABLE IF EXISTS semgrep_results")
        logging.info("Database reset: Existing table dropped.")
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
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON semgrep_results(file_path)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON semgrep_results(severity)")
    conn.commit()
    conn.close()


def save_to_database(findings, db_file, scan_name, scan_date):
    """
    Save scan findings into the SQLite database while skipping duplicates.
    Each finding is stored with its scan name and date.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    for finding in findings:
        file_path = finding.get("path")
        line_start = finding.get("start", {}).get("line")
        line_end = finding.get("end", {}).get("line")
        col_start = finding.get("start", {}).get("col", 0)
        col_end = finding.get("end", {}).get("col", 0)
        check_id = finding.get("check_id")
        message = finding.get("extra", {}).get("message")
        severity = finding.get("extra", {}).get("severity")
        cursor.execute("""
            SELECT 1 FROM semgrep_results
             WHERE scan_name=? AND file_path=? AND line_start=? AND check_id=? LIMIT 1
        """, (scan_name, file_path, line_start, check_id))
        if cursor.fetchone():
            continue
        cursor.execute("""
            INSERT INTO semgrep_results (
                scan_name, scan_date, file_path, line_start, line_end,
                column_start, column_end, check_id, message, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_name, scan_date, file_path, line_start, line_end,
              col_start, col_end-1, check_id, message, severity))
    conn.commit()
    conn.close()


# --- File and Language Helpers ---
def gather_all_files(target_path):
    """
    Recursively gather all files under target_path.
    If target_path is a file, return a list with that single file.
    """
    all_files = []
    target_path = os.path.abspath(target_path)
    if os.path.isfile(target_path):
        all_files.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for fname in files:
                full_path = os.path.join(root, fname)
                all_files.append(os.path.abspath(full_path))
    return all_files


def get_language_from_extension(file_path):
    """Naively determine the language based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.py':
        return 'python'
    elif ext == '.java':
        return 'java'
    elif ext in ['.c', '.h']:
        return 'c'
    else:
        return 'unknown'


# --- Pattern Conversion Helper ---
def pattern_to_regex(pattern: str) -> str:
    """
    Convert a Semgrep‑style pattern to a regex.
      - Replace '...' with a non‑greedy wildcard (.*?)
      - Replace metavariables (e.g. $X, $SIZE) with named capturing groups that match digits.
      - Escape all other characters.
    """
    placeholder_wild = "__WILDCARD__"
    pattern = pattern.replace("...", placeholder_wild)

    def replace_metavar(match):
        varname = match.group(0)[1:]
        return f"__VAR_{varname}__"

    pattern = re.sub(r'\$[A-Za-z_]+', replace_metavar, pattern)
    pattern = re.escape(pattern)
    pattern = pattern.replace(re.escape(placeholder_wild), ".*?")
    pattern = re.sub(r'\\s\\\*', lambda m: r'\s*', pattern)

    def revert_metavar(match):
        varname = match.group(1)
        return r"(?P<%s>\d+)" % varname

    pattern = re.sub(r'__VAR_([A-Za-z_]+)__', revert_metavar, pattern)
    return pattern


# --- Embedded Rules ---
def load_embedded_rules():
    """
    Load all hardcoded rules from an embedded YAML string.
    """
    rules_yaml = r"""
rules:
    #RSA-python
  - id: detect-small-rsa
    languages: [python]
    message: "RSA < 2048 bits is insecure. Use ≥2048."
    patterns:
      - pattern: RSA.generate($X)
      - metavariable-comparison:
          metavariable: $X
          comparison: $X.value < 2048
    severity: ERROR

  - id: detect-small-rsa-key-size
    languages: [python]
    message: "RSA < 2048 bits is insecure. Use ≥2048."
    patterns:
      - pattern: rsa.generate_private_key(..., key_size=$X)
      - metavariable-comparison:
          metavariable: $X
          comparison: $X.value < 2048
    severity: ERROR

  # One-way hash functions
  - id: detect-md5
    patterns:
      - pattern: hashlib.md5(...)
    message: "Usage of MD5 is insecure due to collision attacks. Use SHA-256 or SHA-3."
    severity: ERROR
    languages: [python]

  - id: detect-sha1
    patterns:
      - pattern: hashlib.sha1(...)
    message: "SHA-1 is deprecated due to collision attacks. Use SHA-256 or SHA-3."
    severity: WARNING
    languages: [python]

  # Symmetric key cryptography
  - id: detect-des
    patterns:
      - pattern: DES.new(...)
    message: "DES is insecure due to its small key size. Use AES-256."
    severity: ERROR
    languages: [python]

  - id: detect-3des
    patterns:
      - pattern: Crypto.Cipher.DES3.new(...)
    message: "3DES is deprecated due to meet-in-the-middle attacks. Use AES-256."
    severity: ERROR
    languages: [python]

  - id: detect-ecb
    patterns:
      - pattern: Crypto.Cipher.AES.new(..., mode=Crypto.Cipher.AES.MODE_ECB)
    message: "ECB mode leaks data patterns. Use CBC or GCM."
    severity: ERROR
    languages: [python]

  - id: detect-cbc-without-integrity
    patterns:
      - pattern: Crypto.Cipher.AES.new(..., mode=Crypto.Cipher.AES.MODE_CBC)
    message: "CBC without integrity checks is vulnerable. Use GCM."
    severity: WARNING
    languages: [python]

  - id: detect-short-aes
    patterns:
      - pattern: Crypto.Cipher.AES.new(..., key_size=$X)
    message: "AES-128 is quantum-vulnerable. Use AES-256."
    severity: WARNING
    languages: [python]
    pattern-where-python: "isinstance(vars['X'].value, int) and int(vars['X'].value) < 256"

  - id: detect-static-iv
    patterns:
      - pattern: iv = b\"1234567890123456\"
      - pattern-inside: |
          cipher = Crypto.Cipher.AES.new(..., iv=iv)
    message: "Static IVs are insecure. Use randomized IVs."
    severity: ERROR
    languages: [python]

  # RSA key size
  - id: detect-small-rsa
    raw: true
    message: "RSA < 2048 bits is insecure. Use ≥2048."
    severity: ERROR
    languages: [python]
    pattern: RSA\.generate\s*\(\s*(\d+)\s*\)
    pattern-where-python: "isinstance(vars['X'].value, int) and int(vars['X'].value) < 2048"

  - id: detect-small-rsa-key-size
    patterns:
      - pattern: rsa.generate_private_key(..., key_size=$X)
    pattern-where-python: "int(vars['X'].value) < 2048"
    message: "RSA < 2048 bits is insecure. Use ≥2048."
    severity: ERROR
    languages: [python]

  - id: detect-dsa
    patterns:
      - pattern: Crypto.PublicKey.DSA.generate(...)
    message: "DSA has quantum risks. Use ECDSA with strong curves."
    severity: WARNING
    languages: [python]

  - id: detect-static-dh
    patterns:
      - pattern: DHStaticKey(...)
    message: "Static DH lacks forward secrecy. Use ephemeral DH."
    severity: WARNING
    languages: [python]

  # Digital signatures
  - id: detect-md5-signature
    patterns:
      - pattern: sign(..., hashlib.md5(...))
    message: "MD5 signatures are insecure. Use SHA-256/3."
    severity: ERROR
    languages: [python]

  - id: detect-sha1-signature
    patterns:
      - pattern: sign(..., hashlib.sha1(...))
    message: "SHA-1 signatures are insecure. Use SHA-256/3."
    severity: WARNING
    languages: [python]

  # RNGs - FIXED: Added crypto context
  - id: detect-insecure-rng
    patterns:
      - pattern: random.random()
      - pattern-inside: |
          key = random.random()
          cipher = Crypto.Cipher.AES.new(key)
    message: "Insecure RNG for crypto. Use secrets or os.urandom."
    severity: ERROR
    languages: [python]

  - id: detect-sha2
    patterns:
      - pattern: hashlib.sha256(...)
    message: "SHA-256 has quantum risks. Consider SHA-3."
    severity: INFO
    languages: [python]

  # Additional rules
  - id: detect-rc4
    patterns:
      - pattern: RC4.new(...)
    message: "RC4 is insecure. Use AES-GCM."
    severity: ERROR
    languages: [python]

  - id: detect-blowfish
    patterns:
      - pattern: Blowfish.new(...)
    message: "Blowfish is weak. Use AES-GCM."
    severity: WARNING
    languages: [python]

  - id: detect-idea
    patterns:
      - pattern: IDEA.new(...)
    message: "IDEA is deprecated. Use AES-GCM."
    severity: INFO
    languages: [python]

  # FIXED: Added crypto context for hardcoded keys
  - id: detect-hardcoded-keys
    patterns:
      - pattern: key = b"..."
      - pattern-inside: |
          Crypto.Cipher.<...>.new(..., key=key, ...)
    message: "Hard-coded keys are insecure."
    severity: ERROR
    languages: [python]

  - id: detect-hardcoded-secrets
    patterns:
      - pattern: secret_key = b"..."
      - pattern-inside: |
          JWT.encode(..., key=secret_key, ...)
    message: "Hardcoded secrets are insecure."
    severity: ERROR
    languages: [python]

  - id: detect-rsa-no-oaep
    patterns:
      - pattern: PKCS1_v1_5.new(...)
    message: "RSA without OAEP is insecure. Use OAEP."
    severity: ERROR
    languages: [python]

  - id: detect-weak-ecc
    patterns:
      - pattern: ECC.generate(curve='secp192r1')
    message: "secp192r1 is weak. Use secp256r1."
    severity: ERROR
    languages: [python]

  # FIXED: Corrected syntax for these rules
  - id: insecure-cipher-algorithm-rc4
    patterns:
      - pattern: cryptography.hazmat.primitives.ciphers.algorithms.ARC4(...)
    message: "RC4 has vulnerabilities. Use AES."
    severity: ERROR
    languages: [python]

  - id: insecure-cipher-algorithm-blowfish
    patterns:
      - pattern: cryptography.hazmat.primitives.ciphers.algorithms.Blowfish(...)
    message: "Blowfish is insecure. Use AES."
    severity: WARNING
    languages: [python]

  - id: insecure-cipher-algorithm-idea
    patterns:
      - pattern: cryptography.hazmat.primitives.ciphers.algorithms.IDEA(...)
    message: "IDEA is deprecated. Use AES."
    severity: INFO
    languages: [python]

  # Java Rules - FIXED: Tighter patterns
  - id: detect-md5-java
    patterns:
      - pattern: MessageDigest.getInstance("MD5")
    message: "MD5 is insecure. Use SHA-256/3."
    severity: ERROR
    languages: [java]

  - id: detect-sha1-java
    patterns:
      - pattern: MessageDigest.getInstance("SHA-1")
    message: "SHA-1 is deprecated. Use SHA-256/3."
    severity: WARNING
    languages: [java]

  - id: detect-3des-java
    patterns:
      - pattern: Cipher.getInstance("DESede/...")
    message: "Triple DES (3DES) is deprecated due to meet-in-the-middle attacks. Use AES-256."
    severity: ERROR
    languages: [java]

  - id: detect-des-java
    patterns:
      - pattern: Cipher.getInstance("DES/...")
    message: "DES is insecure. Use AES-256."
    severity: ERROR
    languages: [java]

  - id: detect-static-key-java
    patterns:
      - pattern: new SecretKeySpec(new byte[] { ... }, "AES")
    message: "Hardcoded keys are insecure."
    severity: ERROR
    languages: [java]

  - id: detect-weak-rsa-java
    patterns:
      - pattern: KeyPairGenerator.getInstance("RSA").initialize($X)
    pattern-where-python: "isinstance(vars['X'].value, int) and int(vars['X'].value) < 2048"
    message: "RSA <2048 bits is insecure."
    severity: ERROR
    languages: [java]

  - id: detect-rsa-no-padding-java
    patterns:
      - pattern: Cipher.getInstance("RSA/ECB/NoPadding")
    message: "No padding detected"
    severity: ERROR
    languages: [java]

  # C Rules - FIXED: Added context
  - id: detect-md5-c
    patterns:
      - pattern: MD5(...)
      - pattern-inside: |
          EVP_DigestInit(..., MD5(...))
    message: "MD5 is insecure. Use SHA-256/3."
    severity: ERROR
    languages: [c]

  - id: detect-sha1-c
    languages: [c]
    message: "SHA-1 is deprecated due to collision attacks. Use SHA-256 or SHA-3."
    patterns:
      - pattern: SHA1(...)
    severity: WARNING

  - id: detect-des-c
    patterns:
      - pattern: DES_set_key(...)
    message: "DES is insecure. Use AES-256."
    severity: ERROR
    languages: [c]

  - id: detect-hardcoded-keys-c
    languages: [c]
    message: "Hardcoded keys are insecure."
    patterns:
      - pattern: const unsigned char key[$SIZE] = "..."
      - pattern-inside: |
            AES_set_encrypt_key(key, ...)
    severity: ERROR

  - id: detect-weak-rsa-c
    languages: [c]
    message: "RSA <2048 bits is insecure. Use ≥2048."
    patterns:
      - pattern: RSA_generate_key($X, ...)
      - metavariable-comparison:
          metavariable: $X
          comparison: $X.value < 2048
    severity: ERROR

  - id: detect-weak-aes-c
    languages: [c]
    message: "AES keys <256 bits are insecure."
    patterns:
      - pattern: AES_set_encrypt_key(..., $X, ...)
      - metavariable-comparison:
          metavariable: $X
          comparison: $X.value < 256
    severity: ERROR
"""
    data = yaml.safe_load(rules_yaml)
    return data.get("rules", [])


# --- A Helper Class for Captured Variables in pattern-where Evaluations ---
class Captured:
    def __init__(self, value):
        self.value = value
        self.constant = value.isdigit()


# --- Scanning Functions (Internal Engine) ---
def scan_code(code_text: str, rules: list) -> list:
    """
    Scan the provided code text using the given rules.
    Returns a list of findings with rule id, message, severity, and an approximate
    line and column numbers. Supports 'pattern', 'patterns', 'pattern-inside',
    and 'pattern-where-python'.
    """
    findings = []
    for rule in rules:
        rule_matched = True
        cap_vars = {}  # Dictionary to store captured metavariables

        # Handle a single "pattern" field
        if "pattern" in rule:
            pat = rule["pattern"]
            if rule.get("raw", False):
                regex_pat = re.compile(pat, re.DOTALL)
            else:
                regex_pat = re.compile(pattern_to_regex(pat), re.DOTALL)
            m = regex_pat.search(code_text)
            if not m:
                rule_matched = False
            else:
                # If there are no named groups but capturing groups exist, store first group as $X
                if not m.groupdict() and m.groups():
                    cap_vars.setdefault("$X", []).append(m.group(1))
                else:
                    for var, val in m.groupdict().items():
                        cap_vars.setdefault("$" + var, []).append(val)
        # Handle "patterns" list
        elif "patterns" in rule:
            for item in rule["patterns"]:
                if "pattern" in item:
                    pat = item["pattern"]
                    if rule.get("raw", False):
                        regex_pat = re.compile(pat, re.DOTALL)
                    else:
                        regex_pat = re.compile(pattern_to_regex(pat), re.DOTALL)
                    m = regex_pat.search(code_text)
                    if not m:
                        rule_matched = False
                        break
                    if not m.groupdict() and m.groups():
                        cap_vars.setdefault("$X", []).append(m.group(1))
                    else:
                        for var, val in m.groupdict().items():
                            cap_vars.setdefault("$" + var, []).append(val)
                elif "pattern-inside" in item:
                    pat_inside = item["pattern-inside"]
                    regex_pat = re.compile(pattern_to_regex(pat_inside), re.DOTALL)
                    m = regex_pat.search(code_text)
                    if not m:
                        rule_matched = False
                        break
                elif "metavariable-comparison" in item:
                    comp = item["metavariable-comparison"]
                    var = comp["metavariable"]
                    if var not in cap_vars or not cap_vars[var]:
                        rule_matched = False
                        break
                    valid = False
                    for val in cap_vars[var]:
                        try:
                            expr = comp["comparison"].replace("$X.value", str(val))
                            if eval(expr, {"__builtins__": {}}):
                                valid = True
                                break
                        except Exception:
                            pass
                    if not valid:
                        rule_matched = False
                        break
        else:
            rule_matched = False

        # Evaluate top-level pattern-where-python if present.
        if rule_matched and "pattern-where-python" in rule:
            expr = rule["pattern-where-python"]
            local_vars = {"vars": {}}
            for key, vals in cap_vars.items():
                local_vars["vars"][key[1:]] = Captured(vals[0])
            try:
                if not eval(expr, {"__builtins__": {}}, local_vars):
                    rule_matched = False
            except Exception:
                rule_matched = False

        if rule_matched:
            start_line = -1
            start_col = -1
            end_line = -1
            end_col = -1
            match_found = None

            if "pattern" in rule:
                if rule.get("raw", False):
                    regex_pat = re.compile(rule["pattern"], re.DOTALL)
                else:
                    regex_pat = re.compile(pattern_to_regex(rule["pattern"]), re.DOTALL)
                match_found = regex_pat.search(code_text)
            elif "patterns" in rule:
                for item in rule["patterns"]:
                    if "pattern" in item:
                        regex_pat = re.compile(pattern_to_regex(item["pattern"]), re.DOTALL)
                        match_found = regex_pat.search(code_text)
                        if match_found:
                            break

            if match_found:
                start_line = code_text[:match_found.start()].count("\n") + 1
                last_newline = code_text.rfind("\n", 0, match_found.start())
                if last_newline == -1:
                    start_col = match_found.start() + 1
                else:
                    start_col = match_found.start() - last_newline
                end_line = code_text[:match_found.end()].count("\n") + 1
                last_newline_end = code_text.rfind("\n", 0, match_found.end())
                if last_newline_end == -1:
                    end_col = match_found.end() + 1
                else:
                    end_col = match_found.end() - last_newline_end

            findings.append({
                "check_id": rule.get("id"),
                "start": {"line": start_line, "col": start_col},
                "end": {"line": end_line, "col": end_col},
                "extra": {"message": rule.get("message"), "severity": rule.get("severity")}
            })
    return findings


def scan_file(file_path: str, rules: list) -> list:
    """Read a file and scan its content using the vulnerability rules. Returns findings with file path added."""
    try:
        with open(file_path, "r", errors="ignore") as f:
            code_text = f.read()
    except Exception as e:
        logging.warning(f"Error reading file {file_path}: {e}")
        return []
    findings = scan_code(code_text, rules)
    for finding in findings:
        finding["path"] = file_path
    return findings


def scan_directory(target: str, rules: list) -> (list, list):
    """Scan all files under the target (directory or file) and return findings and the file list."""
    all_files = gather_all_files(target)
    all_findings = []
    for file_path in all_files:
        file_findings = scan_file(file_path, rules)
        if file_findings:
            logging.debug(f"Found {len(file_findings)} issues in {file_path}")
        all_findings.extend(file_findings)
    return all_findings, all_files


def display_findings(findings: list, all_files: list):
    """
    Produce a detailed report of vulnerabilities along with a summary.
    The summary lists, for each language, the number of vulnerable files and a list (just the filename) of vulnerable files.
    """
    if not findings:
        print("\nNo vulnerabilities found.\n")
        return
    print("\n=== Vulnerabilities Report ===\n")
    for i, finding in enumerate(findings, start=1):
        print(f"Vulnerability #{i}:")
        print(f"  Rule       : {finding.get('check_id')}")
        print(f"  File       : {finding.get('path')}")
        start = finding.get("start", {})
        print(f"  Start Line : {start.get('line')}, Column: {start.get('col')}")
        end = finding.get("end", {})
        print(f"  End Line   : {end.get('line')}, Column: {end.get('col')}")
        extra = finding.get("extra", {})
        print(f"  Severity   : {extra.get('severity')}")
        print(f"  Message    : {extra.get('message')}\n")
    file_stats = defaultdict(lambda: {"total": 0, "vulnerable": 0, "vul_files": set()})
    for file_path in all_files:
        lang = get_language_from_extension(file_path)
        file_stats[lang]["total"] += 1
    for finding in findings:
        file_path = finding.get("path")
        lang = get_language_from_extension(file_path)
        file_stats[lang]["vulnerable"] += 1
        file_stats[lang]["vul_files"].add(os.path.basename(file_path))
    print("=== Scan Summary ===")
    for lang, stats in file_stats.items():
        vul_list = sorted(stats["vul_files"])
        print(f"  {lang.capitalize()}: {stats['vulnerable']} vulnerabilities out of {stats['total']} scanned {vul_list}")
    print("")


# --- External Semgrep Runner (Optional Mode) ---
def run_semgrep(rule_file, target):
    """
    Run Semgrep on a target file/directory with a specific rule file.
    Captures JSON output and also saves the raw results as YAML.
    """
    if not os.path.exists(rule_file):
        logging.error(f"Rule file not found: {rule_file}")
        exit(1)
    try:
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


# --- Main Program ---
def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory (or file) for vulnerabilities using hardcoded Semgrep‑style rules."
    )
    parser.add_argument("--target", help="Path to the target directory or file")
    parser.add_argument("--rules",
                        help="Path to an external Semgrep-like rules file. "
                             "If omitted, embedded rules are used (unless --external is used).",
                        default=None)
    parser.add_argument("--db", help="Path to the SQLite DB file. If omitted, results are not saved to a DB.",
                        default=None)
    parser.add_argument("--reset-db", help="Reset the database before saving", action="store_true")
    parser.add_argument("--external", help="Use external Semgrep (via subprocess) instead of the internal scanner",
                        action="store_true")
    args = parser.parse_args()

    # Prompt for target if not provided
    if not args.target:
        args.target = input("Enter the path to the target file/folder to scan: ").strip()

    # For external mode, prompt for rules file if not provided
    if args.external and not args.rules:
        args.rules = input("Enter the path to your Semgrep rules file: ").strip()

    # Determine scanning method
    if args.external:
        findings = run_semgrep(args.rules, args.target)
        all_files = gather_all_files(args.target)
    else:
        if args.rules:
            try:
                with open(args.rules, "r") as f:
                    rules_data = yaml.safe_load(f)
                rules = rules_data.get("rules", [])
            except Exception as e:
                logging.error(f"Error reading rules file {args.rules}: {e}")
                sys.exit(1)
        else:
            rules = load_embedded_rules()
        findings, all_files = scan_directory(args.target, rules)

    display_findings(findings, all_files)

    # Database export (only if the --db flag was provided)
    if args.db:
        scan_name = input("Enter a name for this scan: ").strip()
        if not scan_name:
            scan_name = "Unnamed_Scan"
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        create_database(args.db, reset=args.reset_db)
        save_to_database(findings, args.db, scan_name, scan_date)
        logging.info(f"Results saved to database '{args.db}' (scan: '{scan_name}', date: {scan_date}).")


if __name__ == "__main__":
    main()
