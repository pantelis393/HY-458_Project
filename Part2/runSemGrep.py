import subprocess
import json
import yaml
import argparse
import tempfile

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

# Example usage
if __name__ == "__main__":
    # Define default rule file and target file/directory
    default_rule_file = "rules.yaml"
    default_target = "test.py"

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run Semgrep with specified rules and target.')
    parser.add_argument('--rules', help='Path to the Semgrep rule file (YAML).')
    parser.add_argument('--target', help='Path to the target file or directory to scan.')

    args = parser.parse_args()

    rule_file = args.rules if args.rules else default_rule_file
    target = args.target if args.target else default_target

    # Run Semgrep and display results
    findings = run_semgrep(rule_file, target)
    display_findings(findings)
