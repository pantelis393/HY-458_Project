import yaml
import re
import argparse
from pathlib import Path

def load_rules(rules_file):
    """
    Load fix rules from the YAML configuration file.
    Each rule is expected to have:
      - id
      - pattern (regex)
      - fix (replacement string)
    """
    with open(rules_file, "r") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])

def apply_fixes_to_file(file_path, rules):
    """
    Apply regex-based fixes to the file based on loaded rules.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        original_content = f.read()

    updated_content = original_content
    has_changes = False

    for rule in rules:
        rule_id = rule.get("id")
        pattern = rule.get("pattern")
        fix = rule.get("fix")
        message = rule.get("message")

        if not pattern or not fix:
            continue  # skip incomplete rules

        # Compile the pattern in MULTILINE mode to match line by line
        # NOTE: For a more advanced approach, you may want re.DOTALL, etc.
        regex = re.compile(pattern, re.MULTILINE)

        # If the pattern is found, do the substitution
        if regex.search(updated_content):
            print(f"Applying fix for '{rule_id}' - {message}")
            updated_content = regex.sub(fix, updated_content)
            has_changes = True

    # Write file if changed
    if has_changes and updated_content != original_content:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(updated_content)
        print(f"Fixes applied to {file_path}")
    else:
        print(f"No vulnerabilities detected in {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Apply simple regex-based fixes to a file.")
    parser.add_argument("--file", required=True, help="Path to the target file to fix.")
    parser.add_argument("--rules", required=True, help="Path to the YAML file containing fix rules.")

    args = parser.parse_args()
    file_path = Path(args.file)
    rules_file = Path(args.rules)

    if not file_path.exists():
        print(f"Error: File '{file_path}' does not exist.")
        return

    if not rules_file.exists():
        print(f"Error: Rules file '{rules_file}' does not exist.")
        return

    rules = load_rules(rules_file)
    apply_fixes_to_file(file_path, rules)

if __name__ == "__main__":
    main()
