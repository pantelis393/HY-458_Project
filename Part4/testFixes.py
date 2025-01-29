import os
import tempfile
import shutil
import yaml
from apply_fixes import apply_fixes_to_file, load_fixes

# Sample fixes.yaml content
fixes_content = """
fixes:
  detect-md5:
    pattern: "hashlib\\.md5\\(.*\\)"
    fix_snippet: |
      import hashlib
      # Replace MD5 with SHA-256
      sha256_hash = hashlib.sha256(data).hexdigest()
    description: "Replace MD5 with SHA-256 for secure hashing."
    reference: "https://csrc.nist.gov/publications/detail/fips/180/4/final"

  detect-static-iv:
    pattern: "iv = b\\\"1234567890123456\\\""
    fix_snippet: |
      from Crypto.Random import get_random_bytes
      iv = get_random_bytes(16)  # Use a random IV
    description: "Replace static IVs with randomized IVs."
    reference: "https://csrc.nist.gov/publications/detail/sp/800-38a/final"
"""

# Sample vulnerable code
vulnerable_code = """
import hashlib

data = b"example data"
# Vulnerable MD5 usage
md5_hash = hashlib.md5(data).hexdigest()

# Static IV example
iv = b"1234567890123456"
"""

# Expected fixed code
expected_fixed_code = """
import hashlib

data = b"example data"
# Replace MD5 with SHA-256
sha256_hash = hashlib.sha256(data).hexdigest()

from Crypto.Random import get_random_bytes
iv = get_random_bytes(16)  # Use a random IV
"""

def test_apply_fixes():
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    try:
        # Create temporary files for vulnerable code and fixes.yaml
        temp_code_file = os.path.join(temp_dir, "vulnerable.py")
        temp_fixes_file = os.path.join(temp_dir, "fixes.yaml")

        with open(temp_code_file, "w") as code_file:
            code_file.write(vulnerable_code)

        with open(temp_fixes_file, "w") as fixes_file:
            fixes_file.write(fixes_content)

        # Load fixes
        fixes = load_fixes(temp_fixes_file)

        # Apply fixes to the vulnerable file
        apply_fixes_to_file(temp_code_file, fixes)

        # Read back the fixed file
        with open(temp_code_file, "r") as fixed_file:
            fixed_code = fixed_file.read()

        # Assert that the fixed code matches the expected output
        assert fixed_code.strip() == expected_fixed_code.strip(), "Fixes did not apply as expected."

        print("Test passed: Fixes applied correctly.")
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_apply_fixes()
