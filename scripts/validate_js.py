import re
import subprocess
import tempfile
import os
import sys

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(repo_root, "family_finances_os", "web_server.py")
    
    with open(target, "r", encoding="utf-8") as f:
        text = f.read()

    # Find script blocks inside HTML
    script_blocks = re.findall(r'<script.*?>\s*(.*?)\s*</script>', text, re.DOTALL)
    print(f"Found {len(script_blocks)} <script> blocks in HTML.")

    # Service worker block
    sw_match = re.search(r'sw_code\s*=\s*"""(.*?)"""', text, re.DOTALL)
    if sw_match:
        print("Found sw_code (Service Worker) block.")
        script_blocks.append(sw_match.group(1))

    all_passed = True
    for i, code in enumerate(script_blocks):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tf:
            tf.write(code)
            tf_name = tf.name
        try:
            res = subprocess.run(["node", "--check", tf_name], capture_output=True, text=True)
            if res.returncode == 0:
                print(f"  [OK] Block {i}: node --check PASSED ({len(code.splitlines())} lines)")
            else:
                all_passed = False
                print(f"  [FAIL] Block {i}: node --check FAILED with return code {res.returncode}")
                print("STDOUT:", res.stdout)
                print("STDERR:", res.stderr)
        finally:
            if os.path.exists(tf_name):
                os.remove(tf_name)

    if not all_passed:
        sys.exit(1)
    print("\nAll JavaScript blocks in web_server.py validated successfully with node --check!")

if __name__ == "__main__":
    main()
