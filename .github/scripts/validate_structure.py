import os
import re
import sys

REQUIRED_MAIN_HEADINGS = [r"^#*\s*32\s*Bit", r"^#*\s*64\s*Bit"]
REQUIRED_SUB_HEADINGS = [r"^#*\s*Vulnerable", r"^#*\s*Secured"]

def file_has_required_headings(content, required):
    found = [any(re.search(h, line, re.IGNORECASE) for line in content) for h in required]
    return all(found)

def validate_markdown(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    main_ok = file_has_required_headings(lines, REQUIRED_MAIN_HEADINGS)
    sub_ok = file_has_required_headings(lines, REQUIRED_SUB_HEADINGS)
    return main_ok and sub_ok

def main():
    failed = []

    for root, _, files in os.walk("."):
        for file in files:
            if file.endswith(".md"):
                full_path = os.path.join(root, file)
                if not validate_markdown(full_path):
                    failed.append(full_path)

    if failed:
        print("❌ The following files are missing required headings:")
        for f in failed:
            print(f"- {f}")
        sys.exit(1)
    else:
        print("✅ All Markdown files contain required headings.")

if __name__ == "__main__":
    main()
