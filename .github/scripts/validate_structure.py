import os
import re
import sys

# Structure for headings/subheadings
REQUIRED_STRUCTURE = {
    "32 Bit": ["Vulnerable", "Secured"],
    "64 Bit": ["Vulnerable", "Secured"]
}

# Tool outputs required under each subheading in certain .md files
REQUIRED_TOOL_OUTPUTS = [
    "file output",
    "checksec output",
    "ldd output",
    "grep output",
    "readelf output",
    "nm output",
    "nm -D output",
    "strings output",
    "strace output",
    "ltrace output",
    "objdump output",
    "gdb output",
    "radare2 analysis",
    "cfg output",
    "ghidra analysis"
]

def heading_regex(text):
    return re.compile(rf"^#+\s*{re.escape(text)}\s*$", re.IGNORECASE)

def marker_regex(marker):
    # Flexible: allow section headers or bold marker or code block markers
    return re.compile(rf"^(#+\s*|\*\*|\s*|\`*\s*){re.escape(marker)}", re.IGNORECASE)

def get_heading_indices(lines, heading):
    return [i for i, line in enumerate(lines) if heading_regex(heading).match(line.strip())]

def get_section_lines_between(lines, start_idx, end_idx):
    return lines[start_idx+1:end_idx]

def find_markers(lines, markers):
    found = set()
    for marker in markers:
        reg = marker_regex(marker)
        if any(reg.search(line) for line in lines):
            found.add(marker)
    return found

def check_file(filename):
    issues = {}
    with open(filename, encoding="utf-8") as f:
        lines = [line.rstrip('\n') for line in f.readlines()]

    for main_heading in REQUIRED_STRUCTURE:
        main_indices = get_heading_indices(lines, main_heading)
        if not main_indices:
            issues[main_heading] = "missing entirely"
            continue
        for main_idx in main_indices:
            # Find where this main heading's section ends
            next_main_idx = min([i for i in get_heading_indices(lines, "32 Bit") + get_heading_indices(lines, "64 Bit") if i > main_idx], default=len(lines))
            subheadings = REQUIRED_STRUCTURE[main_heading]
            for sub in subheadings:
                sub_indices = [i for i in range(main_idx + 1, next_main_idx) if heading_regex(sub).match(lines[i].strip())]
                if not sub_indices:
                    if main_heading not in issues or issues[main_heading] == "missing entirely":
                        issues[main_heading] = {}
                    issues[main_heading][sub] = "missing entirely"
                else:
                    for sub_idx in sub_indices:
                        # End of subheading is before next subheading or end of main section
                        next_sub_idx = min([i for i in range(sub_idx + 1, next_main_idx) if any(heading_regex(x).match(lines[i].strip()) for x in subheadings)], default=next_main_idx)
                        section_lines = get_section_lines_between(lines, sub_idx, next_sub_idx)
                        found_markers = find_markers(section_lines, REQUIRED_TOOL_OUTPUTS)
                        missing_markers = set(REQUIRED_TOOL_OUTPUTS) - found_markers
                        if missing_markers:
                            if main_heading not in issues or issues[main_heading] == "missing entirely":
                                issues[main_heading] = {}
                            if sub not in issues[main_heading] or issues[main_heading][sub] == "missing entirely":
                                issues[main_heading][sub] = []
                            issues[main_heading][sub].extend(missing_markers)
    return issues

def main():
    failed = {}
    for root, _, files in os.walk("."):
        for file in files:
            if file.endswith(".md") and file.lower() not in ["readme.md", "windows.md"]:
                full_path = os.path.join(root, file)
                issues = check_file(full_path)
                if issues:
                    failed[full_path] = issues
    if failed:
        print("❌ The following files are missing required sections/tools:")
        for f, headings in failed.items():
            print(f"- {f}")
            for main, subdict in headings.items():
                if subdict == "missing entirely":
                    print(f"    * Main heading '{main}' is missing entirely")
                else:
                    for sub, missing in subdict.items():
                        if missing == "missing entirely":
                            print(f"    * Under '{main}': Subheading '{sub}' missing entirely")
                        else:
                            print(f"    * Under '{main}' > '{sub}': Missing tool outputs: {', '.join(missing)}")
        sys.exit(1)
    else:
        print("✅ All Markdown files contain required headings and tool output markers.")

if __name__ == "__main__":
    main()
