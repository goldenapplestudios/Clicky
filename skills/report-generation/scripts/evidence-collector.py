#!/usr/bin/env python3
"""Evidence Collector - organize screenshots and command output into the
evidence/ directory structure by severity.

Usage:
    evidence-collector.py screenshot --tag TAG --vuln VULN_ID [--severity critical|high|medium|low] [--file PATH]
    evidence-collector.py add-output --file PATH --section SECTION

This does not capture screenshots itself (a text-based agent has no
display to capture) - it files an already-captured image into the right
place, or prints the exact target path/filename for whatever tool did
capture one (headless-browser screenshot, terminal capture, etc.) to save
to directly.
"""
import argparse
import shutil
import sys
from pathlib import Path

EVIDENCE_ROOT = Path("evidence")


def cmd_screenshot(args):
    severity_dir = EVIDENCE_ROOT / args.severity
    severity_dir.mkdir(parents=True, exist_ok=True)

    safe_tag = args.tag.replace(" ", "_").replace("/", "_")
    dest_name = f"{args.vuln}_{safe_tag}.png"
    dest = severity_dir / dest_name

    if args.file:
        src = Path(args.file)
        if not src.exists():
            print(f"ERROR: source file not found: {src}", file=sys.stderr)
            sys.exit(1)
        shutil.copy2(src, dest)
        print(f"Filed: {src} -> {dest}")
    else:
        print(f"No --file given. Save the captured screenshot to this exact path:")
        print(f"  {dest}")
        print(f"(capture it with a headless browser tool - e.g. `shot-scraper` / `wkhtmltoimage` /")
        print(f" a Playwright/Puppeteer script - then re-run with --file to file it, or save directly)")

    return dest


def cmd_add_output(args):
    src = Path(args.file)
    if not src.exists():
        print(f"ERROR: source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    section_dir = EVIDENCE_ROOT / "command_output" / args.section
    section_dir.mkdir(parents=True, exist_ok=True)
    dest = section_dir / src.name
    shutil.copy2(src, dest)

    # Maintain a simple manifest so report-generator.sh can enumerate evidence
    manifest = EVIDENCE_ROOT / "manifest.txt"
    with open(manifest, "a") as f:
        f.write(f"{args.section}\t{dest}\n")

    print(f"Filed: {src} -> {dest}")
    print(f"Recorded in {manifest}")


def main():
    parser = argparse.ArgumentParser(description="Organize pentest evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    p_screenshot = sub.add_parser("screenshot")
    p_screenshot.add_argument("--tag", required=True)
    p_screenshot.add_argument("--vuln", required=True)
    p_screenshot.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low"])
    p_screenshot.add_argument("--file", default=None)

    p_output = sub.add_parser("add-output")
    p_output.add_argument("--file", required=True)
    p_output.add_argument("--section", required=True)

    args = parser.parse_args()

    if args.command == "screenshot":
        cmd_screenshot(args)
    elif args.command == "add-output":
        cmd_add_output(args)


if __name__ == "__main__":
    main()
