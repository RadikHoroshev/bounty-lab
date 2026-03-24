#!/usr/bin/env python3
"""
submit_to_huntr.py
------------------
Автоматическая подача отчёта на huntr.com из Markdown-файла.

Использует стабильные field ID обнаруженные 2026-03-24:
  #target-url, #package-select, #version-select,
  #react-select-5-input (vuln type), #write-up-title,
  #readmeProp-input, #impactProp-input,
  #permalink-url-N, #description-N

Requirements:
  pip install playwright
  playwright install chromium

Usage:
  python3 submit_to_huntr.py report.md                  # dry-run (печатает что будет заполнено)
  python3 submit_to_huntr.py report.md --submit          # реальная отправка
  python3 submit_to_huntr.py report.md --submit --headless

Report format (BOUNTY_STANDARD.md):
  # <Title>
  **Target:** Owner/repo
  **Version:** ≤ X.Y.Z
  **CVSS:** N.N Severity (AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_)
  **CWE:** CWE-NNN: <Name>
  ## Summary
  ## Proof of Concept
  ## Impact
  ## Vulnerable Code Locations   ← таблица с permalink'ами
"""

import argparse
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Mapping: CVSS vector → huntr button labels
# ---------------------------------------------------------------------------
CVSS_MAP = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}

CVSS_HEADINGS = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S":  "Scope",
    "C":  "Confidentiality",
    "I":  "Integrity",
    "A":  "Availability",
}

# Package manager detection
PKG_MAP = {
    "python": "pypi", "pypi": "pypi",
    "npm": "npm", "node": "npm", "javascript": "npm", "typescript": "npm",
    "go": "golang", "golang": "golang",
    "ruby": "rubygems", "gem": "rubygems",
    "java": "maven", "maven": "maven",
    "php": "packagist", "composer": "packagist",
    "dotnet": "nuget", "csharp": "nuget", "nuget": "nuget",
}

# ---------------------------------------------------------------------------
# Report parser
# ---------------------------------------------------------------------------
def parse_report(md: str) -> dict:
    """Extract huntr form fields from BOUNTY_STANDARD markdown."""

    def field(pattern, default=""):
        m = re.search(pattern, md, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else default

    def section(heading):
        pattern = rf"^##+ {re.escape(heading)}\s*\n(.*?)(?=^##+ |\Z)"
        m = re.search(pattern, md, re.MULTILINE | re.DOTALL)
        return m.group(1).strip() if m else ""

    # Title: first line starting with #
    title_m = re.match(r"^#\s+(.+)", md.strip(), re.MULTILINE)
    title = title_m.group(1).strip() if title_m else ""

    # Target → repo (Owner/repo or full GitHub URL)
    target_raw = field(r"\*\*Target:\*\*\s*(.+)")
    if "/" in target_raw and "github.com" not in target_raw:
        repo_url = f"https://github.com/{target_raw}"
    elif "github.com" in target_raw:
        repo_url = target_raw
    else:
        repo_url = target_raw

    # Version
    version = field(r"\*\*Version:\*\*\s*(.+)")

    # CVSS score and vector
    cvss_raw = field(r"\*\*CVSS:\*\*\s*(.+)")
    cvss_score_m = re.search(r"(\d+\.\d+)", cvss_raw)
    cvss_score = cvss_score_m.group(1) if cvss_score_m else ""
    cvss_vector_m = re.search(r"AV:(\w)/AC:(\w)/PR:(\w)/UI:(\w)/S:(\w)/C:(\w)/I:(\w)/A:(\w)", cvss_raw)
    cvss_components = {}
    if cvss_vector_m:
        keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for i, k in enumerate(keys):
            cvss_components[k] = CVSS_MAP[k].get(cvss_vector_m.group(i+1), "")

    # CWE type (for React-select)
    cwe_raw = field(r"\*\*CWE:\*\*\s*(.+)")
    cwe_name_m = re.search(r"CWE-\d+[:\s]+(.+)", cwe_raw)
    cwe_type = cwe_name_m.group(1).strip() if cwe_name_m else cwe_raw

    # Package manager: detect from repo URL, then explicit language markers
    pkg_manager = "pypi"  # default for AI/ML (Python) targets
    repo_lower = repo_url.lower()
    # Repo-name based detection (most reliable)
    REPO_PKG = {
        "ollama/ollama": "golang",
        "open-webui/open-webui": "npm",
        "langchain-ai/": "pypi",
        "huggingface/": "pypi",
        "berriai/litellm": "pypi",
        "nltk/nltk": "pypi",
        "mlflow/mlflow": "pypi",
    }
    for repo_pattern, pm in REPO_PKG.items():
        if repo_pattern in repo_lower:
            pkg_manager = pm
            break
    else:
        # Fallback: look for explicit language markers (word boundaries)
        if re.search(r'\bgo\.mod\b|\bgolang\b', md[:800], re.IGNORECASE):
            pkg_manager = "golang"
        elif re.search(r'\bpackage\.json\b|\bnpm\b|\bnode\.js\b', md[:800], re.IGNORECASE):
            pkg_manager = "npm"
        elif re.search(r'\bGemfile\b|\bruby\b', md[:800], re.IGNORECASE):
            pkg_manager = "rubygems"
        elif re.search(r'\bpom\.xml\b|\bmaven\b', md[:800], re.IGNORECASE):
            pkg_manager = "maven"

    # Description = Summary + Root Cause sections
    summary = section("Summary")
    root_cause = section("Root Cause")
    description = ""
    if summary:
        description += f"# Summary\n{summary}\n\n"
    if root_cause:
        description += f"# Root Cause\n{root_cause}"
    if not description:
        description = section("Description") or ""

    # Impact section
    impact_raw = section("Impact")
    # Clean up table format to plain text if needed
    impact = impact_raw if impact_raw else "See report description."

    # Proof of Concept
    poc = section("Proof of Concept")
    if not poc:
        poc = section("PoC")

    # Full description (Description field in huntr = writeup)
    writeup = description.strip()
    if poc:
        writeup += f"\n\n# Proof of Concept\n{poc}"

    # Occurrences from "Vulnerable Code Locations" table
    occurrences = []
    vuln_locs = section("Vulnerable Code Locations")
    if vuln_locs:
        # Parse markdown table rows
        for line in vuln_locs.split("\n"):
            cells = [c.strip() for c in line.split("|") if c.strip()]
            if len(cells) >= 2 and not cells[0].startswith("-"):
                # Check if first cell looks like a file path
                filepath = cells[0].strip("`")
                if "/" in filepath and not filepath.startswith("File"):
                    occurrences.append({"file": filepath, "desc": cells[-1] if len(cells) > 2 else ""})

    # If no table, find GitHub permalink patterns in text (prefer SHA-based over branch)
    if not occurrences:
        permalinks = re.findall(
            r"https://github\.com/[^\s\"')\]>,]+/blob/[a-f0-9]{7,40}/[^\s\"')\]>,]+#L\d+(?:-L\d+)?",
            md
        )
        if not permalinks:  # fallback to branch-based
            permalinks = re.findall(
                r"https://github\.com/[^\s\"')\]>,]+/blob/[^\s\"')\]>,]+#L\d+(?:-L\d+)?",
                md
            )
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in permalinks:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        occurrences = [{"permalink": p, "desc": ""} for p in unique[:8]]

    return {
        "repo_url": repo_url,
        "package_manager": pkg_manager,
        "version": version,
        "cwe_type": cwe_type,
        "cvss_score": cvss_score,
        "cvss_components": cvss_components,
        "title": title,
        "description": writeup,
        "impact": impact,
        "occurrences": occurrences,
    }


# ---------------------------------------------------------------------------
# React controlled input setter (bypasses React's synthetic event system)
# ---------------------------------------------------------------------------
REACT_SETTER_JS = """
(id, value) => {
    const el = document.getElementById(id);
    if (!el) return `NOT FOUND: ${id}`;
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    )?.set || Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
    )?.set;
    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
        el.value = value;
    }
    return `OK: ${id}`;
}
"""

REACT_TEXTAREA_JS = """
(id, value) => {
    const el = document.getElementById(id);
    if (!el) return `NOT FOUND: ${id}`;
    const nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
    )?.set;
    if (nativeSetter) {
        nativeSetter.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    return `OK: ${id}`;
}
"""

# ---------------------------------------------------------------------------
# Form filler
# ---------------------------------------------------------------------------
def fill_form(page, data: dict, submit: bool):
    from playwright.sync_api import expect

    print("\n[1/9] Repo URL →", data["repo_url"])
    page.evaluate(REACT_SETTER_JS, ["target-url", data["repo_url"]])
    page.locator("#target-url").press("Enter")
    page.wait_for_timeout(800)

    print("[2/9] Package manager →", data["package_manager"])
    page.select_option("#package-select", value=data["package_manager"])

    print("[3/9] Version →", data["version"])
    page.evaluate(REACT_SETTER_JS, ["version-select", data["version"]])

    print("[4/9] Vulnerability type →", data["cwe_type"])
    vuln_input = page.locator("#react-select-5-input")
    vuln_input.click()
    vuln_input.type(data["cwe_type"][:20], delay=30)
    page.wait_for_timeout(600)
    page.keyboard.press("Enter")
    page.wait_for_timeout(300)

    print("[5/9] CVSS buttons")
    for metric, value_label in data["cvss_components"].items():
        heading_text = CVSS_HEADINGS[metric]
        # Find h1 with the metric name, go up one level, find button with value
        clicked = page.evaluate("""
        (args) => {
            const [heading, label] = args;
            const h1 = Array.from(document.querySelectorAll('h1'))
                .find(h => h.textContent.trim() === heading);
            if (!h1) return `h1 not found: ${heading}`;
            const container = h1.parentElement;
            const btn = Array.from(container.querySelectorAll('button'))
                .find(b => b.textContent.trim() === label);
            if (!btn) return `btn not found: ${label}`;
            btn.click();
            return `clicked: ${heading} = ${label}`;
        }
        """, [heading_text, value_label])
        print(f"    {metric}: {clicked}")

    print("[6/9] Title →", data["title"][:60])
    page.evaluate(REACT_SETTER_JS, ["write-up-title", data["title"]])

    print("[7/9] Description ({} chars)".format(len(data["description"])))
    page.evaluate(REACT_TEXTAREA_JS, ["readmeProp-input", data["description"]])

    print("[8/9] Impact ({} chars)".format(len(data["impact"])))
    page.evaluate(REACT_TEXTAREA_JS, ["impactProp-input", data["impact"]])

    print("[9/9] Occurrences →", len(data["occurrences"]))
    for i, occ in enumerate(data["occurrences"]):
        if i > 0:
            # Click "NEW OCCURRENCE" button
            page.locator("button:has-text('NEW OCCURRENCE')").click()
            page.wait_for_timeout(400)
        permalink = occ.get("permalink", "")
        if not permalink and occ.get("file"):
            # Will be filled as a placeholder — user needs to provide real permalink
            permalink = f"https://github.com/<repo>/blob/<sha>/{occ['file']}"
        page.evaluate(REACT_SETTER_JS, [f"permalink-url-{i}", permalink])
        if occ.get("desc"):
            page.evaluate(REACT_TEXTAREA_JS, [f"description-{i}", occ["desc"]])

    if submit:
        print("\n>>> SUBMITTING (you have 20 minutes to edit after submission)")
        submit_btn = page.locator("button:has-text('Submit Report')")
        submit_btn.wait_for(state="enabled", timeout=5000)
        submit_btn.click()
        page.wait_for_url("**/bounties/**", timeout=15000)
        final_url = page.url
        print(f"✅ SUBMITTED: {final_url}")
        return final_url
    else:
        print("\n[DRY RUN] Form filled. Pass --submit to actually submit.")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Submit huntr.com bug bounty report from Markdown")
    parser.add_argument("report", help="Path to markdown report file")
    parser.add_argument("--submit", action="store_true", help="Actually submit (default: dry-run)")
    parser.add_argument("--headless", action="store_true", help="Run browser headless")
    args = parser.parse_args()

    md_path = Path(args.report)
    if not md_path.exists():
        print(f"ERROR: file not found: {md_path}")
        sys.exit(1)

    md = md_path.read_text()
    data = parse_report(md)

    print("=" * 60)
    print("PARSED FIELDS:")
    print(f"  repo_url:        {data['repo_url']}")
    print(f"  package_manager: {data['package_manager']}")
    print(f"  version:         {data['version']}")
    print(f"  cwe_type:        {data['cwe_type']}")
    print(f"  cvss_score:      {data['cvss_score']}")
    print(f"  cvss_components: {data['cvss_components']}")
    print(f"  title:           {data['title'][:60]}")
    print(f"  description:     {len(data['description'])} chars")
    print(f"  impact:          {len(data['impact'])} chars")
    print(f"  occurrences:     {len(data['occurrences'])}")
    for i, occ in enumerate(data["occurrences"]):
        print(f"    [{i}] {occ.get('permalink','') or occ.get('file','')}")
    print("=" * 60)

    if not args.submit:
        print("\n[DRY RUN] Use --submit to open browser and fill the form.")
        return

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=args.headless,
            channel="chrome" if not args.headless else None,
        )
        # Try to use existing Chrome profile for authentication
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()

        print("\nOpening huntr.com/bounties/disclose/opensource ...")
        page.goto("https://huntr.com/bounties/disclose/opensource")
        page.wait_for_load_state("networkidle")

        # Check if logged in
        session = page.evaluate("() => fetch('/api/auth/session').then(r => r.json())")
        if not session.get("user"):
            print("ERROR: Not logged in. Open Chrome manually, log into huntr.com, then re-run.")
            browser.close()
            sys.exit(1)

        print(f"Logged in as: {session['user'].get('username', session['user'].get('email'))}")

        result_url = fill_form(page, data, submit=True)

        if result_url:
            print(f"\nReport URL: {result_url}")
            # Save to clipboard
            page.evaluate(f"() => navigator.clipboard?.writeText('{result_url}')")

        page.wait_for_timeout(3000)
        browser.close()


if __name__ == "__main__":
    main()
