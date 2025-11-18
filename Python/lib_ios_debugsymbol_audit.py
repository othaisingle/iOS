#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lib_ios_debugsymbol_audit.py
Professional iOS Debug Symbol Auditor (Windows Ready)

✅ Features
- Automatically downloads strings.exe from Microsoft Sysinternals if missing
- Extracts .ipa into a dedicated folder
- Dumps all binary strings to symbols.txt
- Searches /Users (or any keyword) from symbols.txt
- Analyzes DWARF sections & symbol counts via LIEF
- Displays a professional audit report (5 sections total)
"""

import zipfile
import plistlib
import shutil
import argparse
import sys
import urllib.request
import subprocess
import textwrap
from pathlib import Path
from textwrap import shorten
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

try:
    import lief
except Exception:
    lief = None


# ---------------------------------------------------------------------
# Utility: download strings.exe automatically if missing
# ---------------------------------------------------------------------
def ensure_strings_exe() -> Path | None:
    base_dir = Path(__file__).parent / "lib"
    base_dir.mkdir(exist_ok=True)
    strings_path = base_dir / "strings.exe"
    zip_path = base_dir / "Strings.zip"
    console = Console()

    if strings_path.exists():
        return strings_path

    console.print("[yellow]Downloading strings.exe from Microsoft Sysinternals...[/yellow]")
    url = "https://download.sysinternals.com/files/Strings.zip"

    try:
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for f in zf.namelist():
                if f.lower().endswith("strings.exe"):
                    zf.extract(f, base_dir)
                    extracted = base_dir / f
                    extracted.rename(strings_path)
                    break
        zip_path.unlink(missing_ok=True)
        console.print(f"[green]✓ strings.exe downloaded successfully at {strings_path}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to download strings.exe: {e}[/red]")
        console.print("[red]Please download manually from: https://learn.microsoft.com/en-us/sysinternals/downloads/strings[/red]")

    return strings_path if strings_path.exists() else None


# ---------------------------------------------------------------------
# Extract IPA & locate binary
# ---------------------------------------------------------------------
def extract_ipa(ipa_path: Path):
    extract_dir = ipa_path.parent / f"{ipa_path.stem}_Extracted"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(str(ipa_path), "r") as z:
        z.extractall(extract_dir)

    payload = extract_dir / "Payload"
    apps = list(payload.glob("*.app"))
    if not apps:
        raise FileNotFoundError("No .app found inside Payload/")
    return extract_dir, apps[0]


def read_info_plist(app_dir: Path):
    plist_path = app_dir / "Info.plist"
    if plist_path.exists():
        with plist_path.open("rb") as f:
            return plistlib.load(f)
    return {}


def locate_executable(app_dir: Path, info: dict):
    exe_name = info.get("CFBundleExecutable")
    if exe_name:
        candidate = app_dir / exe_name
        if candidate.exists():
            return candidate
    candidates = [p for p in app_dir.iterdir() if p.is_file() and not p.suffix]
    return max(candidates, key=lambda p: p.stat().st_size) if candidates else None


# ---------------------------------------------------------------------
# Dump strings
# ---------------------------------------------------------------------
def dump_strings_to_file(binary_path: Path, output_path: Path):
    console = Console()
    try:
        if sys.platform.startswith("win"):
            strings_exe = ensure_strings_exe()
            if not strings_exe:
                console.print("[red]strings.exe missing.[/red]")
                return False
            cmd = [str(strings_exe), "-nobanner", str(binary_path)]
        else:
            cmd = ["strings", str(binary_path)]

        with open(output_path, "w", encoding="utf-8", errors="ignore") as out:
            subprocess.run(cmd, stdout=out, stderr=subprocess.DEVNULL, text=True)
        console.print(f"[green]✓ Saved strings to {output_path}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Failed to run strings: {e}[/red]")
        return False


# ---------------------------------------------------------------------
# Search keyword
# ---------------------------------------------------------------------
def search_in_symbols_file(symbol_file: Path, term: str, limit=10):
    if not symbol_file.exists():
        return [f"[Error] symbols.txt not found: {symbol_file}"]
    with open(symbol_file, "r", encoding="utf-8", errors="ignore") as f:
        matches = [line.strip() for line in f if term.lower() in line.lower()]
    return matches[:limit] if matches else []


# ---------------------------------------------------------------------
# Binary inspection
# ---------------------------------------------------------------------
def inspect_binary(bin_path: Path, threshold: int = 50):
    result = {
        "path": str(bin_path),
        "status": "UNKNOWN",
        "dwarf_sections": [],
        "symbols_count": 0,
        "sample_symbols": [],
        "found_by_dwarf": False,
        "found_by_symbol_count": False,
    }

    if lief is None:
        result["error"] = "LIEF not installed"
        return result

    binary = lief.parse(str(bin_path))
    if not binary:
        result["status"] = "INVALID"
        return result

    dwarf_sections = [s.name for s in binary.sections if "__DWARF" in s.name or ".debug" in s.name]
    symbols = [s.name for s in binary.symbols if getattr(s, "name", None)]
    result["dwarf_sections"] = dwarf_sections
    result["symbols_count"] = len(symbols)
    result["sample_symbols"] = symbols[:10]
    result["found_by_dwarf"] = bool(dwarf_sections)
    result["found_by_symbol_count"] = len(symbols) > threshold
    result["status"] = "FOUND" if (result["found_by_dwarf"] or result["found_by_symbol_count"]) else "NOT_FOUND"
    return result


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------
def print_audit_report(ipa_path: Path, exe: Path, result: dict, threshold: int, symbol_file: Path, search_term: str):
    console = Console()

    # 1. PURPOSE
    console.rule("[bold green]1. PURPOSE OF INSPECTION[/bold green]", style="green")
    console.print(
        "This inspection determines whether the iOS application (.ipa) contains residual Debug Symbols "
        "(DWARF or symbol tables). It ensures that the final binary is stripped before production release, "
        "preventing disclosure of developer metadata.\n",
        style="white",
    )
    console.print(Panel(f"File analyzed: {ipa_path.name}\nExecutable: {exe.name}", border_style="grey58"))

    # 2. TECHNICAL ASSESSMENT TABLE
    console.rule("[bold green]2. TECHNICAL ASSESSMENT AND EVIDENCE TABLE[/bold green]", style="green")
    table = Table(box=box.SQUARE, show_lines=True, border_style="grey58", header_style="bold white")

    table.add_column("No.", justify="center", width=6)
    table.add_column("Inspection Criteria", width=50)
    table.add_column("Evidence / Data Reviewed", width=55)
    table.add_column("Assessment Result", justify="center", width=18)

    def mark(cond): return "[green]PASS[/]" if cond else "[red]FAIL[/]"
    dwarf_sections = ", ".join(result.get("dwarf_sections") or ["None detected"])
    symbols_count = result["symbols_count"]
    sample_symbols = ", ".join(result.get("sample_symbols") or ["No readable symbols"])

    table.add_row("1", "Presence of DWARF Sections", dwarf_sections, mark(not result["found_by_dwarf"]))
    table.add_row("2", f"Symbol Count (Threshold: {threshold})", f"{symbols_count} symbols", mark(not result["found_by_symbol_count"]))
    table.add_row("3", "Sample Symbols Review", shorten(sample_symbols, width=150, placeholder="..."), mark(result["status"] != "FOUND"))
    overall = "[green]PASS – Binary Stripped[/]" if result["status"] == "NOT_FOUND" else "[red]FAIL – Debug Symbols Found[/]"
    table.add_row("4", "Overall Assessment", "Combined evaluation of items 1–3", overall)

    console.print(table)

    # PRINCIPLE SUMMARY SECTION
    console.print()
    console.print("[bold grey70]Principle Summary[/bold grey70]")
    console.print(
        "[grey70]1. Mach-O binaries containing '__DWARF' or '.debug_*' sections indicate embedded debugging information.[/grey70]\n"
        "[grey70]2. Excessive symbols (> threshold) suggest that the binary was not stripped of debugging metadata.[/grey70]\n"
        "[grey70]3. Readable symbols such as 'radr://', '_OBJC_EHTYPE_', or class/function names indicate active debug mappings.[/grey70]\n"
        "[grey70]4. Combined evaluation of DWARF presence, symbol count, and sample review determines whether debug data remains.[/grey70]\n"
    )

    # 3. PROOF OF CONCEPT
    console.rule("[bold green]3. PROOF OF CONCEPT[/bold green]", style="green")
    console.print(
        Panel(
            f"[grey70]All extracted strings saved to:[/grey70]\n[bold]{symbol_file}[/bold]\n\n"
            f"[bold]Search keyword:[/bold] {search_term}",
            border_style="grey58",
        )
    )

    results = search_in_symbols_file(symbol_file, search_term)
    if results and not results[0].startswith("[Error]"):
        console.print(f"\n[bold grey70]Top matches for '{search_term}':[/bold grey70]")
        for r in results:
            wrapped = textwrap.fill(r, width=116, subsequent_indent=" " * 5)
            console.print(f"   • [white]{wrapped}[/white]")
    else:
        console.print(f"[green]No results found for '{search_term}'. Binary likely stripped.[/green]")

    # 4. SECURITY IMPLICATIONS
    console.rule("[bold green]4. SECURITY IMPLICATIONS[/bold green]", style="green")
    console.print(
        Panel(
            "[grey70]- [bold]Confidentiality[/bold]: Debug info can expose file paths, API names, or internal code structures.\n"
            "- [bold]Integrity[/bold]: May aid attackers in understanding or modifying app logic.\n"
            "- [bold]Availability[/bold]: Could assist in crafting targeted attacks or exploit attempts.[/grey70]",
            border_style="grey58",
        )
    )

    # 5. TECHNICAL RECOMMENDATIONS
    console.rule("[bold green]5. TECHNICAL RECOMMENDATIONS[/bold green]", style="green")
    if result["status"] == "FOUND":
        rec = Table(box=box.SQUARE, border_style="grey58", show_lines=True)
        rec.add_column("Recommended Xcode Build Configuration", style="white", width=60)
        rec.add_column("Value", justify="center", style="white", width=10)
        rec.add_row("Generate Debug Symbols", "NO")
        rec.add_row("Debug Information Format", "DWARF with dSYM File")
        rec.add_row("Strip Debug Symbols During Copy", "YES")
        rec.add_row("Deployment Postprocessing", "YES")
        rec.add_row("Strip Linked Product", "YES")
        console.print(rec)
    else:
        console.print("[green]Binary appears production-safe; no debug symbols found.[/green]")

    console.print(Panel(f"Strings dump file saved at: {symbol_file}", border_style="grey58"))


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Audit iOS IPA for Debug Symbols (Windows Ready)")
    parser.add_argument("ipa", help="Path to .ipa file")
    parser.add_argument("--threshold", type=int, default=50)
    parser.add_argument("--search", type=str, default="/Users")
    args = parser.parse_args()

    ipa_path = Path(args.ipa)
    if not ipa_path.exists():
        print(f"[!] File not found: {ipa_path}")
        sys.exit(1)

    extract_dir, app_dir = extract_ipa(ipa_path)
    info = read_info_plist(app_dir)
    exe = locate_executable(app_dir, info)
    if not exe:
        print("[!] Executable not found.")
        sys.exit(1)

    result = inspect_binary(exe, args.threshold)
    symbol_file = extract_dir / "symbols.txt"
    dump_strings_to_file(exe, symbol_file)
    print_audit_report(ipa_path, exe, result, args.threshold, symbol_file, args.search)


if __name__ == "__main__":
    main()
