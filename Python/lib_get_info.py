#!/usr/bin/env python3
"""
lib_display_info.py
──────────────────────────────────────────────────────────────────────────────
IPA quick summary by default (no big tables). Pretty table only when --search is used.

Behavior:
- Default: print a one‑page app/provisioning SUMMARY (no table)
  • Info.plist path, .app path, Bundle Identifier, Version, Min iOS
  • Provision Name, UUID, TeamName, AppIDName, ExpirationDate
  • Counts (Info keys, Provision keys, App Extensions)
- --search <keyword>: show ONLY matching key/value rows in a pretty, wrapped table

No third‑party tools required except `tabulate` for pretty tables (only used on --search).
Install:  pip install tabulate
"""

import zipfile
import plistlib
import re
import argparse
import json
import textwrap
from pathlib import PurePosixPath
from tabulate import tabulate

# ─────────────────────────────────────────────────────────────────────────────
# Parsers & helpers
# ─────────────────────────────────────────────────────────────────────────────

def extract_plist_from_provision(data: bytes):
    pattern = re.compile(br'<\?xml.*?<plist[\s\S]*?</plist>', re.DOTALL)
    m = pattern.search(data)
    if not m:
        return {}
    try:
        return plistlib.loads(m.group(0))
    except Exception:
        return {}


def flatten(prefix, obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten(f"{prefix}.{k}" if prefix else k, v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from flatten(f"{prefix}[{i}]", v)
    else:
        yield prefix, obj


def safe_str(value):
    try:
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", errors="ignore")
            except Exception:
                return repr(value)
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)
    except Exception:
        return repr(value)


def find_first(z: zipfile.ZipFile, pattern: str):
    import fnmatch
    for name in z.namelist():
        if fnmatch.fnmatch(name, pattern):
            return name
    return None


def find_all(z: zipfile.ZipFile, pattern: str):
    import fnmatch
    return [n for n in z.namelist() if fnmatch.fnmatch(n, pattern)]


def prewrap_rows(rows, wrap_width: int):
    w = max(20, wrap_width)
    out = []
    for k, v in rows:
        k_wrapped = "\n".join(textwrap.wrap(k, width=min(60, w)))
        v_wrapped = "\n".join(textwrap.wrap(v, width=w)) if v else ""
        out.append((k_wrapped, v_wrapped))
    return out

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main(ipa_path: str, keyword: str | None, wrap: int):
    if not zipfile.is_zipfile(ipa_path):
        print("Invalid IPA file.")
        return

    with zipfile.ZipFile(ipa_path, 'r') as z:
        info_path = find_first(z, 'Payload/*.app/Info.plist')
        prov_path = find_first(z, 'Payload/*.app/embedded.mobileprovision')
        appex_infos = find_all(z, 'Payload/*.app/PlugIns/*.appex/Info.plist')

        info = {}
        prov = {}
        if info_path:
            with z.open(info_path) as f:
                info = plistlib.load(f)
        if prov_path:
            with z.open(prov_path) as f:
                prov = extract_plist_from_provision(f.read())

    # Derive paths
    app_dir = None
    if info_path:
        p = PurePosixPath(info_path)
        app_dir = str(p.parent)

    # Summary fields
    bundle_id = safe_str(info.get('CFBundleIdentifier', ''))
    ver_short = safe_str(info.get('CFBundleShortVersionString', ''))
    ver_build = safe_str(info.get('CFBundleVersion', ''))
    min_os = safe_str(info.get('MinimumOSVersion', ''))

    prov_name = safe_str(prov.get('Name', ''))
    prov_uuid = safe_str(prov.get('UUID', ''))
    prov_team = safe_str(prov.get('TeamName', ''))
    prov_appid = safe_str(prov.get('AppIDName', ''))
    prov_exp = safe_str(prov.get('ExpirationDate', ''))

    # Build flattened rows (strings) for optional search
    pairs = []
    pairs.extend((f"Info.{k}", v) for k, v in flatten('', info))
    pairs.extend((f"Provision.{k}", v) for k, v in flatten('', prov))
    rows = [(str(k), safe_str(v)) for k, v in pairs]

    if not keyword:
        # ── DEFAULT: SUMMARY ONLY (render pretty table) ───────────────────────
        summary = []
        summary.append(("IPA file", ipa_path))
        if info_path:
            summary.append(("Info.plist path", info_path))
        if app_dir:
            summary.append((".app path", app_dir))
        if prov_path:
            summary.append(("Provision path", prov_path))
        if bundle_id:
            summary.append(("Bundle Identifier", bundle_id))
        if ver_short or ver_build:
            v = ver_short if ver_short else "?"
            b = ver_build if ver_build else "?"
            summary.append(("Version", f"{v} (build {b})"))
        if min_os:
            summary.append(("Minimum iOS", min_os))
        if prov_name:
            summary.append(("Provision Name", prov_name))
        if prov_uuid:
            summary.append(("Provision UUID", prov_uuid))
        if prov_team:
            summary.append(("Team Name", prov_team))
        if prov_appid:
            summary.append(("AppID Name", prov_appid))
        if prov_exp:
            summary.append(("Expiration Date", prov_exp))
        
        # Ensure pure strings and render
        summary = [(str(k), str(v)) for k, v in summary]
        print(tabulate(summary, headers=["Field", "Value"], tablefmt="fancy_grid", stralign="left", disable_numparse=True))
        return

    # ── SEARCH MODE: pretty table with wrapping ─────────────────────────────
    kw = keyword.lower()
    filt = [(k, v) for k, v in rows if kw in k.lower() or kw in v.lower()]

    if not filt:
        print(f"No matching results for: {keyword}")
        return

    wrapped = prewrap_rows(filt, wrap)
    print(tabulate(wrapped, headers=["Key", "Value"], tablefmt="fancy_grid", stralign="left", disable_numparse=True))
    print(f"\nMatched rows: {len(filt)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPA inspector: summary by default; table only when searching.")
    parser.add_argument('ipa', help='Path to .ipa file')
    parser.add_argument('--search', '-s', help='Search keyword (optional)')
    parser.add_argument('--wrap', type=int, default=80, help='Wrap width for Value column when searching (default: 80)')
    args = parser.parse_args()
    main(args.ipa, args.search, args.wrap)
