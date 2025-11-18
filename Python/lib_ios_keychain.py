#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pull_keychain_and_print.py
SSH into a jailbroken iOS device, run keychain_dumper, and print an ASCII table.

Default target: root/alpine@192.168.0.105
Override with CLI flags, e.g.:
  python pull_keychain_and_print.py --host 192.168.0.105 --user root --password alpine

Columns:
- class
- acct (account)
- service/server
- accessible
- accessControl
- value (preview; maskable)

Notes:
- Requires: pip install paramiko
- iPhone must have keychain_dumper installed (e.g. /usr/bin/keychain_dumper)
"""

import argparse
import re
import socket
import sys
import textwrap
from typing import Dict, List, Optional

try:
    import paramiko
except ImportError:
    print("[!] Missing dependency: paramiko. Install with: pip install paramiko")
    sys.exit(1)


# ---------- Config ----------
DEFAULT_HOST = "192.168.0.105"
DEFAULT_USER = "root"
DEFAULT_PASS = "alpine"
VALUE_PREVIEW_LEN = 64
MASK_VALUES = False  # set True to mask secret values by default
# ----------------------------


def shorten(s: Optional[str], width: int) -> str:
    if not s:
        return ""
    s = str(s).replace("\r", " ").replace("\n", " ").strip()
    return textwrap.shorten(s, width=width, placeholder="…")


def mask(s: Optional[str]) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return "********"
    return s[:2] + "****" + s[-2:]


def find_keychain_dumper(ssh) -> Optional[str]:
    candidates = [
        "/usr/bin/keychain_dumper",
        "/usr/local/bin/keychain_dumper",
        "/bin/keychain_dumper",
        "keychain_dumper",
    ]
    for c in candidates:
        stdin, stdout, stderr = ssh.exec_command(f"test -x {c} && echo OK || which {c}")
        out = (stdout.read() or b"").decode().strip()
        err = (stderr.read() or b"").decode().strip()
        if out == "OK":
            return c
        if out and "keychain_dumper" in out:
            return out.strip()
    return None


def run_keychain_dumper(ssh, tool_path: str) -> str:
    # -a (all) if available; otherwise plain. Redirect stderr away to avoid TCC noise.
    # Many builds accept -a; if not, it will still dump default set.
    cmd = f"{tool_path} -a 2>/dev/null || {tool_path} 2>/dev/null"
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=False)
    out = (stdout.read() or b"").decode(errors="ignore")
    # do not rely on stderr; many jailbreak tools spam it
    return out


def parse_keychain_dumper(text: str) -> List[Dict[str, str]]:
    """
    Try to parse diverse outputs of keychain_dumper.
    It commonly prints entries separated by blank lines, with lines like:
      Keychain Item Class: genp
      Account: foo
      Service: com.example
      Accessible Attribute: kSecAttrAccessibleWhenUnlocked
      Access Control: UserPresence, ThisDeviceOnly
      Data: secret-value-here
    Some builds use short keys (acct/svce/agrp/...) or lowercase labels.

    We'll support a wide set of patterns and normalize to our columns.
    """
    # Split blocks by blank lines
    blocks = re.split(r"\n\s*\n", text.strip(), flags=re.MULTILINE)
    items: List[Dict[str, str]] = []

    # Define regex patterns (case-insensitive)
    pat_class = re.compile(r"(?:Keychain\s+Item\s+Class|class)\s*:\s*(.+)", re.I)
    pat_acct = re.compile(r"(?:Account|acct)\s*:\s*(.+)", re.I)
    pat_svce = re.compile(r"(?:Service|Server|svce|srvr)\s*:\s*(.+)", re.I)
    pat_accessible = re.compile(r"(?:Accessible(?:\s+Attribute)?|kSecAttrAccessible)\s*:\s*(.+)", re.I)
    pat_access_control = re.compile(r"(?:Access\s*Control|accessControl|acls?)\s*:\s*(.+)", re.I)
    pat_data = re.compile(r"(?:Data|value|pwd|blob|secret)\s*:\s*(.+)", re.I)

    # Also capture “short-form” kv lines like: class: genp, acct: foo, svce: bar, data: base64...
    # Already covered by regexes above.

    for raw_block in blocks:
        block = raw_block.strip()
        if not block:
            continue

        # Heuristic: ignore blocks that are pure headers or warnings
        if len(block.splitlines()) < 2:
            continue

        entry = {
            "class": "",
            "acct": "",
            "service": "",
            "accessible": "",
            "accessControl": "",
            "value": "",
        }

        # Greedy search line-by-line to be robust
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue

            m = pat_class.search(line)
            if m: entry["class"] = m.group(1).strip(); continue

            m = pat_acct.search(line)
            if m: entry["acct"] = m.group(1).strip(); continue

            m = pat_svce.search(line)
            if m: entry["service"] = m.group(1).strip(); continue

            m = pat_accessible.search(line)
            if m: entry["accessible"] = m.group(1).strip(); continue

            m = pat_access_control.search(line)
            if m: entry["accessControl"] = m.group(1).strip(); continue

            m = pat_data.search(line)
            if m: entry["value"] = m.group(1).strip(); continue

        # Only keep if it looks like a real item
        if any(entry.values()):
            items.append(entry)

    return items


def print_ascii_table(items: List[Dict[str, str]]):
    # Compute widths
    headers = ["class", "acct", "service/server", "accessible", "accessControl", "value"]
    col_widths = {h: len(h) for h in headers}

    # Prepare rows
    rows = []
    for it in items:
        cls = shorten(it.get("class", ""), 18)
        acct = shorten(it.get("acct", ""), 28)
        svce = shorten(it.get("service", ""), 40)
        accs = shorten(it.get("accessible", ""), 28)
        ac   = shorten(it.get("accessControl", ""), 28)
        val  = it.get("value", "")

        if MASK_VALUES and val:
            val = mask(val)

        val = shorten(val, VALUE_PREVIEW_LEN)

        row = [cls, acct, svce, accs, ac, val]
        rows.append(row)

        # track max width
        for h, v in zip(headers, row):
            col_widths[h] = max(col_widths[h], len(v))

    # Horizontal line
    def hline(char="-", cross="+"):
        segs = []
        for h in headers:
            segs.append(char * (col_widths[h] + 2))
        return cross + cross.join(segs) + cross

    # Print
    print(hline("=","+"))
    # Header row
    head_cells = []
    for h in headers:
        head_cells.append(" " + h.ljust(col_widths[h]) + " ")
    print("|" + "|".join(head_cells) + "|")
    print(hline("-","+"))

    # Body
    for r in rows:
        cells = []
        for h, v in zip(headers, r):
            cells.append(" " + v.ljust(col_widths[h]) + " ")
        print("|" + "|".join(cells) + "|")
    print(hline("=","+"))

    print(f"\nTotal items: {len(items)}")


def main():
    ap = argparse.ArgumentParser(description="SSH into iOS and dump keychain via keychain_dumper")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--password", default=DEFAULT_PASS)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--no-mask", action="store_true", help="show full values (do not mask)")
    args = ap.parse_args()

    global MASK_VALUES
    if args.no_mask:
        MASK_VALUES = False  # explicit
    # else keep default (False) unless you want masking by default

    print(f"[i] Connecting to {args.user}@{args.host}:{args.port} ...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(args.host, port=args.port, username=args.user, password=args.password, timeout=10)
    except (paramiko.SSHException, socket.error) as e:
        print(f"[!] SSH connect failed: {e}")
        sys.exit(2)

    try:
        tool = find_keychain_dumper(ssh)
        if not tool:
            print("[!] keychain_dumper not found on device.")
            print("    Please install it (e.g., via Cydia/Sileo) so it’s available at /usr/bin/keychain_dumper")
            sys.exit(3)

        print(f"[i] Using keychain_dumper at: {tool}")
        raw = run_keychain_dumper(ssh, tool)
        if not raw.strip():
            print("[!] Empty output from keychain_dumper. Ensure it has permissions on your jailbreak.")
            sys.exit(4)

        items = parse_keychain_dumper(raw)
        if not items:
            print("[!] No keychain items parsed. Raw output follows for troubleshooting:\n")
            print(raw[:4000])
            sys.exit(5)

        print_ascii_table(items)

    finally:
        ssh.close()


if __name__ == "__main__":
    main()
