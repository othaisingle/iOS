#!/usr/bin/env python3
r"""
lib_inj_frida.py (adaptive)
-------------------------------------------------------------
Try multiple strategies to reduce "app crash on launch" after gadget injection.

Key flags:
  --placement {frameworks,root}   Where to place the dylib inside .app (default: frameworks)
  --no-config                      Do not write gadget config next to dylib
  --stealth-name NAME              Dylib name inside bundle (default: libAudioCodecSupport.dylib)
  --gadget-build {arm64,universal} Prefer which build (default: arm64)
  --weak                           Use LC_LOAD_WEAK_DYLIB via optool (if available)
  --keep-temp                      Keep extracted IPA folder for inspection

Usage:
  python lib_inj_frida.py --ipa app.ipa
  python lib_inj_frida.py --ipa app.ipa --placement root --no-config
  python lib_inj_frida.py --ipa app.ipa --weak
  python lib_inj_frida.py --ipa app.ipa --stealth-name CoreAudioCodec.dylib
-------------------------------------------------------------
"""
from __future__ import annotations
import argparse, gzip, lzma, os, plistlib, shutil, sys, tempfile, time, zipfile
from pathlib import Path
from subprocess import run, CalledProcessError
from typing import Optional, List

def log(m): print(f"[*] {m}")
def err(m): print(f"[!] {m}", file=sys.stderr)
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def os_walk(p: Path): return __import__("os").walk(str(p))

# ---------------- Frida download ----------------
def get_frida_version() -> Optional[str]:
    try:
        import frida
        return getattr(frida, "__version__", None)
    except Exception:
        return None

def try_download(url: str, dest: Path) -> bool:
    log(f"Trying: {url}")
    try:
        import requests
        with requests.get(url, stream=True, timeout=30) as r:
            if r.status_code != 200:
                log(f"  -> HTTP {r.status_code}")
                return False
            with open(dest, "wb") as f:
                for chunk in r.iter_content(8192):
                    if chunk: f.write(chunk)
        return True
    except Exception:
        from urllib.request import urlopen, Request
        try:
            req = Request(url, headers={"User-Agent":"python"})
            with urlopen(req, timeout=30) as r, open(dest,"wb") as f:
                shutil.copyfileobj(r, f)
            return True
        except Exception as e:
            err(f"Download failed: {e}")
            return False

def decompress(src: Path, dest: Path) -> bool:
    try:
        name = src.name.lower()
        if name.endswith(".gz"):
            log("Decompressing gzip...")
            import gzip as _gz
            with _gz.open(src, "rb") as fi, open(dest, "wb") as fo: shutil.copyfileobj(fi, fo)
        elif name.endswith(".xz"):
            log("Decompressing xz...")
            import lzma as _xz
            with _xz.open(src, "rb") as fi, open(dest, "wb") as fo: shutil.copyfileobj(fi, fo)
        else:
            shutil.copy2(src, dest)
        return True
    except Exception as e:
        err(f"Decompression error: {e}")
        return False

def download_gadget(lib_dir: Path, prefer_build: str) -> Path:
    ensure_dir(lib_dir)
    ver = get_frida_version()
    if not ver:
        err("Cannot detect Frida version. pip install frida"); sys.exit(2)
    log(f"Detected Frida version: {ver}")

    order = (["arm64","universal"] if prefer_build=="arm64" else ["universal","arm64"])
    names = []
    for b in order:
        names += [
            f"frida-gadget-{ver}-ios-{b}.dylib.gz",
            f"frida-gadget-{ver}-ios-{b}.dylib.xz",
            f"frida-gadget-{ver}-ios-{b}.dylib",
        ]

    base = f"https://github.com/frida/frida/releases/download/{ver}/"
    tmp = Path(tempfile.mkdtemp(prefix="fridadl_"))
    out = lib_dir / "gadget-ios.dylib"
    try:
        for n in names:
            u = base + n
            t = tmp / n
            if try_download(u, t) and decompress(t, out):
                log(f"Saved gadget: {out}")
                return out
        err("Failed to download gadget for your frida version."); sys.exit(3)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ---------------- IPA helpers ----------------
def unzip_to(ipa: Path, dst: Path):
    log(f"Unzipping {ipa} -> {dst}")
    with zipfile.ZipFile(ipa,"r") as z: z.extractall(dst)

def list_apps(root: Path) -> List[Path]:
    p = root/"Payload"
    return sorted([x for x in p.glob("*.app") if x.is_dir()]) if p.exists() else []

def pick_largest(apps: List[Path]) -> Optional[Path]:
    if not apps: return None
    def size(d: Path) -> int:
        tot=0
        for r,_,fs in os_walk(d):
            rp = Path(r)
            for f in fs:
                try: tot += (rp/f).stat().st_size
                except: pass
        return tot
    return max(apps, key=size)

def read_info(app: Path) -> dict:
    with open(app/"Info.plist","rb") as f: return plistlib.load(f)

def resolve_exec(app: Path, name: Optional[str]) -> Path:
    if name:
        p = app/name
        if p.exists(): return p
        cand = list(app.glob(name+"*"))
        if cand: return cand[0]
    files = [p for p in app.iterdir() if p.is_file() and "." not in p.name]
    return max(files, key=lambda p: p.stat().st_size) if files else app/"UNKNOWN_EXEC"

# ---------------- Placement & config ----------------
def place_dylib_frameworks(dylib: Path, app: Path, new_name: str) -> Path:
    fw = app/"Frameworks"; ensure_dir(fw)
    dest = fw/new_name
    log(f"Copying {dylib} -> {dest}")
    shutil.copy2(dylib, dest)
    try: dest.chmod(0o644)
    except: pass
    return dest

def place_dylib_root(dylib: Path, app: Path, new_name: str) -> Path:
    dest = app/new_name
    log(f"Copying {dylib} -> {dest}")
    shutil.copy2(dylib, dest)
    try: dest.chmod(0o644)
    except: pass
    return dest

def write_config(next_to: Path, logging_level: str, addr: str, port: int, on_load="resume"):
    cfg = next_to.with_suffix(".config")
    s = (
        '{'
        f'"interaction":{{"type":"listen","address":"{addr}","port":{port},"on_load":"{on_load}"}},'
        f'"logging":{{"level":"{logging_level}"}}'
        '}'
    )
    cfg.write_text(s, encoding="utf-8")
    try: cfg.chmod(0o644)
    except: pass
    log(f"Wrote config: {cfg.name}")

# ---------------- Injection ----------------
def which_optool() -> Optional[str]:
    from shutil import which
    return which("optool")

def try_import_lief():
    try:
        import lief
        return lief
    except Exception:
        return None

def inject_with_optool(optool: str, exe: Path, dylib_rel: str, weak: bool):
    cmd = [optool, "install", "-c", ("weak" if weak else "load"), "-p", dylib_rel, "-t", str(exe)]
    # บาง optool ใช้ -W มากกว่า "weak"
    if weak:
        cmd = [optool, "install", "-W", "-p", dylib_rel, "-t", str(exe)]
    log("Using optool: " + " ".join(cmd))
    try:
        run(cmd, check=True)
    except CalledProcessError as e:
        err(f"optool failed (code {e.returncode})"); raise

def list_lief_libs(macho) -> List[str]:
    libs=[]
    for lib in getattr(macho,"libraries",[]):
        name = getattr(lib,"name",None) or (str(lib) if lib is not None else "")
        libs.append(name)
    return libs

def inject_with_lief(exe: Path, dylib_rel: str):
    lief = try_import_lief()
    if not lief: raise RuntimeError("LIEF not available. pip install lief")
    log("Using LIEF to inject LC_LOAD_DYLIB...")
    fat = lief.parse(str(exe))
    if fat is None: raise RuntimeError("LIEF parse failed.")
    try:
        slices = [s for s in fat]  # fat
    except TypeError:
        slices = [fat]             # thin
    changed=False
    for m in slices:
        if dylib_rel in list_lief_libs(m):
            log(f"Already present: {dylib_rel}"); continue
        try:
            m.add_library(dylib_rel)  # LIEF doesn't expose weak easily; strong load here
            changed=True; log(f"Added: {dylib_rel}")
        except Exception as e:
            err(f"LIEF add_library failed: {e}")
    fat.write(str(exe))
    log("LIEF injection complete." if changed else "No change (already present).")

# ---------------- Repack ----------------
def rezip(src: Path, dest: Path):
    log(f"Repacking -> {dest}")
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for r,_,fs in os_walk(src):
            rp = Path(r)
            for f in fs:
                p = rp/f
                z.write(p, p.relative_to(src))
    try: dest.chmod(0o644)
    except: pass

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Adaptive Frida Gadget injector for .ipa")
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--force","-f", action="store_true")
    ap.add_argument("--placement", choices=["frameworks","root"], default="frameworks")
    ap.add_argument("--stealth-name", default="libAudioCodecSupport.dylib")
    ap.add_argument("--gadget-build", choices=["arm64","universal"], default="arm64")
    ap.add_argument("--no-config", action="store_true")
    ap.add_argument("--logging-level", choices=["trace","debug","info","warning","error","fatal"], default="info")
    ap.add_argument("--listen-addr", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=27042)
    ap.add_argument("--optool-path")
    ap.add_argument("--weak", action="store_true", help="Use weak load with optool if possible")
    ap.add_argument("--keep-temp", action="store_true")
    args = ap.parse_args()

    ipa = Path(args.ipa).resolve()
    if not ipa.exists(): err(f"IPA not found: {ipa}"); sys.exit(1)

    out = ipa.with_name(ipa.stem + "_modified.ipa")
    if out.exists() and not args.force:
        err(f"{out} exists. Use --force to overwrite."); sys.exit(2)

    base = Path(__file__).resolve().parent
    libdir = base/"lib"
    dylib = download_gadget(libdir, args.gadget_build)

    tmp = Path(tempfile.mkdtemp(prefix="ipa_inj_"))
    try:
        unzip_to(ipa, tmp)
        apps = list_apps(tmp); app = pick_largest(apps)
        if not app: err("No .app found in Payload/"); sys.exit(3)
        log(f"Selected app bundle: {app.name}")

        info = read_info(app)
        exe = resolve_exec(app, info.get("CFBundleExecutable"))
        log(f"Executable: {exe.relative_to(tmp)}")

        # placement
        if args.placement == "frameworks":
            placed = place_dylib_frameworks(dylib, app, args.stealth_name)
            rel = f"@executable_path/Frameworks/{placed.name}"
            cfg_dir = app/"Frameworks"
        else:
            placed = place_dylib_root(dylib, app, args.stealth_name)
            rel = f"@executable_path/{placed.name}"
            cfg_dir = app

        # config
        if not args.no_config:
            write_config(cfg_dir/placed.name, args.logging_level, args.listen_addr, args.listen_port)

        # inject
        injected=False
        optool = args.optool_path or which_optool()
        if optool:
            try:
                inject_with_optool(optool, exe, rel, weak=args.weak); injected=True
            except Exception as e:
                err(f"optool injection failed: {e}")
        if not injected:
            try:
                inject_with_lief(exe, rel); injected=True
            except Exception as e:
                err(f"LIEF injection failed: {e}")
        if not injected:
            err("Injection failed. You can try --no-config, switch --placement, or run on macOS with optool.")

        # repack
        rezip(tmp, out)
        log(f"Modified IPA saved: {out}")
        log("Re-sign and install (e.g., Sideloadly). If it still crashes, try another --placement or --no-config and check idevicesyslog.")
    finally:
        if args.keep_temp:
            log(f"Keeping temp at: {tmp}")
        else:
            time.sleep(0.05)
            shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
