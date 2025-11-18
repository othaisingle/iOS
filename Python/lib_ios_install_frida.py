import os
import sys
import subprocess
import paramiko
import requests

# ----------------- CONFIG -----------------
IOS_IP = "192.168.0.105"
IOS_USER = "root"
IOS_PASS = "alpine"

# Default Frida version for Objection-friendly setup
DEFAULT_FRIDA_VERSION = "16.7.19"
DEFAULT_FRIDA_TOOLS_VERSION = "13.7.1"
# -----------------------------------------


# --------------------------------------------------------
# Helper: run pip commands using the current Python
# --------------------------------------------------------
def run_pip(args, check=False):
    """
    Run `python -m pip <args>` using the current interpreter.
    """
    cmd = [sys.executable, "-m", "pip"] + args
    print(f"[pip] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        raise RuntimeError(f"pip command failed: {' '.join(cmd)}")
    return result.returncode


# --------------------------------------------------------
# Step 0: Clean & install Frida / Frida-tools on Windows
# --------------------------------------------------------
def setup_frida_on_windows():
    """
    1) Uninstall all existing frida / frida-tools.
    2) Fetch latest Frida release from GitHub.
    3) Let the user choose between:
       - Latest version from GitHub
       - Default version 16.7.19 (stable for Objection)
    4) Install frida + frida-tools accordingly.
    5) Return the chosen Frida version (as seen by import frida).
    """

    print("[0] Cleaning existing Frida / Frida-tools installation on Windows ...")
    run_pip(["uninstall", "-y", "frida", "frida-tools"])

    print("[0] Fetching latest Frida version from GitHub ...")
    try:
        resp = requests.get(
            "https://api.github.com/repos/frida/frida/releases/latest",
            timeout=10
        )
        data = resp.json()
        latest_tag = data.get("tag_name", "").lstrip("v")
        if not latest_tag:
            raise ValueError("Empty tag_name from GitHub API")
        print(f"[0] Latest Frida version on GitHub: {latest_tag}")
    except Exception as e:
        print(f"[!] Failed to fetch latest version from GitHub: {e}")
        print(f"[!] Falling back to default version: {DEFAULT_FRIDA_VERSION}")
        latest_tag = DEFAULT_FRIDA_VERSION

    print("")
    print("=== Frida version selection ===")
    print(f"[1] Latest from GitHub : {latest_tag}")
    print(f"[2] Default (Objection-friendly) : {DEFAULT_FRIDA_VERSION}")
    choice = input("Choose Frida version [1/2] (press Enter for default 2): ").strip()

    if choice == "1":
        target_version = latest_tag
        print(f"[0] You selected LATEST Frida version: {target_version}")
        run_pip(["install", "--upgrade", "frida-tools"], check=True)
    else:
        target_version = DEFAULT_FRIDA_VERSION
        print(f"[0] You selected DEFAULT Frida version: {target_version}")
        run_pip(
            ["install", f"frida=={target_version}", f"frida-tools=={DEFAULT_FRIDA_TOOLS_VERSION}"],
            check=True,
        )

    try:
        import importlib
        import frida  # type: ignore

        importlib.reload(frida)
        current_version = frida.__version__
        print(f"[0] Windows Frida Python package version: {current_version}")

        if current_version != target_version:
            print(
                f"[!] WARNING: Installed Frida version ({current_version}) "
                f"differs from target ({target_version}). "
                f"Frida-server will use {current_version}."
            )
            target_version = current_version
    except Exception as e:
        raise RuntimeError(
            f"Failed to import Frida after installation. Error: {e}"
        )

    print(f"[0] Frida environment on Windows is ready. Using version: {target_version}")
    return target_version


# --------------------------------------------------------
# Locate 7z.exe automatically
# --------------------------------------------------------
def locate_7zip():
    possible_paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for p in possible_paths:
        if os.path.exists(p):
            return p
    raise Exception("❌ 7z.exe not found! Please install 7-Zip on Windows.")


# --------------------------------------------------------
# SSH connect to iPhone
# --------------------------------------------------------
def ssh_connect():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(IOS_IP, username=IOS_USER, password=IOS_PASS)
    return ssh


# --------------------------------------------------------
# Execute command on iPhone (blocking)
# --------------------------------------------------------
def ssh_exec(ssh, cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return out, err


# --------------------------------------------------------
# Detect jailbreak type: rootful / rootless
# --------------------------------------------------------
def detect_jb_mode(ssh):
    out, _ = ssh_exec(ssh, "ls /var/jb 2>/dev/null || echo NOJB")
    if "NOJB" in out:
        print("[+] Device is: ROOTFUL jailbreak")
        return "rootful"
    else:
        print("[+] Device is: ROOTLESS jailbreak")
        return "rootless"


# --------------------------------------------------------
# Detect iOS architecture (32/64-bit)
# --------------------------------------------------------
def detect_ios_arch(ssh):
    out, _ = ssh_exec(ssh, "uname -m 2>/dev/null")
    arch_raw = (out or "").strip()
    print(f"[+] Detected iOS arch (uname -m): {arch_raw or 'unknown'}")

    arch_lower = arch_raw.lower()

    if arch_raw.startswith("arm64") or arch_raw.startswith("arm64e"):
        return "arm64"
    if arch_raw.startswith("armv7") or arch_raw.startswith("armv6"):
        return "arm"

    if arch_lower.startswith("iphone") or arch_lower.startswith("ipad") or arch_lower.startswith("ipod"):
        print("[+] Detected device identifier, assuming 64-bit (arm64).")
        return "arm64"

    print("[!] Unknown architecture, falling back to 'arm'")
    return "arm"


# --------------------------------------------------------
# Choose .deb name candidates based on version + architecture
# --------------------------------------------------------
def choose_deb_names(version, arch):
    candidates = []
    if arch == "arm64":
        candidates.append(f"frida_{version}_iphoneos-arm64.deb")
        candidates.append(f"frida_{version}_iphoneos-arm.deb")
    else:
        candidates.append(f"frida_{version}_iphoneos-arm.deb")
    return candidates


# --------------------------------------------------------
# Download + extract frida-server and frida-agent from .deb using 7-Zip
# --------------------------------------------------------
def download_and_extract_frida_binaries(version, arch):
    candidates = choose_deb_names(version, arch)

    last_status = None
    content = None

    for name in candidates:
        url = f"https://github.com/frida/frida/releases/download/{version}/{name}"
        print(f"[+] Trying download: {url}")
        r = requests.get(url)
        last_status = r.status_code
        if r.status_code == 200:
            content = r.content
            print(f"[+] Found matching .deb: {name}")
            break
        else:
            print(f"[!] Not found ({r.status_code}): {name}")

    if content is None:
        raise Exception(
            f"❌ ERROR: No suitable .deb found for version {version} and arch {arch}. "
            f"Last HTTP status: {last_status}"
        )

    for f in ["frida.deb", "data.tar", "data.tar.xz"]:
        if os.path.exists(f):
            os.remove(f)
    if os.path.isdir("usr"):
        import shutil
        shutil.rmtree("usr", ignore_errors=True)
    if os.path.isdir("var"):
        import shutil
        shutil.rmtree("var", ignore_errors=True)

    with open("frida.deb", "wb") as f:
        f.write(content)
    print("[+] Downloaded: frida.deb")

    sevenzip = locate_7zip()
    print("[+] Extracting .deb using 7-Zip ...")

    subprocess.run([sevenzip, "x", "-y", "frida.deb"], check=True)

    if os.path.exists("data.tar.xz"):
        subprocess.run([sevenzip, "x", "-y", "data.tar.xz"], check=True)

    if not os.path.exists("data.tar"):
        raise Exception("❌ data.tar not found after extracting .deb")

    subprocess.run([sevenzip, "x", "-y", "data.tar"], check=True)

    frida_server_local = None
    frida_agent_local = None
    preferred_server = None

    for root, dirs, files in os.walk("."):
        # frida-server
        if "frida-server" in files:
            full_path = os.path.join(root, "frida-server")
            norm = full_path.replace("\\", "/")
            if "/var/jb/usr/sbin/frida-server" in norm or "/usr/sbin/frida-server" in norm:
                preferred_server = full_path
            if frida_server_local is None:
                frida_server_local = full_path

        # frida-agent.dylib
        if "frida-agent.dylib" in files:
            full_agent = os.path.join(root, "frida-agent.dylib")
            frida_agent_local = full_agent

    if preferred_server:
        frida_server_local = preferred_server

    if not frida_server_local:
        print("[!] Dumping extracted tree for debugging:")
        for root, dirs, files in os.walk("."):
            print(root, "dirs:", dirs, "files:", files)
        raise Exception("❌ frida-server not found inside extracted .deb!")

    print(f"[+] SUCCESS: Found local frida-server at: {frida_server_local}")
    if frida_agent_local:
        print(f"[+] SUCCESS: Found local frida-agent at: {frida_agent_local}")
    else:
        print("[!] WARNING: frida-agent.dylib not found inside extracted .deb. "
              "Frida/Objection may fail to inject agents.")

    return frida_server_local, frida_agent_local


# --------------------------------------------------------
# Upload frida-server (+ frida-agent) to iPhone
# --------------------------------------------------------
def upload_frida_binaries(ssh, mode, local_server_path, local_agent_path=None):
    sftp = ssh.open_sftp()

    if mode == "rootful":
        remote_server = "/usr/sbin/frida-server"
        mkdir_server = "mkdir -p /usr/sbin"
        remote_agent = "/usr/lib/frida/frida-agent.dylib"
        mkdir_agent = "mkdir -p /usr/lib/frida"
    else:
        remote_server = "/var/jb/usr/sbin/frida-server"
        mkdir_server = "mkdir -p /var/jb/usr/sbin"
        remote_agent = "/var/jb/usr/lib/frida/frida-agent.dylib"
        mkdir_agent = "mkdir -p /var/jb/usr/lib/frida"

    print(f"[+] Preparing remote directory for: {remote_server}")
    ssh_exec(ssh, mkdir_server)

    if local_agent_path:
        print(f"[+] Preparing remote directory for agent: {remote_agent}")
        ssh_exec(ssh, mkdir_agent)

    print("[+] Stopping any existing frida-server before upload ...")
    ssh_exec(ssh, "killall -9 frida-server 2>/dev/null || true")

    print(f"[+] Uploading frida-server to: {remote_server}")
    sftp.put(local_server_path, remote_server)
    sftp.chmod(remote_server, 0o755)

    if local_agent_path:
        print(f"[+] Uploading frida-agent.dylib to: {remote_agent}")
        sftp.put(local_agent_path, remote_agent)
        sftp.chmod(remote_agent, 0o644)

    sftp.close()
    print("[+] Upload complete.")

    print("[+] Ensuring no old frida-server instances are running ...")
    ssh_exec(ssh, "killall -9 frida-server 2>/dev/null || true")

    print("[+] Starting new frida-server (non-blocking) ...")
    ssh.exec_command(f"nohup {remote_server} >/dev/null 2>&1 &")

    print("[+] frida-server start command sent.")


# --------------------------------------------------------
# Main
# --------------------------------------------------------
def main():
    chosen_frida_version = setup_frida_on_windows()

    print("\n[1] Connecting to iPhone over SSH ...")
    ssh = ssh_connect()

    print("[2] Detecting jailbreak mode ...")
    mode = detect_jb_mode(ssh)

    print("[3] Detecting iOS architecture ...")
    arch = detect_ios_arch(ssh)

    print(f"[4] Downloading + extracting frida-server {chosen_frida_version} for arch {arch} ...")
    local_frida_server, local_frida_agent = download_and_extract_frida_binaries(
        chosen_frida_version, arch
    )

    print("[5] Uploading frida-server (and agent) to device ...")
    upload_frida_binaries(ssh, mode, local_frida_server, local_frida_agent)

    print("[6] frida-server should now be running on the device.")
    print("[7] Testing connection using: frida-ps -Ua")
    os.system("frida-ps -Ua || echo 'NOTE: frida-ps -Ua failed or device not detected.'")


if __name__ == "__main__":
    main()
