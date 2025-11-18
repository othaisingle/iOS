#!/usr/bin/env python3
# lldb_attach_search_and_run_manual.py
# Search apps on iOS, ask user to open manually, find PID, attach LLDB, interactive console

import paramiko
import time
import sys
import shlex

PROMPT = "(lldb)"
READ_TIMEOUT = 0.3


def show_status(msg):
    print(f"[status] {msg}")
    sys.stdout.flush()


def run_ssh_command(ssh, command, timeout=10):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    exit_status = stdout.channel.recv_exit_status()
    return out, err, exit_status


def open_interactive_shell(ssh):
    chan = ssh.invoke_shell(term="vt100")
    time.sleep(0.5)
    chan.send("\n")
    time.sleep(0.2)
    wait_for_data(chan, timeout=1.0)
    return chan


def wait_for_data(chan, timeout=READ_TIMEOUT):
    all_output = ""
    end_time = time.time() + timeout
    while True:
        if chan.recv_ready():
            data = chan.recv(4096).decode(errors="ignore")
            sys.stdout.write(data)
            sys.stdout.flush()
            all_output += data
            end_time = time.time() + timeout
        else:
            time.sleep(0.05)
            if time.time() > end_time:
                break
    return all_output


def search_apps(ssh, keyword):
    paths_to_search = [
        "/Applications",
        "/var/containers/Bundle/Application",
        "/var/mobile/Containers/Bundle/Application",
    ]
    matches = []

    for base in paths_to_search:
        cmd = f"ls -1 {shlex.quote(base)} 2>/dev/null || true"
        out, _, _ = run_ssh_command(ssh, cmd)
        if not out:
            continue
        for line in out.splitlines():
            line = line.strip()
            if line.lower().endswith(".app"):
                app_path = f"{base}/{line}"
                if keyword.lower() in line.lower():
                    exe_guess = line[:-4]
                    out2, _, _ = run_ssh_command(
                        ssh, f"ls -1 {shlex.quote(app_path)} 2>/dev/null || true"
                    )
                    exe_name = None
                    for f in out2.splitlines():
                        f = f.strip()
                        if f == exe_guess or ("." not in f):
                            exe_name = f
                            break
                    if exe_name:
                        matches.append((line, app_path, exe_name))
            else:
                subdir = f"{base}/{line}"
                find_cmd = f"find {shlex.quote(subdir)} -maxdepth 2 -type d -name '*.app' 2>/dev/null || true"
                out3, _, _ = run_ssh_command(ssh, find_cmd)
                for appdir in out3.splitlines():
                    appdir = appdir.strip()
                    if keyword.lower() in appdir.lower():
                        disp = appdir.split("/")[-1]
                        exe_guess = disp[:-4] if disp.lower().endswith(".app") else disp
                        out4, _, _ = run_ssh_command(
                            ssh, f"ls -1 {shlex.quote(appdir)} 2>/dev/null || true"
                        )
                        exe_name = None
                        for f in out4.splitlines():
                            f = f.strip()
                            if f == exe_guess or ("." not in f):
                                exe_name = f
                                break
                        if exe_name:
                            matches.append((disp, appdir, exe_name))

    # Deduplicate
    unique = []
    seen = set()
    for t in matches:
        if t[1] not in seen:
            unique.append(t)
            seen.add(t[1])
    return unique


def find_running_pids(ssh, executable_name):
    cmds = [
        "ps -e -o pid,comm 2>/dev/null || true",
        "ps aux 2>/dev/null || true",
    ]
    results = []
    for cmd in cmds:
        out, _, _ = run_ssh_command(ssh, cmd)
        if not out:
            continue
        for line in out.splitlines():
            if executable_name in line:
                parts = line.split()
                pid = None
                if cmd.startswith("ps -e"):
                    try:
                        pid = parts[0]
                        cmdline = " ".join(parts[1:])
                    except:
                        continue
                else:
                    if len(parts) >= 2:
                        pid = parts[1]
                        cmdline = (
                            " ".join(parts[10:]) if len(parts) > 10 else " ".join(parts[2:])
                        )
                if pid and pid.isdigit():
                    results.append((pid, cmdline))
    uniq = {}
    for pid, cmdline in results:
        uniq[pid] = cmdline
    return [(p, uniq[p]) for p in uniq]


def interactive_lldb_session(ssh, pid, app_name):
    show_status(f"Opening interactive LLDB and attaching to PID {pid} ({app_name})")
    chan = open_interactive_shell(ssh)
    chan.send("lldb\n")
    time.sleep(1)
    wait_for_data(chan, timeout=1.0)

    attach_cmd = f"process attach -p {pid}\n"
    chan.send(attach_cmd)
    time.sleep(1.5)
    wait_for_data(chan, timeout=1.0)

    show_status(f"Attached to process {app_name} successfully. Debug session ready.")
    print("------------------------------------------------------------")
    print(" LLDB is now attached to the target process.")
    print(" You can enter LLDB commands such as:")
    print("   (lldb) thread list")
    print("   (lldb) frame info")
    print("   (lldb) register read")
    print("   (lldb) memory read 0x100000000 64")
    print("   (lldb) disassemble --frame")
    print("   (lldb) bt     # Show backtrace")
    print(" Type 'exit' or 'quit' to end the session.")
    print("------------------------------------------------------------\n")

    try:
        while True:
            user_cmd = input(f"{PROMPT} ").strip()
            if user_cmd.lower() in ("exit", "quit"):
                chan.send("quit\n")
                time.sleep(0.2)
                break
            if not user_cmd:
                continue
            chan.send(user_cmd + "\n")
            time.sleep(0.1)
            wait_for_data(chan, timeout=1.0)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt, detaching and closing.")
    finally:
        try:
            chan.close()
        except:
            pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 lldb_attach_search_and_run_manual.py <device_ip> [username] [password]")
        return

    device_ip = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "root"
    password = sys.argv[3] if len(sys.argv) > 3 else "alpine"

    print(f"LLDB attach helper (manual app launch mode)")
    print(f"Target device: {device_ip}  (User: {username})\n")

    search_keyword = input("Enter app search keyword (part of .app name or bundle folder): ").strip()
    if not search_keyword:
        print("No keyword provided. Exiting.")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        show_status(f"Connecting to {device_ip} ...")
        ssh.connect(
            hostname=device_ip,
            port=22,
            username=username,
            password=password,
            timeout=10,
        )
    except Exception as e:
        print(f"SSH connection failed: {e}")
        return

    show_status("SSH connected")
    show_status("Searching for installed apps...")
    matches = search_apps(ssh, search_keyword)
    if not matches:
        print("No app bundles found matching the keyword.")
        ssh.close()
        return

    print("\nFound apps:")
    for i, (disp, path, exe) in enumerate(matches, start=1):
        print(f"  [{i}] {disp}  (path: {path}, exec: {exe})")

    choice = None
    if len(matches) == 1:
        choice = 1
    else:
        while True:
            sel = input(f"Select app to use [1-{len(matches)}] (or 'q' to quit): ").strip()
            if sel.lower() in ("q", "quit", "exit"):
                ssh.close()
                return
            if sel.isdigit() and 1 <= int(sel) <= len(matches):
                choice = int(sel)
                break
            else:
                print("Invalid selection.")

    disp, app_path, exe_name = matches[choice - 1]
    show_status(f"Selected: {disp} ({app_path})")
    print("\nPlease open the selected app on your iOS device now.")
    print("Waiting for the process to appear (Ctrl+C to cancel)...\n")

    chosen_pid = None
    try:
        for attempt in range(60):
            pids = find_running_pids(ssh, exe_name)
            if pids:
                chosen_pid = pids[0][0]
                break
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        ssh.close()
        return

    if not chosen_pid:
        print("Timeout: app process not detected. Please open the app manually and re-run the script.")
        ssh.close()
        return

    show_status(f"Detected running process PID {chosen_pid} ({disp})")
    interactive_lldb_session(ssh, chosen_pid, disp)
    ssh.close()
    show_status("SSH closed, exiting.")


if __name__ == "__main__":
    main()
