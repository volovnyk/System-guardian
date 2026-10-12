import argparse
import os
import platform
import re
import stat
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

import psutil

COMMON_SYSTEM_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/lib/",
    "/opt/",
    "/snap/",
    "C:/Windows/System32/",
    "C:/Program Files/",
    "C:/Program Files (x86)/",
    "C:/Windows/SysWOW64/",
)
SUSPICIOUS_PATH_HINTS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\Temp\\",
    "\\Downloads\\",
    "\\Desktop\\",
)
ERROR_PATTERNS = (
    "error",
    "failed",
    "denied",
    "authentication failure",
    "invalid user",
    "segmentation fault",
    "exception",
    "panic",
)
SUSPICIOUS_LOGIN_PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "session opened",
    "sudo",
)
DEFAULT_LOG_PATHS = {"linux": ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"], "windows": [r"C:\Windows\System32\winevt\Logs\Security.evtx"]}


def sanitize_for_public(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b", "[PRIVATE_ADDRESS]", text)
    user_home = os.path.expanduser("~").replace("\\", "/")
    normalized = text.replace("\\", "/")
    if user_home and normalized.startswith(user_home):
        return "[USER_HOME]" + normalized[len(user_home):]
    match = re.match(r"(?i)^([A-Za-z]:/Users/)[^/]+", normalized)
    if match:
        return match.group(1) + "[USER]" + normalized[match.end():]
    return normalized


def get_top_processes(limit: int = 10) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent", "exe", "username", "status", "cmdline"]):
        try:
            info = proc.info
            rows.append(
                {
                    "pid": info.get("pid"),
                    "name": sanitize_for_public(info.get("name") or "unknown"),
                    "cpu_percent": round(float(info.get("cpu_percent") or 0.0), 2),
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                    "status": info.get("status") or "unknown",
                    "exe": sanitize_for_public(info.get("exe") or ""),
                    "cmdline": sanitize_for_public(" ".join(info.get("cmdline") or [])),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(rows, key=lambda item: (item["cpu_percent"], item["memory_percent"]), reverse=True)[:limit]


def _looks_suspicious_executable(path: str) -> bool:
    if not path:
        return False
    normalized = os.path.normcase(path).lower()
    if any(normalized.startswith(prefix.lower()) for prefix in COMMON_SYSTEM_PREFIXES):
        return False
    if any(hint.lower() in normalized for hint in SUSPICIOUS_PATH_HINTS):
        return True
    user_home = os.path.expanduser("~").lower()
    if user_home and normalized.startswith(user_home):
        if any(segment in normalized for segment in ("\\downloads\\", "\\desktop\\", "\\documents\\", "\\music\\", "\\pictures\\", "/downloads/", "/desktop/", "/documents/")):
            return True
        return False
    return not any(part in normalized for part in ("windows", "system32", "program files", "/bin/", "/usr/", "/lib/")) and os.path.dirname(path) not in ("", ".")


def detect_suspicious_processes(limit: int = 10) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "username", "status"]):
        try:
            info = proc.info
            exe = info.get("exe") or ""
            cmdline = info.get("cmdline") or []
            cmd = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            if not exe and not cmd:
                continue
            if _looks_suspicious_executable(exe or cmd):
                out.append(
                    {
                        "pid": info.get("pid"),
                        "name": sanitize_for_public(info.get("name") or "unknown"),
                        "exe": sanitize_for_public(exe),
                        "cmdline": sanitize_for_public(cmd),
                        "username": sanitize_for_public(info.get("username") or "unknown"),
                        "status": info.get("status") or "unknown",
                        "reason": "Executable path is outside common system directories or points to temp/download/desktop locations.",
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out[:limit]


def check_firewall() -> Dict[str, Any]:
    system = platform.system().lower()
    if system == "linux":
        for command in (["ufw", "status"], ["iptables", "-S"], ["nft", "list", "ruleset"]):
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    output = (result.stdout or "") + (result.stderr or "")
                    if "active" in output.lower() or "filter" in output.lower() or "chain" in output.lower():
                        return {"status": "enabled", "details": output.strip()[:500]}
            except (FileNotFoundError, subprocess.SubprocessError):
                continue
        return {"status": "unknown", "details": "Firewall status could not be determined automatically."}
    if system == "windows":
        try:
            result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True, timeout=8)
            if result.returncode == 0:
                output = (result.stdout or "") + (result.stderr or "")
                if "on" in output.lower():
                    return {"status": "enabled", "details": output.strip()[:500]}
                return {"status": "disabled", "details": output.strip()[:500]}
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        return {"status": "unknown", "details": "Firewall status could not be read on this Windows system."}
    return {"status": "unknown", "details": f"Unsupported platform: {platform.system()}"}


def check_open_ports() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            out.append({"local_address": sanitize_for_public(f"{conn.laddr.ip}:{conn.laddr.port}"), "pid": conn.pid, "status": str(conn.status)})
    except (psutil.AccessDenied, psutil.Error):
        return [{"local_address": "unknown", "pid": None, "status": "permission_denied"}]
    return out


def check_world_writable_files(limit: int = 50) -> List[str]:
    out: List[str] = []
    roots: Iterable[str]
    if platform.system().lower() == "linux":
        roots = ["/tmp", "/var/tmp", "/home", "/opt", "/srv"]
    else:
        roots = [os.path.expanduser("~"), r"C:\Temp", r"C:\Users"]
    for root in roots:
        path_root = Path(root)
        if not path_root.exists():
            continue
        for child in path_root.rglob("*"):
            try:
                if child.is_dir():
                    continue
                mode = stat.S_IMODE(child.stat().st_mode)
                if mode == 0o777:
                    out.append(sanitize_for_public(str(child)))
                    if len(out) >= limit:
                        return out
            except (FileNotFoundError, OSError, PermissionError):
                continue
    return out


def _read_log_file(path: str, max_lines: int = 200) -> List[str]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            return [line.rstrip() for line in handle.readlines()[-max_lines:]]
    except OSError:
        return []


def analyze_logs(log_paths: List[str] | None = None, max_lines: int = 200) -> Dict[str, Any]:
    selected_paths = log_paths or DEFAULT_LOG_PATHS.get(platform.system().lower(), DEFAULT_LOG_PATHS["linux"])
    checked_files: List[str] = []
    errors: List[str] = []
    suspicious_entries: List[Dict[str, str]] = []
    for path in selected_paths:
        lines = _read_log_file(path, max_lines=max_lines)
        if not lines:
            continue
        checked_files.append(path)
        for line in lines:
            lowered = line.lower()
            if any(pattern in lowered for pattern in ERROR_PATTERNS):
                errors.append(line)
            if any(pattern in lowered for pattern in SUSPICIOUS_LOGIN_PATTERNS):
                suspicious_entries.append({"file": sanitize_for_public(path), "entry": sanitize_for_public(line)})
    repeated = [
        {"message": message, "count": count}
        for message, count in sorted(Counter(errors).items(), key=lambda item: item[1], reverse=True)[:10]
    ]
    return {
        "files_checked": [sanitize_for_public(path) for path in checked_files],
        "repeated_errors": repeated,
        "suspicious_entries": suspicious_entries[:20],
        "summary": {"error_count": len(errors), "suspicious_count": len(suspicious_entries)},
    }


def generate_report(results: Dict[str, Any], output_path: str | None = None) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    top_processes = results.get("top_processes", [])
    suspicious_processes = results.get("suspicious_processes", [])
    security = results.get("security", {})
    logs = results.get("logs", {})
    lines = [
        "# System Guardian Report",
        "",
        f"Generated: {now}",
        "",
        "## Executive summary",
        "",
        f"- Top processes inspected: {len(top_processes)}",
        f"- Suspicious processes detected: {len(suspicious_processes)}",
        f"- Firewall status: {security.get('firewall', {}).get('status', 'unknown')}",
        f"- Open listening ports: {len(security.get('open_ports', []))}",
        f"- World-writable files: {len(security.get('world_writable_files', []))}",
        f"- Security-related log entries: {logs.get('summary', {}).get('suspicious_count', 0)}",
        "",
        "## Top CPU/RAM processes",
        "",
    ]
    if top_processes:
        lines.append("| PID | Name | CPU % | RAM % | Status |")
        lines.append("| --- | --- | ---: | ---: | --- |")
        for proc in top_processes:
            lines.append(f"| {proc.get('pid', 'n/a')} | {sanitize_for_public(proc.get('name', 'unknown'))} | {proc.get('cpu_percent', 0)} | {proc.get('memory_percent', 0)} | {proc.get('status', 'unknown')} |")
    else:
        lines.append("No process information available.")
    lines.extend(["", "## Suspicious processes", ""])
    if suspicious_processes:
        lines.append("| PID | Name | Command | Reason |")
        lines.append("| --- | --- | --- | --- |")
        for proc in suspicious_processes:
            lines.append(f"| {proc.get('pid', 'n/a')} | {sanitize_for_public(proc.get('name', 'unknown'))} | {sanitize_for_public(proc.get('cmdline', ''))[:80]} | {proc.get('reason', 'unknown')} |")
    else:
        lines.append("No suspicious processes found during this scan.")
    lines.extend(["", "## Security posture", ""])
    firewall = security.get("firewall", {})
    lines.append(f"- Firewall status: {firewall.get('status', 'unknown')}")
    lines.append(f"- Firewall details: {firewall.get('details', 'No details available.')}")
    if security.get("open_ports"):
        lines.append("- Listening ports:")
        for port in security["open_ports"]:
            lines.append(f"  - {sanitize_for_public(port.get('local_address', 'unknown'))} (PID: {port.get('pid', 'unknown')})")
    else:
        lines.append("- No listening ports detected.")
    if security.get("world_writable_files"):
        lines.append("- World-writable files:")
        for item in security["world_writable_files"][:10]:
            lines.append(f"  - {sanitize_for_public(item)}")
    else:
        lines.append("- No files with mode 777 detected in monitored directories.")
    lines.extend(["", "## Log analysis", ""])
    repeated_errors = logs.get("repeated_errors", [])
    suspicious_entries = logs.get("suspicious_entries", [])
    if repeated_errors:
        lines.append("| Error | Occurrences |")
        lines.append("| --- | ---: |")
        for item in repeated_errors:
            lines.append(f"| {sanitize_for_public(item.get('message', 'unknown'))[:120]} | {item.get('count', 0)} |")
    else:
        lines.append("No repeated error patterns were found in checked logs.")
    if suspicious_entries:
        lines.append("")
        lines.append("Suspicious login or security-related entries:")
        for entry in suspicious_entries[:10]:
            lines.append(f"- [{sanitize_for_public(entry.get('file', 'unknown'))}] {sanitize_for_public(entry.get('entry', ''))[:160]}")
    else:
        lines.append("No suspicious security log entries were detected.")
    lines.extend(["", "## Recommendations", "", "- Ensure all suspicious processes are reviewed and, if malicious, terminated immediately.", "- Confirm firewall rules are enabled and restrict unnecessary listening ports.", "- Remove or repair world-writable files and enforce secure permissions (for example 755 or 750 where appropriate).", "- Review system logs for repeated failures and investigate failed authentication attempts promptly.", "- Keep the OS, applications, and endpoint security agents updated to reduce exposure."])
    report = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
    return report


def collect_system_state() -> Dict[str, Any]:
    return {
        "top_processes": get_top_processes(10),
        "suspicious_processes": detect_suspicious_processes(10),
        "security": {
            "firewall": check_firewall(),
            "open_ports": check_open_ports(),
            "world_writable_files": check_world_writable_files(),
        },
        "logs": analyze_logs(max_lines=200),
    }


try:
    import tkinter as tk
    from tkinter import scrolledtext
except Exception:  # pragma: no cover
    tk = None
    scrolledtext = None


class GuardianApp:
    def __init__(self, root: Any) -> None:
        self.root = root
        self.root.title("System Guardian")
        self.root.geometry("900x600")
        self.scan_button = tk.Button(root, text="Scan system", command=self.run_scan, width=18)
        self.scan_button.pack(pady=(12, 8))
        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, state="disabled")
        self.output.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

    def run_scan(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, generate_report(collect_system_state()))
        self.output.configure(state="disabled")


def start_gui() -> None:
    if tk is None:
        raise RuntimeError("Tkinter is not available in this environment.")
    root = tk.Tk()
    GuardianApp(root)
    root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="System Guardian")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical interface")
    parser.add_argument("--output", default="system_guardian_report.md", help="Output path for the Markdown report")
    args = parser.parse_args()
    if args.gui:
        start_gui()
        return
    results = collect_system_state()
    output_path = Path(args.output)
    report = generate_report(results, str(output_path))
    print(report)
    print(f"\nReport written to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
