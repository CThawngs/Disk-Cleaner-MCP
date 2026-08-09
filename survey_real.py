#!/usr/bin/env python3
"""READ-ONLY real-disk junk survey — measures how much reclaimable space exists.
Deletes NOTHING. Prints per-directory sizes + top junk categories."""
import os
import sys
from collections import defaultdict

# Junk extension signatures (lowercase, no dot)
JUNK_EXTS = {
    # temp/intermediate
    "tmp", "temp", "bak", "old", "dmp", "log", "cache", "crdownload", "part",
    "partial", "download", "opdownload", "etl", "blg", "evtx", "wpr",
    # installers & archives (dup risk)
    "msi", "exe", "cab", "zip", "rar", "7z", "dmg", "pkg", "iso", "asar",
    # caches
    "pyc", "pyo", "o", "obj", "class", "node_modules",
    # thumbnails / previews
    "db", "ini~", "lnk~",
    # office temp
    "~$", "xlsx~", "docx~", "pptx~",
}

SKIP_DIRS = {
    "$recycle.bin", "system volume information",
    "windows", "program files", "program files (x86)", "programdata",
    "appdata\\roaming\\microsoft\\windows", "node_modules",
}

def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def is_junk_path(p):
    """Heuristic for obviously-junk files."""
    name = os.path.basename(p).lower()
    if name.startswith("~$"):
        return True
    ext = os.path.splitext(name)[1].lstrip(".")
    # multi-part ext like .log.1
    parts = name.split(".")
    if len(parts) >= 3 and parts[-1].isdigit():
        return True
    return ext in JUNK_EXTS or name.endswith(".log.1") or name.endswith(".tmp")

def main():
    targets = [
        os.environ.get("LOCALAPPDATA", "") + r"\Temp",
        os.path.expanduser(r"~\Downloads"),
        os.environ.get("LOCALAPPDATA", "") + r"\npm-cache",
        os.environ.get("LOCALAPPDATA", "") + r"\pip\cache",
        os.environ.get("LOCALAPPDATA", "") + r"\Microsoft\Windows\INetCache",
        os.path.expanduser(r"~\.cargo\registry"),
        os.environ.get("LOCALAPPDATA", "") + r"\Microsoft\Windows\Explorer",
        os.path.expanduser(r"~\AppData\Local\CrashDumps"),
        os.path.expanduser(r"~\AppData\Local\D3DSCache"),
        os.path.expanduser(r"~\.gradle\caches"),
        os.path.expanduser(r"~\.m2\repository"),
        os.path.expanduser(r"~\.nuget\packages"),
        os.environ.get("LOCALAPPDATA", "") + r"\JetBrains",
        os.environ.get("LOCALAPPDATA", "") + r"\Google\Chrome\User Data\Default\Cache",
        os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data\Default\Cache"),
    ]

    total_junk = 0
    total_all = 0
    print("READ-ONLY junk survey on C:  (nothing deleted)\n")
    print(f"{'directory':<52} {'junk':>10} {'all':>10}")
    print("-" * 76)

    for t in targets:
        if not os.path.isdir(t):
            continue
        junk = 0
        all_size = 0
        nfiles = 0
        njunk = 0
        for dp, dns, fns in os.walk(t):
            # prune deep system dirs
            dns[:] = [d for d in dns if d.lower() not in SKIP_DIRS and not d.startswith(".")]
            for f in fns:
                fp = os.path.join(dp, f)
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue
                all_size += sz
                nfiles += 1
                if is_junk_path(fp):
                    junk += sz
                    njunk += 1
        if all_size:
            print(f"{t:<52} {human(junk):>10} {human(all_size):>10}  ({njunk}/{nfiles} junk files)")
            total_junk += junk
            total_all += all_size

    print("-" * 76)
    print(f"{'TOTAL':<52} {human(total_junk):>10} {human(total_all):>10}")
    print(f"\nReclaimable junk estimate: {human(total_junk)} → frees ~{human(total_junk)} on C:")
    print(f"(of which Temp alone often holds most of the reclaimable bytes)")

if __name__ == "__main__":
    main()