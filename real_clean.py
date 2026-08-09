#!/usr/bin/env python3
"""Phase B: delete REAL junk (recycle bin, never permanent) after user review.

Reads the token dump from Phase A, picks ONLY clearly-junk files
(.tmp/.dmp/.crdownload/.log/.etl/VSIX installers/crash dumps), sends them to
the MCP 'delete' tool (trash), and reports recovered bytes. Your real documents
(images, PDFs, code, videos) are untouched by design.

Usage: python real_clean.py <tokens.json>  [--dry-run]
"""
import json
import os
import subprocess
import sys
import time

BIN = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\nguye\.cargo\target\dc-mcp\release\disk-cleaner-mcp.exe"
TOKENS = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_survey_tokens.json")
DRY = "--dry-run" in sys.argv


class MCPServer:
    def __init__(self, bin_path):
        self.proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.req_id = 0

    def request(self, method, params=None):
        self.req_id += 1
        msg = {"jsonrpc": "2.0", "id": self.req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        return json.loads(line)

    def close(self):
        self.proc.kill()


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


# ONLY these are auto-picked. Everything else = kept.
# Extremely conservative: nothing that could be a document or installer you
# might still want. Crash dumps, partial downloads, temp files only.
JUNK_SUFFIXES = (
    ".dmp", ".tmp", ".temp", ".crdownload", ".part", ".download",
    ".opdownload", ".etl", ".blg", ".evtx", ".wpr",
)
JUNK_NAMES = ()  # no exe/msi auto-picks


def is_safe_junk(path, size):
    """Conservative: only delete files that are UNAMBIGUOUSLY junk."""
    name = os.path.basename(path).lower()
    if name.startswith("~$"):
        return True
    for suffix in JUNK_SUFFIXES:
        if name.endswith(suffix):
            return True
    return False


def main():
    if not os.path.isfile(TOKENS):
        print(f"FATAL: token file not found: {TOKENS}")
        sys.exit(2)

    with open(TOKENS, "r", encoding="utf-8") as f:
        entries = json.load(f)

    picks = [e for e in entries if is_safe_junk(e["path"], e["size"])]
    by_dir = {}
    for e in picks:
        d = os.path.dirname(e["path"])
        by_dir.setdefault(d, []).append(e)

    print(f"Token file: {TOKENS}")
    print(f"Entries: {len(entries)} → junk candidates: {len(picks)} "
          f"({human(sum(e['size'] for e in picks))})")
    for d, es in sorted(by_dir.items()):
        print(f"  {human(sum(e['size'] for e in es)):>10}  {d}  ({len(es)} files)")

    if DRY:
        print("\n[DRY-RUN] Nothing deleted. Cancelling.")
        return

    # Group by scanId: the token dump doesn't keep scanId per entry.
    # Simplest safe path: re-scan each affected dir, match by path, then delete.
    dirs = sorted(by_dir.keys())
    srv = MCPServer(BIN)
    srv.request("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "real-clean", "version": "1"},
    })

    total_freed = 0
    per_dir = []
    for d in dirs:
        print(f"\n=== process {d} ===")
        resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": d}})
        if "error" in resp:
            print(f"  scan error: {resp.get('error')}")
            continue
        scan = json.loads(resp["result"]["content"][0]["text"])
        scan_id = scan["summary"]["scanId"]

        # Fresh tokens for the exact files we want to delete
        resp = srv.request("tools/call", {"name": "analyze", "arguments": {"scanId": scan_id, "limit": 1000}})
        if "error" in resp:
            print(f"  analyze error: {resp.get('error')}")
            continue
        page = json.loads(resp["result"]["content"][0]["text"])
        fresh = page.get("page", [])
        fresh_by_path = {e["path"].replace("\\", "/"): e for e in fresh}

        targets = []
        for e in picks:
            if os.path.dirname(e["path"]) == d:
                key = e["path"]
                fe = fresh_by_path.get(key)
                if fe is None:
                    print(f"  [gone?] {os.path.basename(key)}")
                    continue
                targets.append({"approvalToken": fe["approvalToken"], "path": fe["path"]})

        if not targets:
            continue
        resp = srv.request("tools/call", {
            "name": "delete",
            "arguments": {"scanId": scan_id, "items": targets, "permanent": False},
        })
        if "error" in resp:
            print(f"  delete error: {resp.get('error')}")
            continue
        res = json.loads(resp["result"]["content"][0]["text"])
        freed = sum(e["size"] for e in picks if os.path.dirname(e["path"]) == d)
        total_freed += freed
        print(f"  trashed={res['trashed']} rejected={res['rejected']} errors={res['errors']} "
              f"→ freed ≈ {human(freed)}")
        per_dir.append((d, res["trashed"], freed))

    srv.proc.kill()

    print(f"\n{'='*60}")
    print(f"TOTAL freed (to Recycle Bin): {human(total_freed)}")
    for d, t, f in per_dir:
        print(f"  {human(f):>10}  {d} ({t} files trashed)")
    print("\nAll deletions went to the OS Recycle Bin — fully recoverable.")


if __name__ == "__main__":
    main()