#!/usr/bin/env python3
"""Drive disk-cleaner-mcp MCP server against REAL user dirs (READ-ONLY safe path).

Phase A (read-only): scan Downloads + Temp + CrashDumps, analyze, and print the
top junk candidates by size WITH approval tokens — the agent (you) can review
before any delete happens. Nothing is deleted here.
"""
import json
import os
import subprocess
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else r"target/release/disk-cleaner-mcp.exe"


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


def main():
    if not os.path.isfile(BIN):
        print(f"FATAL: binary not found: {BIN}")
        sys.exit(2)

    srv = MCPServer(BIN)
    srv.request("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "real-scan", "version": "1"},
    })

    targets = [
        os.path.expanduser(r"~\Downloads"),
        os.environ.get("LOCALAPPDATA", "") + r"\Temp",
        os.path.expanduser(r"~\AppData\Local\CrashDumps"),
    ]

    all_junk = []
    for t in targets:
        if not os.path.isdir(t):
            print(f"SKIP (gone): {t}")
            continue
        print(f"\n=== SCAN {t} ===")
        print("... (this may take a moment) ...")
        resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": t}})
        if "error" in resp:
            print(f"  scan error: {resp.get('error')}")
            continue
        scan = json.loads(resp["result"]["content"][0]["text"])
        s = scan["summary"]
        print(f"  scanId={s['scanId']} files={s['filesScanned']} dirs={s['dirsScanned']} "
              f"total={human(s['totalSize'])} dur={s['durationMs']}ms")
        if s.get("warnings"):
            for w in s["warnings"][:3]:
                print(f"  warn: {w}")

        # analyze top 200 files by size (default sort = size desc)
        resp = srv.request("tools/call", {"name": "analyze", "arguments": {"scanId": s["scanId"], "limit": 200}})
        if "error" in resp:
            print(f"  analyze error: {resp.get('error')}")
            continue
        page = json.loads(resp["result"]["content"][0]["text"])
        entries = page.get("page", [])
        print(f"  analyze: {len(entries)} entries (top 200 by size)")
        # print top junk-looking
        shown = 0
        for e in entries:
            name = os.path.basename(e["path"]).lower()
            if shown < 25:
                flag = ""
                if name.startswith("~$") or name.endswith((".tmp", ".crdownload", ".part", ".download", ".opdownload", ".dmp", ".log")):
                    flag = "  << JUNK"
                print(f"    {human(e['size']):>9}  {e['category']:<14} {os.path.basename(e['path'])}{flag}")
                shown += 1
            all_junk.append(e)

    print(f"\n\nTOTAL detections: {len(all_junk)} entries")
    print("Nothing was deleted — this was a READ-ONLY survey.")
    srv.proc.kill()

    # Also dump tokens file so a follow-up script can delete after review
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_survey_tokens.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(all_junk, f, indent=1)
    print(f"Tokens saved to {out} (for the optional delete step — DO NOT share)")


if __name__ == "__main__":
    main()