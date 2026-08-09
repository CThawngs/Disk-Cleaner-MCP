#!/usr/bin/env python3
"""REAL-WORLD demo of disk-cleaner-mcp: junk cleanup + full organize cycle.

Creates a realistic messy folder (junk files of many kinds), then drives the
binary over MCP stdio to: scan → analyze → organize (by category AND extension)
→ delete (trash) → verify on disk. Everything happens inside a temp folder;
the ONLY system-wide thing touched is the OS trash (one junk file).
"""
import json
import os
import subprocess
import sys
import tempfile
import shutil
import time

BIN = sys.argv[1] if len(sys.argv) > 1 else r"target/release/disk-cleaner-mcp.exe"


def make_messy_dir(root):
    """Create a realistic junk-filled folder."""
    os.makedirs(root, exist_ok=True)
    files = {
        "report_final.pdf": b"%PDF-1.4 fake",
        "photo_holiday.jpg": b"\xff\xd8\xff fake jpeg",
        "photo_holiday.png": b"\x89PNG fake png",
        "notes.txt": b"hello world\n",
        "data.csv": b"a,b,c\n1,2,3\n",
        "archive.zip": b"PK\x03\x04 fake zip",
        "setup.exe": b"MZ fake exe",
        "debug.log": b"[INFO] fake log",
        "cache.tmp": b"tmp data",
        "song.mp3": b"ID3 fake mp3",
        "movie.mp4": b"\x00\x00\x00 ftypmp42",
        "noext_data": b"some bytes",
    }
    for name, content in files.items():
        with open(os.path.join(root, name), "wb") as f:
            f.write(content)
    sub = os.path.join(root, "subfolder")
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, "junk.log"), "wb") as f:
        f.write(b"nested junk")
    with open(os.path.join(sub, "doc.txt"), "wb") as f:
        f.write(b"nested doc")
    return root


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


def main():
    print(f"Server: {BIN}")
    if not os.path.isfile(BIN):
        print(f"FATAL: binary not found: {BIN}")
        sys.exit(2)

    work = tempfile.mkdtemp(prefix="dc-mcp-demo-")
    messy = os.path.join(work, "MessyDownloads")
    organized = os.path.join(work, "Organized")
    os.makedirs(organized, exist_ok=True)
    make_messy_dir(messy)
    print(f"Messy folder:   {messy}")
    print(f"Organize dest:  {organized}")
    before = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, fns in os.walk(messy) for f in fns
    )
    print(f"Total junk bytes: {before}\n")

    srv = MCPServer(BIN)

    # initialize
    srv.request("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "demo", "version": "1"},
    })

    # --- 1. SCAN the real messy folder ---
    resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": messy}})
    scan = json.loads(resp["result"]["content"][0]["text"])
    s = scan["summary"]
    scan_id = s["scanId"]
    print(f"1) SCAN: {s['filesScanned']} files, {s['dirsScanned']} dirs, "
          f"{s['totalSize']} bytes in {s['durationMs']}ms")
    print(f"   categories: {[(c['category'], c['count']) for c in s['categoryTotals']]}")

    # --- 2. ANALYZE all files ---
    resp = srv.request("tools/call", {"name": "analyze", "arguments": {"scanId": scan_id, "limit": 500}})
    page = json.loads(resp["result"]["content"][0]["text"])
    entries = page["page"]
    print(f"2) ANALYZE: {len(entries)} entries found")
    for e in entries[:14]:
        print(f"   {e['category']:<24} {os.path.basename(e['path'])} ({e['size']}B)")

    # --- 3. ORGANIZE by category (dry-run) ---
    org_items = [{"approvalToken": e["approvalToken"], "path": e["path"]} for e in entries]
    resp = srv.request("tools/call", {
        "name": "organize",
        "arguments": {
            "scanId": scan_id, "items": org_items,
            "destDir": organized, "dryRun": True,
        },
    })
    plan = json.loads(resp["result"]["content"][0]["text"])
    print(f"3) ORGANIZE dry-run: {plan['dryRun']} planned moves, {plan['skipped']} skipped, "
          f"{plan['rejected']} rejected")
    for o in plan["outcomes"][:14]:
        print(f"   -> {o['dest']}")

    # --- 4. DELETE for real (trash!) BEFORE organize so the path still exists ---
    entry = next(e for e in entries if e["path"].endswith("setup.exe"))
    resp = srv.request("tools/call", {
        "name": "delete",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": entry["approvalToken"], "path": entry["path"]}],
            "permanent": False,
        },
    })
    del_res = json.loads(resp["result"]["content"][0]["text"])
    if del_res["trashed"] == 1:
        print(f"4) DELETE → TRASHED into OS recycle bin (status='trashed')")
        print(f"   setup.exe gone from source: {not os.path.exists(entry['path'])}")
    else:
        print(f"4) DELETE result: {del_res}")

    # Scan again to refresh (setup.exe now gone) then organize the rest
    resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": messy}})
    scan2 = json.loads(resp["result"]["content"][0]["text"])
    scan_id2 = scan2["summary"]["scanId"]
    resp = srv.request("tools/call", {"name": "analyze", "arguments": {"scanId": scan_id2, "limit": 500}})
    page2 = json.loads(resp["result"]["content"][0]["text"])
    entries2 = page2["page"]
    org_items2 = [{"approvalToken": e["approvalToken"], "path": e["path"]} for e in entries2]

    # --- 5. ORGANIZE for real (by extension) ---
    resp = srv.request("tools/call", {
        "name": "organize",
        "arguments": {
            "scanId": scan_id2, "items": org_items2,
            "destDir": organized, "strategy": "extension", "dryRun": False,
        },
    })
    res = json.loads(resp["result"]["content"][0]["text"])
    print(f"5) ORGANIZE real: {res['moved']} MOVED, {res['skipped']} skipped, "
          f"{res['errors']} errors, {res['rejected']} rejected")
    print("   Resulting tree:")
    for dp, _, fns in os.walk(organized):
        rel = os.path.relpath(dp, organized)
        indent = "   " + ("  " * (rel.count(os.sep)))
        if rel != ".":
            print(f"{indent}[{rel}]/")
        for fn in sorted(fns):
            print(f"{indent}  {fn}")

    # Check the messy dir is now almost empty
    leftovers = []
    for dp, _, fns in os.walk(messy):
        for f in fns:
            leftovers.append(os.path.join(dp, f))
    print(f"   leftovers in source: {len(leftovers)} (should be dirs only)")

    # Restore note
    time.sleep(1)
    if os.name == "nt":
        print("   (setup.exe moved to Windows Recycle Bin - restore via Explorer)")

    srv.proc.kill()

    after = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, fns in os.walk(messy) for f in fns
    )
    print(f"\nSummary: {before} bytes of junk in source → {after} bytes left "
          f"(rest organized into {organized})")
    print("\nREAL-WORLD DEMO COMPLETE ✅")
    # Don't clean up work dir yet - user may want to inspect
    print(f"Demo folder kept for inspection: {work}")


if __name__ == "__main__":
    main()