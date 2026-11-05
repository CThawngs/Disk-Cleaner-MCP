#!/usr/bin/env python3
"""Smoke test for disk-cleaner-mcp over MCP stdio JSON-RPC.

Usage: python smoke_test.py [path-to-binary]
Files are only READ; deletions are tested on a throwaway temp dir.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

import platform
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
BIN = sys.argv[1] if len(sys.argv) > 1 else (
    r"target/release/disk-cleaner-mcp.exe" if platform.system() == "Windows"
    else "target/release/disk-cleaner-mcp"
)

# ---- JSON-RPC helpers ----
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

def check_ok(resp, label):
    assert "result" in resp, f"{label}: unexpected error response: {resp}"
    print(f"  ✓ {label}")

def call_tool(srv, name, arguments, label):
    resp = srv.request("tools/call", {"name": name, "arguments": arguments})
    check_ok(resp, label)
    text = resp["result"]["content"][0]["text"]
    return json.loads(text)

# ---- Main ----
def main():
    print(f"Server: {BIN}")
    if not os.path.isfile(BIN):
        print(f"FATAL: binary not found: {BIN}")
        sys.exit(2)

    srv = MCPServer(BIN)

    # 1. initialize
    resp = srv.request("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "smoke-test", "version": "0.1"},
    })
    check_ok(resp, "initialize")

    # 2. tools/list
    resp = srv.request("tools/list", {})
    check_ok(resp, "tools/list")
    tools = resp["result"]["tools"]
    names = [t["name"] for t in tools]
    print(f"  ✤ tools: {names}")
    EXPECTED_TOOLS = {
        "get_system_status", "list_categories", "scan", "analyze", "get_tree",
        "file_types", "find_duplicates", "compare_scans", "organize",
        "delete", "get_report",
    }
    assert EXPECTED_TOOLS <= set(names), f"missing tools: {EXPECTED_TOOLS - set(names)} (got {names})"

    # 3. get_system_status
    resp = srv.request("tools/call", {
        "name": "get_system_status", "arguments": {}
    })
    check_ok(resp, "get_system_status")
    status = json.loads(resp["result"]["content"][0]["text"])
    print(f"  ✤ platform={status.get('platform')} disks={len(status.get('disks', []))}")

    # 4. scan a throwaway temp dir
    tmp = tempfile.mkdtemp(prefix="dc-mcp-smoke-")
    os.makedirs(os.path.join(tmp, "sub"), exist_ok=True)
    with open(os.path.join(tmp, "junk1.log"), "w") as f:
        f.write("x" * 1000)
    with open(os.path.join(tmp, "junk2.tmp"), "w") as f:
        f.write("y" * 500)
    with open(os.path.join(tmp, "sub", "deep.log"), "w") as f:
        f.write("z" * 300)
    # duplicate pair + unique file for the TreeSize-insights checks below
    with open(os.path.join(tmp, "dup_a.bin"), "wb") as f:
        f.write(b"IDENTICAL-CONTENT-1234567890" * 10)
    with open(os.path.join(tmp, "dup_b.bin"), "wb") as f:
        f.write(b"IDENTICAL-CONTENT-1234567890" * 10)
    with open(os.path.join(tmp, "solo.bin"), "wb") as f:
        f.write(b"UNIQUE-BYTES-9999" * 10)

    resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": tmp}})
    check_ok(resp, "scan")
    scan = json.loads(resp["result"]["content"][0]["text"])
    print(f"  ✤ scanId={scan.get('summary', {}).get('scanId')} files={scan.get('summary', {}).get('filesScanned')}")
    scan_id = scan["summary"]["scanId"]

    # 5. analyze
    resp = srv.request("tools/call", {"name": "analyze", "arguments": {"scanId": scan_id}})
    check_ok(resp, "analyze")
    page = json.loads(resp["result"]["content"][0]["text"])
    entries = page.get("page", [])
    print(f"  ✤ entries={len(entries)}")
    assert len(entries) >= 2, "expected at least 2 entries"

    # find a token
    tok_entry = entries[0]
    token = tok_entry["approvalToken"]
    del_path = tok_entry["path"]
    print(f"  ✤ token entry: {os.path.basename(del_path)}")

    # 5a. TreeSize insights: get_tree / file_types / find_duplicates
    resp = srv.request("tools/call", {"name": "get_tree", "arguments": {"scanId": scan_id}})
    check_ok(resp, "get_tree")
    tree = json.loads(resp["result"]["content"][0]["text"])
    assert tree["size"] > 0, f"tree root size must be > 0: {tree}"
    assert tree["children"], "tree root must have children"
    print(f"  ✤ tree: root={tree['size']}B children={len(tree['children'])}")

    resp = srv.request("tools/call", {"name": "file_types", "arguments": {"scanId": scan_id}})
    check_ok(resp, "file_types")
    ft = json.loads(resp["result"]["content"][0]["text"])
    exts = {e["extension"] for e in ft["byExtension"]}
    assert {"log", "tmp", "bin"} <= exts, f"expected log/tmp/bin extensions, got {exts}"
    print(f"  ✤ file_types: {ft['extensionCount']} extensions, {ft['totalSize']}B")

    resp = srv.request("tools/call", {
        "name": "find_duplicates",
        "arguments": {"scanId": scan_id, "minSize": 0},
    })
    check_ok(resp, "find_duplicates")
    dups = json.loads(resp["result"]["content"][0]["text"])
    assert dups["groupsFound"] >= 1, f"expected >=1 duplicate group: {dups}"
    group = dups["topGroups"][0]
    assert group["fileCount"] == 2, f"expected 2 identical files: {group}"
    assert group["files"][0]["approvalToken"], "duplicate files must carry approvalToken"
    assert dups["totalWasted"] == group["size"], "wasted = one copy of the pair"
    print(f"  ✤ find_duplicates: {dups['groupsFound']} group(s), wasted={dups['totalWasted']}B")

    # 5b. organize test: dry-run first (nothing moves)
    organized_dir = os.path.join(tmp, "organized")
    os.makedirs(organized_dir, exist_ok=True)
    resp = srv.request("tools/call", {
        "name": "organize",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": token, "path": del_path}],
            "destDir": organized_dir,
            "dryRun": True,
        },
    })
    check_ok(resp, "organize (dry run)")
    org = json.loads(resp["result"]["content"][0]["text"])
    assert org.get("dryRun", 0) >= 1, f"expected dryRun plan, got: {org}"
    assert org.get("moved", 0) == 0, "dry run must not move anything"
    print(f"  ✓ dry-run planned (no files moved)")

    # 5c. organize WRONG token → rejected, nothing moves
    resp = srv.request("tools/call", {
        "name": "organize",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": "deadbeef", "path": del_path}],
            "destDir": organized_dir,
            "dryRun": False,
        },
    })
    check_ok(resp, "organize (wrong token → rejected)")
    org = json.loads(resp["result"]["content"][0]["text"])
    assert org.get("rejected", 0) >= 1, f"expected rejection, got: {org}"
    assert os.path.exists(del_path), "file must still exist after rejected organize"
    print("  ✓ organize token rejection verified")

    # 6. delete (trash) — expect ok
    resp = srv.request("tools/call", {
        "name": "delete",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": token, "path": del_path}],
            "permanent": False,
        },
    })
    check_ok(resp, "delete (trash)")

    # 7. delete with WRONG token must fail gracefully (still a result)
    resp = srv.request("tools/call", {
        "name": "delete",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": "deadbeef", "path": del_path}],
        },
    })
    check_ok(resp, "delete (wrong token → rejected)")
    outcome = json.loads(resp["result"]["content"][0]["text"])
    rejected = outcome.get("rejected", 0)
    assert rejected >= 1, f"expected token rejection, got: {outcome}"
    print("  ✓ token rejection verified")

    # 7b. rescan + compare_scans: junk1.log was trashed above → removed
    resp = srv.request("tools/call", {"name": "scan", "arguments": {"root": tmp}})
    check_ok(resp, "scan (second, for compare)")
    scan2 = json.loads(resp["result"]["content"][0]["text"])
    scan_id2 = scan2["summary"]["scanId"]

    resp = srv.request("tools/call", {
        "name": "compare_scans",
        "arguments": {"scanIdA": scan_id, "scanIdB": scan_id2},
    })
    check_ok(resp, "compare_scans")
    diff = json.loads(resp["result"]["content"][0]["text"])
    assert diff["removedCount"] >= 1, f"expected >=1 removed file: {diff}"
    assert diff["netDelta"] < 0, f"net delta must be negative after cleanup: {diff}"
    print(f"  ✤ compare_scans: net={diff['netDelta']}B removed={diff['removedCount']}")

    # 8. cleanup temp dir
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    srv.proc.kill()
    print("\nALL SMOKE TESTS PASSED 🎉")

if __name__ == "__main__":
    main()