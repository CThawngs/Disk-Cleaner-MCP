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
    init_info = resp["result"].get("serverInfo", {})
    assert init_info.get("version") == "0.6.0", f"expected server version 0.6.0, got {init_info}"

    # 2. tools/list
    resp = srv.request("tools/list", {})
    check_ok(resp, "tools/list")
    tools = resp["result"]["tools"]
    names = [t["name"] for t in tools]
    print(f"  ✤ tools: {names}")

    EXPECTED_TOOLS = {
        "get_system_status", "get_metrics", "list_categories", "scan", "analyze", "get_tree",
        "file_types", "find_duplicates", "compare_scans", "organize",
        "delete", "get_report", "empty_trash", "list_trash",
        "smart_scan", "scan_browsers", "scan_app_leftovers",
        "scan_startup_items", "get_hardware_health", "find_large_forgotten",
    }
    assert set(names) == EXPECTED_TOOLS, f"tool mismatch: missing={EXPECTED_TOOLS - set(names)} extra={set(names) - EXPECTED_TOOLS}"
    print(f"  ✓ verified all {len(names)} MCP tools (v0.6.0)")

    # 3. get_system_status
    resp = srv.request("tools/call", {
        "name": "get_system_status", "arguments": {}
    })
    check_ok(resp, "get_system_status")
    status = json.loads(resp["result"]["content"][0]["text"])
    print(f"  ✤ platform={status.get('platform')} disks={len(status.get('disks', []))}")

    # 3b. get_metrics
    resp = srv.request("tools/call", {
        "name": "get_metrics", "arguments": {}
    })
    check_ok(resp, "get_metrics")
    metrics = json.loads(resp["result"]["content"][0]["text"])
    print(f"  ✤ metrics: disks={metrics.get('diskCount')} maxUsage={metrics.get('maxUsagePercent')}")

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
            "confirmRisk": True,
            "dryRun": False,
        },
    })
    check_ok(resp, "delete (trash)")
    trashed = json.loads(resp["result"]["content"][0]["text"])
    assert trashed.get("trashed", 0) >= 1, f"expected trash success, got: {trashed}"

    # 7. delete with WRONG token must fail gracefully (still a result)
    resp = srv.request("tools/call", {
        "name": "delete",
        "arguments": {
            "scanId": scan_id,
            "items": [{"approvalToken": "deadbeef", "path": del_path}],
            "dryRun": False,
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

    # 8. empty_trash without confirm → rejected, nothing purged
    resp = srv.request("tools/call", {
        "name": "empty_trash", "arguments": {"confirm": False}
    })
    check_ok(resp, "empty_trash (no confirm)")
    et = json.loads(resp["result"]["content"][0]["text"])
    assert et["purgedItems"] == 0 and "confirm" in (et.get("message") or ""), f"expected confirm rejection: {et}"
    print(f"  ✓ empty_trash confirm rejection verified")

    # 8b. list_trash — lists OS Recycle Bin / Trash contents
    resp = srv.request("tools/call", {
        "name": "list_trash", "arguments": {"limit": 5}
    })
    check_ok(resp, "list_trash")
    lt = json.loads(resp["result"]["content"][0]["text"])
    assert "items" in lt and "totalItems" in lt, f"expected items/totalItems: {lt}"
    print(f"  ✓ list_trash: {lt['totalItems']} item(s) in trash")


    # 8c. v0.6.0 E2E Suite — 6 new tools + Negative Safety Invariants
    v06_tmp = tempfile.mkdtemp(prefix="dc-mcp-v06-")

    # (A) get_hardware_health (zero-estimation + Agent I/O Guardrails)
    hw = call_tool(srv, "get_hardware_health", {}, "get_hardware_health")
    guard = hw.get("agentGuardrails", {})
    assert guard.get("ioSafetyLevel") in {"green", "caution", "critical"}, f"bad guardrails: {hw}"
    print(f"  ✤ hardware_health: ioSafetyLevel={guard.get('ioSafetyLevel')} disks={len(hw.get('disks', []))}")

    # (B) smart_scan (Allowlist + AI-Stack HF .incomplete + Never-Touch .ssh trap + targetFreeBytes plan)
    ss_root = os.path.join(v06_tmp, "smart")
    hf_blobs = os.path.join(ss_root, "huggingface", "hub", "models--demo--llm", "blobs")
    os.makedirs(hf_blobs, exist_ok=True)
    with open(os.path.join(hf_blobs, "part1.incomplete"), "wb") as f:
        f.write(b"I" * 131072)
    ssh_trap = os.path.join(ss_root, ".ssh")
    os.makedirs(ssh_trap, exist_ok=True)
    with open(os.path.join(ssh_trap, "id_ed25519"), "w") as f:
        f.write("PRIVATE-KEY-NEVER-TOUCH")
    for env_name in (".env", ".env.development", ".env.log"):
        env_p = os.path.join(ss_root, env_name)
        with open(env_p, "w") as f:
            f.write("SECRET_KEY=never_delete_" + env_name * 8000)
        old_env_ts = time.time() - (10 * 86400)
        os.utime(env_p, (old_env_ts, old_env_ts))
    npm_cache = os.path.join(ss_root, "npm-cache")
    os.makedirs(npm_cache, exist_ok=True)
    with open(os.path.join(npm_cache, "pkg.tgz"), "wb") as f:
        f.write(b"N" * 65536)

    ss = call_tool(srv, "smart_scan", {
        "customRootsOverride": [ss_root],
        "targetFreeBytes": 65536,
        "detailLevel": "brief",
    }, "smart_scan (sandbox + reclaim planner)")
    ss_full = call_tool(srv, "smart_scan", {
        "customRootsOverride": [ss_root],
        "detailLevel": "full",
    }, "smart_scan (.env.* + .ssh Never-Touch full check)")
    ss_paths = [u["path"].lower() for u in ss_full.get("units", [])]
    assert not any(".ssh" in p or "id_ed25519" in p or ".env" in p for p in ss_paths), f"Never-Touch .ssh/.env.* leaked: {ss_paths}"
    env_log_p = os.path.join(ss_root, ".env.log")
    env_del = call_tool(srv, "delete", {
        "scanId": ss_full["scanId"],
        "items": [{"path": env_log_p, "approvalToken": "00" * 32}],
        "permanent": True,
        "confirmPermanent": True,
        "confirmRisk": False,
        "dryRun": False,
    }, "delete (.env.log -> rejected/not_found, file preserved)")
    assert os.path.exists(env_log_p), f".env.log must never be deleted: {env_del}"
    assert ss.get("planTotalBytes", 0) >= 65536 and ss.get("targetMet") is True, f"planner failed: {ss}"
    plan_u = ss["recommendedPlan"][0]
    ss_del = call_tool(srv, "delete", {
        "scanId": ss["scanId"],
        "items": [{"path": plan_u["path"], "approvalToken": plan_u["approvalToken"]}],
        "dryRun": True,
    }, "smart_scan -> delete (dryRun)")
    assert ss_del.get("dryRun", 0) >= 1, f"expected dryRun=1 from smart_scan token: {ss_del}"

    # (C) scan_browsers (3 groups + Never-Touch Cookies/Login Data + WebsiteStorage Trash-only gate)
    brw_root = os.path.join(v06_tmp, "browsers")
    prof_dir = os.path.join(brw_root, "Google", "Chrome", "User Data", "Default")
    os.makedirs(os.path.join(prof_dir, "GPUCache"), exist_ok=True)
    with open(os.path.join(prof_dir, "GPUCache", "data_0"), "wb") as f:
        f.write(b"G" * 8192)
    os.makedirs(os.path.join(prof_dir, "OptGuideOnDeviceModel"), exist_ok=True)
    with open(os.path.join(prof_dir, "OptGuideOnDeviceModel", "weights.bin"), "wb") as f:
        f.write(b"M" * 16384)
    with open(os.path.join(prof_dir, "Cookies"), "wb") as f:
        f.write(b"SECRET-COOKIES")
    with open(os.path.join(prof_dir, "Login Data"), "wb") as f:
        f.write(b"SECRET-PASSWORDS")
    idb_dir = os.path.join(prof_dir, "IndexedDB", "https_example.com_0.indexeddb.leveldb")
    os.makedirs(idb_dir, exist_ok=True)
    with open(os.path.join(idb_dir, "000003.log"), "wb") as f:
        f.write(b"https://example.com/app ")

    b_default = call_tool(srv, "scan_browsers", {
        "browsers": ["Chrome"],
        "customBrowserRoot": brw_root,
    }, "scan_browsers (default includeOrigins=false)")
    assert len(b_default.get("disposableCache", [])) == 1, f"expected GPUCache: {b_default}"
    assert len(b_default.get("aiModels", [])) == 1, f"expected OptGuideOnDeviceModel: {b_default}"
    assert len(b_default.get("websiteStorage", [])) == 0, f"origins must be opt-in: {b_default}"
    b_dump = json.dumps(b_default).lower()
    assert "cookies" not in b_dump and "login data" not in b_dump, f"Never-Touch browser file leaked: {b_default}"

    b_orig = call_tool(srv, "scan_browsers", {
        "browsers": ["Chrome"],
        "customBrowserRoot": brw_root,
        "includeOrigins": True,
    }, "scan_browsers (includeOrigins=true)")
    assert len(b_orig.get("websiteStorage", [])) >= 1, f"expected IndexedDB origin: {b_orig}"
    ws_item = b_orig["websiteStorage"][0]
    # Negative test: websiteStorage MUST reject permanent=True even with confirmPermanent+confirmRisk!
    ws_perm = call_tool(srv, "delete", {
        "scanId": b_orig["scanId"],
        "items": [{"path": ws_item["path"], "approvalToken": ws_item["approvalToken"]}],
        "permanent": True,
        "confirmPermanent": True,
        "confirmRisk": True,
        "dryRun": False,
    }, "scan_browsers websiteStorage permanent=true -> rejected (Trash-only)")
    assert ws_perm.get("rejected", 0) >= 1, f"websiteStorage must be Trash-only: {ws_perm}"

    # (D) scan_app_leftovers (aged cache vs installed hint + confirmRisk gate)
    lo_caches = os.path.join(v06_tmp, "Caches")
    ghost_dir = os.path.join(lo_caches, "GhostUninstalledApp")
    installed_dir = os.path.join(lo_caches, "ActiveInstalledApp")
    os.makedirs(ghost_dir, exist_ok=True)
    os.makedirs(installed_dir, exist_ok=True)
    ghost_file = os.path.join(ghost_dir, "cache.bin")
    with open(ghost_file, "wb") as f:
        f.write(b"L" * 4096)
    with open(os.path.join(installed_dir, "cache.bin"), "wb") as f:
        f.write(b"A" * 4096)
    old_ts = time.time() - (45 * 86400)
    os.utime(ghost_file, (old_ts, old_ts))
    os.utime(ghost_dir, (old_ts, old_ts))

    lo = call_tool(srv, "scan_app_leftovers", {
        "minAgeDays": 30,
        "customScanRoots": [lo_caches],
        "installedHints": ["ActiveInstalledApp"],
    }, "scan_app_leftovers")
    safe_lo = lo.get("safeLeftovers", [])
    assert any("GhostUninstalledApp" in x["name"] for x in safe_lo), f"expected GhostUninstalledApp: {lo}"
    assert not any("ActiveInstalledApp" in x["name"] for x in safe_lo), f"installed app must be skipped: {lo}"
    lo_item = [x for x in safe_lo if "GhostUninstalledApp" in x["name"]][0]
    lo_rej = call_tool(srv, "delete", {
        "scanId": lo["scanId"],
        "items": [{"path": lo_item["path"], "approvalToken": lo_item["approvalToken"]}],
        "confirmRisk": False,
        "dryRun": False,
    }, "scan_app_leftovers delete without confirmRisk -> rejected")
    assert lo_rej.get("rejected", 0) >= 1, f"review leftover must require confirmRisk: {lo_rej}"

    # (E) scan_startup_items (orphaned binary + CLI secret redaction)
    st_dir = os.path.join(v06_tmp, "startup")
    os.makedirs(st_dir, exist_ok=True)
    missing_bin = os.path.join(v06_tmp, "nonexistent_daemon.exe" if platform.system() == "Windows" else "nonexistent_daemon")
    desktop_entry = os.path.join(st_dir, "ghost-agent.desktop")
    with open(desktop_entry, "w", encoding="utf-8") as f:
        f.write(
            f'[Desktop Entry]\nType=Application\nName=GhostAgent\n'
            f'Exec="{missing_bin}" --api-key sk-live-SUPERSECRET999 -H "Authorization: Bearer BEARERSECRET888" https://admin:URLPASS777@api.example.com/hook\n'
        )
    st = call_tool(srv, "scan_startup_items", {
        "customDir": st_dir,
        "orphansOnly": True,
    }, "scan_startup_items (orphan + secret redaction)")
    assert st.get("orphanedCount", 0) == 1, f"expected 1 orphaned startup item: {st}"
    st_raw = json.dumps(st)
    for secret_marker in ("SUPERSECRET999", "BEARERSECRET888", "URLPASS777", "admin:"):
        assert secret_marker not in st_raw, f"CLI secret {secret_marker} leaked in startup report: {st_raw}"
    assert st["items"][0].get("approvalToken"), f"writable startup orphan must have approvalToken: {st}"

    # (F) find_large_forgotten (semantic ml_model kind + review token)
    lf_dir = os.path.join(v06_tmp, "large")
    os.makedirs(lf_dir, exist_ok=True)
    gguf_path = os.path.join(lf_dir, "forgotten-q4.gguf")
    with open(gguf_path, "wb") as f:
        f.write(b"Q" * (1100 * 1024))
    os.utime(gguf_path, (old_ts, old_ts))
    lf = call_tool(srv, "find_large_forgotten", {
        "root": lf_dir,
        "minSize": 1024 * 1024,
        "unusedDays": 30,
    }, "find_large_forgotten")
    assert lf.get("totalMatchedFiles", 0) == 1 and lf["files"][0]["semanticKind"] == "ml_model", f"expected ml_model: {lf}"
    assert lf["files"][0].get("approvalToken"), f"expected approvalToken on large file: {lf}"

    # (G) get_report on a custom v0.6.0 session
    rep = srv.request("tools/call", {"name": "get_report", "arguments": {"scanId": lf["scanId"]}})
    check_ok(resp=rep, label="get_report (v0.6.0 session)")

    import shutil as _shutil
    _shutil.rmtree(v06_tmp, ignore_errors=True)

    # 9. cleanup temp dir
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    srv.proc.kill()
    print("\nALL SMOKE TESTS PASSED 🎉")

if __name__ == "__main__":
    main()