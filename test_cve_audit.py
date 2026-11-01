# -*- coding: utf-8 -*-
"""CVE 比對模組測試（不連網；用資料包餵公告）。  python3 test_cve_audit.py"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core.cve_audit as ca  # noqa: E402
from core.cve_audit import (CVEAudit, deb_compare, demux, parse_upgrades, range_status,  # noqa: E402
                            slim_record, normalize_source, version_hints, slim_generic, parse_cve_input)

NOW = 1793409930


def make_bundle(running="5.15.0-198-generic", reboot=True, os_id="ubuntu", ver="22.04",
                upgrades="", extra_pkgs="", cpu=""):
    return f"""=== [CVE_OS] ===
PRETTY_NAME="{os_id} {ver}"
ID={os_id}
VERSION_ID="{ver}"
=== [CVE_KERNEL] ===
RUNNING={running}
HOST=testhost
NOW={NOW}
UPTIME_SECONDS=382893.75
REBOOT_REQUIRED={'yes' if reboot else 'no'}
{'REBOOT_SINCE=' + str(NOW - 3 * 86400) if reboot else ''}
{'REBOOT_PKG=linux-image-5.15.0-202-generic' if reboot else ''}
=== [CVE_PKGS] ===
linux-image-5.15.0-198-generic 5.15.0-198.208 linux-signed 5.15.0-198.208
linux-image-5.15.0-202-generic 5.15.0-202.212 linux-signed 5.15.0-202.212
linux-image-unsigned-5.15.0-107-generic 5.15.0-107.117 linux 5.15.0-107.117
openssl 3.0.2-0ubuntu1.14 openssl 3.0.2-0ubuntu1.14
libssl3 3.0.2-0ubuntu1.14 openssl 3.0.2-0ubuntu1.14
xz-utils 5.2.5-2ubuntu1.2 xz-utils 5.2.5-2ubuntu1.2
{extra_pkgs}
=== [CVE_UPGRADES] ===
{upgrades}
=== [CVE_CPUVULN] ===
{cpu}
"""


def rec(pkg, events, eco="Ubuntu:22.04:LTS", rid="UBUNTU-CVE-2099-0001"):
    return {"id": rid, "summary": "test", "upstream": [],
            "affected": [{"ecosystem": eco, "package": pkg, "ranges": [events]}]}


def audit(bundle, cve, record, **kw):
    pack = {"records": {f"UBUNTU-{cve}": record} if record else {}, "missing": [] if record else [f"UBUNTU-{cve}"]}
    return CVEAudit().audit(bundle, cves=[cve], pack=pack, offline=True, **kw)


class TestDebCompare(unittest.TestCase):
    def test_order(self):
        lt = [("1.0-1", "1.0-2"), ("5.15.0-198.208", "5.15.0-202.212"), ("1.0~rc1", "1.0"),
              ("3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15"), ("1.9", "1.10"), ("2.35-0ubuntu3.9", "2.35-0ubuntu3.15"),
              ("1.0", "1.0+dfsg"), ("2.0", "1:0.5"), ("5.15.0-99.109", "5.15.0-100.110")]
        for a, b in lt:
            self.assertLess(deb_compare(a, b), 0, f"{a} < {b}")
            self.assertGreater(deb_compare(b, a), 0, f"{b} > {a}")
        self.assertEqual(deb_compare("1.0-1", "1.0-1"), 0)
        self.assertEqual(deb_compare("1.0-1", "0001.0-1"), 0)


class TestParsing(unittest.TestCase):
    def test_demux_and_upgrades(self):
        s = demux(make_bundle())
        self.assertIn("PRETTY_NAME", s["OS"])
        self.assertIn("RUNNING=", s["KERNEL"])
        u = parse_upgrades("Inst openssl [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-updates, "
                           "Ubuntu:22.04/jammy-security [amd64])\nInst gh [2.1] (2.2 gh:cli.github.com [amd64])")
        self.assertTrue(u[0]["security"])
        self.assertFalse(u[1]["security"])
        self.assertEqual(u[0]["to"], "3.0.2-0ubuntu1.15")

    def test_upgrade_lines_new_package_and_kept_back(self):
        txt = ("Inst linux-firmware [20240318-0ubuntu2.26] (20240318-0ubuntu3.1 Ubuntu:24.04/noble-updates [all]) []\n"
               "Inst linux-firmware-realtek (20240318-0ubuntu3.1 Ubuntu:24.04/noble-updates [all])\n"
               "Inst linux-image-6.8.0-148-generic (6.8.0-148.148 Ubuntu:24.04/noble-security [amd64])")
        u = parse_upgrades(txt)
        self.assertEqual([x["name"] for x in u], ["linux-firmware", "linux-firmware-realtek", "linux-image-6.8.0-148-generic"])
        self.assertEqual([bool(x["from"]) for x in u], [True, False, False])
        self.assertTrue(u[2]["security"])
        r = CVEAudit().audit(make_bundle(upgrades=txt))
        self.assertEqual(r["pending_security_updates"], [])   # 新增套件（沒有舊版）不算安全更新
        self.assertEqual(r["pending_updates_total"], 1)
        self.assertEqual(r["pending_new_packages"], 2)
        self.assertIn("linux-image-6.8.0-148-generic", r["kernel"]["pending_kernel_updates"])

    def test_normalize_source(self):
        self.assertEqual(normalize_source("linux-signed"), "linux")
        self.assertEqual(normalize_source("linux-signed-hwe-5.15"), "linux-hwe-5.15")
        self.assertEqual(normalize_source("openssl"), "openssl")

    def test_cpu_vuln_line_with_slash_does_not_crash(self):
        cpu = ("/sys/devices/system/cpu/vulnerabilities/mds:Vulnerable: Clear CPU buffers attempted / no microcode\n"
               "/sys/devices/system/cpu/vulnerabilities/spectre_v2:Mitigation: IBRS; IBPB: conditional")
        r = CVEAudit().audit(make_bundle(cpu=cpu))
        self.assertEqual([c["name"] for c in r["cpu_vulnerabilities"]], ["mds"])


class TestKernelStatus(unittest.TestCase):
    def test_reboot_pending_when_newer_installed(self):
        k = CVEAudit().audit(make_bundle())["kernel"]
        self.assertTrue(k["reboot_pending"])
        self.assertTrue(k["behind_installed"])
        self.assertEqual(k["newest_installed"], "5.15.0-202-generic")
        self.assertEqual(k["running_version"], "5.15.0-198.208")
        self.assertEqual(k["reboot_pending_days"], 3.0)

    def test_up_to_date(self):
        k = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=False))["kernel"]
        self.assertFalse(k["reboot_pending"])

    def test_flag_only(self):
        # 已經是最新 kernel，但系統標記要重開機（例如 libc 更新）
        k = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=True))["kernel"]
        self.assertTrue(k["reboot_pending"])
        self.assertFalse(k["behind_installed"])


class TestVerdicts(unittest.TestCase):
    def v(self, pkg, events, **kw):
        return audit(make_bundle(**kw), "CVE-2099-0001", rec(pkg, events))["cves"][0]

    def test_kernel_reboot_needed(self):
        c = self.v("linux", [("introduced", "0"), ("fixed", "5.15.0-200.210")])
        self.assertEqual(c["verdict"], "REBOOT_NEEDED")

    def test_kernel_update_needed(self):
        c = self.v("linux", [("introduced", "0"), ("fixed", "5.15.0-205.215")])
        self.assertEqual(c["verdict"], "UPDATE_NEEDED")

    def test_kernel_fixed_when_running_new(self):
        c = self.v("linux", [("introduced", "0"), ("fixed", "5.15.0-200.210")],
                   running="5.15.0-202-generic", reboot=False)
        self.assertEqual(c["verdict"], "FIXED")

    def test_kernel_fixed_old(self):
        self.assertEqual(self.v("linux", [("introduced", "0"), ("fixed", "5.15.0-190.200")])["verdict"], "FIXED")

    def test_no_fix_yet(self):
        self.assertEqual(self.v("linux", [("introduced", "0")])["verdict"], "NO_FIX_YET")

    def test_low_priority_no_fix_does_not_alarm(self):
        r = rec("linux", [("introduced", "0")])
        r["priority"] = "low"
        out = audit(make_bundle(running="5.15.0-202-generic", reboot=False), "CVE-2099-0001", r)
        self.assertEqual(out["cves"][0]["verdict"], "NO_FIX_YET")
        self.assertEqual(out["exit_code"], 0)
        r["priority"] = "high"
        out = audit(make_bundle(running="5.15.0-202-generic", reboot=False), "CVE-2099-0001", r)
        self.assertEqual(out["exit_code"], 2)
        self.assertIn("尚未提供修復", out["verdict"]["title"])

    def test_not_installed(self):
        self.assertEqual(self.v("nginx", [("introduced", "0"), ("fixed", "9")])["verdict"], "NOT_INSTALLED")

    def test_introduced_after_installed_is_not_vulnerable(self):
        c = self.v("openssl", [("introduced", "3.0.2-0ubuntu1.20"), ("fixed", "3.0.2-0ubuntu1.25")])
        self.assertEqual(c["verdict"], "FIXED")

    def test_package_update_needed_and_available(self):
        up = "Inst openssl [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])"
        c = self.v("openssl", [("introduced", "0"), ("fixed", "3.0.2-0ubuntu1.15")], upgrades=up)
        self.assertEqual(c["verdict"], "UPDATE_NEEDED")
        self.assertTrue(c["details"][0]["update_available"])

    def test_package_fixed(self):
        c = self.v("openssl", [("introduced", "0"), ("fixed", "3.0.2-0ubuntu1.10")])
        self.assertEqual(c["verdict"], "FIXED")

    def test_worst_of_multiple_entries(self):
        r = {"id": "x", "summary": "", "upstream": [], "affected": [
            {"ecosystem": "Ubuntu:22.04:LTS", "package": "nginx", "ranges": [[("introduced", "0"), ("fixed", "9")]]},
            {"ecosystem": "Ubuntu:22.04:LTS", "package": "openssl", "ranges": [[("introduced", "0"), ("fixed", "3.0.2-0ubuntu1.99")]]}]}
        self.assertEqual(audit(make_bundle(), "CVE-2099-0001", r)["cves"][0]["verdict"], "UPDATE_NEEDED")

    def test_unknown_cve_is_not_called_safe(self):
        c = audit(make_bundle(), "CVE-2099-0001", None)["cves"][0]
        self.assertEqual(c["verdict"], "UNKNOWN")
        self.assertIn("不等於", c["note"])

    def test_other_ecosystem_only(self):
        r = rec("linux", [("introduced", "0"), ("fixed", "9")], eco="Ubuntu:20.04:LTS")
        self.assertEqual(audit(make_bundle(), "CVE-2099-0001", r)["cves"][0]["verdict"], "UNKNOWN")

    def test_bad_cve_format(self):
        r = CVEAudit().audit(make_bundle(), cves=["not-a-cve"], offline=True)
        self.assertEqual(r["cves"][0]["verdict"], "UNKNOWN")

    def test_unsupported_distro(self):
        r = CVEAudit().audit(make_bundle(os_id="rocky", ver="9.4"), cves=["CVE-2099-0001"], offline=True)
        self.assertEqual(r["cves"][0]["verdict"], "UNSUPPORTED")
        self.assertTrue(r["errors"])

    def test_offline_missing_pack_entry_reports_error(self):
        r = CVEAudit().audit(make_bundle(), cves=["CVE-2099-0001"], pack={"records": {}}, offline=True)
        self.assertTrue(r["errors"])
        self.assertEqual(r["cves"][0]["verdict"], "UNKNOWN")


class TestPackAndOutputs(unittest.TestCase):
    def test_slim_roundtrip_through_json(self):
        raw = {"id": "UBUNTU-CVE-2099-0001", "details": "d" * 500, "upstream": ["CVE-2099-0001"],
               "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "linux"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.15.0-200.210"}]}],
                             "ecosystem_specific": {"binaries": [{"binary_name": "x"}] * 100}}]}
        slim = json.loads(json.dumps(slim_record(raw)))
        self.assertNotIn("binaries", json.dumps(slim))
        self.assertEqual(len(slim["summary"]), 300)
        c = audit(make_bundle(), "CVE-2099-0001", slim)["cves"][0]
        self.assertEqual(c["verdict"], "REBOOT_NEEDED")

    def test_range_status_multiple_ranges(self):
        ranges = [[("introduced", "0"), ("fixed", "2.0")], [("introduced", "3.0"), ("fixed", "3.5")]]
        self.assertEqual(range_status("1.5", ranges), (True, "2.0"))
        self.assertEqual(range_status("2.5", ranges), (False, None))
        self.assertEqual(range_status("3.2", ranges), (True, "3.5"))

    def test_exit_codes(self):
        a = CVEAudit()
        r = a.audit(make_bundle(running="5.15.0-202-generic", reboot=False))
        self.assertEqual(r["exit_code"], 0)
        self.assertEqual(a.audit(make_bundle())["exit_code"], 1)
        up = "Inst openssl [1] (2 Ubuntu:22.04/jammy-security [amd64])"
        self.assertEqual(a.audit(make_bundle(running="5.15.0-202-generic", reboot=False, upgrades=up))["exit_code"], 2)
        self.assertEqual(a.audit(make_bundle(upgrades=up))["exit_code"], 3)

    def test_one_line_and_prescription(self):
        r = CVEAudit().audit(make_bundle())
        line = CVEAudit.one_line(r)
        self.assertIn("reboot_pending=1", line)
        self.assertIn("reboot_pending_days=3.0", line)
        cmds = " ".join(s["cmd"] for s in r["prescription"])
        self.assertIn("sudo reboot", cmds)
        self.assertEqual(r["verdict"]["title"].startswith("已經更新過，但還沒重開機"), True)

    def test_clean_host(self):
        r = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=False))
        self.assertEqual(r["prescription"][0]["level"], "OK")
        self.assertEqual(r["verdict"]["color"], "#10b981")


def gen(summary, details=""):
    return slim_generic({"id": "CVE-2099-0002", "summary": summary, "details": details, "published": "2026-01-01T00:00:00Z"})


def audit_app(cve, generic, app_version=None, bundle=None):
    pack = {"records": {}, "missing": [f"UBUNTU-{cve}"], "generic": {cve: generic} if generic else {}}
    return CVEAudit().audit(bundle or make_bundle(running="5.15.0-202-generic", reboot=False),
                            cves=[cve], pack=pack, offline=True, app_version=app_version)


class TestAppLevel(unittest.TestCase):
    def test_hints(self):
        h = version_hints("LibreNMS before 26.5.0 Remote Code Execution")
        self.assertEqual(h["fixed_in"], ["26.5.0"])
        h = version_hints("Versions 25.12.0 and below have a SQL injection")
        self.assertEqual(h["last_affected"], ["25.12.0"])
        h = version_hints("affects versions up to 3.1 and fixed in 3.2.1")
        self.assertEqual((h["last_affected"], h["fixed_in"]), (["3.1"], ["3.2.1"]))
        self.assertEqual(version_hints("no versions here"), {"fixed_in": [], "last_affected": []})

    def test_affected_when_older(self):
        r = audit_app("CVE-2099-0002", gen("LibreNMS before 26.5.0 RCE"), "26.3.0")
        self.assertEqual(r["cves"][0]["verdict"], "APP_LIKELY_AFFECTED")
        self.assertEqual(r["exit_code"], 2)
        self.assertIn("應用程式層級", r["verdict"]["title"])

    def test_fixed_when_newer_and_boundary(self):
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.5.0"), "26.10.0")["cves"][0]["verdict"], "APP_LIKELY_FIXED")
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.5.0"), "26.5.0")["cves"][0]["verdict"], "APP_LIKELY_FIXED")
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.5.0"), "26.4.9")["cves"][0]["verdict"], "APP_LIKELY_AFFECTED")

    def test_numeric_not_string_compare(self):
        # 26.10.0 > 26.9.0（字串比較會錯）
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.9.0"), "26.10.0")["cves"][0]["verdict"], "APP_LIKELY_FIXED")

    def test_git_describe_version(self):
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.5.0"), "26.10.0-94-gcc1335d8e4")["cves"][0]["verdict"], "APP_LIKELY_FIXED")

    def test_and_below_uses_last_affected(self):
        g = gen("SQLi", "Versions 25.12.0 and below are vulnerable")
        self.assertEqual(audit_app("CVE-2099-0002", g, "25.12.0")["cves"][0]["verdict"], "APP_LIKELY_AFFECTED")
        self.assertEqual(audit_app("CVE-2099-0002", g, "26.1.0")["cves"][0]["verdict"], "APP_LIKELY_FIXED")

    def test_manual_without_version_or_text(self):
        self.assertEqual(audit_app("CVE-2099-0002", gen("RCE in module"), "26.10.0")["cves"][0]["verdict"], "APP_MANUAL")
        self.assertEqual(audit_app("CVE-2099-0002", gen("before 26.5.0"), None)["cves"][0]["verdict"], "APP_MANUAL")

    def test_unresolved_is_never_reported_as_all_clear(self):
        # 回歸：曾經所有 CVE 都『查無』時，結論卻寫成「未發現待處理」
        for r in (audit_app("CVE-2099-0002", gen("RCE in module"), None),
                  audit(make_bundle(running="5.15.0-202-generic", reboot=False), "CVE-2099-0001", None)):
            self.assertNotIn("未發現", r["verdict"]["title"])
            self.assertIn("無法判斷", r["verdict"]["title"])
            self.assertEqual(r["verdict"]["color"], "#f59e0b")
            self.assertEqual(r["exit_code"], 4)

    def test_distro_record_wins_over_generic(self):
        pack = {"records": {"UBUNTU-CVE-2099-0001": rec("linux", [("introduced", "0"), ("fixed", "5.15.0-190.200")])},
                "generic": {"CVE-2099-0001": gen("before 99.0")}}
        r = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=False), cves=["CVE-2099-0001"],
                             pack=pack, offline=True, app_version="1.0")
        self.assertEqual(r["cves"][0]["verdict"], "FIXED")


UPG = ("Inst openssl [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])\n"
       "Inst libssl3 [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])\n"
       "Inst linux-image-5.15.0-205-generic [5.15.0-202.212] (5.15.0-205.215 Ubuntu:22.04/jammy-security [amd64])\n"
       "Inst brand-new-pkg (1.0 Ubuntu:22.04/jammy-security [amd64])")


def fake_osv(queries, **kw):
    out = []
    for name, eco, ver in queries:
        if ver == "3.0.2-0ubuntu1.14":
            out.append({"UBUNTU-CVE-2024-0001", "UBUNTU-CVE-2024-0002", "USN-9999-1"})
        else:
            out.append({"UBUNTU-CVE-2024-0002"})
    return out, set()


class TestAutoFixes(unittest.TestCase):
    def run_audit(self, **kw):
        b = make_bundle(running="5.15.0-202-generic", reboot=False, upgrades=UPG)
        return CVEAudit().audit(b, **kw)

    def test_diff_is_what_update_fixes(self):
        with mock.patch.object(ca, "osv_query_all", fake_osv):
            r = self.run_audit(auto=True)
        items = r["auto_fixes"]["items"]
        self.assertEqual(len(items), 1)                      # openssl / libssl3 同 source 只算一次；kernel 與新增套件排除
        self.assertEqual(items[0]["source"], "openssl")
        self.assertEqual(items[0]["cves"], ["CVE-2024-0001"])  # 更新後仍受影響的 0002 不算，USN 不是 CVE
        self.assertEqual(r["auto_fixes"]["total_cves"], 1)
        self.assertIn("會修掉 1 個", r["verdict"]["title"])

    def test_not_called_when_offline_or_not_requested(self):
        with mock.patch.object(ca, "osv_query_all", side_effect=AssertionError("不該連網")):
            self.run_audit(auto=True, offline=True)
            self.run_audit(auto=False)

    def test_network_failure_is_reported_not_crash(self):
        with mock.patch.object(ca, "osv_query_all", side_effect=RuntimeError("無法連線 OSV：URLError")):
            r = self.run_audit(auto=True)
        self.assertTrue(any("自動比對" in e for e in r["errors"]))
        self.assertEqual(r["auto_fixes"]["items"], [])
        self.assertEqual(len(r["pending_security_updates"]), 3)   # openssl、libssl3、kernel；沒有 CVE 對應也不影響待更新結論

    def test_truncated_is_flagged(self):
        def trunc(queries, **kw):
            res, _ = fake_osv(queries)
            return res, {0}
        with mock.patch.object(ca, "osv_query_all", trunc):
            r = self.run_audit(auto=True)
        self.assertEqual(r["auto_fixes"]["truncated"], ["openssl"])


class TestCveInput(unittest.TestCase):
    def test_plain_ids_and_list(self):
        self.assertEqual(parse_cve_input("CVE-2024-1086 CVE-2024-3094")["ids"], ["CVE-2024-1086", "CVE-2024-3094"])
        self.assertEqual(parse_cve_input(["CVE-2024-1086", "cve-2024-3094"])["ids"], ["CVE-2024-1086", "CVE-2024-3094"])

    def test_messy_pasted_page(self):
        page = """Ubuntu Security Notice USN-6688-1 — fixes cve-2024-1086, and also CVE‑2024‑0001 (non-breaking hyphen),
        CVE–2024–0002 (en dash). See https://ubuntu.com/security/CVE-2024-1086.json and (CVE-2023-4567).
        Duplicate: CVE-2024-1086. Not a CVE: CVE-2024-123 and CVE-24-1234567."""
        info = parse_cve_input(page)
        self.assertEqual(info["ids"], ["CVE-2024-1086", "CVE-2024-0001", "CVE-2024-0002", "CVE-2023-4567"])
        self.assertEqual(info["found"], 4)

    def test_limit_and_truncated(self):
        text = " ".join(f"CVE-2024-{1000 + i}" for i in range(45))
        info = parse_cve_input(text)
        self.assertEqual((len(info["ids"]), info["found"], info["truncated"]), (30, 45, True))
        self.assertEqual(info["ids"][0], "CVE-2024-1000")

    def test_empty_and_nothing_found(self):
        self.assertFalse(parse_cve_input("")["had_input"])
        self.assertFalse(parse_cve_input(None)["had_input"])
        info = parse_cve_input("今天網路怪怪的，幫我看看")
        self.assertTrue(info["had_input"])
        self.assertEqual(info["found"], 0)

    def test_nothing_found_is_not_green(self):
        # 回歸：貼了內容卻沒找到 CVE，不可回「未發現待處理」
        info = parse_cve_input("這段話裡沒有編號")
        r = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=False), cves=info["ids"],
                             offline=True, cve_input=info)
        self.assertNotIn("未發現", r["verdict"]["title"])
        self.assertIn("沒有找到 CVE", r["verdict"]["title"])
        self.assertEqual(r["exit_code"], 4)

    def test_empty_input_stays_normal(self):
        info = parse_cve_input("")
        r = CVEAudit().audit(make_bundle(running="5.15.0-202-generic", reboot=False), cves=[], offline=True, cve_input=info)
        self.assertEqual(r["exit_code"], 0)
        self.assertIn("未發現", r["verdict"]["title"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
