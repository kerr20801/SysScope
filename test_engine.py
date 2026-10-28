# -*- coding: utf-8 -*-
"""
SysScope Test Engine (全功能單元測試)
測試覆蓋：
1. DiskDoctor: 幽靈磁碟日誌咬住未釋放 + Inode 耗盡
2. HistoryForensic: 事故前指令歷史審計 + 自殺翻車指令抓取 + 事故導火線串聯
3. SystemdCatcher: 全域崩潰服務捕手 (systemctl status / systemctl --failed / Port 被搶 / 語法報錯 / CrashLoop)
4. OOMForensic: dmesg OOM 殺人案還原
5. RebootReadiness: /etc/fstab 重開機地雷檢驗 (NFS缺少_netdev,nofail)
6. NetKernelAudit: 監聽 IP 陷阱 (127.0.0.1 誤綁)
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.disk_doctor import DiskDoctor
from core.history_forensic import HistoryForensic
from core.systemd_catcher import SystemdCatcher
from core.oom_forensic import OOMForensic
from core.reboot_readiness import RebootReadiness
from core.net_kernel_audit import NetKernelAudit
from core.master_synthesizer import MasterSynthesizer

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

class TestSysScopeSuite(unittest.TestCase):
    def test_disk_doctor_ghost_files(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_ghost_disk.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        doctor = DiskDoctor()
        res = doctor.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertGreaterEqual(len(res["ghost_files"]), 2)
        top = res["ghost_files"][0]
        self.assertEqual(top["command"], "java")
        self.assertEqual(top["pid"], "1821")
        self.assertIn("/proc/1821/fd/4", top["remedy_cmd"])
        print(f"[OK] DiskDoctor correctly identified ghost file: {top['path']} ({top['size_mb']} MB)")

    def test_history_forensic_crash(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_history_crash.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        forensic = HistoryForensic()
        res = forensic.audit(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertGreaterEqual(len(res["flagged_events"]), 3)

        types = [e["type"] for e in res["flagged_events"]]
        self.assertIn("IPTABLES_FLUSH", types)
        self.assertIn("CHMOD_DANGEROUS", types)
        self.assertIn("SWAPOFF_TRIGGER_OOM", types)
        self.assertGreater(len(res["correlation_insights"]), 0)
        self.assertGreater(res["category_counts"]["CONFIG"], 0)
        self.assertGreater(res["category_counts"]["SERVICE"], 0)
        print(f"[OK] HistoryForensic caught {len(res['flagged_events'])} suicidal commands and {len(res['correlation_insights'])} correlation insights")

    def test_systemd_catcher_table(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_systemd_fail.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        catcher = SystemdCatcher()
        res = catcher.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertEqual(res["failed_count"], 2)
        self.assertIn("Address already in use", res["verdict"]["reason"])
        print(f"[OK] SystemdCatcher caught crashed nginx.service from table with EADDRINUSE!")

    def test_systemd_catcher_status_format(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_systemd_status.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        catcher = SystemdCatcher()
        res = catcher.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertEqual(res["cause_type"], "PORT_CONFLICT")
        self.assertIn("80", res["detected_ports"])
        self.assertEqual(res["failed_units"][0]["unit"], "nginx.service")
        print(f"[OK] SystemdCatcher successfully parsed real systemctl status: unit={res['failed_units'][0]['unit']}, port={res['detected_ports']}")

    def test_systemd_catcher_syntax_error(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_systemd_syntax.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        catcher = SystemdCatcher()
        res = catcher.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertEqual(res["cause_type"], "CONFIG_SYNTAX_ERROR")
        self.assertIn("nginx -t", res["remedy_commands"][0])
        print(f"[OK] SystemdCatcher correctly diagnosed configuration syntax error and suggested nginx -t!")

    def test_systemd_catcher_crashloop(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_systemd_crashloop.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        catcher = SystemdCatcher()
        res = catcher.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertEqual(res["cause_type"], "CRASH_LOOP")
        self.assertEqual(res["failed_units"][0]["unit"], "myapp-worker.service")
        print(f"[OK] SystemdCatcher correctly caught CrashLoopBackOff on myapp-worker.service!")

    def test_oom_forensic(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_oom_dmesg.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        forensic = OOMForensic()
        res = forensic.parse_and_diagnose(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertGreaterEqual(len(res["oom_events"]), 1)
        victim = res["oom_events"][0]
        self.assertEqual(victim["victim_cmd"], "mysqld")
        self.assertEqual(victim["victim_pid"], "18291")
        print(f"[OK] OOMForensic reconstructed victim: {victim['victim_cmd']} (PID: {victim['victim_pid']})")

    def test_reboot_readiness(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_fstab_broken.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        readiness = RebootReadiness()
        res = readiness.audit(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertLess(res["readiness_score"], 70)
        types = [h["type"] for h in res["hazards"]]
        self.assertIn("NETWORK_MOUNT_WITHOUT_NETDEV", types)
        print(f"[OK] RebootReadiness caught fstab hazard: score {res['readiness_score']} (NFS missing _netdev)")

    def test_net_kernel_audit(self):
        sample_ss = """
        Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:PortProcess
        tcp   LISTEN 0      128     127.0.0.1:8080      0.0.0.0:*       users:(("nginx",pid=1234,fd=6))
        tcp   LISTEN 0      511     0.0.0.0:22          0.0.0.0:*       users:(("sshd",pid=982,fd=3))
        """
        audit = NetKernelAudit()
        res = audit.audit(sample_ss)

        self.assertTrue(res["success"])
        self.assertEqual(len(res["localhost_traps"]), 1)
        trap = res["localhost_traps"][0]
        self.assertEqual(trap["port"], 8080)
        self.assertEqual(trap["ip_bind"], "127.0.0.1")
        print(f"[OK] NetKernelAudit caught Localhost trap on port {trap['port']}")

    def test_master_synthesizer_bundle(self):
        fpath = os.path.join(SAMPLES_DIR, "sample_full_bundle.txt")
        with open(fpath, "r", encoding="utf-8") as f:
            txt = f.read()

        synth = MasterSynthesizer()
        res = synth.synthesize(txt)

        self.assertTrue(res["success"])
        self.assertEqual(res["master_verdict"]["level"], "CRITICAL")
        self.assertLessEqual(res["health_score"], 20)
        self.assertGreaterEqual(len(res["incident_chains"]), 3)
        self.assertGreaterEqual(len(res["prioritized_worklist"]), 4)

        # 驗證跨維度因果鏈推演
        chain_titles = [c["title"] for c in res["incident_chains"]]
        self.assertTrue(any("swapoff" in t or "OOM" in t for t in chain_titles))
        self.assertTrue(any("rm -rf" in t or "幽靈" in t or "未釋放" in t for t in chain_titles))
        self.assertTrue(any("Port 80" in t or "Apache" in t or "衝突" in t for t in chain_titles))

        # 驗證工作清單
        p1_items = [w for w in res["prioritized_worklist"] if "P1" in w["priority"]]
        self.assertGreater(len(p1_items), 0)
        self.assertTrue(all("commands" in w and len(w["commands"]) > 0 for w in res["prioritized_worklist"]))

        print(f"[OK] MasterSynthesizer successfully synthesized Cisco tech-support bundle: Score={res['health_score']}/100, Chains={len(res['incident_chains'])}, Worklist={len(res['prioritized_worklist'])}")

if __name__ == "__main__":
    unittest.main()
