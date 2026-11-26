# -*- coding: utf-8 -*-
"""
Unit tests for SysScope Backdoor & Implant Hunter (core/backdoor_hunter.py)
"""

import sys
import unittest
from pathlib import Path

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.backdoor_hunter import BackdoorHunter
from core.master_synthesizer import MasterSynthesizer


class TestBackdoorHunter(unittest.TestCase):

    def setUp(self):
        self.hunter = BackdoorHunter()
        self.samples_dir = Path(ROOT_DIR) / "samples"

    def test_sample_backdoor_hunt_detects_all_vectors_without_fp(self):
        sample_text = (self.samples_dir / "sample_backdoor_hunt.txt").read_text(encoding="utf-8")
        res = self.hunter.hunt(sample_text)

        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertGreaterEqual(res["critical_count"], 5)
        self.assertEqual(res["security_score"], 0)

        categories = {f["category"] for f in res["findings"]}
        self.assertIn("隱藏特權帳號", categories)
        self.assertIn("系統底層劫持 (Rootkit)", categories)
        self.assertIn("SSH 金鑰後門", categories)
        self.assertIn("排程 / 啟動後門", categories)
        self.assertIn("挖礦木馬 / 惡意行程", categories)
        self.assertIn("無檔名記憶體常駐", categories)
        self.assertIn("疑似反彈 Shell 外連", categories)
        self.assertIn("SUID 提權後門", categories)
        self.assertIn("暫存區隱藏檔案", categories)

        # 確保正常系統檔不會誤報
        evidences = "\n".join(f["evidence"] for f in res["findings"])
        self.assertNotIn("/usr/bin/sudo", evidences)
        self.assertNotIn("/usr/bin/passwd", evidences)
        self.assertNotIn(".X11-unix", evidences)
        self.assertNotIn("/usr/local/bin/db_backup.sh", evidences)

        # 確保每筆都有白話解釋與唯讀確認指令
        for f in res["findings"]:
            self.assertTrue(f["plain_explain"])
            self.assertTrue(f["normal_baseline"])
            self.assertTrue(f["safe_verify_cmd"])
            self.assertTrue(f["remedy_advice"])

    def test_clean_host_returns_healthy_green(self):
        clean_text = """=== [7] BACKDOOR ===
--- [UID0_PASSWD] ---
root:x:0:0:root:/root:/bin/bash
--- [SUDOERS] ---
%sudo ALL=(ALL:ALL) ALL
ubuntu ALL=(ALL) NOPASSWD: ALL
--- [SSH_KEYS] ---
FILE:/root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleNormalKey admin@office
--- [CRON] ---
0 2 * * * root /usr/local/bin/backup.sh
--- [LD_PRELOAD] ---
--- [STARTUP] ---
--- [PROCESSES] ---
root       1  0.0  0.1 168920 11200 ? Ss 08:00 0:02 /sbin/init
www-data 412  0.2  0.5  52000  8120 ? S  08:01 0:05 nginx: worker process
--- [DELETED_EXE] ---
--- [OUTBOUND] ---
tcp ESTAB 0 0 10.0.1.15:50122 93.184.216.34:443 users:(("apt-get",pid=901,fd=4))
--- [SUID] ---
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/ping
--- [TMP_HIDDEN] ---
drwxrwxrwt 2 root root 40 Nov 26 08:00 .X11-unix
drwxrwxrwt 2 root root 40 Nov 26 08:00 .ICE-unix
"""
        res = self.hunter.hunt(clean_text)
        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "HEALTHY")
        self.assertEqual(res["security_score"], 100)
        self.assertEqual(res["total_findings"], 0)

    def test_raw_webshell_detection(self):
        raw = "/var/www/html/uploads/cache.php:1:<?php @eval($_POST['cmd']); ?>"
        res = self.hunter.hunt(raw)
        self.assertEqual(res["verdict"]["level"], "CRITICAL")
        self.assertTrue(any("Webshell" in f["category"] for f in res["findings"]))

    def test_empty_input_returns_info(self):
        res = self.hunter.hunt("")
        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"]["level"], "INFO")
        self.assertEqual(res["total_findings"], 0)

    def test_master_synthesizer_integrates_backdoor_dimension(self):
        sample_text = (self.samples_dir / "sample_backdoor_hunt.txt").read_text(encoding="utf-8")
        ms = MasterSynthesizer()
        res = ms.synthesize(sample_text)
        self.assertIn("backdoor", res["dimensions"])
        self.assertEqual(res["dimensions"]["backdoor"]["verdict"]["level"], "CRITICAL")
        self.assertGreater(len(res["incident_chains"]), 0)
        self.assertIn("後門", res["incident_chains"][0]["title"])
        self.assertLess(res["health_score"], 70)


if __name__ == "__main__":
    unittest.main()
