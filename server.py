# -*- coding: utf-8 -*-
"""
SysScope Server - 系統主機全方位異常透視儀
純 Python 3 原生標準庫 (Zero-Dependency)
跨平台支援：Windows | macOS | Linux
功能：
1. 磁碟空間與幽靈日誌急救站 (/api/diagnose/disk)
2. 指令歷史與人為翻車鑑識 (/api/diagnose/history)
3. Systemd 全域服務崩潰捕手 (/api/diagnose/systemd)
4. OOM Killer 案發現場還原 (/api/diagnose/oom)
5. 重開機安全驗收雷達 (/api/diagnose/reboot)
6. 核心網路連線與 Port 綁定診斷 (/api/diagnose/network)
7. 本機全自動一鍵掃描 (/api/auto-scan-host)
8. CVE 比對與 kernel 白話狀態 (/api/diagnose/cve，/api/cve/collector)
"""
import sys
import os
import re
import json
import socket
import time
import subprocess
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

from core.disk_doctor import DiskDoctor
from core.history_forensic import HistoryForensic
from core.systemd_catcher import SystemdCatcher
from core.oom_forensic import OOMForensic
from core.reboot_readiness import RebootReadiness
from core.net_kernel_audit import NetKernelAudit
from core.master_synthesizer import MasterSynthesizer
from core.remedy_executor import remedy_executor
import core.cve_audit as cve_audit_mod
from core.cve_audit import CVEAudit, COLLECTOR_ONELINER, collect_local, load_pack

PORT = 8940
for i, arg in enumerate(sys.argv):
    if arg == "--port" and i + 1 < len(sys.argv):
        try:
            PORT = int(sys.argv[i + 1])
        except ValueError:
            pass
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
INDEX_PATH = os.path.join(WEB_DIR, "index.html")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

disk_doctor = DiskDoctor()
history_forensic = HistoryForensic()
systemd_catcher = SystemdCatcher()
oom_forensic = OOMForensic()
reboot_readiness = RebootReadiness()
net_kernel_audit = NetKernelAudit()
master_synthesizer = MasterSynthesizer()
cve_audit = CVEAudit()
# 離線資料包（可選）：環境變數 SYSSCOPE_CVE_PACK 指向用 `cve_check.py build-pack` 製作的 JSON
CVE_PACK_PATH = os.environ.get("SYSSCOPE_CVE_PACK", "")

class SysScopeHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        # 資安防護：強制禁止任何硬碟快取與資料殘留 (Zero-Disk-Retention)
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            if os.path.exists(INDEX_PATH):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(INDEX_PATH, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "index.html not found")

        elif path == "/api/cve/collector":
            self._send_json({"success": True, "command": COLLECTOR_ONELINER})

        elif path == "/api/sysinfo":
            self._send_json({
                "success": True,
                "hostname": socket.gethostname(),
                "os": sys.platform,
                "python_version": sys.version.split()[0],
                "time": time.strftime("%Y-%m-%d %H:%M:%S")
            })

        elif path == "/api/target-status":
            self._send_json({"success": True, "target": remedy_executor.get_cached_target()})

        elif path == "/api/sample":
            qs = urllib.parse.parse_qs(parsed.query)
            sample_type = qs.get("type", ["bundle"])[0]
            fname_map = {
                "bundle": "sample_full_bundle.txt",
                "techsupport": "sample_full_bundle.txt",
                "all": "sample_full_bundle.txt",
                "history": "sample_history_crash.txt",
                "ghost": "sample_ghost_disk.txt",
                "disk": "sample_ghost_disk.txt",
                "oom": "sample_oom_dmesg.txt",
                "oom_mysql": "sample_oom_dmesg.txt",
                "oom_cgroup": "sample_oom_cgroup.txt",
                "oom_healthy": "sample_oom_healthy.txt",
                "fstab": "sample_fstab_broken.txt",
                "reboot": "sample_fstab_broken.txt",
                "systemd": "sample_systemd_status.txt",
                "systemd_status": "sample_systemd_status.txt",
                "systemd_syntax": "sample_systemd_syntax.txt",
                "systemd_crashloop": "sample_systemd_crashloop.txt"
            }
            fname = fname_map.get(sample_type, "sample_full_bundle.txt")
            fpath = os.path.join(SAMPLES_DIR, fname)
            content = ""
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            self._send_json({"success": True, "type": sample_type, "content": content})

        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length)
        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            body = {}

        if path == "/api/diagnose/all-in-one":
            text = body.get("text", "")
            res = master_synthesizer.synthesize(text)
            self._send_json(res)

        elif path == "/api/diagnose/disk":
            text = body.get("text", "")
            res = disk_doctor.parse_and_diagnose(text)
            self._send_json(res)

        elif path == "/api/diagnose/history":
            text = body.get("text", "")
            res = history_forensic.audit(text)
            self._send_json(res)

        elif path == "/api/diagnose/systemd":
            text = body.get("text", "")
            res = systemd_catcher.parse_and_diagnose(text)
            self._send_json(res)

        elif path == "/api/diagnose/oom":
            text = body.get("text", "")
            res = oom_forensic.parse_and_diagnose(text)
            self._send_json(res)

        elif path == "/api/diagnose/reboot":
            fstab_text = body.get("fstab_text", "")
            mounts_text = body.get("mounts_text", "")
            res = reboot_readiness.audit(fstab_text, mounts_text=mounts_text)
            self._send_json(res)

        elif path == "/api/diagnose/network":
            ss_text = body.get("ss_text", "")
            kernel_stats = body.get("kernel_stats", "")
            res = net_kernel_audit.audit(ss_text, kernel_stats=kernel_stats)
            self._send_json(res)

        elif path == "/api/diagnose/cve":
            cve_info = cve_audit_mod.parse_cve_input(body.get("cves", ""))
            cves = cve_info["ids"]
            text = body.get("text", "")
            if body.get("live") and sys.platform.startswith("linux"):
                text = collect_local()
            if not text.strip():
                self._send_json({"success": False, "error": "沒有收集資料：請貼上收集指令的輸出，或在 Linux 主機上使用本機掃描。"}, 400)
                return
            pack = None
            try:
                if CVE_PACK_PATH and os.path.exists(CVE_PACK_PATH):
                    pack = load_pack(CVE_PACK_PATH)
            except Exception:
                pack = None
            res = cve_audit.audit(text, cves=cves, pack=pack, offline=bool(body.get("offline")),
                                  app_version=(str(body.get("app_version", "")).strip() or None),
                                  auto=(not cve_info["had_input"] and not body.get("offline")),
                                  cve_input=cve_info)
            res["success"] = True
            self._send_json(res)

        elif path == "/api/auto-scan-host":
            # 本機一鍵自動掃描 (在 Linux / Mac / Windows 伺服器直接執行)
            res = self._run_host_live_scan()
            self._send_json(res)

        elif path == "/api/exec-remedy":
            cmd = body.get("command", "")
            host = body.get("host")
            user = body.get("user")
            password = body.get("password")
            port = int(body.get("port", 22)) if body.get("port") else 22
            res = remedy_executor.execute(cmd, host=host, user=user, password=password, port=port)
            self._send_json(res)

        elif path == "/api/target-reset":
            remedy_executor.set_cached_target(None, "", None, 22)
            self._send_json({"success": True, "target": remedy_executor.get_cached_target()})

        elif path == "/api/remote-scan":
            host = body.get("host", "").strip()
            user = body.get("user", "").strip()
            password = body.get("password", "")
            port = int(body.get("port", 22)) if body.get("port") else 22
            if not host:
                self._send_json({"success": False, "error": "請提供目標主機 IP / Hostname！"}, 400)
                return
            remedy_executor.set_cached_target(host, user, password, port)
            collector_cmd = (
                '(echo "=== [1] HISTORY ==="; HISTTIMEFORMAT="%F %T " history 300 2>/dev/null || cat ~/.bash_history 2>/dev/null | tail -n 300; '
                'echo "=== [2] SYSTEMD ==="; systemctl --failed --no-pager 2>/dev/null; journalctl -p 3 -xb -n 30 --no-pager 2>/dev/null; '
                'echo "=== [3] DISK ==="; df -h; echo "---"; df -i; lsof +L1 2>/dev/null | grep deleted | head -n 30; '
                'echo "=== [4] MEM_OOM ==="; free -m; dmesg -T 2>/dev/null | grep -Ei "oom|killed process|out of memory" | tail -n 50; '
                'echo "=== [5] REBOOT ==="; cat /etc/fstab 2>/dev/null; cat /proc/mounts 2>/dev/null; '
                'echo "=== [6] NETWORK ==="; ss -tulpn 2>/dev/null)'
            )
            exec_res = remedy_executor.execute(collector_cmd, host=host, user=user, password=password, port=port, timeout=15)
            if not exec_res["success"] and not exec_res["stdout"]:
                self._send_json({"success": False, "error": f"遠端連線或採集失敗: {exec_res['stderr']}"}, 500)
                return
            bundle_raw = exec_res["stdout"]
            synthesis = master_synthesizer.synthesize(bundle_raw)
            self._send_json({
                "success": True,
                "is_live": True,
                "target": f"{user}@{host}:{port}",
                "bundle_raw": bundle_raw,
                "synthesis": synthesis
            })

        else:
            self.send_error(404, "Not Found")

    def _run_host_live_scan(self):
        """現場本機即時執行原生探測 (Cisco Tech-Support 風格全主機一體化)"""
        is_linux = sys.platform.startswith("linux")

        def run_sh(cmd):
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="ignore", timeout=3)
                return (r.stdout or "").strip()
            except Exception:
                return ""

        if is_linux:
            hist_out = run_sh("HISTTIMEFORMAT='%F %T ' history 300 2>/dev/null || cat ~/.bash_history 2>/dev/null | tail -n 300")
            df_out = run_sh("df -h; echo '---'; df -i")
            lsof_out = run_sh("lsof +L1 2>/dev/null | grep deleted | head -n 30")
            dmesg_out = run_sh("free -m; echo '---'; dmesg -T 2>/dev/null | grep -Ei 'oom|killed process|out of memory' | tail -n 50")
            systemd_out = run_sh("systemctl --failed --no-pager 2>/dev/null; journalctl -p 3 -xb -n 30 --no-pager 2>/dev/null")
            fstab_out = run_sh("cat /etc/fstab 2>/dev/null")
            mounts_out = run_sh("cat /proc/mounts 2>/dev/null")
            ss_out = run_sh("ss -tulpn 2>/dev/null")

            bundle_raw = (
                f"=== [1] HISTORY ===\n{hist_out}\n\n"
                f"=== [2] SYSTEMD ===\n{systemd_out}\n\n"
                f"=== [3] DISK ===\n{df_out}\n{lsof_out}\n\n"
                f"=== [4] MEM_OOM ===\n{dmesg_out}\n\n"
                f"=== [5] REBOOT ===\n{fstab_out}\n---\n{mounts_out}\n\n"
                f"=== [6] NETWORK ===\n{ss_out}\n"
            )
            synthesis = master_synthesizer.synthesize(bundle_raw)
            return {
                "success": True,
                "is_live": True,
                "bundle_raw": bundle_raw,
                "synthesis": synthesis
            }
        else:
            return {
                "success": True,
                "is_live": False,
                "message": f"當前運行環境為 {sys.platform}。完整本機即時探測請在 Linux 生產伺服器上執行，或點擊下方按鈕直接載入 Cisco 風格全景範例！"
            }

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, SysScopeHandler)
    url = f"http://localhost:{PORT}"
    print("=" * 60)
    print(" ⬡ SysScope - 系統主機全方位異常透視儀 (Master Host Doctor)")
    print(f" URL: {url}")
    print(" Architecture: 100% Pure Python Zero-Dependency")
    print(" Press Ctrl + C to stop.")
    print("=" * 60)

    if "--no-browser" not in sys.argv:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SysScope Server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
