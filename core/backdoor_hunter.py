# -*- coding: utf-8 -*-
"""
SysScope Backdoor & Implant Hunter (Linux 後門、植入物與異常駐留獵捕器)

專為「不熟悉 Linux 也能快速排查有沒有被埋東西」設計，純 Python 零依賴。
支援離線貼上採集結果或透過 SSH 一鍵即時採集，檢查 7 大常見後門藏匿點：
  1. 幽靈特權帳號與 Sudoers 後門 (/etc/passwd UID=0, NOPASSWD: ALL)
  2. SSH 金鑰後門 (authorized_keys 強制指令 / 異常大量金鑰)
  3. 排程與開機啟動後門 (crontab / cron.d / rc.local / .bashrc / systemd)
  4. 動態函式庫劫持 (LD_PRELOAD Rootkit: /etc/ld.so.preload)
  5. 可疑行程、挖礦程式、反彈 Shell 與無檔名記憶體常駐 (/tmp, /dev/shm, deleted exe)
  6. 異常對外連線與高危 SUID 提權陷阱 (ss -tunap, 異常 SUID 二進位)
  7. 暫存區隱藏執行檔與 Webshell 線索 (/tmp/.xxx, eval($_POST...))

每筆告警皆附帶：白話解釋、正常機器基準、安全唯讀確認指令（先查再動）與處置建議。
"""

import re
from typing import Dict, Any, List


# 單行唯讀安全採集指令（新手直接複製貼上到 Linux 終端機即可，不會修改任何系統檔案）
BACKDOOR_COLLECTOR_ONELINER = (
    'echo "=== [7] BACKDOOR ==="; '
    'echo "--- [UID0_PASSWD] ---"; awk -F: \'$3==0 {print $0}\' /etc/passwd 2>/dev/null; '
    'echo "--- [SUDOERS] ---"; grep -RniE "NOPASSWD|ALL=\\(ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | head -n 30; '
    'echo "--- [SSH_KEYS] ---"; for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && echo "FILE:$f" && cat "$f"; done 2>/dev/null; '
    'echo "--- [CRON] ---"; (crontab -l 2>/dev/null; grep -Rnv "^#" /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null) | grep -v "^$" | head -n 80; '
    'echo "--- [LD_PRELOAD] ---"; [ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload 2>/dev/null; '
    'echo "--- [STARTUP] ---"; grep -RniE "curl|wget|bash|python|nc |/dev/tcp|base64|/tmp/|/dev/shm" /etc/rc.local /root/.bashrc /home/*/.bashrc /etc/profile /etc/systemd/system/*.service 2>/dev/null | head -n 50; '
    'echo "--- [PROCESSES] ---"; ps auxww 2>/dev/null | head -n 150; '
    'echo "--- [DELETED_EXE] ---"; ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" | head -n 30; '
    'echo "--- [OUTBOUND] ---"; ss -tunap 2>/dev/null | grep -i ESTAB | head -n 80; '
    'echo "--- [SUID] ---"; find /usr/bin /bin /usr/sbin /sbin /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | head -n 80; '
    'echo "--- [TMP_HIDDEN] ---"; ls -la /tmp /var/tmp /dev/shm 2>/dev/null | head -n 60'
)

# 高危 SUID 二進位（正常 Linux 絕不應該對這些工具開 SUID）
DANGEROUS_SUID_BINS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
    "find", "vim", "vi", "nano", "ed", "awk", "gawk", "sed",
    "cp", "mv", "tar", "zip", "unzip", "dd", "tee",
    "nc", "ncat", "netcat", "socat", "curl", "wget", "nmap",
    "env", "strace", "gdb", "less", "more", "cat", "chmod", "chown",
}

# 正常 Linux 常見於 /tmp 的系統隱藏目錄（避免誤報）
BENIGN_TMP_HIDDEN = {
    ".", "..", ".x11-unix", ".ice-unix", ".xim-unix", ".font-unix",
    ".test-unix", ".snap", ".org.chromium.chromium", ".tmp",
}

# 常見 C2 / 反彈 Shell / 礦池高危遠端埠
SUSPICIOUS_PORTS = {"4444", "1337", "3333", "5555", "6666", "7777", "9001", "14444", "45700", "31337"}

# 惡意下載/執行/反彈 Shell 關鍵特徵
RE_MALICIOUS_CMD = re.compile(
    r"(?:"
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"
    r"|bash\s+-i\s+>&"
    r"|\b(?:nc|ncat|netcat)\b[^\n]*(?:\s-e\s|\s-c\s)"
    r"|\bsocat\b[^\n]*exec:"
    r"|base64\s+-d[^\n]*\|\s*(?:ba|z|da)?sh\b"
    r"|python3?\s+-c\s+['\"][^\n]*(?:socket|pty\.spawn|subprocess|base64)"
    r")",
    re.IGNORECASE,
)

RE_MINER_PROC = re.compile(
    r"\b(?:xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|t-rex|nbminer|lolminer|nanominer)\b|stratum\+tcp://|pool\.minexmr|supportxmr",
    re.IGNORECASE,
)

RE_TMP_EXEC = re.compile(
    r"(?:^|\s)(?:/tmp/|/dev/shm/|/var/tmp/)(?:\.?[a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE,
)

RE_WEBSHELL = re.compile(
    r"(?:eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*(?:@?\$_(?:POST|GET|REQUEST|COOKIE)|base64_decode\s*\()",
    re.IGNORECASE,
)


class BackdoorHunter:
    """Linux 後門、植入物與異常駐留獵捕引擎（新手白話友善版）"""

    def _split_sections(self, raw_text: str) -> Dict[str, List[str]]:
        """依子區塊標籤拆解；若使用者直接貼未分段文字，歸入 raw 全文掃描"""
        sections: Dict[str, List[str]] = {
            "UID0_PASSWD": [],
            "SUDOERS": [],
            "SSH_KEYS": [],
            "CRON": [],
            "LD_PRELOAD": [],
            "STARTUP": [],
            "PROCESSES": [],
            "DELETED_EXE": [],
            "OUTBOUND": [],
            "SUID": [],
            "TMP_HIDDEN": [],
            "RAW": [],
        }
        current = "RAW"
        header_re = re.compile(r"^---\s*\[([A-Z0-9_]+)\]\s*---$", re.IGNORECASE)

        for line in raw_text.splitlines():
            s = line.strip()
            if not s or s.startswith("=== ["):
                continue
            m = header_re.match(s)
            if m:
                key = m.group(1).upper()
                if key in sections:
                    current = key
                    continue
            sections[current].append(line)
        return sections

    @staticmethod
    def _is_collector_self_line(line: str) -> bool:
        """過濾採集指令本身或 grep 查詢行，避免自己掃到自己"""
        low = line.lower()
        if "grep " in low and ("backdoor" in low or "stratum" in low or "nopasswd" in low or "/dev/tcp" in low):
            return True
        if "--- [uid0_passwd] ---" in low or "=== [7] backdoor ===" in low:
            return True
        return False

    def hunt(self, raw_text: str) -> Dict[str, Any]:
        if not raw_text or not raw_text.strip():
            return {
                "success": True,
                "verdict": {
                    "level": "INFO",
                    "title": "尚無檢體資料",
                    "summary": "請貼上 Linux 主機採集輸出，或點擊上方「載入範例」體驗後門獵捕功能。",
                    "color": "#64748b",
                    "badge": "⚪ 等待輸入",
                },
                "security_score": 100,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "total_findings": 0,
                "findings": [],
                "category_counts": {},
                "checked_areas": 0,
                "beginner_checklist": [
                    "點擊「複製一鍵安全採集指令」，貼到 Linux 終端機執行（純唯讀，不會改動系統）。",
                    "將終端機輸出貼回左側文字框，按下「開始獵捕分析」。",
                ],
                "collector_command": BACKDOOR_COLLECTOR_ONELINER,
            }

        sec = self._split_sections(raw_text)
        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        def add_finding(severity: str, category: str, title: str, plain_explain: str,
                        normal_baseline: str, evidence: str, safe_verify_cmd: str,
                        remedy_advice: str):
            dedup = (category, title, evidence[:80])
            if dedup in seen_keys:
                return
            seen_keys.add(dedup)
            findings.append({
                "severity": severity,
                "category": category,
                "title": title,
                "plain_explain": plain_explain,
                "normal_baseline": normal_baseline,
                "evidence": evidence.strip()[:300],
                "safe_verify_cmd": safe_verify_cmd,
                "remedy_advice": remedy_advice,
            })

        # ------------------------------------------------------------------
        # 1. 幽靈 Root 帳號 (/etc/passwd UID=0)
        # ------------------------------------------------------------------
        passwd_lines = sec["UID0_PASSWD"] + [
            l for l in sec["RAW"] if re.match(r"^[a-zA-Z0-9_\-\.]+:[^:]*:0:\d+:", l.strip())
        ]
        for line in passwd_lines:
            parts = line.strip().split(":")
            if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
                acct = parts[0]
                add_finding(
                    severity="CRITICAL",
                    category="隱藏特權帳號",
                    title=f"發現非 root 的最高權限幽靈帳號：{acct} (UID=0)",
                    plain_explain=f"這台機器除了正常的 root 之外，還藏了一個叫「{acct}」的帳號，卻擁有跟最高管理員一模一樣的生殺大權。這是駭客留後門最經典的手法之一。",
                    normal_baseline="正常的 Linux 伺服器，UID 為 0 的帳號只應該有「root」這一個。",
                    evidence=line,
                    safe_verify_cmd=f"grep ':0:' /etc/passwd && lastlog -u {acct}",
                    remedy_advice=f"若團隊無人認識此帳號，請立即鎖定並停用：sudo passwd -l {acct} && sudo usermod -s /usr/sbin/nologin {acct}",
                )

        # ------------------------------------------------------------------
        # 2. LD_PRELOAD Rootkit (/etc/ld.so.preload)
        # ------------------------------------------------------------------
        ld_lines = sec["LD_PRELOAD"] + [
            l for l in sec["RAW"] if "/etc/ld.so.preload" in l and ".so" in l and not self._is_collector_self_line(l)
        ]
        for line in ld_lines:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if ".so" in s or s.startswith("/"):
                add_finding(
                    severity="CRITICAL",
                    category="系統底層劫持 (Rootkit)",
                    title=f"偵測到 /etc/ld.so.preload 動態載入劫持：{s}",
                    plain_explain="系統的程式載入器被偷塞了一個外掛函式庫。駭客常用這招讓「ps / ls / netstat」看不到他們的惡意程式（像隱形斗篷一樣）。",
                    normal_baseline="一般正常 Linux 系統不會有 /etc/ld.so.preload 檔案，或裡面應該是完全空白的。",
                    evidence=s,
                    safe_verify_cmd=f"ls -la /etc/ld.so.preload && file {s.split()[0]}",
                    remedy_advice="請資安人員先備份該 .so 檔案留存鑑識，再清空 /etc/ld.so.preload 並重啟受影響服務。",
                )

        # ------------------------------------------------------------------
        # 3. SSH 金鑰後門 (authorized_keys)
        # ------------------------------------------------------------------
        current_key_file = "authorized_keys"
        key_counts: Dict[str, int] = {}
        ssh_lines = sec["SSH_KEYS"] + [
            l for l in sec["RAW"] if ("ssh-rsa " in l or "ssh-ed25519 " in l or "ecdsa-sha2-" in l)
        ]
        for line in ssh_lines:
            s = line.strip()
            if s.startswith("FILE:"):
                current_key_file = s[5:].strip()
                continue
            if not s or s.startswith("#"):
                continue
            if any(k in s for k in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-")):
                key_counts[current_key_file] = key_counts.get(current_key_file, 0) + 1
                if re.search(r'\bcommand\s*=\s*"', s, re.IGNORECASE):
                    add_finding(
                        severity="HIGH",
                        category="SSH 金鑰後門",
                        title=f"SSH 金鑰內夾帶強制執行指令 (command=...)：{current_key_file}",
                        plain_explain="有人在免密碼登入的 SSH 金鑰前面加了「只要這把鑰匙連進來就自動跑某段指令」。如果不是你們刻意設定的自動化備份腳本，很可能是後門。",
                        normal_baseline="一般工程師的 SSH 公鑰開頭應直接是 ssh-ed25519 或 ssh-rsa，不會夾帶 command=\"...\"。",
                        evidence=s,
                        safe_verify_cmd=f"cat -n {current_key_file}",
                        remedy_advice=f"請逐一核對 {current_key_file} 裡每一把金鑰尾端的註解（例如 user@host），刪除不認識的鑰匙。",
                    )
        for kfile, cnt in key_counts.items():
            if cnt >= 6:
                add_finding(
                    severity="MEDIUM",
                    category="SSH 金鑰盤點",
                    title=f"{kfile} 存在大量 SSH 免密金鑰（共 {cnt} 把）",
                    plain_explain=f"這份清單裡放了 {cnt} 把可以免輸入密碼直接登入的鑰匙，容易混入離職員工或不明人士的鑰匙。",
                    normal_baseline="建議每台主機只保留必要維運人員的金鑰（通常 1~3 把）。",
                    evidence=f"{kfile} 共 {cnt} 筆金鑰",
                    safe_verify_cmd=f"nl -ba {kfile}",
                    remedy_advice="請定期盤點並移除非現任維運人員的公鑰。",
                )

        # ------------------------------------------------------------------
        # 4. 排程後門與開機腳本 (Cron / rc.local / .bashrc / systemd)
        # ------------------------------------------------------------------
        persist_lines = sec["CRON"] + sec["STARTUP"] + sec["RAW"]
        for line in persist_lines:
            s = line.strip()
            if not s or s.startswith("#") or self._is_collector_self_line(s):
                continue
            if RE_MALICIOUS_CMD.search(s):
                add_finding(
                    severity="CRITICAL",
                    category="排程 / 啟動後門",
                    title="偵測到自動下載執行或反彈 Shell 的惡意排程 / 啟動指令",
                    plain_explain="系統的「定時排程」或「開機自動執行清單」裡，藏了一段會主動上網下載腳本並直接執行（或反連駭客主機）的指令。就算你殺掉程式，過幾分鐘又會自己復活！",
                    normal_baseline="正常的排程只會跑備份、清日誌或公司內部腳本，絕不會寫「curl 網址 | bash」或「/dev/tcp」。",
                    evidence=s,
                    safe_verify_cmd="crontab -l; ls -la /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null",
                    remedy_advice="先將該排程行加上 # 註解停用，截圖留存後再查找對應惡意行程並終止。",
                )
            elif (line in sec["CRON"] or line in sec["STARTUP"]) and RE_TMP_EXEC.search(s):
                add_finding(
                    severity="HIGH",
                    category="排程 / 啟動後門",
                    title="排程或開機腳本指向暫存區 (/tmp 或 /dev/shm) 執行程式",
                    plain_explain="有人設定定時去執行放在「暫存垃圾桶 (/tmp 或 /dev/shm)」裡的程式。正常軟體不會裝在暫存區，這是惡意程式常用的藏身地。",
                    normal_baseline="正規系統程式應安裝在 /usr/bin、/usr/local/bin 或 /opt，不會從 /tmp 啟動。",
                    evidence=s,
                    safe_verify_cmd="ls -la /tmp /dev/shm /var/tmp",
                    remedy_advice="確認該檔案來源；若非自家測試腳本，請先停用排程並隔離該檔案。",
                )

        # ------------------------------------------------------------------
        # 5. Sudoers 異常提權
        # ------------------------------------------------------------------
        for line in sec["SUDOERS"]:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "NOPASSWD" in s.upper() and "ALL" in s.upper() and not re.search(r"\b(root|vagrant|ubuntu|ec2-user|cloud-init)\b", s):
                add_finding(
                    severity="MEDIUM",
                    category="異常提權設定",
                    title="發現非預設帳號擁有免密碼最高權限 (NOPASSWD: ALL)",
                    plain_explain="這個設定允許某個普通帳號不用輸入密碼就能直接切換成最高管理員，若該帳號密碼外洩，整台機器瞬間淪陷。",
                    normal_baseline="正式主機建議輸入密碼才可 sudo，或僅開放特定幾支維運指令。",
                    evidence=s,
                    safe_verify_cmd="sudo visudo -c && ls -la /etc/sudoers.d/",
                    remedy_advice="確認是否為業務必要設定；若否，請用 sudo visudo 移除或限縮權限。",
                )

        # ------------------------------------------------------------------
        # 6. 可疑行程、挖礦程式與無檔名記憶體常駐
        # ------------------------------------------------------------------
        proc_lines = sec["PROCESSES"] + sec["RAW"]
        for line in proc_lines:
            s = line.strip()
            if not s or self._is_collector_self_line(s):
                continue
            if RE_MINER_PROC.search(s):
                add_finding(
                    severity="CRITICAL",
                    category="挖礦木馬 / 惡意行程",
                    title="偵測到疑似加密貨幣挖礦程式正在運行！",
                    plain_explain="系統裡正在跑常見的挖礦木馬（如 xmrig / kinsing / kdevtmpfsi），會吃光主機 CPU 讓網站變超慢，通常代表主機已被入侵。",
                    normal_baseline="正常伺服器不會出現 xmrig、stratum+tcp 或 kdevtmpfsi 等行程。",
                    evidence=s,
                    safe_verify_cmd="ps aux --sort=-%cpu | head -n 15",
                    remedy_advice="先檢查 crontab 與 /etc/systemd/system 找出讓它復活的排程並停用，再 kill -9 終止該 PID。",
                )
            elif (line in sec["PROCESSES"]) and RE_TMP_EXEC.search(s) and not any(
                ok in s for ok in ("/tmp/pymp-", "/tmp/systemd-private", "pytest", "vscode-server")
            ):
                add_finding(
                    severity="HIGH",
                    category="可疑執行路徑",
                    title="發現正在從暫存目錄 (/tmp 或 /dev/shm) 執行的程式",
                    plain_explain="有一個執行中的程式不是裝在正規目錄，而是直接從暫存區（或記憶體碟 /dev/shm）啟動。駭客最愛用 /dev/shm 躲避硬碟檢查。",
                    normal_baseline="正式服務應從 /usr、/opt、/var/www 等正規路徑啟動。",
                    evidence=s,
                    safe_verify_cmd="ls -la /proc/<PID>/exe /proc/<PID>/cwd",
                    remedy_advice="記下該行程的 PID，先用 ls -la /proc/<PID>/exe 確認真實路徑，確認異常後再終止。",
                )

        for line in sec["DELETED_EXE"] + [l for l in sec["RAW"] if "/proc/" in l and "(deleted)" in l]:
            s = line.strip()
            if not s or self._is_collector_self_line(s):
                continue
            if "(deleted)" in s:
                is_tmp = any(p in s for p in ("/tmp/", "/dev/shm/", "/var/tmp/"))
                add_finding(
                    severity="CRITICAL" if is_tmp else "MEDIUM",
                    category="無檔名記憶體常駐",
                    title="程式執行檔已被刪除，但仍在記憶體偷偷運行 (deleted)" if is_tmp else "偵測到執行檔已刪除的常駐行程 (deleted)",
                    plain_explain=(
                        "這個程式先從暫存區啟動後再把自己刪掉，企圖「毀屍滅跡」只躲在記憶體裡跑，是極高風險的無檔名後門特徵！"
                        if is_tmp else
                        "這支程式的硬碟檔案已經不見了，但記憶體裡還在跑。可能是剛做完系統更新還沒重啟服務，也可能是惡意程式刻意刪除本體藏匿。"
                    ),
                    normal_baseline="正常未更新中的服務，/proc/<PID>/exe 都應該指向硬碟上真實存在的檔案。",
                    evidence=s,
                    safe_verify_cmd="ps -fp <PID> && ss -tunap | grep <PID>",
                    remedy_advice="若是剛更新過的正常服務（如 nginx/sshd）重啟即可；若來源不明或位於 /tmp，請立即阻斷其網路並終止。",
                )

        # ------------------------------------------------------------------
        # 7. 異常對外連線 (Outbound C2)
        # ------------------------------------------------------------------
        out_lines = sec["OUTBOUND"] + [l for l in sec["RAW"] if "ESTAB" in l]
        for line in out_lines:
            s = line.strip()
            if not s or self._is_collector_self_line(s):
                continue
            # 抓遠端 IP:Port 與行程名稱
            port_matches = re.findall(r":(\d{2,5})\b", s)
            proc_match = re.search(r'users:\(\("([^"]+)"', s)
            proc_name = proc_match.group(1) if proc_match else ""
            bad_ports = [p for p in port_matches if p in SUSPICIOUS_PORTS]

            if proc_name in ("bash", "sh", "dash", "nc", "ncat", "netcat", "socat"):
                add_finding(
                    severity="CRITICAL",
                    category="疑似反彈 Shell 外連",
                    title=f"命令列工具「{proc_name}」正在直接連線到外部主機！",
                    plain_explain=f"正常的伺服器上，終端機程式（{proc_name}）不會自己開網路往外連。這極高機率是「反彈 Shell 後門」，代表外面有人正遠端控制這台機器！",
                    normal_baseline="對外連線通常由瀏覽器、套件管理器或業務程式發起，不該由 bash / nc 直接建立。",
                    evidence=s,
                    safe_verify_cmd=f"ss -tunap | grep '{proc_name}'",
                    remedy_advice="立即記錄遠端 IP，於防火牆封鎖該 IP 並終止該行程，接著全面檢查排程與 SSH 金鑰。",
                )
            elif bad_ports:
                add_finding(
                    severity="HIGH",
                    category="異常高危埠外連",
                    title=f"偵測到連向高危通訊埠 (Port {bad_ports[0]}) 的外部連線",
                    plain_explain=f"這台機器正在連線到外部的 Port {bad_ports[0]}，這是常見的後門控制端或挖礦礦池專用埠號。",
                    normal_baseline="一般正常對外連線多為 80 (HTTP)、443 (HTTPS)、53 (DNS) 或公司內部資料庫埠。",
                    evidence=s,
                    safe_verify_cmd=f"ss -tunap | grep ':{bad_ports[0]}'",
                    remedy_advice="請核對該目標 IP 是否為公司合法服務；若不是，請立即在出口防火牆封鎖。",
                )

        # ------------------------------------------------------------------
        # 8. 高危 SUID 提權陷阱
        # ------------------------------------------------------------------
        suid_lines = sec["SUID"] + [l for l in sec["RAW"] if re.match(r"^/(?:usr/|bin/|sbin/|tmp/|var/|dev/)", l.strip())]
        for line in suid_lines:
            s = line.strip()
            if not s or " " in s:
                continue
            bname = s.rsplit("/", 1)[-1]
            in_tmp = s.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
            if in_tmp or bname in DANGEROUS_SUID_BINS:
                add_finding(
                    severity="CRITICAL" if (in_tmp or bname in ("bash", "sh", "python", "python3", "find")) else "HIGH",
                    category="SUID 提權後門",
                    title=f"高危工具被偷開最高權限旗標 (SUID)：{s}",
                    plain_explain=f"「{s}」被加上了 SUID 特殊權限，代表任何普通帳號只要執行它，就能瞬間變身成最高管理員 root！這幾乎不可能是系統預設值，通常是駭客留下的提權後門。",
                    normal_baseline="正常 Linux 只會對 sudo、passwd、ping 等少數系統工具開 SUID，絕不會對 bash/python/find 開。",
                    evidence=s,
                    safe_verify_cmd=f"ls -la {s} && stat {s}",
                    remedy_advice=f"若確認非特殊需求，可立即移除 SUID 旗標：sudo chmod u-s {s}",
                )

        # ------------------------------------------------------------------
        # 9. /tmp /dev/shm 隱藏檔案與 Webshell 線索
        # ------------------------------------------------------------------
        for line in sec["TMP_HIDDEN"]:
            s = line.strip()
            m = re.match(r"^([-d][rwxst\-]{9})\s+\d+\s+\S+\s+\S+\s+\S+\s+.+\s+(\.\S+)$", s)
            if m:
                perms, fname = m.group(1), m.group(2)
                if fname.lower() not in BENIGN_TMP_HIDDEN and not fname.startswith(".org.chromium"):
                    is_exec = "x" in perms and perms.startswith("-")
                    add_finding(
                        severity="HIGH" if is_exec else "MEDIUM",
                        category="暫存區隱藏檔案",
                        title=f"暫存目錄發現可疑隱藏{'執行檔' if is_exec else '檔案'}：{fname}",
                        plain_explain=f"有人在暫存區藏了一個以「.」開頭的隱藏檔（{fname}），用一般 ls 看不到。{'而且它具備「可直接執行」權限，非常可疑！' if is_exec else '建議確認裡面裝什麼。'}",
                        normal_baseline="暫存區的隱藏檔通常只有 .X11-unix、.ICE-unix 等系統通訊檔，不該出現不明可執行檔。",
                        evidence=s,
                        safe_verify_cmd=f"file /tmp/{fname} /dev/shm/{fname} 2>/dev/null",
                        remedy_advice="先用 file 與 strings 檢視內容（不要直接執行！），確認惡意後隔離刪除。",
                    )

        for line in sec["RAW"]:
            s = line.strip()
            if s and not self._is_collector_self_line(s) and RE_WEBSHELL.search(s):
                add_finding(
                    severity="CRITICAL",
                    category="疑似網站後門 (Webshell)",
                    title="偵測到疑似 PHP / 網站一句話木馬特徵",
                    plain_explain="在網站程式碼或掃描紀錄中發現直接將外部傳入參數丟進 eval/system 執行的危險寫法，駭客可以透過瀏覽器直接控制整台主機。",
                    normal_baseline="正規網站程式不會直接把 $_POST / $_GET 交給 eval() 或 system() 執行。",
                    evidence=s,
                    safe_verify_cmd="ls -la --time-style=full-iso <檔案路徑>",
                    remedy_advice="立即備份該檔後移出網站根目錄，並檢查同一時間點前後被修改過的所有檔案。",
                )

        # ------------------------------------------------------------------
        # 評分、分類統計與紅綠燈總判定
        # ------------------------------------------------------------------
        sev_weight = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "INFO": 0}
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
        findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

        score = 100
        cat_counts: Dict[str, int] = {}
        crit_cnt = high_cnt = med_cnt = 0
        for f in findings:
            score -= sev_weight.get(f["severity"], 0)
            cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1
            if f["severity"] == "CRITICAL":
                crit_cnt += 1
            elif f["severity"] == "HIGH":
                high_cnt += 1
            elif f["severity"] == "MEDIUM":
                med_cnt += 1
        score = max(0, score)

        checked_areas = sum(1 for k, v in sec.items() if k != "RAW" and len(v) > 0)
        if checked_areas == 0 and len(sec["RAW"]) > 0:
            checked_areas = 1

        if crit_cnt > 0:
            verdict = {
                "level": "CRITICAL",
                "badge": "🔴 紅燈警報：高度疑似遭植入後門",
                "title": f"發現 {crit_cnt} 項重大後門 / 入侵徵兆（總計 {len(findings)} 項異常）",
                "summary": "系統出現明確的高危入侵指標（如幽靈 root、排程下載執行、挖礦、反彈 Shell 或 Rootkit）。請勿直接重開機或急著刪除，建議先照下方「安全確認指令」留存證據，再逐步清除！",
                "color": "#ef4444",
            }
            checklist = [
                "先別慌，也不要馬上重開機（避免記憶體證據消失或觸發開機後門）。",
                "先對照下方每張卡片的「安全唯讀確認指令」，核實是否為團隊成員建立。",
                "若確認遭入侵：先在防火牆切斷這台主機對外連線 → 清除排程/啟動後門 → 終止惡意行程 → 全面更換密碼與 SSH 金鑰。",
            ]
        elif high_cnt > 0:
            verdict = {
                "level": "HIGH",
                "badge": "🟠 橘燈警戒：發現高可疑植入跡象",
                "title": f"發現 {high_cnt} 項高風險異常（總計 {len(findings)} 項）",
                "summary": "系統存在不符合常規的可疑設定或執行路徑（例如暫存區執行檔、異常外連埠或 SSH 強制指令），建議盡快逐項人工確認。",
                "color": "#f97316",
            }
            checklist = [
                "依序執行每張卡片提供的「安全唯讀確認指令」，確認檔案與連線來源。",
                "若不確定是否為業務程式，先詢問負責該系統的工程師再做處置。",
            ]
        elif med_cnt > 0:
            verdict = {
                "level": "MEDIUM",
                "badge": "🟡 黃燈提醒：建議盤點安全衛生",
                "title": f"未見明確木馬，但有 {med_cnt} 項建議檢查項目",
                "summary": "沒有發現典型後門，但存在過多 SSH 金鑰、免密 sudo 或更新後未重啟的行程，建議順手整理。",
                "color": "#eab308",
            }
            checklist = [
                "定期盤點 authorized_keys 與 sudoers，保持最小權限原則。",
                "若剛執行過系統更新，建議安排維護時段重啟相關服務。",
            ]
        else:
            verdict = {
                "level": "HEALTHY",
                "badge": "🟢 綠燈通過：未發現已知後門特徵",
                "title": "快速快篩通過，未偵測到常見後門與異常植入物",
                "summary": "在本次提交的檢查項目中，未發現幽靈帳號、LD_PRELOAD 劫持、惡意排程、挖礦或反彈 Shell 等常見後門跡象。（註：本工具為快速初篩，若懷疑遭高階滲透仍建議交由專業資安鑑識。）",
                "color": "#10b981",
            }
            checklist = [
                "建議搭配 SysScope「CVE 漏洞比對」確認系統套件與核心是否已修補最新漏洞。",
                "若只貼了部分日誌，建議使用上方「一鍵完整採集指令」做全項目複檢。",
            ]

        return {
            "success": True,
            "verdict": verdict,
            "security_score": score,
            "critical_count": crit_cnt,
            "high_count": high_cnt,
            "medium_count": med_cnt,
            "total_findings": len(findings),
            "checked_areas": checked_areas,
            "category_counts": cat_counts,
            "findings": findings,
            "beginner_checklist": checklist,
            "collector_command": BACKDOOR_COLLECTOR_ONELINER,
        }
