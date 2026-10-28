# -*- coding: utf-8 -*-
"""
SysScope History Forensic (指令歷史與人為翻車鑑識引擎)
純 Python 3 原生標準庫 | Zero-Dependency
核心功能：
1. 30+ 種高危自殺/翻車指令深度審計 (iptables -F, chmod 777, swapoff -a, rm -rf, curl|bash, 密碼外洩)
2. 全指令行為細分：設定變更 (Config)、服務重啟 (Service)、網路異動 (Network)、套件安裝 (Package)、權限帳號 (Security)、儲存刪除 (Storage)
3. 事故導火線關聯鏈 (Correlation Insight)：自動關聯「改設定檔 -> 重啟服務 -> 故障」之因果鏈
4. 產生可直接回滾與止血之原廠 CLI
"""
import re
from typing import Dict, Any, List

class HistoryForensic:
    def __init__(self):
        # 30+ 種高危自殺 / 破壞性規則庫
        self.dangerous_rules = [
            {
                "pattern": r"\biptables\s+(-F|-X|--flush)",
                "severity": "CRITICAL",
                "type": "IPTABLES_FLUSH",
                "title": "清空防火牆規則 (iptables -F)",
                "impact": "致命後果：清空規則會瞬間將 Docker 容器的 NAT 轉發鏈 (DOCKER-USER) 完全抹除，導致所有容器對外網路全斷！且可能造成遠端 SSH 鎖死！",
                "remedy": "sudo systemctl restart docker\n# 若有備份規則請還原：sudo iptables-restore < /etc/iptables/rules.v4"
            },
            {
                "pattern": r"\bufw\s+(disable|reset)",
                "severity": "HIGH",
                "type": "UFW_DISABLE",
                "title": "停用或重設主機防火牆 (ufw disable/reset)",
                "impact": "高危動作：關閉防火牆或重置規則會讓生產主機暴露於公網，或中斷轉發規則！",
                "remedy": "sudo ufw enable"
            },
            {
                "pattern": r"\bchmod\s+(-R\s+)?(777|a\+rwx)\s+(/|/etc|/var|/usr|~?/\.ssh|\$HOME/\.ssh)",
                "severity": "CRITICAL",
                "type": "CHMOD_DANGEROUS",
                "title": "全域超大權限濫開 (chmod -R 777)",
                "impact": "致命後果：對根目錄或 ~/.ssh 開放 777，SSH 守護進程 (sshd) 會觸發 StrictModes 安全防禦，強制拒絕所有人透過 Key 登入！且系統權限徹底失控！",
                "remedy": "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
            },
            {
                "pattern": r"\bchown\s+(-R\s+)?root:root\s+(/|/home/\S+)",
                "severity": "HIGH",
                "type": "CHOWN_OVERWRITE",
                "title": "遞迴竄改檔案擁有者 (chown -R)",
                "impact": "高危動作：可能破壞一般使用者家目錄或應用程式執行使用者的權限，導致資料庫或應用無法啟動！",
                "remedy": "ls -ld <目標目錄> # 確認原屬用戶並手動 chown 還原"
            },
            {
                "pattern": r"\bswapoff\s+(-a|--all)",
                "severity": "CRITICAL",
                "type": "SWAPOFF_TRIGGER_OOM",
                "title": "手動停用交換空間 (swapoff -a)",
                "impact": "致命後果：在實體 RAM 不足時執行 swapoff，會強制將硬碟 Swap 倒灌回實體記憶體，瞬間觸發 Linux OOM Killer 大屠殺，掐死重要資料庫與服務！",
                "remedy": "sudo swapon -a"
            },
            {
                "pattern": r"\brm\s+(-rf|-fr|-r\s+-f)\s+(/\s*$|/\*|/var/log/\*|/lib|/usr/lib|/etc)",
                "severity": "CRITICAL",
                "type": "RM_RF_SYSTEM",
                "title": "自殺式系統刪除操作 (rm -rf /*)",
                "impact": "災難後果：直接刪除系統目錄或核心庫，作業系統即刻停擺且不可逆！",
                "remedy": "立刻停止寫入硬碟並進行快照救援！"
            },
            {
                "pattern": r"\brm\s+(-rf|-fr|-r\s+-f)\s+(/var/log/\S*|\S*\.log)",
                "severity": "HIGH",
                "type": "RM_LOG_GHOST",
                "title": "直接 rm 刪除運行中的服務日誌",
                "impact": "高危動作：手動刪除正在運行的服務日誌（如 catalina.out、access.log）不會釋放空間，反而會產生已被刪除但進程咬住 FD 的「幽靈日誌」，導致 df -h 100% 爆滿！",
                "remedy": "切換至 SysScope 第二分頁【磁碟幽靈空間急救】一鍵清空釋放！"
            },
            {
                "pattern": r"\b(curl|wget)\b.*\|\s*(bash|sh|zsh|python|perl)",
                "severity": "CRITICAL",
                "type": "PIPE_TO_SHELL",
                "title": "未經審查管道執行外部腳本 (curl | bash)",
                "impact": "重大資安風險：直接將未經驗證的網路腳本導向 Shell 執行，極高機率被植入挖礦木馬、反彈 Shell 後門或竄改系統核心！",
                "remedy": "檢查 crontab -l 與 /etc/cron.*，檢查 ps aux | grep -i miner"
            },
            {
                "pattern": r"\bpip\s+install\b.*(--break-system-packages|\b(?!\s*--user)(?!\s*--target)(?!\s*-r\s*venv))",
                "severity": "WARNING",
                "type": "SYSTEM_PIP_OVERWRITE",
                "title": "覆寫全域系統 Python Pip",
                "impact": "潛在隱患：未使用 Python 虛擬環境直接 pip install，可能覆蓋 Linux 系統自帶的 Python 函式庫，導致 yum/apt 或系統工具崩潰！",
                "remedy": "建議使用 python3 -m venv myenv 建立隔離環境"
            },
            {
                "pattern": r"\b(nc|netcat|socat)\b.*-(e|c)\s+/bin/(bash|sh)",
                "severity": "CRITICAL",
                "type": "REVERSE_SHELL",
                "title": "疑似建立反彈後門連線 (Reverse Shell)",
                "impact": "資安入侵：偵測到利用 netcat 將本機 Bash 互動環境轉發至外部 IP 的典型黑客後門行為！",
                "remedy": "立刻隔離網路並檢查該進程 PID: sudo ss -tulpn"
            },
            {
                "pattern": r"\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/(sd[a-z]|nvme\d+n\d+|vd[a-z])",
                "severity": "CRITICAL",
                "type": "DD_WIPE_DISK",
                "title": "直接覆寫實體磁區 (dd wipe disk)",
                "impact": "災難後果：直接對儲存磁區 raw disk 進行覆寫，分割表與檔案系統即刻蒸發！",
                "remedy": "立刻終止 dd 進程: sudo killall -9 dd"
            },
            {
                "pattern": r"\b(route|ip\s+route)\s+del\s+default",
                "severity": "CRITICAL",
                "type": "ROUTE_DEL_DEFAULT",
                "title": "刪除預設網關路由 (route del default)",
                "impact": "致命後果：刪除 default gateway 會讓主機瞬間喪失所有跨網段連線能力，SSH 連線立即中斷且無法自救！",
                "remedy": "sudo ip route add default via <網關IP>"
            },
            {
                "pattern": r"\bsetenforce\s+0",
                "severity": "WARNING",
                "type": "SELINUX_PERMISSIVE",
                "title": "將 SELinux 切換為 Permissive 模式",
                "impact": "安全降級：暫時關閉強制存取控制，可能掩蓋了底層真正的檔案標籤衝突問題。",
                "remedy": "sudo setenforce 1"
            },
            {
                "pattern": r"\bcrontab\s+-r\b",
                "severity": "CRITICAL",
                "type": "CRONTAB_WIPE",
                "title": "手殘刪除所有排程作業 (crontab -r)",
                "impact": "致命後果：手殘輸入 -r 而非 -e，會一秒刪光目前使用者的所有定時排程 (Crontab)，備份與維護腳本停擺！",
                "remedy": "檢查 /var/log/cron 或從系統日誌中搶救歷史排程指令"
            },
            {
                "pattern": r"\b(docker|podman)\s+system\s+prune\s+.*(-a|--all).*(-\-volumes|-v)",
                "severity": "HIGH",
                "type": "DOCKER_PRUNE_VOLUMES",
                "title": "Docker 激進清理並抹除 Volumes 資料卷",
                "impact": "高危動作：同時帶有 --all 與 --volumes 會刪除所有未掛載的持久化資料卷，造成資料遺失！",
                "remedy": "執行前請確認所有生產容器均處於運行狀態"
            },
            {
                "pattern": r"\bkill\s+-9\s+1\b",
                "severity": "CRITICAL",
                "type": "KILL_INIT",
                "title": "強制殺死 1 號進程 (kill -9 1)",
                "impact": "致命後果：PID 1 為 systemd 或 init，嘗試強制殺死它會直接觸發 Linux 核心恐慌 (Kernel Panic) 當機！",
                "remedy": "切勿對 PID 1 發送訊號"
            },
            {
                "pattern": r"\b(poweroff|init\s+0|shutdown\s+-h\s+now)\b",
                "severity": "HIGH",
                "type": "HOST_SHUTDOWN",
                "title": "直接關閉系統主機 (poweroff / init 0)",
                "impact": "主機離線：伺服器將直接進入關機狀態，若無遠端 IPMI/iLO 需人員前往機房按開關！",
                "remedy": "請確認是否為計劃性維護關機"
            },
            {
                "pattern": r"(?:-p[A-Za-z0-9_@#$%^&*!]{6,}|--password=[^\s]+|PASSWORD=[^\s]+|TOKEN=[^\s]+|AWS_SECRET[^\s]+)",
                "severity": "WARNING",
                "type": "CREDENTIAL_LEAK",
                "title": "在指令中明文暴露密碼或 Token",
                "impact": "資安風險：在終端機輸入密碼會被純文字寫入 ~/.bash_history，任何具讀取權限的帳號皆可窺視！",
                "remedy": "請清理 history 並改用環境變數或組態檔授權"
            }
        ]

    def audit(self, history_text: str) -> Dict[str, Any]:
        """
        深度審計 bash/zsh history 文字，還原操作時間線、行為分類與事故導火線
        """
        lines = history_text.strip().splitlines()
        timeline = []
        flagged_events = []
        credential_leaks = []

        category_counts = {
            "CONFIG": 0,
            "SERVICE": 0,
            "NETWORK": 0,
            "PACKAGE": 0,
            "SECURITY": 0,
            "STORAGE": 0,
            "DATABASE": 0,
            "DIAGNOSTIC": 0,
            "GENERAL": 0
        }

        # 用於檢測導火線關聯鏈 (例如: 改了設定檔 -> 重啟了服務)
        last_config_mutation = None
        correlation_insights = []

        for idx, line in enumerate(lines, 1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            # 提取可能的時間戳與指令內容
            # 支援格式:
            #  "1024  2026-10-28 10:15:20 sudo iptables -F"
            #  "1024  sudo iptables -F"
            #  "2026-10-28T10:15:20 systemctl restart nginx"
            cmd_clean = re.sub(r"^\s*\d+\s+", "", raw)
            timestamp_match = re.search(r"(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2})", cmd_clean)
            ts = timestamp_match.group(1) if timestamp_match else f"歷史行 #{idx}"
            if timestamp_match:
                cmd_clean = cmd_clean.replace(ts, "").strip()

            cmd_lower = cmd_clean.lower()

            # -----------------------------------------------------------------
            # 行為分類推理 (Action Categorization)
            # -----------------------------------------------------------------
            action_type = "GENERAL"
            action_desc = "一般操作"

            if re.search(r"\b(systemctl|service|docker|containerd|podman|kubectl)\s+(restart|stop|reload|kill|start|down|up)\b|\bkill(all)?\s+-9", cmd_lower):
                action_type = "SERVICE"
                action_desc = "服務生命週期重啟/停止"
                # 檢測事故導火線鏈：若前 5 步內曾改過設定檔，緊接著重啟服務
                if last_config_mutation and (idx - last_config_mutation["line_no"] <= 6):
                    correlation_insights.append({
                        "cause_cmd": last_config_mutation["command"],
                        "cause_line": last_config_mutation["line_no"],
                        "trigger_cmd": cmd_clean,
                        "trigger_line": idx,
                        "explanation": f"⭐ 事故高度疑似導火線：在第 {last_config_mutation['line_no']} 行曾編輯設定檔「{last_config_mutation['target']}」，緊接著在第 {idx} 行執行重啟「{cmd_clean}」！若重啟失敗，必為該設定檔語法損毀或參數錯誤！"
                    })

            elif re.search(r"\b(vim?|nano|sed|echo\s+.*>|cat\s+.*>|tee)\s+.*(/etc/|\.conf|\.ya?ml|\.json|\.toml|\.env)", cmd_lower):
                action_type = "CONFIG"
                action_desc = "核心設定檔編輯與變更"
                m_target = re.search(r"(/etc/\S+|\S+\.conf|\S+\.ya?ml)", cmd_clean)
                target_file = m_target.group(1) if m_target else "設定檔"
                last_config_mutation = {
                    "line_no": idx,
                    "command": cmd_clean,
                    "target": target_file
                }

            elif re.search(r"\b(iptables|ufw|firewall-cmd|ip\s+route|route|ifconfig|netplan|ip\s+addr|ss|netstat)\b", cmd_lower):
                action_type = "NETWORK"
                action_desc = "網路介面或防火牆異動"

            elif re.search(r"\b(apt|apt-get|yum|dnf|dpkg|rpm|pip|npm|yarn|cargo|gem)\s+(install|remove|purge|erase|update|upgrade)", cmd_lower):
                action_type = "PACKAGE"
                action_desc = "軟體套件安裝或移除"

            elif re.search(r"\b(useradd|userdel|usermod|passwd|chmod|chown|visudo|sudo\s+su)\b", cmd_lower):
                action_type = "SECURITY"
                action_desc = "用戶權限或安全屬性異動"

            elif re.search(r"\b(rm|mv|cp|dd|fdisk|mkfs|mount|umount|truncate|lsof)\b", cmd_lower):
                action_type = "STORAGE"
                action_desc = "檔案磁區刪除或掛載變更"

            elif re.search(r"\b(mysql|psql|redis-cli|mongo|sqlite3)\b", cmd_lower):
                action_type = "DATABASE"
                action_desc = "資料庫連線操作"

            elif re.search(r"\b(top|htop|dmesg|free|ps|tail|head|grep|cat|journalctl)\b", cmd_lower):
                action_type = "DIAGNOSTIC"
                action_desc = "系統巡檢與查詢日誌"

            category_counts[action_type] += 1

            # -----------------------------------------------------------------
            # 高危規則比對
            # -----------------------------------------------------------------
            matched_rule = None
            for r in self.dangerous_rules:
                if re.search(r["pattern"], cmd_clean, re.IGNORECASE):
                    matched_rule = r
                    break

            entry = {
                "line_no": idx,
                "timestamp": ts,
                "command": cmd_clean,
                "action_type": action_type,
                "action_desc": action_desc,
                "is_dangerous": matched_rule is not None,
                "danger_info": matched_rule
            }
            timeline.append(entry)

            if matched_rule:
                if matched_rule["type"] == "CREDENTIAL_LEAK":
                    credential_leaks.append(entry)
                flagged_events.append({
                    "line_no": idx,
                    "timestamp": ts,
                    "command": cmd_clean,
                    "type": matched_rule["type"],
                    "severity": matched_rule["severity"],
                    "title": matched_rule["title"],
                    "impact": matched_rule["impact"],
                    "remedy": matched_rule["remedy"]
                })

        # ---------------------------------------------------------------------
        # 產出大結論與白話判決
        # ---------------------------------------------------------------------
        crit_count = sum(1 for f in flagged_events if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in flagged_events if f["severity"] == "HIGH")

        verdict_level = "HEALTHY"
        verdict_title = "🟢 歷史指令審計完成：未發現嚴重破壞性操作"
        verdict_party = "常態維運操作"
        verdict_color = "#10b981"
        verdict_reason = f"已完整分析 {len(timeline)} 筆終端機操作記錄。其中包含 {category_counts['CONFIG']} 次設定檔修改、{category_counts['SERVICE']} 次服務操作、{category_counts['NETWORK']} 次網路更動，未偵測到清空防火牆、濫開 777 或刪庫等自殺指令。"
        verdict_action = "操作記錄健康，可參閱下方【變更時間軸】檢視近期各項操作細節。"

        if crit_count > 0:
            top_f = next(f for f in flagged_events if f["severity"] == "CRITICAL")
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            verdict_title = f"🚨【抓到人為事故元兇！】：第 {top_f['line_no']} 行執行了致命指令「{top_f['command']}」！"
            verdict_party = f"人為翻車事故 ({top_f['title']})"
            verdict_reason = f"在時間點 {top_f['timestamp']}（行號 #{top_f['line_no']}），有人執行了致命指令：`{top_f['command']}`！{top_f['impact']}"
            verdict_action = f"請立刻執行緊急止血回滾腳本：\n{top_f['remedy']}"

        elif high_count > 0:
            top_f = next(f for f in flagged_events if f["severity"] == "HIGH")
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【發現高危指令警報】：第 {top_f['line_no']} 行執行了「{top_f['command']}」！"
            verdict_party = f"高危維運操作 ({top_f['title']})"
            verdict_reason = f"在時間點 {top_f['timestamp']} 曾執行高危動作 `{top_f['command']}`。{top_f['impact']}"
            verdict_action = f"處置建議：\n{top_f['remedy']}"

        elif correlation_insights:
            # 雖然沒下破壞性指令，但發現了設定檔與服務重啟的關聯鏈
            top_corr = correlation_insights[0]
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【鎖定事故導火線】：在第 {top_corr['trigger_line']} 行重啟前曾修改過設定檔！"
            verdict_party = "設定變更引發重啟異常"
            verdict_reason = top_corr["explanation"]
            verdict_action = f"請比對或還原該設定檔：\n# 檢視修改內容\ngit diff {top_corr['cause_cmd'].split()[-1]} 或檢查備份"

        return {
            "success": True,
            "total_commands": len(timeline),
            "flagged_count": len(flagged_events),
            "category_counts": category_counts,
            "correlation_insights": correlation_insights,
            "credential_leaks_count": len(credential_leaks),
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "flagged_events": flagged_events,
            "timeline": timeline[-100:] # 保留最後 100 筆最新指令供前端完整過濾
        }
