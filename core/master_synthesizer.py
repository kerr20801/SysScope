# -*- coding: utf-8 -*-
"""
SysScope Master Synthesizer (全主機一體化全景急診室 & 上下文因果串聯引擎)
比照 Cisco "show tech-support" 理念：
1. 一次性接收 Linux 6 大維度匯總日誌 (History, Systemd, Disk, OOM, Reboot, Network)
2. 自動分流剖析 (Auto-Demux & Segment Parser)
3. 跨維度上下文因果鏈推理 (Cross-Context Incident Chain Reaction):
   - 下了 swapoff -a ➔ 導致 OOM Killer 槍斃資料庫
   - 改了 nginx.conf ➔ 導致 systemctl reload 失敗並陷入 CrashLoop
   - 刪了 catalina.out ➔ 導致 46GB 幽靈日誌咬住硬碟爆滿
   - 搶了 Port 80 ➔ 導致 Web 服務無法啟動
   - 掛載 NFS 漏配 _netdev ➔ 導致下一次重開機進入 Emergency Mode 死機
4. 計算「主機綜合健康指數 (0~100)」與產出「優先級現場排障處方籤 (Prioritized Worklist)」
"""
import re
from typing import Dict, Any, List

from core.disk_doctor import DiskDoctor
from core.history_forensic import HistoryForensic
from core.systemd_catcher import SystemdCatcher
from core.oom_forensic import OOMForensic
from core.reboot_readiness import RebootReadiness
from core.net_kernel_audit import NetKernelAudit

class MasterSynthesizer:
    def __init__(self):
        self.disk_doctor = DiskDoctor()
        self.history_forensic = HistoryForensic()
        self.systemd_catcher = SystemdCatcher()
        self.oom_forensic = OOMForensic()
        self.reboot_readiness = RebootReadiness()
        self.net_kernel_audit = NetKernelAudit()

    def demux_bundle(self, raw_text: str) -> Dict[str, str]:
        """
        將一體化日誌自動依標籤或特徵拆解為 6 大區塊
        """
        sections = {
            "history": "",
            "systemd": "",
            "disk": "",
            "oom": "",
            "reboot": "",
            "network": ""
        }

        # 標籤正則比對 (支援標準 === [X] NAME === 格式)
        pattern = r"===\s*\[?\d?\]?\s*(HISTORY|HIST|SYSTEMD|SERVICE|DISK|STORAGE|MEM_OOM|OOM|MEM|REBOOT|FSTAB|NETWORK|NET)\s*==="
        chunks = re.split(pattern, raw_text, flags=re.IGNORECASE)

        if len(chunks) > 1:
            # 第一個 chunk 是開頭 (若有)
            for i in range(1, len(chunks), 2):
                header = chunks[i].upper()
                body = chunks[i+1].strip() if i+1 < len(chunks) else ""

                if "HIST" in header:
                    sections["history"] = body
                elif "SYSTEMD" in header or "SERVICE" in header:
                    sections["systemd"] = body
                elif "DISK" in header or "STORAGE" in header:
                    sections["disk"] = body
                elif "OOM" in header or "MEM" in header:
                    sections["oom"] = body
                elif "REBOOT" in header or "FSTAB" in header:
                    sections["reboot"] = body
                elif "NET" in header:
                    sections["network"] = body

        else:
            # 若無明確的分段標籤，啟動「智慧特徵自動嗅探 (Smart Content Sniffing)」
            hist_lines, sys_lines, disk_lines, oom_lines, reboot_lines, net_lines = [], [], [], [], [], []
            for line in raw_text.splitlines():
                line_str = line.strip()
                if not line_str:
                    continue

                if re.search(r"^\s*\d+\s+(?:\d{4}-\d{2}-\d{2}\s+)?(?:sudo\s+|cd\s+|vim?\s+|systemctl\s+|chmod|iptables)", line_str):
                    hist_lines.append(line)
                elif re.search(r"(?:\.service|\.socket|journalctl|systemd\[|Active:\s+(?:failed|activating)|Loaded:\s+loaded)", line_str):
                    sys_lines.append(line)
                elif re.search(r"(?:Filesystem\s+Size|/dev/sd|lsof|\(deleted\)|/var/log)", line_str):
                    disk_lines.append(line)
                elif re.search(r"(?:out of memory|killed process|oom-killer|total\s+used\s+free|Mem:\s+\d+|Swap:\s+\d+)", line_str, re.I):
                    oom_lines.append(line)
                elif re.search(r"(?:UUID=|/etc/fstab|/proc/mounts|errors=remount|defaults\s+\d\s+\d)", line_str):
                    reboot_lines.append(line)
                elif re.search(r"(?:LISTEN|Local Address:Port|0\.0\.0\.0:|127\.0\.0\.1:|ss -tulpn)", line_str):
                    net_lines.append(line)

            sections["history"] = "\n".join(hist_lines)
            sections["systemd"] = "\n".join(sys_lines)
            sections["disk"] = "\n".join(disk_lines)
            sections["oom"] = "\n".join(oom_lines)
            sections["reboot"] = "\n".join(reboot_lines)
            sections["network"] = "\n".join(net_lines)

        return sections

    def synthesize(self, raw_bundle_text: str) -> Dict[str, Any]:
        """
        核心全景診斷：依序剖析 6 大維度，並進行上下文跨維度關聯推理
        """
        sec = self.demux_bundle(raw_bundle_text)

        # 執行 6 大專業引擎剖析
        res_history = self.history_forensic.audit(sec["history"]) if sec["history"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供歷史紀錄", "color": "#64748b"}, "flagged_events": [], "category_counts": {}, "correlation_insights": [], "timeline": []}
        res_systemd = self.systemd_catcher.parse_and_diagnose(sec["systemd"]) if sec["systemd"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供服務狀態", "color": "#64748b"}, "failed_units": [], "key_error_logs": [], "remedy_commands": []}
        res_disk = self.disk_doctor.parse_and_diagnose(sec["disk"]) if sec["disk"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供磁碟日誌", "color": "#64748b"}, "ghost_files": [], "total_ghost_mb": 0, "df_disks": []}
        res_oom = self.oom_forensic.parse_and_diagnose(sec["oom"]) if sec["oom"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供 OOM 核心日誌", "color": "#64748b"}, "oom_events": [], "mem_info": {}}
        res_reboot = self.reboot_readiness.audit(sec["reboot"]) if sec["reboot"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供 fstab 掛載點", "color": "#64748b"}, "hazards": [], "readiness_score": 100}
        res_network = self.net_kernel_audit.audit(sec["network"]) if sec["network"] else {"success": True, "verdict": {"level": "INFO", "title": "未提供網路連線表", "color": "#64748b"}, "localhost_traps": [], "remedies": []}

        # ---------------------------------------------------------------------
        # 跨維度上下文因果關聯推演 (Cross-Context Incident Chain Reaction)
        # ---------------------------------------------------------------------
        incident_chains = []
        prioritized_worklist = []
        health_score = 100

        # 1. 關聯：人為 swapoff -a ➔ 觸發 OOM Killer 斬首進程
        has_swapoff = any(f["type"] == "SWAPOFF_TRIGGER_OOM" for f in res_history.get("flagged_events", []))
        has_oom = len(res_oom.get("oom_events", [])) > 0
        if has_swapoff and has_oom:
            victim_name = res_oom["oom_events"][0]["victim_cmd"]
            incident_chains.append({
                "severity": "CRITICAL",
                "title": "人為關閉 Swap 倒灌實體記憶體，引發 OOM Killer 核心大屠殺",
                "flow": f"終端機執行 `swapoff -a` ➔ 實體 RAM 瞬間過載 ➔ 核心處決 `{victim_name}` (PID: {res_oom['oom_events'][0]['victim_pid']})",
                "explanation": f"在操作歷史中發現曾執行 `swapoff -a`。在系統記憶體吃緊時關閉交換區，會強行將硬碟頁面倒灌回 RAM，直接觸發 OOM Killer 拔刀槍斃了核心進程 `{victim_name}`！"
            })
            prioritized_worklist.append({
                "priority": "P0 (致命急診)",
                "action": f"重新啟用 Swap 並重啟被害進程 {victim_name}",
                "commands": [
                    "sudo swapon -a",
                    f"sudo systemctl restart {victim_name} || sudo systemctl restart docker"
                ]
            })
            health_score -= 30

        # 2. 關聯：手動 rm 刪除日誌 ➔ 進程未重啟咬住 FD 造成 100% 幽靈空間
        has_rm_log = any("RM" in f.get("type", "") for f in res_history.get("flagged_events", []))
        ghost_count = len(res_disk.get("ghost_files", []))
        if (has_rm_log or ghost_count > 0) and ghost_count > 0:
            top_ghost = res_disk["ghost_files"][0]
            incident_chains.append({
                "severity": "CRITICAL",
                "title": f"手動刪除日誌造成幽靈日誌咬住未釋放 ({res_disk['total_ghost_mb']} MB)",
                "flow": f"手動 rm 檔案 ➔ 進程 `{top_ghost['command']}` (PID: {top_ghost['pid']}) 未釋放 FD ➔ df -h 空間持續 100% 爆滿",
                "explanation": f"現場人員誤以為 rm 可以清空間，但守護進程仍持有檔案描述符。底層 Inode 依然佔據 {res_disk['total_ghost_mb']} MB 硬碟空間！"
            })
            prioritized_worklist.append({
                "priority": "P0 (空間搶救)",
                "action": f"免重啟進程秒殺清空幽靈檔案 ({top_ghost['path']})",
                "commands": [top_ghost["remedy_cmd"]]
            })
            health_score -= 25

        # 3. 關聯：編輯設定檔 ➔ 重啟服務失敗 (Port 被搶 / 語法報錯)
        failed_count = res_systemd.get("failed_count", 0)
        systemd_cause = res_systemd.get("cause_type", "NONE")
        if failed_count > 0:
            failed_unit = res_systemd["failed_units"][0]["unit"]
            if systemd_cause == "PORT_CONFLICT":
                port = res_systemd.get("detected_ports", ["80"])[0] if res_systemd.get("detected_ports") else "80"
                incident_chains.append({
                    "severity": "CRITICAL",
                    "title": f"服務 `{failed_unit}` 啟動失敗：通訊埠 Port {port} 遭搶佔衝突 (EADDRINUSE)",
                    "flow": f"啟動或重載 `{failed_unit}` ➔ 核心報錯 Address already in use ➔ 服務崩潰退出",
                    "explanation": f"服務欲監聽的 Port {port} 已被現有進程搶先佔據，導致 bind() 失敗。"
                })
                prioritized_worklist.append({
                    "priority": "P1 (服務復原)",
                    "action": f"查殺霸佔 Port {port} 的衝突進程並重啟 {failed_unit}",
                    "commands": [
                        f"sudo ss -tulpn | grep :{port}",
                        f"sudo fuser -k {port}/tcp",
                        f"sudo systemctl restart {failed_unit}"
                    ]
                })
                health_score -= 25

            elif systemd_cause == "CONFIG_SYNTAX_ERROR":
                incident_chains.append({
                    "severity": "CRITICAL",
                    "title": f"服務 `{failed_unit}` 啟動失敗：近期修改之設定檔語法損毀 (Syntax Error)",
                    "flow": f"修改設定檔 ➔ 執行 systemctl restart/reload ➔ 語法檢查失敗秒退",
                    "explanation": f"設定檔中存在無效指令、少括號或遺漏分號，導致服務載入中斷。"
                })
                prioritized_worklist.append({
                    "priority": "P1 (設定修復)",
                    "action": f"執行語法驗證並修復 {failed_unit} 設定檔",
                    "commands": res_systemd.get("remedy_commands", [f"sudo systemctl status {failed_unit} -l"])
                })
                health_score -= 20

            else:
                incident_chains.append({
                    "severity": "HIGH",
                    "title": f"服務 `{failed_unit}` 處於崩潰罷工狀態 (Failed / CrashLoop)",
                    "flow": f"服務啟動 ➔ 異常退出 ➔ Systemd 標記為 Failed",
                    "explanation": f"服務異常終止，請檢視 journalctl 錯誤日誌。"
                })
                prioritized_worklist.append({
                    "priority": "P1 (服務復原)",
                    "action": f"查看 {failed_unit} 崩潰日誌並重置狀態",
                    "commands": [
                        f"sudo journalctl -u {failed_unit} -n 30 --no-pager",
                        f"sudo systemctl reset-failed {failed_unit}"
                    ]
                })
                health_score -= 15

        # 4. 關聯：清空防火牆 (iptables -F) ➔ Docker 網路轉發全斷
        has_iptables_flush = any(f["type"] == "IPTABLES_FLUSH" for f in res_history.get("flagged_events", []))
        if has_iptables_flush:
            incident_chains.append({
                "severity": "CRITICAL",
                "title": "人為執行 iptables -F 清空防火牆，抹除 Docker 容器轉發鏈",
                "flow": f"執行 `sudo iptables -F` ➔ DOCKER-USER 鏈蒸發 ➔ 所有容器外網全斷",
                "explanation": "清空 iptables 會將 Docker 自動生成的 NAT 與 Forward 規則一併洗除，外部流量再也進不來容器！"
            })
            prioritized_worklist.append({
                "priority": "P1 (網路搶救)",
                "action": "重啟 Docker 守護進程自動重建 iptables 轉發鏈",
                "commands": [
                    "sudo systemctl restart docker",
                    "sudo iptables -L -n -v | head -n 20"
                ]
            })
            health_score -= 20

        # 5. 關聯：fstab 缺少 _netdev,nofail ➔ 重開機定時炸彈
        fstab_hazards = res_reboot.get("hazards", [])
        if len(fstab_hazards) > 0:
            top_hazard = fstab_hazards[0]
            incident_chains.append({
                "severity": "HIGH",
                "title": f"重開機死亡陷阱：/etc/fstab 遠端掛載遺漏容錯參數 (評分僅 {res_reboot['readiness_score']} 分)",
                "flow": f"主機重開機 ➔ 網路未就緒嘗試掛載 ➔ 逾時失敗 ➔ 強制卡死進入 Emergency Mode",
                "explanation": f"第 {top_hazard['line_no']} 行掛載點缺少 `_netdev,nofail`，下次主機維護重開機時將無法正常開機！"
            })
            prioritized_worklist.append({
                "priority": "P2 (防患未然)",
                "action": f"修復 /etc/fstab 第 {top_hazard['line_no']} 行掛載參數，避免開機卡死",
                "commands": [
                    "# 在掛載參數中補上 _netdev,nofail",
                    f"# 建議參考修正: {top_hazard['remedy']}"
                ]
            })
            health_score -= 15

        # 6. 關聯：Localhost 監聽綁定陷阱
        traps = res_network.get("localhost_traps", [])
        if len(traps) > 0:
            top_trap = traps[0]
            incident_chains.append({
                "severity": "WARNING",
                "title": f"Localhost 綁定陷阱：Port {top_trap['port']} 僅監聽 127.0.0.1 (外部連不上)",
                "flow": f"外部發起連線 ➔ 核心以非本機 IP 丟棄 ➔ 外部顯示連線逾時，但內部 curl 通",
                "explanation": f"進程 `{top_trap['process']}` 僅綁定在 127.0.0.1，導致局域網與公網流量完全被隔離。"
            })
            prioritized_worklist.append({
                "priority": "P2 (配置優化)",
                "action": f"將 Port {top_trap['port']} 綁定改為 0.0.0.0",
                "commands": [f"# 修改服務設定檔將 listen 127.0.0.1:{top_trap['port']} 改為 0.0.0.0:{top_trap['port']}"]
            })
            health_score -= 5

        health_score = max(5, min(100, health_score))

        # 綜合大結論 (Executive Summary)
        if health_score < 60:
            master_level = "CRITICAL"
            master_color = "#ef4444"
            master_title = f"🚨【主機綜合健康指數：{health_score} 分 (高度危急)】：偵測到多重人為事故與連鎖崩潰！"
            master_party = "系統連鎖事故 (需立即止血處置)"
            master_reason = f"主機目前同時存在 {len(incident_chains)} 處嚴重併發症！包含人為操作致命破壞、服務中斷或空間枯竭。請依照下方處方籤順序依序止血。"
        elif health_score < 85:
            master_level = "HIGH"
            master_color = "#f59e0b"
            master_title = f"⚠️【主機綜合健康指數：{health_score} 分 (潛在風險)】：發現部分高危異常或配置隱患！"
            master_party = "維運配置隱患"
            master_reason = f"主機存在 {len(incident_chains)} 處異常項目，雖未完全癱瘓，但已有服務罷工、開機卡死風險或幽靈空間殘留。"
        else:
            master_level = "HEALTHY"
            master_color = "#10b981"
            master_title = "🟢【主機綜合健康指數：100 分 (全項健康)】：6 大生命線指標全數達標！"
            master_party = "系統運作正常"
            master_reason = "經跨維度綜合審查，未發現人為自殺指令、服務 CrashLoop、幽靈日誌佔用、OOM 處決或開機掛載地雷。"

        return {
            "success": True,
            "health_score": health_score,
            "master_verdict": {
                "level": master_level,
                "title": master_title,
                "party": master_party,
                "color": master_color,
                "reason": master_reason
            },
            "incident_chains": incident_chains,
            "prioritized_worklist": prioritized_worklist,
            "dimensions": {
                "history": res_history,
                "systemd": res_systemd,
                "disk": res_disk,
                "oom": res_oom,
                "reboot": res_reboot,
                "network": res_network
            }
        }
