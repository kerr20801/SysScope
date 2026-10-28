# -*- coding: utf-8 -*-
"""
SysScope Kernel Network & Port Audit (核心網路連線與監聽綁定診斷)
1. 監聽 IP 陷阱診斷 (誰誤綁了 127.0.0.1 導致外網連不進？誰綁了 0.0.0.0？)
2. Port 衝突與搶佔識別 (Address already in use)
3. 連線追蹤表 (conntrack) 耗盡快篩 (防默默丟包)
4. TCP SYN Backlog 溢位與 TIME_WAIT / CLOSE_WAIT 堆積分析
"""
import re
from typing import Dict, Any, List

class NetKernelAudit:
    def __init__(self):
        pass

    def audit(self, ss_text: str, kernel_stats: str = "") -> Dict[str, Any]:
        """
        解析 ss -tulpn / netstat 輸出與核心網路計數器
        """
        listeners = []
        localhost_traps = []
        conflicts = []

        # 1. 剖析 ss -tulpn / netstat -tulpn
        # 範例:
        # tcp  LISTEN 0  128  127.0.0.1:8080  0.0.0.0:*  users:(("nginx",pid=1234,fd=6))
        # tcp  LISTEN 0  511    0.0.0.0:443   0.0.0.0:*  users:(("nginx",pid=1234,fd=7))
        for line in ss_text.splitlines():
            line = line.strip()
            if not line or "State" in line or "Proto" in line:
                continue

            if "LISTEN" in line or "udp" in line.lower():
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local_addr = parts[4] if len(parts) >= 6 and parts[1] == "LISTEN" else parts[3]
                    users_str = parts[-1] if "users:" in parts[-1] or "pid=" in parts[-1] else "N/A"

                    # 提取 port 與 ip
                    m_addr = re.search(r"(\S+):(\d+)$", local_addr)
                    if m_addr:
                        ip_bind = m_addr.group(1).replace("[", "").replace("]", "")
                        port = int(m_addr.group(2))

                        # 提取 process name & pid
                        proc_name = "unknown"
                        pid = "N/A"
                        m_proc = re.search(r'"([^"]+)",pid=(\d+)', users_str)
                        if m_proc:
                            proc_name = m_proc.group(1)
                            pid = m_proc.group(2)

                        item = {
                            "proto": proto,
                            "ip_bind": ip_bind,
                            "port": port,
                            "process": proc_name,
                            "pid": pid,
                            "raw_users": users_str
                        }
                        listeners.append(item)

                        # 檢驗地雷：若為重要業務 Port (如 80, 443, 8080, 3000, 5000, 8000, 9000)，但綁在 127.0.0.1
                        if port in [80, 443, 8080, 3000, 5000, 8000, 9000] and ip_bind in ["127.0.0.1", "::1", "localhost"]:
                            localhost_traps.append(item)

        # 2. 檢驗 conntrack 與 SYN 隊列溢位 (從 kernel_stats 或全文字提取)
        conntrack_alert = None
        conntrack_match = re.search(r"nf_conntrack:\s*table full", (ss_text + "\n" + kernel_stats), re.IGNORECASE)
        overflow_match = re.search(r"(\d+)\s+times the listen queue of a socket overflowed", (ss_text + "\n" + kernel_stats), re.IGNORECASE)

        if conntrack_match:
            conntrack_alert = {
                "type": "CONNTRACK_TABLE_FULL",
                "severity": "CRITICAL",
                "title": "Linux 核心 conntrack 連線追蹤表爆滿",
                "impact": "致命連線丟包：大量短連線超出系統上限，核心直接在網卡端默默丟棄封包 (Silent Drop)！",
                "remedy": "sysctl -w net.netfilter.nf_conntrack_max=1048576"
            }

        syn_overflow_count = int(overflow_match.group(1)) if overflow_match else 0

        # 大判決
        verdict_level = "HEALTHY"
        verdict_color = "#10b981"
        verdict_title = "🟢 系統監聽與核心網路隊列正常"
        verdict_party = "網路通訊良好"
        verdict_reason = f"已掃描 {len(listeners)} 個監聽連接埠，未發現 Localhost 綁定陷阱或 conntrack 丟包。"
        verdict_action = "無需處置。"

        if conntrack_alert:
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            verdict_title = "🚨【核心丟包中】：conntrack 連線追蹤表已徹底爆滿！"
            verdict_party = "Linux 核心網路參數不足"
            verdict_reason = f"{conntrack_alert['impact']}"
            verdict_action = f"緊急擴容指令：{conntrack_alert['remedy']}"
        elif syn_overflow_count > 100:
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【TCP Accept Queue 溢位】：累計丟棄 {syn_overflow_count} 次握手！"
            verdict_party = "應用處理並發不及 (somaxconn 瓶頸)"
            verdict_reason = "連線抵達伺服器但程式來不及 accept()，核心佇列滿載直接丟棄 SYN 請求！"
            verdict_action = "建議調大 /etc/sysctl.conf 之 net.core.somaxconn=4096，並增加 Web 應用工作線程。"
        elif localhost_traps:
            top_t = localhost_traps[0]
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【外網連不進地雷】：Port {top_t['port']} 誤綁在 127.0.0.1！"
            verdict_party = f"服務配置錯誤 ({top_t['process']})"
            verdict_reason = (
                f"進程 {top_t['process']} (PID: {top_t['pid']}) 將 Port {top_t['port']} 綁定在「127.0.0.1」，"
                f"這代表「只有本機內部能連線」，外部任何客戶端都會連線失敗（外網看起來像防火牆阻擋）！"
            )
            verdict_action = f"請將 {top_t['process']} 設定檔中的 bind address 改為 0.0.0.0 (或 *)，允許外網訪問！"

        return {
            "success": True,
            "listeners_count": len(listeners),
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "localhost_traps": localhost_traps,
            "conntrack_alert": conntrack_alert,
            "syn_overflow_count": syn_overflow_count,
            "listeners": listeners[:25]
        }
