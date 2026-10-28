# -*- coding: utf-8 -*-
"""
SysScope OOM Forensic (OOM Killer 案發現場還原與記憶體診斷)
純 Python 3 原生標準庫 | Zero-Dependency
核心功能：
1. 自動解析 dmesg / journalctl 還原 OOM 殺人案發現場
2. 合併同一 PID 處決事件，取得真實釋放之匿名記憶體 (anon-rss)，杜絕 0.0 MB 誤導
3. 辨識 Docker Cgroup 限制處決 vs 實體主機 RAM 耗盡
4. 深度解析 free -m / free -h (正確區分 available、buff/cache 與 Swap 飽和度)
5. 自動生成排查進程與調優 Swap 之修復 CLI
"""
import re
from typing import Dict, Any, List

class OOMForensic:
    def __init__(self):
        pass

    def parse_and_diagnose(self, text: str) -> Dict[str, Any]:
        """
        解析包含 dmesg、free -m 或 /proc/meminfo 的日誌
        """
        oom_events = self._parse_oom_events(text)
        mem_info = self._parse_free_m(text)
        raw_logs = [l.strip() for l in text.splitlines() if any(k in l.lower() for k in ["oom", "killed process", "kill process", "oom_reaper", "constraint="])]

        verdict_level = "HEALTHY"
        verdict_title = "🟢 記憶體與 Swap 狀態正常"
        verdict_party = "系統記憶體健康"
        verdict_color = "#10b981"
        verdict_reason = "近期未發生 OOM Killer 處決事件，系統未偵測到因記憶體枯竭引發的核心強制殺進程行為。"
        verdict_action = "無需處置。"

        if oom_events:
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            top_oom = oom_events[0]
            is_cgroup = top_oom.get("is_cgroup", False)
            cgroup_str = " (Docker/K8s 容器 Cgroup 上限處決)" if is_cgroup else " (實體主機記憶體耗盡)"
            
            freed_str = f"{top_oom['freed_mb']} MB" if top_oom['freed_mb'] > 0 else "大量實體"
            verdict_title = f"🚨【還原 OOM 殺人案發現場】：進程「{top_oom['victim_cmd']}」遭核心強制槍斃！"
            verdict_party = f"OOM Killer 處決{cgroup_str}"
            verdict_reason = (
                f"在時間點 {top_oom['timestamp']}，系統發生嚴重記憶體枯竭！\n"
                f"Linux 核心 OOM 殺手被迫拔刀，將進程 `{top_oom['victim_cmd']}` (PID: {top_oom['victim_pid']}) 強制處決 (Exit code 137) 以解救作業系統！\n"
                f"被殺進程當時佔用約 {freed_str} 記憶體。"
            )
            verdict_action = (
                f"1. 排查吃記憶體的前 10 大進程：\n   ps aux --sort=-%mem | head -n 10\n"
                f"2. 檢查 Swap 交換空間狀態：\n   swapon --show && free -m\n"
                f"3. 若為容器環境，請調大 pod/container memory limits (目前限制過緊)。"
            )

        elif mem_info and mem_info.get("avail_pct", 100) < 10:
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【記憶體高度吃緊警示】：真實可用量僅剩 {mem_info['avail_pct']}%！"
            verdict_party = "記憶體不足預警"
            verdict_reason = f"系統可用記憶體 (available) 僅剩 {mem_info.get('available', 'N/A')} MB ({mem_info.get('avail_pct') }%)，隨時有觸發 OOM Killer 殺手處決核心服務的風險！"
            verdict_action = "請提早排查吃記憶體的大進程：\nps aux --sort=-%mem | head -n 10"

        return {
            "success": True,
            "oom_count": len(oom_events),
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "oom_events": oom_events,
            "mem_info": mem_info,
            "raw_oom_logs": raw_logs[:15]
        }

    def _parse_oom_events(self, text: str) -> List[Dict[str, Any]]:
        """
        解析典型 dmesg OOM 行並按 PID 合併，取得真實 freed_mb:
        [Wed Oct 28 11:58:32 2026] Out of memory: Kill process 18291 (mysqld) score 851 or sacrifice child
        [Wed Oct 28 11:58:32 2026] Killed process 18291 (mysqld) total-vm:482910kB, anon-rss:382910kB, file-rss:0kB
        [ 2345.123] oom-killer:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0
        """
        events_by_pid = {}
        is_memcg = "constraint=constraint_memcg" in text.lower() or "memcg" in text.lower()

        for line in text.splitlines():
            line_clean = line.strip()
            if not line_clean:
                continue

            lower_l = line_clean.lower()
            if "killed process" in lower_l or "kill process" in lower_l or "oom-killer:" in lower_l:
                # 格式 1: Killed process 18291 (mysqld) total-vm:482910kB, anon-rss:382910kB
                m1 = re.search(r"killed process (\d+)\s+\(([^)]+)\).*?anon-rss:(\d+)kB", line_clean, re.IGNORECASE)
                if m1:
                    pid = m1.group(1)
                    cmd = m1.group(2)
                    rss_kb = int(m1.group(3))
                    freed_mb = round(rss_kb / 1024.0, 1)
                    ts = self._extract_ts(line_clean)
                    if pid in events_by_pid:
                        events_by_pid[pid]["freed_mb"] = max(events_by_pid[pid]["freed_mb"], freed_mb)
                        events_by_pid[pid]["raw_line"] = line_clean
                    else:
                        events_by_pid[pid] = {
                            "victim_pid": pid,
                            "victim_cmd": cmd,
                            "freed_mb": freed_mb,
                            "timestamp": ts,
                            "is_cgroup": is_memcg,
                            "raw_line": line_clean
                        }
                    continue

                # 格式 2: Out of memory: Kill process 18291 (mysqld) score 851
                m2 = re.search(r"kill process (\d+)\s+\(([^)]+)\)", line_clean, re.IGNORECASE)
                if m2:
                    pid = m2.group(1)
                    cmd = m2.group(2)
                    ts = self._extract_ts(line_clean)
                    if pid not in events_by_pid:
                        events_by_pid[pid] = {
                            "victim_pid": pid,
                            "victim_cmd": cmd,
                            "freed_mb": 0.0,
                            "timestamp": ts,
                            "is_cgroup": is_memcg,
                            "raw_line": line_clean
                        }
                    continue

                # 格式 3: oom-killer:... task=mysqld,pid=18291
                m3 = re.search(r"task=([^,]+),pid=(\d+)", line_clean, re.IGNORECASE)
                if m3:
                    cmd = m3.group(1)
                    pid = m3.group(2)
                    ts = self._extract_ts(line_clean)
                    if pid not in events_by_pid:
                        events_by_pid[pid] = {
                            "victim_pid": pid,
                            "victim_cmd": cmd,
                            "freed_mb": 0.0,
                            "timestamp": ts,
                            "is_cgroup": is_memcg,
                            "raw_line": line_clean
                        }
                    continue

        # 回傳列表，優先按 freed_mb 排序 (佔記憶體最大的排前面)
        event_list = list(events_by_pid.values())
        event_list.sort(key=lambda x: x["freed_mb"], reverse=True)
        return event_list

    def _parse_free_m(self, text: str) -> Dict[str, Any]:
        """
        解析 free -m 或 free -h:
                      total        used        free      shared  buff/cache   available
        Mem:          15820       14910         150         310         760         320
        Swap:          2047        2047           0
        """
        mem_info = {}
        swap_info = {}

        def parse_num(val_str: str) -> float:
            val_str = val_str.strip()
            # 支援 15Gi, 320Mi, 15G, 500M 等 free -h 單位
            m_unit = re.search(r"^([\d\.]+)([KkMmGgTt]?i?[Bb]?)", val_str)
            if not m_unit:
                return 0.0
            num = float(m_unit.group(1))
            unit = m_unit.group(2).upper()
            if "G" in unit:
                return round(num * 1024.0, 1)
            elif "T" in unit:
                return round(num * 1024.0 * 1024.0, 1)
            elif "K" in unit:
                return round(num / 1024.0, 1)
            return round(num, 1)

        for line in text.splitlines():
            line_str = line.strip()
            if line_str.startswith("Mem:"):
                parts = line_str.split()
                if len(parts) >= 7:
                    total = parse_num(parts[1])
                    used = parse_num(parts[2])
                    free = parse_num(parts[3])
                    shared = parse_num(parts[4])
                    buff_cache = parse_num(parts[5])
                    avail = parse_num(parts[6])
                    avail_pct = round((avail / total) * 100, 1) if total > 0 else 100.0
                    mem_info = {
                        "total": total,
                        "used": used,
                        "free": free,
                        "shared": shared,
                        "buff_cache": buff_cache,
                        "available": avail,
                        "avail_pct": avail_pct
                    }
            elif line_str.startswith("Swap:"):
                parts = line_str.split()
                if len(parts) >= 4:
                    s_total = parse_num(parts[1])
                    s_used = parse_num(parts[2])
                    s_free = parse_num(parts[3])
                    s_used_pct = round((s_used / s_total) * 100, 1) if s_total > 0 else 0.0
                    swap_info = {
                        "swap_total": s_total,
                        "swap_used": s_used,
                        "swap_free": s_free,
                        "swap_used_pct": s_used_pct
                    }

        if mem_info:
            mem_info.update(swap_info)
        return mem_info

    def _extract_ts(self, line: str) -> str:
        m = re.search(r"\[([^\]]+)\]", line)
        return m.group(1).strip() if m else "近期"
