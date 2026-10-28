# -*- coding: utf-8 -*-
"""
SysScope Disk Doctor (磁碟空間與幽靈日誌急救站)
1. 幽靈磁碟空間偵測 (Deleted but Open Files):
   進程咬住已刪除的大日誌未釋放，導致 df 100% 但 du 找不到檔案。
   提供免重啟進程秒殺指令: echo "" > /proc/<PID>/fd/<FD>
2. Inode 枯竭與碎檔炸彈偵測 (df -i 100%)
3. Docker 容器日誌與 Overlay2 卷積膨脹診斷
4. 巨型日誌與磁碟占用 Top 排行
"""
import re
from typing import Dict, Any, List

class DiskDoctor:
    def __init__(self):
        pass

    def parse_and_diagnose(self, text: str) -> Dict[str, Any]:
        """
        解析包含 df -h, df -i, lsof +L1 / deleted, 或 du 輸出的文字並產出診斷
        """
        df_disks = self._parse_df_h(text)
        inode_disks = self._parse_df_i(text)
        ghost_files = self._parse_ghost_files(text)
        large_files = self._parse_large_files(text)

        conflicts = []
        verdict_level = "HEALTHY"
        verdict_title = "🟢 磁碟與檔案系統狀態良好"
        verdict_party = "系統正常"
        verdict_color = "#10b981"
        verdict_reason = "所有掛載磁碟使用率正常，未發現被刪除咬住的幽靈空間或 Inode 枯竭。"
        verdict_action = "無需進行任何處置。"

        # 1. 檢查幽靈檔案 (Deleted but Open) - 優先級最高！
        total_ghost_mb = sum(g["size_mb"] for g in ghost_files)
        if ghost_files and total_ghost_mb > 500: # 大於 500MB
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            top_ghost = ghost_files[0]
            verdict_title = f"🚨【偵測到幽靈磁碟空間】：進程咬住已刪除日誌，白白佔用 {self._format_mb(total_ghost_mb)}！"
            verdict_party = f"應用進程維運 ({top_ghost['command']}, PID: {top_ghost['pid']})"
            verdict_reason = (
                f"發現有 {len(ghost_files)} 個檔案已被 'rm' 刪除，但由於進程（如 {top_ghost['command']} PID: {top_ghost['pid']}）"
                f"仍在開啟檔案描述符 (FD)，導致 Linux 核心拒絕釋放磁碟空間！"
                f"這就是為什麼 'df -h' 顯示爆滿，但 'du -sh' 卻找不到檔案的真正元兇！"
            )
            verdict_action = f"請複製下方提供的「免重啟進程清空指令」：echo '' > /proc/{top_ghost['pid']}/fd/{top_ghost['fd']}，0.1 秒強制將空間還給作業系統！"
            conflicts.append({
                "type": "GHOST_DELETED_FILES",
                "severity": "CRITICAL",
                "title": f"進程咬住已刪除檔案未釋放 (累計 {self._format_mb(total_ghost_mb)})",
                "remedy": top_ghost["remedy_cmd"],
                "details": f"最大佔用：PID {top_ghost['pid']} ({top_ghost['command']}) 咬住 {top_ghost['path']} ({self._format_mb(top_ghost['size_mb'])})"
            })

        # 2. 檢查 Inode 爆滿 (df -i)
        for d in inode_disks:
            if d.get("use_pct", 0) >= 90:
                if verdict_level != "CRITICAL":
                    verdict_level = "CRITICAL"
                    verdict_color = "#ef4444"
                    verdict_title = f"🚨【Inode 枯竭危機】：掛載點 {d['mounted_on']} Inode 已達 {d['use_pct']}%！"
                    verdict_party = "應用碎檔堆積 (PHP Session / Spool / Mail)"
                    verdict_reason = f"磁碟空間雖然可能還有剩，但 Inode (索引節點) 已經被幾十萬個微型碎檔耗盡，導致系統跳出 'No space left on device' 錯誤！"
                    verdict_action = f"請執行指令：find {d['mounted_on']} -xdev -type f | cut -d '/' -f 2 | sort | uniq -c | sort -n 找出是哪個目錄堆積碎檔！"
                conflicts.append({
                    "type": "INODE_EXHAUSTION",
                    "severity": "CRITICAL",
                    "title": f"掛載點 {d['mounted_on']} Inode 耗盡 ({d['use_pct']}%)",
                    "remedy": f"find {d['mounted_on']} -type d -size +1M",
                    "details": f"已用 Inode: {d.get('iused', 'N/A')} / 總量: {d.get('inodes', 'N/A')}"
                })

        # 3. 檢查實體磁碟容量爆滿 (df -h)
        for d in df_disks:
            if d.get("use_pct", 0) >= 90:
                if verdict_level == "HEALTHY":
                    verdict_level = "HIGH"
                    verdict_color = "#f59e0b"
                    verdict_title = f"⚠️【磁碟容量告警】：掛載點 {d['mounted_on']} 使用率已達 {d['use_pct']}%！"
                    verdict_party = "系統空間不足"
                    verdict_reason = f"掛載點 {d['mounted_on']} 容量已達 {d['use_pct']}% (剩餘 {d.get('avail', 'N/A')})，即將引發資料庫寫入失敗與進程崩潰。"
                    verdict_action = f"建議排查 Top 大檔案或清理 Docker 暫存 (`docker system prune -f`)。"
                conflicts.append({
                    "type": "DISK_CAPACITY_FULL",
                    "severity": "HIGH",
                    "title": f"掛載點 {d['mounted_on']} 容量高達 {d['use_pct']}%",
                    "remedy": f"du -ahx {d['mounted_on']} | sort -rh | head -n 15",
                    "details": f"總容量: {d.get('size')} | 已用: {d.get('used')} | 剩餘: {d.get('avail')}"
                })

        return {
            "success": True,
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "conflicts": conflicts,
            "ghost_files": ghost_files,
            "df_disks": df_disks,
            "inode_disks": inode_disks,
            "large_files": large_files,
            "total_ghost_mb": round(total_ghost_mb, 1)
        }

    def _parse_ghost_files(self, text: str) -> List[Dict[str, Any]]:
        """
        解析 lsof +L1 或 lsof | grep deleted 格式:
        COMMAND  PID  USER   FD   TYPE DEVICE SIZE/OFF NLINK   NODE NAME
        java    1821  root    4w   REG    8,1 48291029192     0 128392 /var/log/catalina.out (deleted)
        """
        ghosts = []
        for line in text.splitlines():
            line = line.strip()
            if not line or "COMMAND" in line:
                continue
            if "(deleted)" in line or "deleted" in line.lower():
                parts = line.split()
                if len(parts) >= 8:
                    cmd = parts[0]
                    pid = parts[1]
                    user = parts[2]
                    fd_raw = parts[3]
                    # extract numeric fd
                    fd_clean = re.sub(r"[^0-9]", "", fd_raw)
                    size_bytes = 0
                    # find size column
                    for p in parts[4:]:
                        if p.isdigit() and int(p) > 1024 * 1024:
                            size_bytes = int(p)
                            break
                    size_mb = round(size_bytes / (1024 * 1024), 1) if size_bytes > 0 else 500.0
                    file_path = parts[-2] if parts[-1] == "(deleted)" else parts[-1]
                    
                    remedy = f"echo '' > /proc/{pid}/fd/{fd_clean}" if fd_clean else f"kill -HUP {pid}"
                    ghosts.append({
                        "command": cmd,
                        "pid": pid,
                        "user": user,
                        "fd": fd_clean or fd_raw,
                        "size_mb": size_mb,
                        "path": file_path,
                        "raw_line": line,
                        "remedy_cmd": remedy
                    })
        # sort by size descending
        ghosts.sort(key=lambda x: x["size_mb"], reverse=True)
        return ghosts

    def _parse_df_h(self, text: str) -> List[Dict[str, Any]]:
        """
        解析 df -h:
        Filesystem      Size  Used Avail Use% Mounted on
        /dev/sda1        98G   92G  1.2G  99% /
        """
        disks = []
        for line in text.splitlines():
            m = re.search(r"(\S+)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+(?:\.\d+)?[KMGTP]?)\s+(\d+)%\s+(/\S*)", line)
            if m:
                disks.append({
                    "filesystem": m.group(1),
                    "size": m.group(2),
                    "used": m.group(3),
                    "avail": m.group(4),
                    "use_pct": int(m.group(5)),
                    "mounted_on": m.group(6)
                })
        return disks

    def _parse_df_i(self, text: str) -> List[Dict[str, Any]]:
        """
        解析 df -i:
        Filesystem       Inodes   IUsed   IFree IUse% Mounted on
        /dev/sda1       6553600 6553590      10  100% /
        """
        inodes = []
        for line in text.splitlines():
            m = re.search(r"(\S+)\s+(\d+[KMGTP]?)\s+(\d+[KMGTP]?)\s+(\d+[KMGTP]?)\s+(\d+)%\s+(/\S*)", line)
            if m and ("Inodes" not in line):
                inodes.append({
                    "filesystem": m.group(1),
                    "inodes": m.group(2),
                    "iused": m.group(3),
                    "ifree": m.group(4),
                    "use_pct": int(m.group(5)),
                    "mounted_on": m.group(6)
                })
        return inodes

    def _parse_large_files(self, text: str) -> List[Dict[str, Any]]:
        """
        解析 du -ah 或 find 輸出的巨型日誌/檔案
        """
        files = []
        for line in text.splitlines():
            m = re.search(r"^(\d+(?:\.\d+)?[GKM]?)\s+(/\S+)", line.strip())
            if m:
                size_str = m.group(1)
                path = m.group(2)
                files.append({"size": size_str, "path": path})
        return files[:10]

    def _format_mb(self, mb: float) -> str:
        if mb >= 1024:
            return f"{round(mb / 1024.0, 2)} GB"
        return f"{round(mb, 1)} MB"
