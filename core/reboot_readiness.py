# -*- coding: utf-8 -*-
"""
SysScope Reboot Readiness (重開機安全驗收雷達)
1. 檢驗 /etc/fstab 地雷：
   遠端 NFS/CIFS 或副硬碟未加 nofail / _netdev，重開機若找不到硬碟必定死在 Emergency Mode！
2. 檢驗檔案系統唯讀狀態 (Read-Only FS Lockdown: /proc/mounts 是否有 ,ro,)
3. 預防開機自啟配置漂移 (Configuration Drift)
4. 產出「重開機前 100 分安全評分」
"""
import re
from typing import Dict, Any, List

class RebootReadiness:
    def __init__(self):
        pass

    def audit(self, fstab_text: str, mounts_text: str = "") -> Dict[str, Any]:
        """
        審計 /etc/fstab 與 /proc/mounts，評估重開機安全性
        """
        fstab_entries = []
        hazards = []
        read_only_mounts = []

        # 1. 檢查 /proc/mounts 是否有唯讀鎖死
        if mounts_text:
            for line in mounts_text.splitlines():
                line = line.strip()
                if line.startswith("/") and (",ro," in line or " ro," in line or ",ro " in line):
                    # 排除 loop 或 squashfs (如 snap)
                    if "squashfs" not in line and "loop" not in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            read_only_mounts.append({"dev": parts[0], "mount": parts[1]})

        # 2. 逐行剖析 /etc/fstab
        for line_no, line in enumerate(fstab_text.splitlines(), 1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            parts = raw.split()
            if len(parts) < 4:
                hazards.append({
                    "line_no": line_no,
                    "severity": "CRITICAL",
                    "type": "FSTAB_SYNTAX_ERROR",
                    "title": f"第 {line_no} 行語法格式殘缺",
                    "raw": raw,
                    "impact": "欄位不足 4 項，重開機時 systemd-fstab-generator 解析失敗可能拒絕啟動！"
                })
                continue

            dev = parts[0]
            mount_point = parts[1]
            fstype = parts[2]
            options = parts[3].split(",")

            fstab_entries.append({
                "line_no": line_no,
                "device": dev,
                "mount_point": mount_point,
                "fstype": fstype,
                "options": options
            })

            # 地雷 1: 網路硬碟 (NFS, CIFS, SMB) 沒加 _netdev 或 nofail
            if fstype.lower() in ["nfs", "nfs4", "cifs", "smb", "glusterfs", "ceph"]:
                if "_netdev" not in options and "nofail" not in options:
                    hazards.append({
                        "line_no": line_no,
                        "severity": "CRITICAL",
                        "type": "NETWORK_MOUNT_WITHOUT_NETDEV",
                        "title": f"第 {line_no} 行網路掛載點缺少 _netdev / nofail 參數",
                        "raw": raw,
                        "impact": f"掛載 {mount_point} 是網路硬碟 ({fstype})，但沒加 '_netdev' 或 'nofail'！開機時網卡尚未連線，系統會因掛載超時直接卡死在 Emergency Mode！",
                        "remedy": f"請在 options 加入: _netdev,nofail"
                    })

            # 地雷 2: 非根目錄掛載點沒有加 nofail (如資料碟、外接磁碟)
            if mount_point not in ["/", "/boot", "/boot/efi", "swap"]:
                if "nofail" not in options:
                    hazards.append({
                        "line_no": line_no,
                        "severity": "HIGH",
                        "type": "SECONDARY_DISK_WITHOUT_NOFAIL",
                        "title": f"第 {line_no} 行資料碟 {mount_point} 缺少 nofail 容錯參數",
                        "raw": raw,
                        "impact": f"若重開機時該硬碟磁區未就緒或 UUID 變更，缺乏 'nofail' 會導致 Linux 強制中斷開機進入緊急維護狀態！",
                        "remedy": f"在 options 追加: nofail"
                    })

        # 計算安全分數
        crit_count = sum(1 for h in hazards if h["severity"] == "CRITICAL")
        high_count = sum(1 for h in hazards if h["severity"] == "HIGH")
        ro_count = len(read_only_mounts)

        score = max(0, 100 - (crit_count * 40) - (high_count * 15) - (ro_count * 50))

        verdict_level = "HEALTHY"
        verdict_color = "#10b981"
        verdict_title = f"🟢 重開機安全評分：{score} 分 (安全可重啟)"
        verdict_party = "重開機就緒"
        verdict_reason = f"已掃描 {len(fstab_entries)} 個掛載點，未發現可能引發 Emergency Mode 的致命 fstab 配置地雷。"
        verdict_action = "可放心安排例行維護重開機。"

        if ro_count > 0:
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            verdict_title = f"🚨【磁碟唯讀鎖死】：偵測到掛載點處於唯讀狀態 (ro)！"
            verdict_party = "底層硬碟損壞或超時"
            verdict_reason = f"硬碟 {read_only_mounts[0]['dev']} (掛載於 {read_only_mounts[0]['mount']}) 已被核心強制降級為唯讀！所有服務已無法寫入！"
            verdict_action = "請執行 dmesg | grep -i error 檢查硬碟壞軌，切勿隨意冷重開機以防檔案系統崩潰！"
        elif crit_count > 0:
            top_h = next(h for h in hazards if h["severity"] == "CRITICAL")
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"
            verdict_title = f"🚨【重開機必定死機 (Emergency Mode 地雷)】：評分僅 {score} 分！"
            verdict_party = f"fstab 配置地雷 (第 {top_h['line_no']} 行)"
            verdict_reason = f"{top_h['impact']}"
            verdict_action = f"千萬不可重開機！請立刻編輯 /etc/fstab 補上：{top_h.get('remedy', 'nofail')}！"
        elif high_count > 0:
            verdict_level = "HIGH"
            verdict_color = "#f59e0b"
            verdict_title = f"⚠️【重開機風險警示】：評分 {score} 分，存在未容錯掛載點"
            verdict_party = "次要硬碟缺乏 nofail"
            verdict_reason = "部分次要掛載點未配置 nofail 容錯，若硬碟異常可能阻斷開機流程。"
            verdict_action = "建議在 /etc/fstab 為非系統磁碟補上 nofail 參數。"

        return {
            "success": True,
            "readiness_score": score,
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "hazards": hazards,
            "fstab_entries": fstab_entries,
            "read_only_mounts": read_only_mounts
        }
