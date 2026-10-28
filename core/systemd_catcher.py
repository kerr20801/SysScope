# -*- coding: utf-8 -*-
"""
SysScope Systemd Catcher (全域服務崩潰捕手 & 錯誤日誌透視儀)
純 Python 3 原生標準庫 | Zero-Dependency
跨格式解析：
1. systemctl status <unit> (支援 Active: failed, activating auto-restart, Process, Main PID)
2. systemctl --failed (支援 bullet ● / * / 各 Linux 發行版欄位)
3. journalctl 錯誤日誌、Docker 崩潰日誌、應用程式 Crash 堆疊
4. 深度識別死因：連接埠衝突 (EADDRINUSE)、權限被拒 (EACCES)、語法錯誤、CrashLoop 死迴圈、OOM Exit 137、相依檔案遺失
5. 自動生成精準修復指令 (含抓出搶 Port PID、語法測試、SELinux 權限排查)
"""
import re
from typing import Dict, Any, List

class SystemdCatcher:
    def __init__(self):
        pass

    def parse_and_diagnose(self, text: str) -> Dict[str, Any]:
        """
        解析 systemctl status, systemctl --failed 與各類服務崩潰日誌
        """
        failed_units = []
        crashed_logs = []
        detected_ports = []
        inferred_service = None

        lines = [line.rstrip() for line in text.splitlines()]

        # ---------------------------------------------------------------------
        # 1. 偵測 systemctl status <unit> 格式
        # ---------------------------------------------------------------------
        status_unit = None
        status_desc = ""
        status_active = None
        status_sub = None
        status_exit_code = None
        status_exec = None

        for line in lines:
            line_str = line.strip()
            # 例如: ● nginx.service - A high performance web server
            m_unit_hdr = re.search(r"^[●*•]?\s*([\w\.\@\-]+\.(?:service|socket|target|timer))\s*(?:-\s*(.*))?$", line_str)
            if m_unit_hdr:
                status_unit = m_unit_hdr.group(1)
                status_desc = m_unit_hdr.group(2) or ""

            # 例如: Active: failed (Result: exit-code) since ...
            # 或:   Active: activating (auto-restart) (Result: exit-code)
            m_active = re.search(r"Active:\s+(failed|activating|inactive)\s+\(([^)]+)\)", line_str)
            if m_active:
                status_active = m_active.group(1)
                status_sub = m_active.group(2)

            # 例如: Process: 12891 ExecStart=/usr/sbin/nginx ... (code=exited, status=1/FAILURE)
            m_proc = re.search(r"Process:\s+(\d+)\s+ExecStart=([^(]+)\((code=[^)]+)\)", line_str)
            if m_proc:
                status_exec = m_proc.group(2).strip()
                status_exit_code = m_proc.group(3).strip()

            # 例如: Main PID: 12891 (code=exited, status=1/FAILURE)
            m_main_pid = re.search(r"Main PID:\s+\d+\s+\((code=[^)]+)\)", line_str)
            if m_main_pid and not status_exit_code:
                status_exit_code = m_main_pid.group(1).strip()

        if status_unit and (status_active in ["failed", "activating"] or status_exit_code):
            failed_units.append({
                "unit": status_unit,
                "active_state": status_active or "failed",
                "sub_state": status_sub or "exit-code",
                "description": status_desc or f"指令: {status_exec or '未知'}",
                "exit_code": status_exit_code or ""
            })
            inferred_service = status_unit

        # ---------------------------------------------------------------------
        # 2. 偵測 systemctl --failed 表格輸出格式
        # ---------------------------------------------------------------------
        for line in lines:
            line_str = line.strip()
            # 支援有無 bullet ● / * 開頭
            # 範例: ● nginx.service loaded failed failed A high performance web server
            m_table = re.search(r"^[●*•]?\s*([\w\.\@\-]+\.(?:service|socket|target))\s+\S+\s+(failed|activating)\s+(\S+)\s+(.*)", line_str)
            if m_table:
                unit_name = m_table.group(1)
                if not any(u["unit"] == unit_name for u in failed_units):
                    failed_units.append({
                        "unit": unit_name,
                        "active_state": m_table.group(2),
                        "sub_state": m_table.group(3),
                        "description": m_table.group(4).strip(),
                        "exit_code": ""
                    })
                    if not inferred_service:
                        inferred_service = unit_name

        # ---------------------------------------------------------------------
        # 3. 提取關鍵錯誤日誌行 (Journalctl / Stack trace / Daemon errors)
        # ---------------------------------------------------------------------
        error_keywords = [
            "failed to start", "address already in use", "permission denied",
            "bind() to", "fatal", "panic", "emerg", "crashloop", "syntax error",
            "no such file or directory", "failed with result", "error while loading",
            "cannot allocate memory", "out of memory", "status=137", "code=killed",
            "port is already allocated", "connection refused", "timed out",
            "start request repeated too quickly", "auto-restart", "start-limit-hit",
            "restart counter"
        ]

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            lower_l = line_str.lower()
            if any(k in lower_l for k in error_keywords):
                crashed_logs.append(line_str)

            # 抓取日誌中提到的 Port (例如: 0.0.0.0:80, [::]:8080, port 3306)
            port_match = re.search(r"(?:bind\(\)\s+to\s+(?:\[[\d\w:]+\]|[\d\.]+):(\d+)|(?:^|\s)(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):(\d+)|\bport\s+(\d+))", line_str, re.IGNORECASE)
            if port_match:
                p = next((g for g in port_match.groups() if g), None)
                if p and p not in detected_ports:
                    detected_ports.append(p)

            # 若未偵測到 Unit，嘗試從日誌頭提取服務名稱 (例如: srv01 nginx[12891]: ...)
            if not inferred_service:
                svc_match = re.search(r"\b([\w\-]+)\[\d+\]:\s*", line_str)
                if svc_match:
                    inferred_service = svc_match.group(1) + ".service"

        # ---------------------------------------------------------------------
        # 4. 根因分類推理 (Root Cause Diagnostics)
        # ---------------------------------------------------------------------
        has_failure = (len(failed_units) > 0) or (len(crashed_logs) > 0)

        # 預設狀態 (健康)
        verdict_level = "HEALTHY"
        verdict_title = "🟢 服務運作正常：未發現崩潰或死循環"
        verdict_party = "系統服務健康"
        verdict_color = "#10b981"
        verdict_reason = "所提供之日誌或服務狀態中，無任何處於 Failed、Activating (CrashLoop) 或嚴重 Error 標記。"
        verdict_action = "服務狀態良好，無需介入。"
        primary_cause_type = "NONE"
        remedy_commands = []

        if has_failure:
            verdict_level = "CRITICAL"
            verdict_color = "#ef4444"

            # 確定主服務名
            main_unit = failed_units[0]["unit"] if failed_units else (inferred_service or "unknown.service")

            # 分析日誌與狀態文字尋找具體死因
            unit_states = " ".join([f"{u.get('active_state','')} {u.get('sub_state','')} {u.get('exit_code','')}" for u in failed_units])
            combined_logs = (" ".join(crashed_logs) + " " + unit_states + " " + text).lower()

            if "address already in use" in combined_logs or "port is already allocated" in combined_logs or (detected_ports and "bind()" in combined_logs):
                primary_cause_type = "PORT_CONFLICT"
                port_str = detected_ports[0] if detected_ports else "80"
                verdict_title = f"🚨【連接埠衝突 (Port {port_str} 被搶)】：服務「{main_unit}」無法綁定通訊埠！"
                verdict_party = f"通訊埠搶佔衝突 (Port {port_str})"
                verdict_reason = f"服務 {main_unit} 啟動失敗，核心報錯「Address already in use」。通訊埠 {port_str} 已被其他進程搶先佔據，導致 bind() 失敗退出！"
                verdict_action = f"1. 查出是誰霸佔 Port {port_str}：\n   sudo ss -tulpn | grep :{port_str}\n2. 強制踢掉佔用進程：\n   sudo fuser -k {port_str}/tcp\n3. 重啟服務：\n   sudo systemctl restart {main_unit}"
                remedy_commands = [
                    f"sudo ss -tulpn | grep :{port_str}",
                    f"sudo fuser -k {port_str}/tcp",
                    f"sudo systemctl restart {main_unit}"
                ]

            elif "permission denied" in combined_logs:
                primary_cause_type = "PERMISSION_DENIED"
                verdict_title = f"🚨【存取權限被拒 (Permission Denied)】：服務「{main_unit}」權限不足！"
                verdict_party = "檔案/通訊端權限異常"
                verdict_reason = f"服務 {main_unit} 嘗試讀取設定檔、寫入 Log 或綁定 Unix Socket 時遭遇 Permission denied，進程被作業系統安全機制強制攔截！"
                verdict_action = f"1. 檢查服務目錄權限與擁有者：\n   ls -ld /var/log/{main_unit.replace('.service','')}* /run/{main_unit.replace('.service','')}*\n2. 查看 SELinux / AppArmor 攔截日誌：\n   sudo ausearch -m avc -ts recent"
                remedy_commands = [
                    f"journalctl -u {main_unit} -n 30 --no-pager",
                    "sudo dmesg -T | grep -i 'apparmor\\|selinux\\|denied'"
                ]

            elif "syntax error" in combined_logs or "test failed" in combined_logs or "[emerg]" in combined_logs:
                primary_cause_type = "CONFIG_SYNTAX_ERROR"
                verdict_title = f"🚨【設定檔語法錯誤 (Syntax Error)】：服務「{main_unit}」設定驗證失敗！"
                verdict_party = "設定檔語法損毀"
                verdict_reason = f"服務 {main_unit} 讀取設定檔時觸發致命錯誤 (Fatal/Emerg)，解析中斷導致啟動終止。通常是近期手動修改過設定檔遺漏分號或標點！"
                
                # 特殊服務提示
                test_cmd = f"journalctl -u {main_unit} -n 30 --no-pager"
                if "nginx" in main_unit:
                    test_cmd = "sudo nginx -t"
                elif "apache" in main_unit or "httpd" in main_unit:
                    test_cmd = "sudo apachectl configtest"
                elif "ssh" in main_unit:
                    test_cmd = "sudo sshd -t"

                verdict_action = f"1. 執行設定檔自動語法檢查：\n   {test_cmd}\n2. 依據報錯行號修復後重啟：\n   sudo systemctl restart {main_unit}"
                remedy_commands = [test_cmd, f"sudo systemctl restart {main_unit}"]

            elif "auto-restart" in combined_logs or "start request repeated too quickly" in combined_logs or "crashloop" in combined_logs:
                primary_cause_type = "CRASH_LOOP"
                verdict_title = f"🚨【陷入無限重啟死循環 (CrashLoopBackOff)】：服務「{main_unit}」反覆崩潰！"
                verdict_party = "進程異常頻繁重啟"
                verdict_reason = f"服務 {main_unit} 處於 activating (auto-restart) 死循環！進程每次剛啟動便瞬間異常崩潰 (exit-code)，Systemd 已觸發重啟限流保護！"
                verdict_action = f"1. 捕捉進程退出前最後堆疊：\n   sudo journalctl -u {main_unit} -n 50 --no-pager\n2. 清除 Systemd 失敗計數器：\n   sudo systemctl reset-failed {main_unit}\n3. 重試啟動：\n   sudo systemctl start {main_unit}"
                remedy_commands = [
                    f"sudo journalctl -u {main_unit} -n 50 --no-pager",
                    f"sudo systemctl reset-failed {main_unit}",
                    f"sudo systemctl start {main_unit}"
                ]

            elif "status=137" in combined_logs or "out of memory" in combined_logs or "code=killed" in combined_logs:
                primary_cause_type = "OOM_KILLED"
                verdict_title = f"🚨【遭核心 OOM Killer 強制處決 (Exit 137)】：服務「{main_unit}」記憶體耗盡！"
                verdict_party = "系統/容器記憶體不足"
                verdict_reason = f"服務 {main_unit} 退出代碼為 137 (SIGKILL 9+128)，代表其未及處理異常即被 Linux 核心記憶體超載保護直接槍斃！"
                verdict_action = f"1. 查看 OOM Killer 處決現場：\n   sudo dmesg -T | grep -i oom\n2. 檢查主機記憶體剩餘：\n   free -h\n3. 或切換至 SysScope 第四頁【OOM 殺人案發現場】進行深入鑑定！"
                remedy_commands = [
                    "sudo dmesg -T | grep -i oom",
                    "free -h"
                ]

            elif "no such file or directory" in combined_logs or "error while loading" in combined_logs:
                primary_cause_type = "MISSING_DEPENDENCY"
                verdict_title = f"🚨【找不到二進位檔或相依套件庫】：服務「{main_unit}」相依性缺失！"
                verdict_party = "執行環境相依性缺失"
                verdict_reason = f"服務 {main_unit} 啟動失敗，作業系統回報 No such file or directory 或找不到動態連結庫 (.so)！"
                verdict_action = f"請檢查 ExecStart 執行檔路徑是否存在，或缺少哪個函式庫：\n   sudo systemctl status {main_unit} -l"
                remedy_commands = [f"sudo systemctl status {main_unit} -l"]

            else:
                primary_cause_type = "GENERAL_FAILURE"
                verdict_title = f"🚨【服務崩潰罷工 (Failed)】：偵測到「{main_unit}」異常停止！"
                verdict_party = f"服務異常退出 ({main_unit})"
                verdict_reason = f"服務 {main_unit} 處於崩潰狀態，日誌中捕捉到異常退出訊號！"
                verdict_action = f"請執行日誌提取指令查看詳細調用棧：\n   sudo journalctl -u {main_unit} -n 30 --no-pager"
                remedy_commands = [f"sudo journalctl -u {main_unit} -n 30 --no-pager"]

        # 若未在表格抓到，但有日誌報錯且未填入 failed_units，為前端補上一筆虛擬 unit
        if not failed_units and has_failure:
            failed_units.append({
                "unit": main_unit,
                "active_state": "failed",
                "sub_state": primary_cause_type,
                "description": f"日誌中偵測到嚴重錯誤 (包含 {len(crashed_logs)} 行 Crash Log)",
                "exit_code": ""
            })

        return {
            "success": True,
            "has_failure": has_failure,
            "failed_count": len(failed_units),
            "cause_type": primary_cause_type,
            "detected_ports": detected_ports,
            "remedy_commands": remedy_commands,
            "verdict": {
                "level": verdict_level,
                "title": verdict_title,
                "party": verdict_party,
                "color": verdict_color,
                "reason": verdict_reason,
                "action": verdict_action
            },
            "failed_units": failed_units,
            "key_error_logs": crashed_logs[:20]
        }
