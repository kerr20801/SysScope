# -*- coding: utf-8 -*-
"""
SysScope Remedy Executor (現場除錯與主動自愈執行器)

負責接收 SysScope 產出之處方籤與排障指令，具備：
1. 本機 (Local Subprocess) 與 遠端 (SSH Paramiko / OpenSSH) 雙模執行能力
2. 高危破壞性指令安全攔截 (Safe-Guardrail)
3. Sudo 提權密碼自動傳遞
4. 毫秒級執行計時與標準輸出/錯誤捕獲
5. 全域連線目標快取 (Sticky Target Cache)
"""

import os
import re
import sys
import time
import subprocess
from typing import Dict, Any, Optional

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# 全域連線快取
_CACHED_TARGET: Dict[str, Any] = {
    "host": None,
    "user": "",
    "password": None,
    "port": 22,
}

# 高危阻斷指令黑名單 (安全防護閥)
BLOCKED_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(?:\s|$)", re.IGNORECASE), # rm -rf /
    re.compile(r"\bmkfs(\.\w+)?\b", re.IGNORECASE),                           # mkfs
    re.compile(r"\bdd\s+[^;&|]*of=/dev/", re.IGNORECASE),                     # dd of=/dev/
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # fork bomb
    re.compile(r"\bdrop\s+database\b", re.IGNORECASE),                        # drop database
    re.compile(r"\b(?:shutdown|poweroff|halt)\b", re.IGNORECASE),             # shutdown
    re.compile(r">\s*/dev/(?:sd|nvme|hd|vd|xvd)", re.IGNORECASE),             # overwrite block dev
]


class RemedyExecutor:
    """現場排障與處方籤除錯指令執行引擎"""

    def __init__(self):
        pass

    @classmethod
    def set_cached_target(cls, host: Optional[str], user: str = "", password: Optional[str] = None, port: int = 22):
        global _CACHED_TARGET
        _CACHED_TARGET["host"] = host
        _CACHED_TARGET["user"] = user or ""
        _CACHED_TARGET["password"] = password
        _CACHED_TARGET["port"] = port or 22

    @classmethod
    def get_cached_target(cls) -> Dict[str, Any]:
        global _CACHED_TARGET
        return dict(_CACHED_TARGET)

    def is_safe_command(self, cmd: str) -> tuple[bool, str]:
        """安全審查：確保指令非格式化、抹盤等自殺性指令"""
        clean_cmd = cmd.strip()
        if not clean_cmd or clean_cmd.startswith("#"):
            return False, "註解或空指令，無需執行"
        for pat in BLOCKED_PATTERNS:
            if pat.search(clean_cmd):
                return False, "安全守衛攔截：偵測到高危系統破壞性指令！"
        return True, "安全通過"

    def execute(self, cmd: str, host: Optional[str] = None, user: Optional[str] = None,
                password: Optional[str] = None, port: int = 22, timeout: int = 30) -> Dict[str, Any]:
        """
        執行排障指令（自動判斷本機或遠端 SSH）
        """
        safe, reason = self.is_safe_command(cmd)
        if not safe:
            return {
                "success": False,
                "exit_code": -1,
                "command": cmd,
                "stdout": "",
                "stderr": reason,
                "execution_time_ms": 0.0,
                "target": "blocked"
            }

        # 決定目標主機
        target_host = host or _CACHED_TARGET.get("host")
        target_user = user or _CACHED_TARGET.get("user") or "docker"
        target_pass = password or _CACHED_TARGET.get("password")
        target_port = port or _CACHED_TARGET.get("port") or 22

        start_t = time.perf_counter()

        # 若有指定遠端主機，透過 SSH 執行
        if target_host and target_host not in ("127.0.0.1", "localhost", "local"):
            res = self._exec_ssh(cmd, target_host, target_user, target_pass, target_port, timeout)
            res["target"] = f"{target_user}@{target_host}:{target_port}"
        else:
            # 本機執行
            res = self._exec_local(cmd, timeout)
            res["target"] = "localhost"

        elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
        res["execution_time_ms"] = elapsed_ms
        res["command"] = cmd
        return res

    def _exec_local(self, cmd: str, timeout: int) -> Dict[str, Any]:
        """本機執行指令"""
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               errors="ignore", timeout=timeout)
            return {
                "success": r.returncode == 0,
                "exit_code": r.returncode,
                "stdout": (r.stdout or "").strip(),
                "stderr": (r.stderr or "").strip(),
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": 124,
                "stdout": "",
                "stderr": f"執行超時 ({timeout}s)",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
            }

    def _exec_ssh(self, cmd: str, host: str, user: str, password: Optional[str],
                  port: int, timeout: int) -> Dict[str, Any]:
        """遠端 SSH 執行指令 (支援 Sudo 自動注入)"""
        if not HAS_PARAMIKO:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": "本地環境未安裝 Paramiko，無法發起遠端 SSH 執行！",
            }

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                look_for_keys=True,
                allow_agent=True
            )

            # 若指令包含 sudo 且有密碼，透過 echo 管道注入 sudo 密碼
            effective_cmd = cmd
            if "sudo " in cmd and password:
                # 替換為 echo password | sudo -S ...
                # 避免破壞原先已有 sudo -S 的指令
                if "sudo -S" not in cmd:
                    effective_cmd = cmd.replace("sudo ", f"echo '{password}' | sudo -S ")

            stdin, stdout, stderr = client.exec_command(effective_cmd, timeout=timeout)
            out_str = stdout.read().decode("utf-8", errors="ignore").strip()
            err_str = stderr.read().decode("utf-8", errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()

            # 清洗 sudo 提示殘留
            err_str = re.sub(r"\[sudo\] password for [^:]+:\s*", "", err_str).strip()

            return {
                "success": exit_code == 0,
                "exit_code": exit_code,
                "stdout": out_str,
                "stderr": err_str,
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"SSH 遠端連線或執行失敗: {type(e).__name__}: {str(e)}",
            }
        finally:
            try:
                client.close()
            except Exception:
                pass


remedy_executor = RemedyExecutor()
