# -*- coding: utf-8 -*-
"""
SysScope Remedy Executor (現場除錯與主動自愈執行器)

負責接收 SysScope 產出之處方籤與排障指令，具備：
1. 本機 (Local Subprocess) 與 遠端 (SSH Paramiko) 雙模執行能力
2. 高危破壞性指令安全攔截 (Safe-Guardrail)
3. Sudo 提權密碼透過 stdin 安全傳遞（不暴露於指令列與 ps 行程表）
4. 非阻塞雙通道輪詢（防止大量 stderr 造成 SSH 死鎖）與逾時保護
5. 全域連線目標快取 (Sticky Target Cache，對外 API 自動遮蔽明文密碼)
"""

import os
import re
import sys
import time
import subprocess
from typing import Dict, Any, Optional, Tuple

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# 全域連線快取（僅駐留記憶體，不寫入硬碟）
_CACHED_TARGET: Dict[str, Any] = {
    "host": None,
    "user": "",
    "password": None,
    "port": 22,
}

# 高危阻斷指令黑名單 (安全防護閥)
BLOCKED_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(?:\*|\s|$)", re.IGNORECASE),     # rm -rf / 或 rm -rf /*
    re.compile(r"\brm\s+[^\n]*--no-preserve-root\b", re.IGNORECASE),                # --no-preserve-root
    re.compile(r"\bmkfs(\.\w+)?\b", re.IGNORECASE),                                 # mkfs
    re.compile(r"\bdd\s+[^;&|]*of=/dev/", re.IGNORECASE),                           # dd of=/dev/
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),         # fork bomb
    re.compile(r"\bdrop\s+database\b", re.IGNORECASE),                              # drop database
    re.compile(r"\b(?:shutdown|poweroff|halt)\b", re.IGNORECASE),                   # shutdown / poweroff / halt
    re.compile(r">\s*/dev/(?:sd|nvme|hd|vd|xvd)", re.IGNORECASE),                   # overwrite block dev
    re.compile(r"\bchmod\s+-[a-zA-Z]*R[a-zA-Z]*\s+777\s+/(?:\s|$)", re.IGNORECASE), # chmod -R 777 /
    re.compile(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.IGNORECASE),  # curl|bash
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
    def get_cached_target(cls, include_secret: bool = False) -> Dict[str, Any]:
        """取得目前快取連線資訊；預設遮蔽明文密碼，避免透過 HTTP API 外洩"""
        global _CACHED_TARGET
        data = {
            "host": _CACHED_TARGET.get("host"),
            "user": _CACHED_TARGET.get("user", ""),
            "port": _CACHED_TARGET.get("port", 22),
            "has_password": bool(_CACHED_TARGET.get("password")),
        }
        if include_secret:
            data["password"] = _CACHED_TARGET.get("password")
        return data

    def is_safe_command(self, cmd: str) -> Tuple[bool, str]:
        """安全審查：確保指令非格式化、抹盤或高危管線等自殺性指令"""
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
        default_user = os.environ.get("SYSSCOPE_SSH_USER", "root")
        target_host = host or _CACHED_TARGET.get("host")
        target_user = user or _CACHED_TARGET.get("user") or default_user
        target_pass = password if password is not None else _CACHED_TARGET.get("password")
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

    @staticmethod
    def _prepare_sudo_command(cmd: str, password: Optional[str]) -> Tuple[str, bool]:
        """
        將 sudo 改寫為 sudo -S -p ''，並回傳是否需要透過 stdin 寫入密碼。
        絕不將密碼拼進 shell 指令字串，避免單引號注入與行程表外洩。
        """
        if not password or not re.search(r"\bsudo\s+", cmd):
            return cmd, False
        if "sudo -S" in cmd:
            return cmd, True
        rewritten = re.sub(r"\bsudo\s+", "sudo -S -p '' ", cmd)
        return rewritten, True

    def _exec_ssh(self, cmd: str, host: str, user: str, password: Optional[str],
                  port: int, timeout: int) -> Dict[str, Any]:
        """遠端 SSH 執行指令 (stdin 安全傳遞 sudo 密碼 + 非阻塞雙通道防死鎖)"""
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

            effective_cmd, need_sudo_stdin = self._prepare_sudo_command(cmd, password)
            effective_cmd = f"DEBIAN_FRONTEND=noninteractive {effective_cmd}"

            stdin, stdout, stderr = client.exec_command(effective_cmd, timeout=timeout)
            chan = stdout.channel

            if need_sudo_stdin and password:
                try:
                    # 針對可能出現多次 sudo 的管線，寫入密碼後關閉寫入端
                    sudo_count = max(1, len(re.findall(r"\bsudo\s+-S", effective_cmd)))
                    stdin.write((password + "\n") * sudo_count)
                    stdin.flush()
                    stdin.channel.shutdown_write()
                except Exception:
                    pass

            out_chunks = []
            err_chunks = []
            deadline = time.monotonic() + max(1, timeout)
            timed_out = False

            while True:
                got_data = False
                if chan.recv_ready():
                    out_chunks.append(chan.recv(8192))
                    got_data = True
                if chan.recv_stderr_ready():
                    err_chunks.append(chan.recv_stderr(8192))
                    got_data = True

                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break

                if time.monotonic() > deadline:
                    timed_out = True
                    try:
                        chan.close()
                    except Exception:
                        pass
                    break

                if not got_data:
                    time.sleep(0.03)

            out_str = b"".join(out_chunks).decode("utf-8", errors="ignore").strip()
            err_str = b"".join(err_chunks).decode("utf-8", errors="ignore").strip()
            err_str = re.sub(r"\[sudo\] password for [^:]+:\s*", "", err_str).strip()

            if timed_out:
                return {
                    "success": False,
                    "exit_code": 124,
                    "stdout": out_str,
                    "stderr": (err_str + f"\nSSH 指令執行超時 ({timeout}s)").strip(),
                }

            exit_code = chan.recv_exit_status()
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
