# -*- coding: utf-8 -*-
"""
Unit tests for SysScope Remedy Executor (core/remedy_executor.py)
"""

import unittest
from core.remedy_executor import remedy_executor, RemedyExecutor

class TestRemedyExecutor(unittest.TestCase):

    def setUp(self):
        self.executor = RemedyExecutor()

    def test_safe_commands_allowed(self):
        safe_cases = [
            'echo "" > /proc/1821/fd/4',
            'systemctl restart nginx',
            'fuser -k 80/tcp',
            'swapon -a',
            'iptables-restore < /etc/iptables.rules',
            'chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys',
            'cat /etc/fstab',
            'systemctl reset-failed apache2',
        ]
        for cmd in safe_cases:
            safe, reason = self.executor.is_safe_command(cmd)
            self.assertTrue(safe, f"Expected '{cmd}' to be safe, but got blocked: {reason}")

    def test_destructive_commands_blocked(self):
        blocked_cases = [
            'rm -rf /',
            'rm -rf / --no-preserve-root',
            'rm -r /',
            'mkfs.ext4 /dev/sda1',
            'mkfs -t xfs /dev/sdb',
            'dd if=/dev/zero of=/dev/sda bs=1M count=100',
            ':(){ :|:& };:',
            'drop database production',
            'shutdown -h now',
            'poweroff',
            'halt',
            'echo zero > /dev/sda',
        ]
        for cmd in blocked_cases:
            safe, reason = self.executor.is_safe_command(cmd)
            self.assertFalse(safe, f"Expected '{cmd}' to be blocked, but was allowed!")
            self.assertIn("安全守衛攔截", reason)

    def test_empty_and_comment_commands(self):
        comment_cases = [
            '# 請手動編輯 /etc/fstab',
            '# 建議擴增實體 RAM 或調高 swappiness',
            '',
            '   '
        ]
        for cmd in comment_cases:
            safe, reason = self.executor.is_safe_command(cmd)
            self.assertFalse(safe)
            self.assertIn("註解或空指令", reason)

    def test_local_execution_echo(self):
        res = self.executor.execute('echo "sysscope_remedy_ok"')
        self.assertTrue(res["success"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("sysscope_remedy_ok", res["stdout"])
        self.assertGreater(res["execution_time_ms"], 0)
        self.assertEqual(res["target"], "localhost")

    def test_blocked_command_execution(self):
        res = self.executor.execute('rm -rf /')
        self.assertFalse(res["success"])
        self.assertEqual(res["exit_code"], -1)
        self.assertEqual(res["target"], "blocked")
        self.assertIn("安全守衛攔截", res["stderr"])

    def test_cached_target(self):
        self.executor.set_cached_target("192.168.1.50", "admin", "secret123", 2222)
        cached = self.executor.get_cached_target()
        self.assertEqual(cached["host"], "192.168.1.50")
        self.assertEqual(cached["user"], "admin")
        self.assertEqual(cached["password"], "secret123")
        self.assertEqual(cached["port"], 2222)
        # Reset
        self.executor.set_cached_target(None, "", None, 22)

if __name__ == '__main__':
    unittest.main()
