#!/usr/bin/env bash
# ==============================================================================
# SysScope - Linux & macOS 通用啟動器 (Universal POSIX Launcher)
# 系統主機全方位異常透視儀 (Master Host Doctor)
# 100% Pure Python 3 Standard Library | Zero-Dependency | Zero-Disk-Retention
# ==============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==================================================================="
echo "    ⬡ SysScope — 系統主機全方位異常透視儀 (Master Host Doctor)"
echo "    機房維運三部曲 L7/OS 篇：人為翻車鑑識 | 幽靈日誌急救 | CrashLoop 捕手"
echo "    Developed by Kerr & Google Gemini"
echo "==================================================================="
echo ""

PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ [錯誤] 未偵測到 Python 3 執行環境！"
    echo "SysScope 為零依賴架構，只需安裝 Python 3 即可原生運行："
    echo "  - Debian/Ubuntu: sudo apt install python3"
    echo "  - RHEL/Rocky/CentOS: sudo dnf install python3"
    echo "  - macOS: brew install python3"
    exit 1
fi

echo "✅ [1/2] 檢測到 Python 環境: $($PYTHON_CMD --version)"
echo "🚀 [2/2] 正在啟動 SysScope 伺服器 (Port 8940)..."
echo "      本機控制台: http://localhost:8940/"
echo ""

exec "$PYTHON_CMD" "$DIR/server.py"
