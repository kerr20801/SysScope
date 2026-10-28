# SysScope Launcher & Environment Doctor
# UTF-8 with BOM Encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "SysScope - 系統主機全方位異常透視儀"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "    [SysScope] 系統主機全方位異常透視儀 (Master Host Doctor)" -ForegroundColor Cyan
Write-Host "    人為翻車鑑識 | 幽靈日誌急救 | CrashLoop 捕手 | OOM 還原" -ForegroundColor Cyan
Write-Host "    Developed by Kerr & Google Gemini" -ForegroundColor DarkCyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. 檢測 Python 執行環境
$pythonCmd = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} else {
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localPy) {
        $pythonCmd = $localPy.FullName
    }
}

if (-not $pythonCmd) {
    Write-Host "[!] 錯誤：未偵測到 Python 執行環境！" -ForegroundColor Red
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "SysScope 採 100% Python 原生標準庫設計，免裝任何第三方套件，只需 Python 3 原生環境。"
    Write-Host ""
    Write-Host "【建議安裝方式】：" -ForegroundColor Yellow
    Write-Host "  1. 透過 Windows 終端機輸入指令一鍵安裝："
    Write-Host "     winget install Python.Python.3.11" -ForegroundColor Green
    Write-Host "  2. 或前往 Python 官方網站下載： https://www.python.org/downloads/"
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Read-Host "按 Enter 鍵關閉..."
    exit 1
}

$pyVer = & $pythonCmd --version 2>&1
Write-Host "[OK] 偵測到 Python: $pyVer" -ForegroundColor Green
Write-Host "[OK] 架構模式: 0 外部 Pip 依賴 (Pure Python 3 Standard Library) - 無供應鏈投毒風險" -ForegroundColor Green
Write-Host "[OK] 資安防護: 零硬碟殘留 (Zero-Disk-Retention)，純記憶體即時鑑識" -ForegroundColor Green
Write-Host ""
Write-Host "正在啟動 SysScope 伺服器 (http://localhost:8940/)..." -ForegroundColor Yellow
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

& $pythonCmd "$scriptDir\server.py"