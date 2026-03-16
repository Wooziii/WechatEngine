$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$appVersion = "v2026.03.15"

Write-Host "[1/4] Installing build dependencies..."
python -m pip install --upgrade pyinstaller pycryptodome zstandard

Write-Host "[2/4] Building one-file exe..."
$pyArgs = @(
  "--noconfirm",
  "--clean",
  "--onefile",
  "--name", "WechatEngine",
  "--add-data", "monitor_web.html;."
)
if (Test-Path (Join-Path $root "WechatEngine.ico")) {
  $pyArgs += @("--icon", "WechatEngine.ico")
} elseif (Test-Path (Join-Path $root "TopicEngine.ico")) {
  $pyArgs += @("--icon", "TopicEngine.ico")
}
if (Test-Path (Join-Path $root "analysis_web.html")) {
  $pyArgs += @("--add-data", "analysis_web.html;.")
}
if (Test-Path (Join-Path $root "mcp_server.py")) {
  $pyArgs += @("--add-data", "mcp_server.py;.")
}
if (Test-Path (Join-Path $root ".mcp.json")) {
  $pyArgs += @("--add-data", ".mcp.json;.")
}
$pyArgs += "monitor_web.py"
python -m PyInstaller @pyArgs

Write-Host "[3/4] Preparing release folder..."
$releaseDir = Join-Path $root "release"
$releaseDirLocked = $false
if (Test-Path $releaseDir) {
  try {
    Remove-Item $releaseDir -Recurse -Force -ErrorAction Stop
  } catch {
    $releaseDirLocked = $true
    $fallbackStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $releaseDir = Join-Path $root ("release_" + $fallbackStamp)
    Write-Warning ("release directory is in use; fallback to " + $releaseDir)
  }
}
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

Copy-Item (Join-Path $root "dist\WechatEngine.exe") (Join-Path $releaseDir "WechatEngine.exe") -Force
Copy-Item (Join-Path $root "monitor_web.html") (Join-Path $releaseDir "monitor_web.html") -Force
Copy-Item (Join-Path $root "config.example.json") (Join-Path $releaseDir "config.example.json") -Force
if (Test-Path (Join-Path $root "README.md")) {
  Copy-Item (Join-Path $root "README.md") (Join-Path $releaseDir "README.md") -Force
}
if (Test-Path (Join-Path $root "analysis_web.html")) {
  Copy-Item (Join-Path $root "analysis_web.html") (Join-Path $releaseDir "analysis_web.html") -Force
}
if (Test-Path (Join-Path $root "mcp_server.py")) {
  Copy-Item (Join-Path $root "mcp_server.py") (Join-Path $releaseDir "mcp_server.py") -Force
}
if (Test-Path (Join-Path $root ".mcp.json")) {
  Copy-Item (Join-Path $root ".mcp.json") (Join-Path $releaseDir ".mcp.json") -Force
}
if (Test-Path (Join-Path $root "WechatEngine.ico")) {
  Copy-Item (Join-Path $root "WechatEngine.ico") (Join-Path $releaseDir "WechatEngine.ico") -Force
} elseif (Test-Path (Join-Path $root "TopicEngine.ico")) {
  Copy-Item (Join-Path $root "TopicEngine.ico") (Join-Path $releaseDir "WechatEngine.ico") -Force
}

$releaseNote = @"
Quick Start
Version: $appVersion
1. Copy config.example.json to config.json.
2. Edit config.json and set db_dir to your WeChat db_storage path.
3. Run WechatEngine.exe as Administrator.
4. The app auto-opens http://localhost:8080 by default.
5. If 8080 is unavailable, the app switches to another free local port and prints the actual URL in the console.
"@
Set-Content -Path (Join-Path $releaseDir "RELEASE_README.txt") -Value $releaseNote -Encoding UTF8

Write-Host "[4/4] Creating zip package..."
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$zipPath = Join-Path $releaseDir ("WechatEngine-" + $appVersion + "-" + $stamp + ".zip")
Compress-Archive -Path (Join-Path $releaseDir "*") -DestinationPath $zipPath -Force

Write-Host "Build done."
if ($releaseDirLocked) {
  Write-Host ("RELEASE_DIR_FALLBACK: " + $releaseDir)
} else {
  Write-Host ("RELEASE_DIR: " + $releaseDir)
}
Write-Host ("EXE: " + (Join-Path $releaseDir "WechatEngine.exe"))
Write-Host ("ZIP: " + $zipPath)
