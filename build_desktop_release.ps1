$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$specDir = Join-Path $root "build\desktop_spec"
New-Item -ItemType Directory -Path $specDir -Force | Out-Null

function Invoke-External {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$ArgumentList
  )

  & $FilePath @ArgumentList
  if ($LASTEXITCODE -ne 0) {
    throw ("Command failed with exit code " + $LASTEXITCODE + ": " + $FilePath + " " + ($ArgumentList -join " "))
  }
}

$monitorHtml = Join-Path $root "monitor_web.html"
$analysisHtml = Join-Path $root "analysis_web.html"
$mcpServer = Join-Path $root "mcp_server.py"
$mcpConfig = Join-Path $root ".mcp.json"
$iconPath = Join-Path $root "WechatEngine.ico"
if (-not (Test-Path $iconPath)) {
  $iconPath = Join-Path $root "TopicEngine.ico"
}
$desktopEntry = Join-Path $root "desktop_shell.py"
$backendEntry = Join-Path $root "monitor_web.py"
$configExample = Join-Path $root "config.example.json"
$configLive = Join-Path $root "config.json"
$keysLive = Join-Path $root "all_keys.json"
$readmePath = Join-Path $root "README.md"
$appVersion = "v2026.03.15"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

Write-Host "[1/5] Installing build dependencies..."
Invoke-External -FilePath "python" -ArgumentList @(
  "-m", "pip", "install", "--upgrade", "pyinstaller", "pycryptodome", "zstandard", "PySide6"
)

Write-Host "[2/5] Building backend core..."
$coreArgs = @(
  "--noconfirm",
  "--clean",
  "--onefile",
  "--name", "WechatEngineCore",
  "--specpath", $specDir,
  "--add-data", ($monitorHtml + ";.")
)
if (Test-Path $analysisHtml) {
  $coreArgs += @("--add-data", ($analysisHtml + ";."))
}
if (Test-Path $mcpServer) {
  $coreArgs += @("--add-data", ($mcpServer + ";."))
}
if (Test-Path $mcpConfig) {
  $coreArgs += @("--add-data", ($mcpConfig + ";."))
}
if (Test-Path $iconPath) {
  $coreArgs += @("--icon", $iconPath)
}
$coreArgs += $backendEntry
$coreCommandArgs = @("-m", "PyInstaller") + $coreArgs
Invoke-External -FilePath "python" -ArgumentList $coreCommandArgs

Write-Host "[3/5] Building desktop shell..."
$desktopArgs = @(
  "--noconfirm",
  "--clean",
  "--onedir",
  "--windowed",
  "--name", "WechatEngine",
  "--specpath", $specDir,
  "--hidden-import", "PySide6.QtWebEngineCore",
  "--hidden-import", "PySide6.QtWebChannel"
)
if (Test-Path $iconPath) {
  $desktopArgs += @("--add-data", ($iconPath + ";."))
}
if (Test-Path $iconPath) {
  $desktopArgs += @("--icon", $iconPath)
}
$desktopArgs += $desktopEntry
$desktopCommandArgs = @("-m", "PyInstaller") + $desktopArgs
Invoke-External -FilePath "python" -ArgumentList $desktopCommandArgs

Write-Host "[4/5] Preparing desktop release folder..."
$releaseDir = Join-Path $root "release_desktop"
if (Test-Path $releaseDir) {
  try {
    Remove-Item $releaseDir -Recurse -Force -ErrorAction Stop
  } catch {
    $releaseDir = Join-Path $root ("release_desktop_" + $stamp)
    if (Test-Path $releaseDir) {
      Remove-Item $releaseDir -Recurse -Force -ErrorAction Stop
    }
  }
}
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

Copy-Item (Join-Path $root "dist\WechatEngine\*") $releaseDir -Recurse -Force
Copy-Item (Join-Path $root "dist\WechatEngineCore.exe") (Join-Path $releaseDir "WechatEngineCore.exe") -Force
Copy-Item $monitorHtml (Join-Path $releaseDir "monitor_web.html") -Force
if (Test-Path $analysisHtml) {
  Copy-Item $analysisHtml (Join-Path $releaseDir "analysis_web.html") -Force
}
Copy-Item $configExample (Join-Path $releaseDir "config.example.json") -Force
if (Test-Path $configLive) {
  Copy-Item $configLive (Join-Path $releaseDir "config.json") -Force
}
if (Test-Path $keysLive) {
  Copy-Item $keysLive (Join-Path $releaseDir "all_keys.json") -Force
}

if (Test-Path $readmePath) {
  Copy-Item $readmePath (Join-Path $releaseDir "README.md") -Force
}
if (Test-Path $iconPath) {
Copy-Item $iconPath (Join-Path $releaseDir "WechatEngine.ico") -Force
}

$releaseNote = @"
WechatEngine Desktop Shell
Version: $appVersion
1. Copy config.example.json to config.json.
2. Edit config.json and set db_dir to your WeChat db_storage path.
3. Run WechatEngine.exe as Administrator.
4. The desktop window embeds the original Web UI locally instead of opening your browser.
5. Closing or minimizing the window keeps it in the system tray.
6. You can toggle startup-on-boot from the tray menu.
"@
Set-Content -Path (Join-Path $releaseDir "RELEASE_README.txt") -Value $releaseNote -Encoding UTF8

Write-Host "[5/5] Creating zip package..."
$zipPath = Join-Path $root ("WechatEngine-desktop-" + $appVersion + "-" + $stamp + ".zip")
if (Test-Path $zipPath) {
  Remove-Item $zipPath -Force
}
try {
  Compress-Archive -Path (Join-Path $releaseDir "*") -DestinationPath $zipPath -Force -ErrorAction Stop
} catch {
  Write-Warning ("Compress-Archive failed, retrying with tar.exe: " + $_.Exception.Message)
  $tarCmd = Get-Command tar.exe -ErrorAction SilentlyContinue
  if (-not $tarCmd) {
    throw
  }
  $releaseLeaf = Split-Path -Leaf $releaseDir
  Push-Location $root
  try {
    & $tarCmd.Source -a -cf $zipPath $releaseLeaf
    if ($LASTEXITCODE -ne 0) {
      throw "tar.exe failed with exit code $LASTEXITCODE"
    }
  } finally {
    Pop-Location
  }
}

Write-Host "Build done."
Write-Host ("RELEASE_DIR: " + $releaseDir)
Write-Host ("DESKTOP_EXE: " + (Join-Path $releaseDir "WechatEngine.exe"))
Write-Host ("BACKEND_EXE: " + (Join-Path $releaseDir "WechatEngineCore.exe"))
Write-Host ("ZIP: " + $zipPath)
