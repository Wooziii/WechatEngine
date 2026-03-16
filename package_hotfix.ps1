$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "[1/3] Building release package..."
powershell -ExecutionPolicy Bypass -File (Join-Path $root "build_release.ps1")

Write-Host "[2/3] Creating hotfix backup..."
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$hotfixDir = Join-Path $root ("release_hotfix_" + $stamp)
New-Item -ItemType Directory -Path $hotfixDir | Out-Null

$rootFiles = @(
  "analysis_web.html",
  ".mcp.json",
  "mcp_server.py",
  "monitor_web.py",
  "monitor_web.html",
  "config.py",
  "config.example.json",
  "README.md",
  "build_release.ps1",
  "package_hotfix.ps1",
  "TopicEngine.ico"
)

foreach ($file in $rootFiles) {
  $src = Join-Path $root $file
  if (Test-Path $src) {
    Copy-Item $src (Join-Path $hotfixDir $file) -Force
  }
}

$releaseDir = Join-Path $hotfixDir "release"
New-Item -ItemType Directory -Path $releaseDir | Out-Null
$releaseFiles = @(
  "TopicEngine.exe",
  "TopicEngine.ico",
  "monitor_web.html",
  "analysis_web.html",
  ".mcp.json",
  "mcp_server.py",
  "config.example.json",
  "README.md",
  "RELEASE_README.txt"
)

foreach ($file in $releaseFiles) {
  $src = Join-Path $root ("release\" + $file)
  if (Test-Path $src) {
    Copy-Item $src (Join-Path $releaseDir $file) -Force
  }
}

$releaseZip = Get-ChildItem (Join-Path $root "release\TopicEngine-*.zip") |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
if ($releaseZip) {
  Copy-Item $releaseZip.FullName (Join-Path $hotfixDir $releaseZip.Name) -Force
}

$note = @(
  "Hotfix backup created: $stamp",
  "",
  "Included root files:",
  "- analysis_web.html",
  "- .mcp.json",
  "- mcp_server.py",
  "- monitor_web.py",
  "- monitor_web.html",
  "- config.py",
  "- config.example.json",
  "- README.md",
  "- build_release.ps1",
  "- package_hotfix.ps1",
  "- TopicEngine.ico",
  "",
  "Included release files:",
  "- TopicEngine.exe",
  "- TopicEngine.ico",
  "- analysis_web.html",
  "- .mcp.json",
  "- mcp_server.py",
  "- config.example.json",
  "- README.md",
  "- RELEASE_README.txt",
  "- latest release zip"
)
Set-Content -Path (Join-Path $hotfixDir "HOTFIX_CONTENTS.txt") -Value $note -Encoding UTF8

Write-Host "[3/3] Creating hotfix zip..."
$hotfixZip = $hotfixDir + ".zip"
if (Test-Path $hotfixZip) {
  Remove-Item $hotfixZip -Force
}
Compress-Archive -Path (Join-Path $hotfixDir "*") -DestinationPath $hotfixZip -Force

Write-Host "Done."
Write-Host ("HOTFIX_DIR: " + $hotfixDir)
Write-Host ("HOTFIX_ZIP: " + $hotfixZip)
if ($releaseZip) {
  Write-Host ("RELEASE_ZIP: " + $releaseZip.FullName)
}
