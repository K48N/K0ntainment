$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$chromeOut = Join-Path $dist 'chrome'
$firefoxOut = Join-Path $dist 'firefox'

if (-not (Test-Path $dist)) {
  New-Item -ItemType Directory -Path $dist | Out-Null
}

if (Test-Path $chromeOut) { Remove-Item -Recurse -Force $chromeOut }
if (Test-Path $firefoxOut) { Remove-Item -Recurse -Force $firefoxOut }

New-Item -ItemType Directory -Path $chromeOut | Out-Null
New-Item -ItemType Directory -Path $firefoxOut | Out-Null

$files = @(
  'manifest.json',
  'background.js',
  'content.js',
  'content.css',
  'options.html',
  'options.css',
  'options.js'
)

foreach ($file in $files) {
  Copy-Item -Path (Join-Path $root $file) -Destination (Join-Path $chromeOut $file)
  Copy-Item -Path (Join-Path $root $file) -Destination (Join-Path $firefoxOut $file)
}

Write-Host 'Dist folders built:'
Write-Host " - $chromeOut"
Write-Host " - $firefoxOut"
