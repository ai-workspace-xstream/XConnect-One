$ErrorActionPreference = 'Stop'

# Release installer for the standalone Windows XConnect One controlled-client.
# Set XCONNECT_ONE_RELEASE_BASE_URL to an approved mirror when GitHub Releases
# are private; the mirror must expose the same asset and SHA256SUMS contract.

$repository = 'ai-workspace-xstream/XConnect-One'
$version = if ($env:XCONNECT_ONE_VERSION) { $env:XCONNECT_ONE_VERSION } else { 'v0.1.11' }
$installDir = if ($env:XCONNECT_ONE_INSTALL_DIR) { $env:XCONNECT_ONE_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'XConnect' }
$releaseBase = if ($env:XCONNECT_ONE_RELEASE_BASE_URL) { $env:XCONNECT_ONE_RELEASE_BASE_URL } else { "https://github.com/$repository/releases/download" }

if ($version -notmatch '^v[0-9A-Za-z._-]+$') { throw "invalid release tag: $version" }
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($arch -ne 'AMD64') { throw "unsupported Windows architecture: $arch" }
$asset = 'xconnect-windows-amd64.exe'

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("xconnect-one-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
try {
  $archive = Join-Path $tmpDir $asset
  $sums = Join-Path $tmpDir 'SHA256SUMS'
  Invoke-WebRequest -UseBasicParsing -Uri ("{0}/{1}/{2}" -f $releaseBase.TrimEnd('/'), $version, $asset) -OutFile $archive
  Invoke-WebRequest -UseBasicParsing -Uri ("{0}/{1}/SHA256SUMS" -f $releaseBase.TrimEnd('/'), $version) -OutFile $sums

  $line = Get-Content $sums | Where-Object { $_ -match ("\s" + [regex]::Escape($asset) + '$') -or $_ -match ("\s" + [regex]::Escape(('dist/' + $asset)) + '$') } | Select-Object -First 1
  if (-not $line) { throw "SHA256SUMS has no entry for $asset" }
  $expected = ($line -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLowerInvariant()
  if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $actual) { throw 'release checksum mismatch' }

  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  Copy-Item -Force $archive (Join-Path $installDir $asset)
  Write-Output ("installed XConnect One {0} at {1}" -f $version, (Join-Path $installDir $asset))
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $tmpDir -ErrorAction SilentlyContinue
}
