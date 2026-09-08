[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'verify-desktop-windows.ps1'
& $scriptPath `
    -CliPath (Join-Path $env:TEMP 'unused-xconnect.exe') `
    -StateDir $env:TEMP `
    -ExpectedDeviceId 'dev_desktop' `
    -ExpectedNetworkId 'net_uat' `
    -GatewayWireGuardPublicKey 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' `
    -OverlayTarget 'http://10.77.0.42:8080/uat/run' `
    -HttpExpectedMarker 'run=34196049126' `
    -OfflineParserTest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
