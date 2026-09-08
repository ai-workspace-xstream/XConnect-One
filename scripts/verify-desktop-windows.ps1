[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CliPath,
    [Parameter(Mandatory = $true)]
    [string]$StateDir,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedDeviceId,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedNetworkId,
    [Parameter(Mandatory = $true)]
    [Alias('GatewayWgPublicKey')]
    [string]$GatewayWireGuardPublicKey,
    [Parameter(Mandatory = $true)]
    [string]$OverlayTarget,
    [Parameter(Mandatory = $true)]
    [string]$HttpExpectedMarker,
    [int]$HandshakeMaxAgeSeconds = 300,
    [int]$CommandTimeoutSeconds = 30,
    [switch]$SkipPing,
    [switch]$SkipHttp,
    [switch]$OfflineParserTest
)

$ErrorActionPreference = 'Stop'
$script:Result = 'PASS'
$script:TempDir = $null
$script:CommandTimeoutSeconds = $CommandTimeoutSeconds

function Write-Check([string]$Name, [string]$Status) {
    # Never print captured command output, the expected marker, or key material.
    Write-Output "check=$Name status=$Status"
}

function Set-Unverified {
    if ($script:Result -eq 'PASS') { $script:Result = 'UNVERIFIED' }
}

function Stop-Fail([string]$Name) {
    Write-Check $Name 'FAIL'
    [Console]::Error.WriteLine("verification failed at check=$Name")
    $script:Result = 'FAIL'
    Exit-Verification 1
}

function Stop-Skipped([string]$Name) {
    Write-Check $Name 'SKIPPED'
    Set-Unverified
}

function Exit-Verification([int]$RequestedCode) {
    if ($script:TempDir -and (Test-Path -LiteralPath $script:TempDir)) {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:Result -eq 'FAIL') {
        Write-Output 'result=FAIL'
        exit 1
    }
    if ($script:Result -eq 'UNVERIFIED') {
        Write-Output 'result=UNVERIFIED'
        exit 2
    }
    Write-Output 'result=PASS'
    exit $RequestedCode
}

function Fail-Input {
    Write-Check input FAIL
    [Console]::Error.WriteLine('verification failed at check=input')
    $script:Result = 'FAIL'
    Exit-Verification 1
}

function Test-PublicWireGuardKey([string]$Value) {
    if ($Value -notmatch '^[A-Za-z0-9+/]{43}=$') { return $false }
    try {
        return ([Convert]::FromBase64String($Value).Length -eq 32)
    } catch {
        return $false
    }
}

function Get-OverlayTarget([string]$Value) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $null }
    if ($uri.Scheme -notin @('http', 'https') -or $uri.UserInfo -ne '') { return $null }
    if ($uri.Host -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $null }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($uri.Host, [ref]$address)) { return $null }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    if (-not $uri.IsDefaultPort -and ($uri.Port -lt 1 -or $uri.Port -gt 65535)) { return $null }
    if ($Value -match '[\x00-\x1f\x7f]') { return $null }
    return $uri
}

function Test-BindingId([string]$Value) {
    return $Value -match '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$'
}

function Quote-ProcessArgument([string]$Value) {
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1) -join ''))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes -join '')); $slashes = 0 }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes) -join '')) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-Captured([string]$Path, [string[]]$Arguments, [string]$OutputPath) {
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Path
    $startInfo.Arguments = (($Arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { return $false }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($script:CommandTimeoutSeconds * 1000)) {
            $process.Kill()
            [void]$process.WaitForExit()
            [void]$stdoutTask.GetAwaiter().GetResult()
            [void]$stderrTask.GetAwaiter().GetResult()
            return $false
        }
        [IO.File]::WriteAllText($OutputPath, $stdoutTask.GetAwaiter().GetResult())
        [void]$stderrTask.GetAwaiter().GetResult()
        return ($process.ExitCode -eq 0)
    } finally {
        $process.Dispose()
    }
}

function Find-External([string]$Name) {
    try { return (Get-Command $Name -CommandType Application -ErrorAction Stop).Source }
    catch { }
    if ($Name -in @('wg.exe', 'wireguard.exe')) {
        $programFiles = [Environment]::GetFolderPath('ProgramFiles')
        if ([string]::IsNullOrEmpty($programFiles)) { $programFiles = $env:ProgramFiles }
        $candidate = Join-Path $programFiles (Join-Path 'WireGuard' $Name)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Get-HandshakeTimestamp([string[]]$Lines, [string]$ExpectedKey) {
    foreach ($line in $Lines) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and $parts[0] -ceq $ExpectedKey) {
            $timestamp = 0L
            if ([Int64]::TryParse($parts[1], [ref]$timestamp)) { return $timestamp }
            return $null
        }
    }
    return $null
}

if ($OfflineParserTest) {
    # Test-only path: local parser and validation checks only. It intentionally
    # returns before any CLI, runtime, ping, HTTP, or remote operation.
    $offlineKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    $offlineTarget = Get-OverlayTarget 'http://10.77.0.42:8080/uat/run'
    $offlineNow = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $offlineTimestamp = Get-HandshakeTimestamp @("$offlineKey $offlineNow") $offlineKey
    if (-not (Test-PublicWireGuardKey $offlineKey) -or $null -eq $offlineTarget -or $offlineTimestamp -ne $offlineNow) {
        Write-Output 'test-desktop-verification: FAIL'
        exit 1
    }
    if ((Get-OverlayTarget 'http://overlay.example/uat/run') -ne $null -or (Test-PublicWireGuardKey 'not-a-key')) {
        Write-Output 'test-desktop-verification: FAIL'
        exit 1
    }
    Write-Output 'test-desktop-verification: PASS'
    exit 0
}

try {
    if (-not [IO.Path]::IsPathRooted($CliPath) -or -not (Test-Path -LiteralPath $CliPath -PathType Leaf)) { Fail-Input }
    if (-not [IO.Path]::IsPathRooted($StateDir) -or [IO.Path]::GetPathRoot($StateDir) -eq $StateDir -or -not (Test-Path -LiteralPath $StateDir -PathType Container)) { Fail-Input }
    if (-not (Test-BindingId $ExpectedDeviceId) -or -not (Test-BindingId $ExpectedNetworkId)) { Fail-Input }
    if (-not (Test-PublicWireGuardKey $GatewayWireGuardPublicKey)) { Fail-Input }
    $targetUri = Get-OverlayTarget $OverlayTarget
    if ($null -eq $targetUri -or [string]::IsNullOrEmpty($HttpExpectedMarker) -or $HttpExpectedMarker.Length -gt 4096 -or $HttpExpectedMarker -match '[\x00\r\n]') { Fail-Input }
    if ($HandshakeMaxAgeSeconds -lt 1 -or $HandshakeMaxAgeSeconds -gt 86400) { Fail-Input }
    if ($CommandTimeoutSeconds -lt 1 -or $CommandTimeoutSeconds -gt 300) { Fail-Input }
    Write-Check input PASS

    $script:TempDir = Join-Path ([IO.Path]::GetTempPath()) ('xconnect-desktop-verify-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null

    if (-not (Invoke-Captured $CliPath @('sync', '--state-dir', $StateDir) (Join-Path $script:TempDir 'sync.txt'))) { Stop-Fail sync }
    Write-Check sync PASS

    $statusPath = Join-Path $script:TempDir 'status.json'
    if (-not (Invoke-Captured $CliPath @('status', '--state-dir', $StateDir) $statusPath)) { Stop-Fail status }
    try { $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json } catch { Stop-Fail status }
    $generation = 0L
    $generationValid = [Int64]::TryParse([string]$status.generations.state, [ref]$generation)
    if ($status.joined -ne $true -or [string]$status.device_id -cne $ExpectedDeviceId -or [string]$status.network_id -cne $ExpectedNetworkId -or $status.runtime.applied -ne $true -or [string]$status.runtime.core_id -cne 'xray' -or $status.credential.present -ne $true -or $status.credential.expired -ne $false -or -not $generationValid -or $generation -le 0) { Stop-Fail status }
    $interface = [string]$status.runtime.interface
    if ($interface -notmatch '^[A-Za-z0-9_.+=-]{1,15}$') { Stop-Fail status }
    Write-Check status PASS

    $xray = Find-External 'xray.exe'
    $wg = Find-External 'wg.exe'
    $wireguard = Find-External 'wireguard.exe'
    if ($null -eq $xray -or $null -eq $wg -or $null -eq $wireguard) {
        Write-Check external-runtime UNVERIFIED
        Set-Unverified
        Stop-Skipped wg-handshake
        Stop-Skipped ping
        Stop-Skipped http-marker
        Exit-Verification 2
    }
    Write-Check external-runtime PASS

    $handshakePath = Join-Path $script:TempDir 'handshakes.txt'
    if (-not (Invoke-Captured $wg @('show', $interface, 'latest-handshakes') $handshakePath)) { Stop-Fail wg-handshake }
    $timestamp = Get-HandshakeTimestamp (Get-Content -LiteralPath $handshakePath) $GatewayWireGuardPublicKey
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($null -eq $timestamp -or $timestamp -le 0 -or $timestamp -gt $now -or ($now - $timestamp) -gt $HandshakeMaxAgeSeconds) { Stop-Fail wg-handshake }
    Write-Check wg-handshake PASS

    if ($SkipPing) {
        Stop-Skipped ping
    } else {
        & ping.exe '-n' '1' '-w' '3000' $targetUri.Host *> $null
        if ($LASTEXITCODE -ne 0) { Stop-Fail ping }
        Write-Check ping PASS
    }

    if ($SkipHttp) {
        Stop-Skipped http-marker
    } else {
        $curl = Find-External 'curl.exe'
        if ($null -eq $curl) {
            Write-Check http-marker UNVERIFIED
            Set-Unverified
        } else {
            $bodyPath = Join-Path $script:TempDir 'http-body.txt'
            & $curl '--fail' '--silent' '--show-error' '--noproxy' '*' '--max-time' '10' '--output' $bodyPath '--' $OverlayTarget 2>$null
            if ($LASTEXITCODE -ne 0) { Stop-Fail http-marker }
            $markerFound = $false
            foreach ($line in (Get-Content -LiteralPath $bodyPath)) {
                if ($line -ceq $HttpExpectedMarker) { $markerFound = $true; break }
            }
            if (-not $markerFound) { Stop-Fail http-marker }
            Write-Check http-marker PASS
        }
    }
    Exit-Verification 0
} catch {
    # Keep unexpected diagnostics bounded and never echo external command data.
    if ($script:Result -ne 'FAIL') {
        $script:Result = 'FAIL'
        Write-Check internal FAIL
        [Console]::Error.WriteLine('verification failed at check=internal')
    }
    Exit-Verification 1
}
