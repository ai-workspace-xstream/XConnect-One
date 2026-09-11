<#
.SYNOPSIS
    XConnect 客户端 Windows 平台 DNS 缓存自查与清理工具
.DESCRIPTION
    诊断 Windows 系统的 DNS 解析机制、DNS Client 缓存状态，并支持一键清空本地 DNS 缓存以解决负缓存阻断问题。
.PARAMETER Action
    要执行的操作: Check (自查), Flush (清理), Both (先清理后自查)。默认是 Check。
.PARAMETER Domains
    指定待检测的一个或多个域名。
.PARAMETER Server
    指定对比的上游公共 DNS (默认: 8.8.8.8)。
.EXAMPLE
    .\dns-cache.ps1 -Action Check
.EXAMPLE
    .\dns-cache.ps1 -Action Flush
.EXAMPLE
    .\dns-cache.ps1 -Action Both -Domains @("jp-xconnect.svc.plus")
#>

[CmdletBinding()]
param(
    [ValidateSet("Check", "Flush", "Both")]
    [string]$Action = "Check",

    [string[]]$Domains = @(
        "jp-xconnect.svc.plus",
        "agent-proxy-selfhost-prod-jp.svc.plus",
        "accounts.svc.plus"
    ),

    [string]$Server = "8.8.8.8"
)

function Write-ColorHost {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    $prev = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    Write-Host $Message
    [Console]::ForegroundColor = $prev
}

Write-ColorHost "=============================================================" -Color Cyan
Write-ColorHost "      XConnect 客户端 Windows DNS 缓存自查与清理工具          " -Color Cyan
Write-ColorHost "=============================================================" -Color Cyan
Write-Host "操作模式: $Action"
Write-Host "测试时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

function Invoke-DnsFlush {
    Write-ColorHost "--- 正在清理 Windows 本地 DNS 缓存 ---" -Color Yellow
    try {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-ColorHost "  • [✓] Clear-DnsClientCache 执行成功" -Color Green
    } catch {
        Write-ColorHost "  • [!] Clear-DnsClientCache 出现警告: $_" -Color DarkYellow
    }

    $flushResult = ipconfig /flushdns
    Write-ColorHost "  • [✓] ipconfig /flushdns: $flushResult" -Color Green
    Write-ColorHost "🎉 Windows 本地 DNS 缓存已清空完成！`n" -Color Green
}

function Invoke-DnsCheck {
    Write-ColorHost "--- [1/2] 系统网络适配器与 DNS 服务器自查 ---" -Color Yellow
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
        foreach ($item in $dnsServers) {
            Write-Host "  • 接口 [$($item.InterfaceAlias)]: $($item.ServerAddresses -join ', ')"
        }
    } catch {
        Write-Host "  • 获取网络适配器信息受限 (非管理员或旧版 PowerShell)"
    }
    Write-Host ""

    Write-ColorHost "--- [2/2] 域名解析与缓存健康状态诊断 ---" -Color Yellow

    $hasNegativeCache = $false
    $hasAnomaly = $false

    foreach ($domain in $Domains) {
        Write-ColorHost "`n🔍 正在检查: $domain" -Color Cyan

        # 1. 检查 Windows DNS 本地缓存表
        $cacheEntries = @()
        try {
            $cacheEntries = Get-DnsClientCache -Name "*$domain*" -ErrorAction SilentlyContinue
        } catch {}

        if ($cacheEntries.Count -gt 0) {
            $cachedRecords = ($cacheEntries | ForEach-Object { "$($_.Entry) -> $($_.Data) ($($_.Status))" }) -join "; "
            Write-Host "  • 本地缓存记录: $cachedRecords"
        } else {
            Write-Host "  • 本地缓存记录: 无活跃缓存项"
        }

        # 2. 系统底层解析 ([System.Net.Dns]::GetHostAddresses)
        $sysStatus = "OK"
        $sysIps = @()
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($domain)
            $sysIps = $addrs | ForEach-Object { $_.IPAddressToString }
        } catch {
            $sysStatus = "FAIL"
            $sysError = $_.Exception.Message
        }

        # 3. 公共 DNS 查询 (Resolve-DnsName)
        $publicIps = @()
        $publicCname = ""
        try {
            $res = Resolve-DnsName -Name $domain -Server $Server -ErrorAction SilentlyContinue
            $publicIps = $res | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }
            $cnameRecord = $res | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
            if ($cnameRecord) { $publicCname = $cnameRecord.NameHost }
        } catch {}

        if ($sysStatus -eq "OK") {
            Write-ColorHost "  • 系统底层解析: $($sysIps -join ', ')" -Color Green
        } else {
            Write-ColorHost "  • 系统底层解析: 失败 ($sysError)" -Color Red
        }

        Write-Host "  • 公共 DNS ($Server): $($publicIps -join ', ') $(if ($publicCname) { "(CNAME: $publicCname)" })"

        # 判定
        if ($sysStatus -eq "FAIL" -and $publicIps.Count -gt 0) {
            Write-ColorHost "  ❌ [异常: 本地负缓存阻断 / Negative Cache Detected]" -Color Red
            Write-ColorHost "     公共 DNS 可以解析出 [$($publicIps -join ', ')]，但 Windows 底层解析失败。" -Color Red
            Write-ColorHost "     建议运行: .\dns-cache.ps1 -Action Flush" -Color Yellow
            $hasNegativeCache = $true
            $hasAnomaly = $true
        } elseif ($sysStatus -eq "FAIL" -and $publicIps.Count -eq 0) {
            Write-ColorHost "  ❌ [异常: 域名完全不可解析]" -Color Red
            $hasAnomaly = $true
        } else {
            if ($publicCname) {
                Write-ColorHost "  ℹ️  [提示: CNAME 扁平化生效] CNAME 指向 [$publicCname]" -Color Blue
            }
            Write-ColorHost "  ✅ [正常: 解析正常通过]" -Color Green
        }
    }

    Write-Host ""
    Write-ColorHost "--- 诊断总结 ---" -Color Yellow
    if ($hasNegativeCache) {
        Write-ColorHost "检测到本地负缓存异常，请使用管理员身份运行: .\dns-cache.ps1 -Action Flush" -Color Red
    } elseif (-not $hasAnomaly) {
        Write-ColorHost "🎉 所有域名解析正常，未发现缓存异常。" -Color Green
    }
}

if ($Action -eq "Flush") {
    Invoke-DnsFlush
} elseif ($Action -eq "Check") {
    Invoke-DnsCheck
} elseif ($Action -eq "Both") {
    Invoke-DnsFlush
    Invoke-DnsCheck
}
