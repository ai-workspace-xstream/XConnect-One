# XConnect-One DNS 缓存自查与清理脚本

本目录提供面向客户端（macOS / Linux / Windows）的 DNS 缓存自查诊断与一键清理脚本，用于排查并解决因本地系统负缓存（Negative Cache）、DNS 劫持、分流异常或配置更新延迟导致的客户端连接故障。

## 脚本清单

| 脚本文件 | 适用平台 | 说明 |
| :--- | :--- | :--- |
| `dns-check.sh` | macOS / Linux | 全面自查系统底层解析（`getaddrinfo`）与公共/权威 DNS 差异，智能识别负缓存 |
| `dns-flush.sh` | macOS / Linux | 一键清理并重置系统级 DNS 缓存守护进程（支持自动自查验证） |
| `dns-cache.ps1` | Windows (PowerShell) | Windows 平台专用的 DNS Client 缓存检查与一键清理脚本 |

---

## 快速使用

### 1. macOS / Linux

#### 诊断自查 (无需 root 权限)
```bash
# 诊断默认接入域名 (jp-xconnect.svc.plus / agent-proxy-selfhost-prod-jp.svc.plus / accounts.svc.plus)
./scripts/dns-check.sh

# 诊断指定域名
./scripts/dns-check.sh my-custom-endpoint.svc.plus

# 指定对比的公共 DNS 服务器 (默认 8.8.8.8)
./scripts/dns-check.sh -s 1.1.1.1 jp-xconnect.svc.plus
```

#### 缓存清理 (需要 sudo 权限)
```bash
# 清理系统 DNS 缓存并自动自查
sudo ./scripts/dns-flush.sh

# 清理后跳过自动自查
sudo ./scripts/dns-flush.sh --no-verify
```

---

### 2. Windows (PowerShell)

以管理员身份启动 PowerShell：

```powershell
# 仅执行自查
.\scripts\dns-cache.ps1 -Action Check

# 仅执行清理 (Clear-DnsClientCache & ipconfig /flushdns)
.\scripts\dns-cache.ps1 -Action Flush

# 先清理后自查
.\scripts\dns-cache.ps1 -Action Both
```

---

## 典型故障场景说明

* **现象**：终端 `ssh` 或客户端报 `Could not resolve hostname: nodename nor servname provided, or not known`，但 `dig` 却能查出 IP。
* **根因**：系统在域名生效前发起过查询，操作系统的 DNS 守护进程（如 macOS `mDNSResponder`）将失败结果写入了内存中的**负缓存 (Negative Cache)**。
* **处置**：直接执行 `sudo ./scripts/dns-flush.sh`，脚本重置守护进程后即刻恢复正常解析。
