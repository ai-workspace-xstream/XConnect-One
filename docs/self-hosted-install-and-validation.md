# XConnect One 自建安装与接入验证

XConnect One 是独立的 controlled-client CLI。它从 XConnect Zero
`accounts` 获取一次性邀请和签名配置，在本机管理外部 Xray 与 WireGuard；它不依赖
XConnect APP，也不实现 macOS host adapter / Packet Tunnel handoff。

## 安装入口

`install.svc.plus` 应只托管经过审核的本仓库安装脚本；脚本再从已批准的 Release
镜像获取带 `SHA256SUMS` 的制品。生产环境建议显式固定版本：

```sh
curl -fsSL https://install.svc.plus/xconnect-one | \
  XCONNECT_ONE_VERSION=v0.1.9 bash
```

环境变量放在管道右侧，才会传给安装脚本；不要把版本号放在
`curl` 进程前面。安装脚本只下载对应平台的公开 Release 制品并校验
`SHA256SUMS`，不会创建 Zero 设备或自动加入网络。

Linux 支持 `amd64` / `arm64`，macOS 支持 Intel / Apple Silicon。默认安装到
`/usr/local/bin/xconnect`；可用 `XCONNECT_ONE_INSTALL_DIR` 指定绝对路径。私有
GitHub Release 通过受控镜像提供时，安装脚本使用
`XCONNECT_ONE_RELEASE_BASE_URL` 覆盖下载根地址。

macOS 也可以使用仓库中的 Homebrew 公式。公式固定到同一版本，并按 Apple
Silicon/Intel 选择制品、校验 sha256；它同样只安装 CLI：

```sh
brew install --formula \
  https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/Formula/xconnect-one.rb
```

如果后续建立专用 Homebrew tap，可将上面的 URL 替换为
`brew install ai-workspace-xstream/tap/xconnect-one`；运行时和 Zero 加入步骤不变。

Windows 在管理员 PowerShell 中执行：

```powershell
$env:XCONNECT_ONE_VERSION = 'v0.1.9'
irm https://install.svc.plus/xconnect-one.ps1 | iex
```

Windows 默认安装到 `%ProgramFiles%\XConnect\xconnect-windows-amd64.exe`。安装器
只下载精确平台制品、读取同版本 `SHA256SUMS` 并在复制前校验；它不会写入 Zero
邀请、设备凭据或私钥。

## 外部运行时

One 不内置 Xray 或 WireGuard。自建节点需要预先安装：

- Linux：`xray`、`wg`、`wg-quick` 和 WireGuard 内核支持；
- macOS：外部 `xray`、`wg`、`wg-quick`、`wireguard-go`；
- Windows：外部 `xray.exe`、`wg.exe`、`wireguard.exe`，并以管理员权限运行。

Xray 必须支持 VLESS/TLS、XUDP 和 UDP `dokodemo-door`。One 生成的 WireGuard
peer Endpoint 指向本机 Xray 的 UDP loopback 入口；不要把 Gateway 的公网
WireGuard UDP 端口写进 One 配置。

### v0.1.10 Linux 受管 bootstrap

Debian/Ubuntu Linux 可以让 One 显式准备运行时：

```sh
sudo /usr/local/bin/xconnect runtime bootstrap \
  --state-dir /var/lib/xconnect-one
```

该命令会通过系统包管理器安装缺失的 `wireguard-tools` / `iproute2`，从固定的
Xray Release 下载与架构匹配的归档，校验内置 sha256，并将 Xray 安装到
`/var/lib/xconnect-one/managed-runtime/bin/xray`。manifest 和生成配置留在
One 自己的受保护目录。

也可以把显式 bootstrap 与首次加入合成一条命令：

```sh
sudo /usr/local/bin/xconnect join --bootstrap \
  --state-dir /var/lib/xconnect-one \
  'xconnect://join/REPLACE_WITH_SHORT_LIVED_INVITE'
```

`--bootstrap` 不会静默启用；macOS/Windows 在各自受管 adapter 发布前会明确返回
runtime unavailable，继续使用已安装的外部运行时。

## 自建加入

使用 Zero Portal 生成针对具体网络、平台和设备 ID 的短期邀请。邀请只交互输入，
不要写进 Git、GitHub Actions input、shell history 或日志：

```sh
sudo /usr/local/bin/xconnect join \
  --state-dir /var/lib/xconnect-one \
  --device-id one-selfhost-macos \
  --name 'selfhost macOS One' \
  --network-id net_uat \
  'xconnect://join/REPLACE_WITH_SHORT_LIVED_INVITE?controller=https%3A%2F%2Faccounts-uat.example'

sudo /usr/local/bin/xconnect sync --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect status --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect diagnose --state-dir /var/lib/xconnect-one
```

`join` / `sync` 的实际顺序是：获取设备会话、验证签名配置和策略、生成本地
Xray/WireGuard 配置、启动受 CLI 所有的运行时、读取应用结果并向 Accounts 发送
ACK。设备私钥只留在本机状态目录。

## 闭环验证

对 Gateway 与 One 分别记录以下结果；所有目标必须是本次 Zero 网络明确授权的地址：

```sh
# One
sudo /usr/local/bin/xconnect status --state-dir /var/lib/xconnect-one
sudo wg show xconone0 latest-handshakes
ping -c 3 10.77.0.1
curl --fail --max-time 10 http://10.77.0.1:8080/uat/run

# Gateway（在 Gateway 主机上）
sudo /usr/local/bin/xconnect-gateway status --state-dir /var/lib/xconnect-gateway
sudo wg show xconnect0 latest-handshakes
sudo systemctl is-active xconnect-gateway-xray.service
sudo ss -lntp | grep ':443'
```

判定为通过必须同时满足：One 和 Gateway 服务状态正常、`latest-handshakes` 命中
精确的对端公钥且时间足够新、私网 ping 成功、私网 HTTP 返回预期的本次运行标记。
只有 ACK 或 Portal 上显示“最近配置已确认”不能单独证明数据面在线。

## 撤销与清理

在 Portal 撤销设备后，One 执行：

```sh
sudo /usr/local/bin/xconnect down --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect status --state-dir /var/lib/xconnect-one
```

Gateway 应重新同步 peer 集合；不要手工删除其他设备的 peer。一次性邀请、设备
凭据、WireGuard 私钥和 TLS 私钥均不属于 GitOps 公开配置。
