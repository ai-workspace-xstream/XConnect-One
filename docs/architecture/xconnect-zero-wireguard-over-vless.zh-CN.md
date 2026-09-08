# XConnect Zero → Gateway → One：WireGuard over VLESS 设计

状态：架构基线。本文说明组件边界、网络链路和分阶段实现方式；不代表某项
未上线能力已经通过 UAT 验证。

## 1. 目标

打通一条由 Zero 控制、Gateway 中转、One 受控接入的私网链路：

```text
XConnect Zero accounts
  ↓ signed config / enrollment / policy
XConnect Gateway
  ↓ WireGuard over VLESS
XConnect One（Linux / Windows / macOS）
```

目标是让网络、设备、策略、配置版本和撤销都由 Zero 管理；让 Gateway 和
One 只执行经过签名验证的配置；让 WireGuard 负责私网身份和加密，Xray
负责把 WireGuard UDP 承载在 VLESS/TLS 传输中。

## 2. 不做什么

- Zero、Portal 不运行 Xray 或 WireGuard，不保存设备 WireGuard 私钥。
- Portal 不直接 SSH、执行节点命令或持有 Gateway/One 的设备凭据。
- One 不成为 Gateway，不签发策略或配置。
- One 不读写、启动、停止或重配 XConnect APP 的 TUN、Xray、SOCKS、账号和
  状态目录。
- GitOps 不保存邀请码、设备凭据、私钥、VLESS 身份或 TLS 私钥。

## 3. 组件职责

| 组件 | 承载内容 | 不承载内容 |
| --- | --- | --- |
| **Zero accounts** | 网络、Gateway、One 设备、邀请、自注册审批、策略、签名配置、会话、ACK、审计 | VPN 数据面、设备私钥、Xray/WireGuard 进程 |
| **Zero portal** | `/panel/xconnect-zero` 用户隔离管理界面、BFF | 私钥、设备凭据、节点远程执行 |
| **Vault** | 签名密钥、Gateway TLS 私钥及其他敏感材料 | GitOps 公开拓扑数据 |
| **XConnect Gateway** | Linux relay/service；Gateway Xray、Gateway WireGuard、已批准 One peer 表、配置同步与 ACK | Portal、策略签发、One 私钥 |
| **XConnect One** | 注册/邀请加入、配置同步和签名验证、本机 WireGuard 生命周期、ACK | Gateway、Zero 签名、APP 状态/进程 |
| **Xray** | 外部运行时；VLESS/TLS/XUDP 传输和本地 UDP relay | 地址分配、设备审批、策略判断 |
| **WireGuard** | 设备密钥、私网地址、peer、AllowedIPs、私网加密 | VLESS 传输、用户授权、配置签发 |
| **XConnect APP** | 独立 APP UI、TUN、Xray/SOCKS/VLESS、插件宿主 | One 专有状态、One 的私钥和 WireGuard 接口 |

## 4. 控制面链路

```text
用户
  ↓
Portal /panel/xconnect-zero
  ↓ 当前登录会话的 BFF
Accounts
  ├─ 网络、Gateway、设备、策略
  ├─ 短期邀请 / One 自注册待审批
  ├─ 设备会话
  ├─ Gateway / One signed config
  └─ ACK、最后配置代次和审计
```

Accounts 是唯一权威来源。Gateway 和 One 必须校验签名、网络、设备、代次、
过期时间和配置绑定后才能应用；拒绝未签名、过期、跨网络、跨设备或回滚配置。

## 5. Gateway 数据面

Gateway 是独立 Linux 节点，生命周期如下：

```text
Gateway 邀请加入
  → 设备会话续期
  → 拉取并验证 signed Gateway config
  → 生成 Gateway Xray + WireGuard 配置
  → 启动并检查运行时
  → 向 Accounts ACK
```

Gateway 的签名配置包含：Gateway 私网地址、TLS/VLESS 入口、传输身份，以及
已批准 One 的 WireGuard 公钥、私网 `/32` 和 AllowedIPs。

```text
Internet / NAT 后客户端
  ↓ TCP + TLS
Gateway Xray VLESS 入站
  ↓ 本机 UDP 51820
Gateway WireGuard
  ↓
受策略保护的私网资源
```

Gateway peer 表只能来自已验证的 signed config，不能从 Portal 表单、GitOps 或
未校验的本地文件推导。

## 6. One 共同控制面行为

Linux、Windows、macOS 的 One CLI 保持相同控制面语义：

```text
register 或 join
  → sync
  → 校验 signed config / policy
  → 应用平台 transport + WireGuard
  → 本机检查
  → ACK
```

- `register`：创建待审批注册；审批前只做 HTTPS 轮询和受保护本地状态写入，
  不启动 Xray/WireGuard、不改路由、不发送 ACK。
- `join`：保留短期正式邀请加入能力。
- `sync`：拉取、验证和编译签名配置。
- `up` / `down`：只操作 One 自己声明、记录并验证归属的运行时。
- `leave`：撤销远端设备并清理 One 自己的本地状态；不触碰 APP 资源。

## 7. 平台数据面分层

### Linux / Windows：独立 One CLI 数据面

Linux 与 Windows 保持独立运行能力。One 生成并管理外部 `xray/tproxy` 和
WireGuard：

```text
One WireGuard
  ↓ 加密 UDP
127.0.0.1:51830 的 One 外部 Xray tproxy
  ↓ VLESS + TLS + XUDP
Gateway Xray
  ↓ 本机 UDP 51820
Gateway WireGuard
```

这里的 Xray 是外部二进制，不是嵌入 One 的代码库或产品模块；但该进程、配置
文件和 loopback relay 由 One 的专有状态目录管理。One 在启动前验证配置，
启动后验证本地 relay 与 WireGuard 接口，失败时仅回滚自己拥有的资源。

### macOS：逐步复用 XConnect APP transport provider

macOS 的目标不是让 One 管理 APP 的 Xray，而是让 APP 插件作为 transport
provider：

```text
One WireGuard
  ↓ 加密 UDP
APP 提供的 loopback UDP relay
  ↓ APP Xray / SOCKS5 / TUN
Gateway Xray
  ↓
Gateway WireGuard
```

One 仍负责注册、同步、签名验证、WireGuard 接口和 ACK；APP 负责它自己的
Xray、SOCKS5、TUN 与对外连接。两边不可共享状态目录、凭据或私钥。

当前版本说明：`v0.1.9` 的 macOS CLI 仍采用独立外部 tproxy 路径。APP
transport provider 是下一阶段目标，必须在插件协议完成后才能切换，不能提前
视为已实现。

### 为什么纯 SOCKS5 不够

WireGuard 发出的是原始 UDP，不会实现 SOCKS5 UDP ASSOCIATE。因此 APP 若只
提供 SOCKS5，不能直接让 WireGuard 把它当 peer Endpoint。APP provider 必须
在内部提供 UDP→SOCKS5/VLESS 适配，或提供 loopback-only `dokodemo-door` UDP
relay。One 只连接该 relay，不能读取 APP 配置。

## 8. macOS APP provider 契约（待实现）

在 macOS 切换到 APP 复用前，插件桥接协议需要新增受版本控制的 transport
provider 契约：

| 字段/操作 | 要求 |
| --- | --- |
| 协议版本 | 显式协商，避免旧 APP 静默接受新配置 |
| relay endpoint | 仅 loopback，返回 `host:port`，不得是公网监听器 |
| provider health | One 可获得“可用/不可用”状态，但不读取 APP 内部配置 |
| apply generation | APP 仅接受绑定当前 One signed-config 代次的请求 |
| withdraw | One 离开时只撤销 One 对该 provider 的绑定，不停止 APP 全局服务 |
| 所有权 | APP 明确拥有 relay、Xray、SOCKS5、TUN；One 明确拥有 WireGuard 与 One 状态 |
| 保密 | 不返回 APP 凭据、私钥、完整 Xray 配置或用户账号信息 |

这是一项新增的、版本化插件能力，不允许通过猜测端口、读取 APP 文件或调用未公开
私有 API 来实现。

## 9. XConnect APP TUN 的位置

即使在 Linux/Windows 独立 tproxy 模式，APP TUN 也可以作为操作系统层的外层
出口，但它不是 One 配置对象：

```text
One Xray tproxy → OS 路由 → APP TUN → 外部网络 → Gateway Xray
```

APP 自己负责防止其上游连接被错误地再次路由回本身。One 不添加 APP 路由、不改
DNS、不配置 TUN，也不依赖 APP 存在。

## 10. 仓库边界

| 仓库 | 唯一职责 |
| --- | --- |
| `accounts` | 正式控制面 API、持久化、签名、策略、会话、设备和 ACK |
| `portal` | 用户隔离 Zero 管理 UI/BFF，保持现有页面布局 |
| `XConnect-Gateway` | Gateway Linux runtime 和发布制品 |
| `XConnect-One` | 三平台 CLI、签名配置验证、平台运行时与发布制品 |
| `xconnect-app` | 独立 APP 与可选 One 插件/provider，不破坏 APP 核心 |
| `iac_modules` | 云资源模块；不包含 OS role 或凭据 |
| `playbooks` | OS 级 Xray/WireGuard role；不保存控制面业务状态 |
| `gitops/vpn-overlay` | 非敏感拓扑、版本、规格和环境声明 |

## 11. 分阶段交付

1. **Gateway + Linux One**：正式 Accounts 预置网络/邀请，Gateway 和 Linux
   One 启动，完成配置同步、ACK、精确 peer 握手、私网 ping/HTTP。
2. **Windows One**：保持同一 CLI/签名配置语义，使用独立外部 tproxy，完成
   Spot 主机验证。
3. **macOS 独立兼容验证**：在 APP provider 上线前，保留独立 tproxy 作为兼容
   路径并完成本机验证。
4. **macOS APP provider**：先发布版本化 loopback UDP relay 契约，再实现 One
   的 provider adapter，最后验证 APP 不受破坏、One 私网连通和撤销边界。

## 12. 验收证据

| 层级 | 通过证据 |
| --- | --- |
| Zero | 用户所属网络、设备与有效签名配置正确 |
| Gateway | 已验证配置、Xray/WireGuard 运行、ACK 已记录 |
| One | 已验证配置、平台 transport 和 WireGuard 运行、ACK 已记录 |
| 传输 | Gateway 与 One 对精确 peer 有新鲜 WireGuard handshake |
| 私网 | 受授权 ping 和带精确标记的 HTTP 请求成功 |
| 隔离 | One 未读写或控制 APP 状态、进程、接口和凭据 |

ACK 或进程存活不能替代握手；握手不能替代 ping/HTTP；任何单项成功都不能代表
整条数据面闭环已经通过。
