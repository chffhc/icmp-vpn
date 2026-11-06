# ICMP VPN

实验性 ICMP 隧道：Linux 服务端 + Android 免 Root VPN 客户端。
Android 通过 `VpnService` 捕获 IPv4 TCP、UDP 和 DNS，经认证加密的 ICMP Echo 请求/应答传到 Linux，由 TUN + NAT 出口转发。

**当前 Android 版本：`0.5.1-profiles`。这是开发项目，不是经过独立安全审计的成熟 VPN。**

## 功能与边界

- Android 8.0 / API 26 及以上，使用普通应用 UID 的 ICMP ping datagram socket，不申请 Root；OEM 与实际网络兼容性需要实测。
- Linux 服务端使用 Go 标准库，需要 TUN、`CAP_NET_RAW` 和 `CAP_NET_ADMIN`。
- 外层只使用 IPv4 ICMP Echo；ICMP 不通时不会自动改走 TCP/UDP。
- IPv4 全局路由，支持 TCP、UDP、DNS；IPv6 捕获后阻断，**不提供 IPv6 转发**。
- 一个服务端同一时刻只支持一个在线客户端。
- Android 支持最多 64 个独立服务器配置；PSK 使用 Android Keystore 加密保存。
- PSK + 按方向/会话派生的 AES-256-GCM，带认证、防重放与服务端持久化会话记录；**没有前向保密**。
- IVP1 明文 IPv4 包上限为 1200 字节；Android TUN MTU 为 1280，配合 TCP MSS 限制及本地 MTU 反馈。
- 包含高延迟流控及可选 Linux split-TCP 加速实验；这些不构成吞吐或可用性保证。

## 目录

| 路径 | 内容 |
| --- | --- |
| `PROTOCOL.md` | 线协议与安全边界 |
| `server/` | Go 服务端、网络脚本与单元测试 |
| `android/` | Java Android 客户端、Gradle wrapper 与测试 |
| `deploy/` | 需要按实际主机审查调整的 systemd 示例 |
| `tests/` | 独立协议向量、参考客户端、容器集成与性能测试工具 |
| `docs/` | 通用构建、运行与验证说明 |

本公开副本不包含真实服务器地址、PSK、部署备份、抓包、APK 签名私钥或内部知识库发布工具。测试向量中的固定 PSK 仅用于测试，**不得用于部署**。

## 快速构建

### Linux 服务端

需要 Go 1.23 或更新版本。从项目根目录执行：

```sh
(cd server && go test -race ./... && go vet ./...)
mkdir -p dist
(cd server && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ../dist/icmpvpn-linux-amd64 ./cmd/icmpvpn)
(cd server && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o ../dist/icmpvpn-linux-arm64 ./cmd/icmpvpn)
```

运行前阅读 [Linux 服务端说明](docs/server.md)。程序启动不会自动配置主机网络；必须先审查并显式执行网络配置步骤。

### Android 客户端

需要 JDK 21、Android SDK 36、Android SDK build tools；配置 `ANDROID_HOME` 或本机 `android/local.properties`：

```sh
cd android
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```

生成的调试 APK 位于 `android/app/build/outputs/apk/debug/app-debug.apk`。公开仓库不携带签名私钥；自行构建的 APK 不保证能覆盖安装已有签名不同的版本。不要为覆盖安装而直接卸载重要配置，卸载会删除应用配置和 Keystore 数据。

使用方法见 [Android 说明](docs/android.md)。

### 独立协议测试

```sh
uv run --python 3.11 --with cryptography python -m unittest discover -s tests -p test_wire.py -v
```

Linux 容器集成测试的拓扑和证据边界见 [验证说明](docs/testing.md)。

## 安全与使用限制

- 仅用于自己拥有或明确获准使用的设备和网络，遵守当地法律及网络使用规则。
- 自定义协议尚未经过独立密码学审计，不适合承载高敏感业务，不宣称可绕过任何特定网络限制。
- ICMP 可能被过滤、限速或异常处理；UDP 为尽力交付，IPv4 分片不支持，大 UDP 数据报可能丢失。
- 本应用没有独立内置 kill switch。若需要系统级断网保护，启用 Android 的“始终开启 VPN”及“阻止未使用 VPN 的连接”，并在目标设备验证。
- **不要删除或回滚会话日志后继续使用原 PSK，也不要把同一 PSK 克隆到两个运行中的服务端。** 这会破坏重启后的 nonce 唯一性保证。详细规则见服务端说明。
- `deploy/` 中的出口网卡、路径、内核能力和加速参数均是示例，不要未经审查直接启用。

单元测试、容器测试、宿主机 WAN 探测、模拟器和真机验收是不同证据层级；编译成功不等于手机实际可用。测试范围与未验证项见 `docs/testing.md`。

## 许可

当前未选择项目许可证。公开可见不等于授予任意使用、修改或再分发权；Gradle wrapper 等第三方组件保留各自许可声明。
