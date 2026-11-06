# 验证与证据边界

## 可重复运行的本地测试

```sh
(cd server && go test -count=1 -race ./... && go vet ./...)
uv run --python 3.11 --with cryptography python -m unittest discover -s tests -p test_wire.py -v
(cd android && ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug :app:lintDebug)
```

Go 的 Linux 专用代码与测试需在 Linux 执行；macOS 的 `go test` 不包含这些运行态路径。Linux 交叉编译只证明可编译，不证明内核行为。

## 容器集成

```sh
docker build -t icmp-vpn-integration:local -f tests/Dockerfile .
python3 tests/run_linux_e2e.py --help
```

按 harness 参数提供真实 Linux 二进制。测试需要 Linux 内核的 TUN、raw/ping socket 和网络 capabilities。先审查脚本及 Docker 拓扑，不要把测试直接指向生产节点。测试会建立隔离网络；不应清空宿主机防火墙。

参考 Python 客户端仅是独立测试工具，不是正式 macOS/Linux 桌面 VPN 客户端。macOS Docker Desktop 和 Android 模拟器的 ICMP 行为不能代替公网 ICMP 实测。

### 高延迟与进阶测试的可移植性

`tests/Dockerfile.highlatency` 在基础集成镜像上安装 JRE；先构建基础镜像，再构建它：

```sh
docker build -t icmp-vpn-integration:local -f tests/Dockerfile .
docker build -t icmp-vpn-highlatency:local -f tests/Dockerfile.highlatency .
```

部分历史进阶测试工具仍包含 Homebrew 工具安装路径或特定 Docker context：`run_linux_e2e.py` 的 `--java-controller` 分支、`run_highlatency_netem.py`、`profile_ui_acceptance.py`、`run_accel_cc.sh` 和 `run_synrto_ab.sh`。这些不是通用一键入口，使用前应按本机 JDK/SDK/ADB 路径和 Linux VM context 调整。基础 E2E 不需要 `--java-controller`；执行命令示例：

```sh
python3 tests/run_linux_e2e.py --binary dist/icmpvpn-linux-arm64
```

二进制架构必须匹配 Docker Linux 内核架构；其构建命令见根 README。高 RTT/BPF/BBR 测试还依赖实际 Linux 内核能力，不应据基础测试通过就宣称这些实验路径通过。

## Android instrumentation

```sh
cd android
./gradlew --no-daemon :app:assembleDebugAndroidTest :app:connectedDebugAndroidTest
```

**仅使用可丢弃模拟器的数据**：配置存储测试会清除测试应用首选项。不要在保存了真实配置的手机上直接运行这些测试。VPN consent 和通知权限需按模拟器状态处理。

## 验收层级

1. Go、Python、Java 单元测试和独立协议向量。
2. 隔离 Linux 容器中的真实 ICMP + TUN + NAT + TCP/UDP/DNS。
3. 宿主机通过公网访问部署节点的认证握手与业务请求。
4. Android 普通应用 UID 的 socket、VPN 与生命周期测试。
5. 实体手机在 Wi-Fi 和蜂窝网络分别验证出口 IP、DNS、IPv6 阻断、断线及停止行为。

公开发布准备期间的实际运行结果由 `verification.md` 记录。历史项目测试或部署记录不作为本次重新运行的证据。没有重新运行的容器、模拟器、WAN 和真机测试均不得据此声称通过。
