# Android 客户端

## 构建

Java 工程，包名 `org.nousresearch.icmpvpn`，min SDK 26、compile/target SDK 36。当前版本 `0.5.1-profiles`。需要 JDK 21、Android SDK 36；构建工具和 Gradle wrapper 版本由仓库固定。

设置 `JAVA_HOME` 和 `ANDROID_HOME`，或使用本机 `android/local.properties` 指定 SDK 路径。不要提交本机路径文件。

```sh
cd android
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug :app:lintDebug :app:assembleDebugAndroidTest
```

输出：`app/build/outputs/apk/debug/app-debug.apk`。这是本机构建的调试签名，不是统一发布签名。

## 使用

1. 安装 APK，在配置界面输入名称、服务端字面量 IPv4、DNS 字面量 IPv4 和 64 位十六进制 PSK。
2. 新建配置必须输入独立 PSK；编辑已有配置时留空可保留该配置的已保存密钥。
3. Start 后接受系统 VPN 授权；只有认证握手完成才会显示已认证连接。Stop 停止隧道。
4. 最多保存 64 个配置。切换配置会丢弃未保存编辑；连接、授权和停止中的状态不允许修改活动配置。
5. PSK 必须通过私密渠道从自己管理的服务端取得，不要使用测试向量中的固定测试密钥。

同一系统通常只能启用一个 VPN/TUN 应用，不能与另一个 VPN 客户端同时工作。

## 升级与数据

配置中的 PSK 由 Android Keystore 加密，按配置 UUID 绑定。旧单配置格式会在验证后迁移；损坏数据不会静默变成空配置。连接及重连使用同一个不可变配置快照。

覆盖安装需要应用包名与签名匹配。不同机器的默认 debug 签名通常不同，不能承诺自行构建 APK 可覆盖已有安装。卸载会移除配置与 Keystore 材料，升级前应规划好重新配置方式，不能导出明文密钥作为普通备份。

## 网络与安全限制

- 应用 UID 使用 ICMP datagram socket，不申请 Root；目标 Android/OEM 是否允许创建该 socket 需要真机验证。
- 外层服务端地址只接受字面量 IPv4，不支持主机名。
- IPv4 流量走隧道；IPv6 被捕获并阻断，不会提供 IPv6 出口。
- Android TUN MTU 1280，IVP1 包上限 1200，TCP MSS 上限 1160。大 UDP/分片业务可能失败。
- 应用错误退出不是断网保护；需要系统级保护时启用并验证“始终开启 VPN”和“阻止未使用 VPN 的连接”。
- 握手或单元测试成功不证明 DNS、出口身份及无漏流，需要实际手机和网络验收。
