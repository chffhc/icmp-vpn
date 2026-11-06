# Public snapshot verification

Checks rerun while preparing the public source snapshot on 2026-11-06. These results apply to this source snapshot, not every device, network or deployment.

## Passed

- macOS arm64: `go test -count=1 -race -json ./...` passed both Go packages; 47 passing test events including subtests, no failures.
- `go vet ./...` passed.
- Linux amd64 and arm64 service binaries cross-built with `CGO_ENABLED=0`.
- Linux arm64 Go test executables ran in isolated containers with no network and all capabilities dropped: VPN package 26 top-level tests passed; CLI package 10 top-level tests passed, including Linux-specific BPF encoding. No race detector in these cross-compiled Linux test executables.
- Independent Python 3.11 / cryptography wire tests: 6 passed.
- Android JDK 21 / SDK 36: all 55 JVM tests passed; zero failures/errors/skips.
- Android debug APK and instrumentation APK built successfully.
- Android lint: zero errors, four warnings.
- Isolated Linux-container end-to-end test: authenticated ICMP + real TUN/NAT; exact 65536-byte TCP upload and download, 10 exact UDP datagrams, controlled DNS response, target source matching server NAT identity. Reference client created its ping socket as UID 65534 with zero effective capabilities. A direct-eth0 rejection rule prevented target bypass. Test containers and temporary network were removed by the harness.

The public snapshot replaces one private-LAN address in a destination-policy test with a generic RFC1918 address and fixes the high-latency test Dockerfile's self-referential base image to use the basic integration image. Application/transport implementation files otherwise retain the original project's bytes. Operational deployment wrappers and private records are not included.

## Not rerun for this publication

- Android emulator instrumentation execution (the instrumentation APK was built, not executed).
- Public-WAN or physical-phone Wi-Fi/cellular acceptance.
- High-latency/loss performance matrix and optional split-TCP runtime acceptance.
- Reproduction of third-party Docker image builds from the Dockerfiles: the E2E reused the locally available test image.
- Independent cryptographic audit, OEM compatibility certification or production-readiness review.

Generated binaries, APKs, raw test logs and deployment records are deliberately untracked and are not part of the public source publication.
