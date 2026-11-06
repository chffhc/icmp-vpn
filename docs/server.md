# Linux server (development MVP)

The wire/security contract is `../PROTOCOL.md`. This server is Go standard-library-only, IPv4-only, single-client, and **does not configure networking** when it starts. It requires an existing persistent TUN named `icmpvpn0`, address `10.77.0.1/24`, UP, MTU 1200, plus Linux raw ICMP capability. The optional interface flag is useful in isolated tests; its address/MTU contract remains fixed.

## Build and tests

From `server/`:

```sh
go test -race -v ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/icmpvpn-linux-amd64 ./cmd/icmpvpn
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/icmpvpn-linux-arm64 ./cmd/icmpvpn
```

`vpn/vector_test.go` reads `../../tests/vectors.json`: independent Python cryptography fixtures are intentionally required. Unit tests are not a live TUN/ICMP/network gate. A macOS build supports key generation and protocol tests, but `serve` refuses non-Linux hosts.

## Key and restart-safe session ledger

Use a private root-owned directory. Never pass the key bytes in arguments or environment. The PSK file contains **32 raw random bytes**, not a hex text file. Android uses their 64-character hexadecimal representation; provision it privately, not through logs/screenshots.

```sh
sudo install -d -m 0700 /etc/icmpvpn
sudo ./server/dist/icmpvpn-linux-arm64 keygen --key-file /etc/icmpvpn/key
```

`keygen` creates a mode-0600 file with exclusive creation and fsync; it refuses existing files or symlinks. `serve` rejects wrong file size, nonregular files, symlinks, or permissions other than 0600. Keep all parent directories trusted: the tools do not claim to secure an attacker-writable directory hierarchy.

Each first authenticated HELLO reserves its nonzero session ID in a **durable mode-0600 journal, fsynced before the first reply is sealed**. Default: `<key-file>.sessions`; override with `--state-file`. The journal has a PSK hash binding, HMAC-authenticated fixed-width ID records (detecting bit corruption), and an exclusive nonblocking flock; a second server using the same journal fails. IDs are retained permanently, not evicted or reset on CLOSE, idle timeout, restart, or repeated HELLO. Repeated HELLO for the active session advances the existing outbound sequence. After restart, even a correctly authenticated old HELLO is rejected; a fresh random client session connects.

Default lifetime capacity is 4096 session IDs; `--max-sessions` accepts 1..65536. Full storage refuses new sessions rather than reusing nonces. Partial/truncated records, wrong key binding, or write/fsync errors fail closed. **Never delete/restore an older journal while retaining the same PSK, never run two journal paths with the same PSK, and never clone the key to another live server.** When capacity is exhausted, stop the server, generate a new key under a new path (and consequently a new journal), reprovision Android, then restart. Safely retain or archive the old key/journal as a pair; backups must not enable ledger rollback. File permissions and fsync do not defend against a malicious root/storage rollback.

## Explicit host setup and rollback

Only run on your own/authorized server, after reviewing existing routes/firewall rules. Root (or equivalent capabilities) is required. `CAP_NET_RAW` opens the raw ICMP socket; `CAP_NET_ADMIN` attaches TUN. The server itself does not need a public TCP/UDP listening port.

1. Check the egress interface and existing rules using `ip route`, `ip address`, `iptables-save`, and `sysctl net.ipv4.ip_forward`.
2. If forwarding is disabled, explicitly enable it yourself. Save its previous value and restore it yourself only after considering other forwarding workloads:

   ```sh
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

3. Install only the dedicated TUN and forwarding/NAT chains. Replace `eth0` with the inspected egress interface:

   ```sh
   sudo bash server/scripts/setup-network.sh up eth0
   ```

   The script refuses existing `icmpvpn0`, `IVP1_FORWARD`, `IVP1_NAT`, or ownership state. It installs an interface-scoped forwarding hook, allows source `10.77.0.2/32` outbound on the named egress, allows conntrack-established return traffic to `10.77.0.2/32`, and drops other traffic through that dedicated interface. NAT is limited to that client source and egress. It attempts rollback on setup failure and logs errors. It **does not change sysctls**, flush unrelated chains, or change a default route. This MVP uses iptables; adapt deliberately if your host is managed by nftables/firewalld or another firewall manager. Do not run concurrent network setup tools against these dedicated names.

4. Explicitly allow inbound IPv4 echo requests to the server's literal public IPv4 in the existing host/cloud firewall. The script does not override ingress policy. Do not silently change `icmp_echo_ignore_all`: normal kernel echo replies can coexist and clients reject their wrong-direction authentication.
5. Start the server in foreground/supervision:

   ```sh
   sudo ./server/dist/icmpvpn-linux-arm64 serve \
     --key-file /etc/icmpvpn/key --tun icmpvpn0 --listen 0.0.0.0
   ```

   `--listen` may be a specific literal local IPv4. `--state-file /private/path/key.sessions` must be unique for this key and retained. `--max-sessions 4096` is the default. SIGINT/SIGTERM closes pollable raw/TUN file descriptors, joins reader goroutines, and prints final counters. Startup, raw socket/TUN read/write, and durable storage errors remain visible on stderr. Aggregate authenticated rejects and malformed ICMP counters are emitted every 30 seconds to avoid attacker-controlled log flooding.

6. Stop the server first; remove only its setup:

   ```sh
   sudo bash server/scripts/setup-network.sh down
   ```

   This removes exact dedicated hooks/chains, the owned persistent TUN, and `/run/icmpvpn-setup.state`. It never removes the PSK/journal. Review reported errors after a partially failed setup/rollback; inspect dedicated rules before manual cleanup. Forwarding remains as you explicitly configured it; restore only if appropriate for the host.

## Library API for integration tests

Module: `icmpvpn/server`, package: `icmpvpn/server/vpn`.

- `Seal(psk []byte, direction Direction, Message) ([]byte,error)` and `Open(...) (Message,error)` implement IVP1 AES-256-GCM, HMAC-derived session/direction keys, authenticated headers, exact lengths and direction-specific control semantics. `Message{SessionID, Sequence, Kind, Payload}`; `ClientToServer`/`ServerToClient`; `Poll`/`IP`/`Hello`/`Close`. Callers of `Seal` own nonce uniqueness.
- `NewEngine(psk, Options{Store, QueueLimit, MaxSessions}) (*Engine,error)`; `Handle(source netip.Addr, frame []byte, now time.Time) (Result,error)`. `Result.Reply` is the response frame; `Result.Upstream` is a validated IPv4 packet to write to TUN before sending the reply. Engine methods are mutex-protected.
- `Enqueue(packet, now) error` validates the destination and copies a TUN read into the bounded downstream queue; `Tick(now)` expires idle state; `Stats()` returns counters and current bounded queue/activity.
- `OpenFileStore(path, psk, capacity)` provides the runtime durable reservation store, with `Close()`. `NewMemoryStore(capacity)` is only for isolated tests; never use it for a restarting server with a persistent PSK.
- `ParseRawEcho([]byte) (Echo,error)` handles variable outer IHL, exact outer length, fragmentation and actual ICMP checksum. `Echo{Source,Identifier,Sequence,Payload}`; `BuildEcho(type,id,seq,payload)` computes checksum and mirrors received identifier/sequence. Ping datagram clients receive ICMP-only headers, unlike the raw server.
- `ValidateIPv4(packet, endpoint, source)` validates IPv4 version/IHL/total length/source-or-destination and rejects reserved/MF/offset fragments. DF and IPv4 header options are allowed. The kernel validates inner checksums, not this boundary checker (TUN reads may involve offload). Max plaintext is 1200; max ICMP datagram 1248.
- `ReplayWindow.Accept(sequence)` uses the bounded reorder window defined in the current implementation. Only call it after authentication and complete semantic validation.


## Examples and optional acceleration

`deploy/` contains systemd examples, not a universal installer. Adapt the egress interface (`ens5` in the network unit), executable paths and permissions to the inspected host. Optional `tcpaccel` experiments additionally depend on kernel NFQUEUE/BPF and congestion-control support; review the scripts and flags before enabling them. Publishing does not install or enable any service.

## Evidence

See `testing.md` and `verification.md` for testing levels and checks rerun for this public snapshot. No production-readiness or independent security-audit claim is made.
