gost - GO Simple Tunnel
======
 
### A simple security tunnel written in Golang

[![GoDoc](https://godoc.org/github.com/ginuerzh/gost?status.svg)](https://godoc.org/github.com/ginuerzh/gost)
[![Go Report Card](https://goreportcard.com/badge/github.com/ginuerzh/gost)](https://goreportcard.com/report/github.com/ginuerzh/gost)
[![codecov](https://codecov.io/gh/ginuerzh/gost/branch/master/graphs/badge.svg)](https://codecov.io/gh/ginuerzh/gost/branch/master)
[![GitHub release](https://img.shields.io/github/release/ginuerzh/gost.svg)](https://github.com/ginuerzh/gost/releases/latest)
[![Docker](https://img.shields.io/docker/pulls/ginuerzh/gost.svg)](https://hub.docker.com/r/ginuerzh/gost/)
[![gost](https://snapcraft.io/gost/badge.svg)](https://snapcraft.io/gost)
 
Features
------
* Listening on multiple ports
* Multi-level forward proxy - proxy chain
* Standard HTTP/HTTPS/HTTP2/SOCKS4(A)/SOCKS5 proxy protocols support
* [Probing resistance](https://v2.gost.run/en/probe_resist/) support for web proxy
* [Support multiple tunnel types](https://v2.gost.run/en/configuration/)
* [TLS encryption via negotiation support for SOCKS5 proxy](https://v2.gost.run/en/socks/)
* [Tunnel UDP over TCP](https://v2.gost.run/en/socks/)
* [TCP/UDP Transparent proxy](https://v2.gost.run/en/redirect/)
* [Local/remote TCP/UDP port forwarding](https://v2.gost.run/en/port-forwarding/)
* Kernel NAT forwarding mode (`--NAT`, in-kernel DNAT — see below)
* [Shadowsocks protocol](https://v2.gost.run/en/ss/)
* [SNI proxy](https://v2.gost.run/en/sni/)
* [Permission control](https://v2.gost.run/en/permission/)
* [Load balancing](https://v2.gost.run/en/load-balancing/)
* [Routing control](https://v2.gost.run/en/bypass/)
* DNS [resolver](https://v2.gost.run/resolver/) and [proxy](https://v2.gost.run/dns/)
* [TUN/TAP device](https://v2.gost.run/en/tuntap/)

Wiki: [v2.gost.run](https://v2.gost.run/en/)

Telegram group: <https://t.me/gogost>

Google group: <https://groups.google.com/d/forum/go-gost>

GOST v3: <https://gost.run>

Installation
------

#### Binary files

<https://github.com/ginuerzh/gost/releases>

#### From source

```bash
git clone https://github.com/ginuerzh/gost.git
cd gost/cmd/gost
go build
```

#### Docker

```bash
docker run --rm ginuerzh/gost -V
```

#### Homebrew

```bash
brew install gost
```

#### Ubuntu store

```bash
sudo snap install core
sudo snap install gost
```

Getting started
------

#### No forward proxy

<img src="https://ginuerzh.github.io/images/gost_01.png" />

* Standard HTTP/SOCKS5 proxy

```bash
gost -L=:8080
```

* Proxy authentication

```bash
gost -L=admin:123456@localhost:8080
```

* Multiple sets of authentication information

```bash
gost -L=localhost:8080?secrets=secrets.txt
```

The secrets parameter allows you to set multiple authentication information for HTTP/SOCKS5 proxies, the format is:

```plain
# username password

test001 123456
test002 12345678
```

* Listen on multiple ports

```bash
gost -L=http2://:443 -L=socks5://:1080 -L=ss://aes-128-cfb:123456@:8338
```

#### Forward proxy

<img src="https://ginuerzh.github.io/images/gost_02.png" />

```bash
gost -L=:8080 -F=192.168.1.1:8081
```

* Forward proxy authentication

```bash
gost -L=:8080 -F=http://admin:123456@192.168.1.1:8081
```

#### Multi-level forward proxy

<img src="https://ginuerzh.github.io/images/gost_03.png" />

```bash
gost -L=:8080 -F=quic://192.168.1.1:6121 -F=socks5+wss://192.168.1.2:1080 -F=http2://192.168.1.3:443 ... -F=a.b.c.d:NNNN
```

Gost forwards the request to a.b.c.d:NNNN through the proxy chain in the order set by -F, 
each forward proxy can be any HTTP/HTTPS/HTTP2/SOCKS4/SOCKS5/Shadowsocks type.

#### Local TCP port forwarding

```bash
gost -L=tcp://:2222/192.168.1.1:22 [-F=...]
```

The data on the local TCP port 2222 is forwarded to 192.168.1.1:22 (through the proxy chain). If the last node of the chain (the last -F parameter) is a SSH forwad tunnel, then gost will use the local port forwarding function of SSH directly:

```bash
gost -L=tcp://:2222/192.168.1.1:22 -F forward+ssh://:2222
```

#### Local UDP port forwarding

```bash
gost -L=udp://:5353/192.168.1.1:53?ttl=60 [-F=...]
```

The data on the local UDP port 5353 is forwarded to 192.168.1.1:53 (through the proxy chain). 
Each forwarding channel has a timeout period. When this time is exceeded and there is no data interaction during this time period, the channel will be closed. The timeout value can be set by the `ttl` parameter. The default value is 60 seconds.

**NOTE:** When forwarding UDP data, if there is a proxy chain, the end of the chain (the last -F parameter) must be gost SOCKS5 proxy, gost will use UDP-over-TCP to forward data.

#### Kernel NAT forwarding mode (`--NAT`)

> Linux only. Requires root (or `CAP_NET_ADMIN`). Opt-in; never auto-enabled.

By default gost forwards `-L` traffic in **userspace** (it accepts the connection, dials the
destination, and copies the bytes). The `--NAT` flag instead programs each forward as an
**in-kernel DNAT rule** (netfilter + conntrack). After the first packet, all traffic is translated
and forwarded entirely in the kernel — gost is never in the data path — giving near-zero
per-connection CPU/memory and much higher throughput.

```bash
sudo gost --NAT -L=tcp://:8080/1.2.3.4:80 -L=udp://:5353/1.2.3.4:53
```

`--NAT` applies to **every** `-L` rule in the process. When `--NAT` is absent, everything behaves
exactly like stock gost.

**Constraints**

* TCP and UDP only; IPv4 only. Each `-L` is an explicit `tcp://` or `udp://` forward to one or more `DESTIP:DESTPORT` targets (a hostname is resolved once at startup and pinned).
* `--NAT` is **incompatible with `-F`** (SOCKS5 chaining); combining them fails at startup. Chaining only works in userspace mode.
* Requires root / `CAP_NET_ADMIN` and a working `nft` or `iptables` (see install below).

**Load balancing across multiple destinations.** A `-L` may list several
comma-separated destinations, each `IP:PORT` with an optional `:WEIGHT` suffix
(a positive integer; default 1). New connections are distributed across the
backends **per connection** — every packet of a connection always goes to the
same backend it was assigned at connection start (conntrack pins the flow), so a
connection is never split. Works for both `tcp` and `udp`, in both modes:

```bash
# equal split across three backends
sudo gost --NAT -L=tcp://:8001/10.0.0.1:80,10.0.0.2:80,10.0.0.3:80
# weighted 3:1 — ~3 of every 4 new connections to the first backend
sudo gost --NAT -L=tcp://:8001/10.0.0.1:80:3,10.0.0.2:80:1
# also works in userspace mode (omit --NAT)
gost -L=tcp://:8001/10.0.0.1:80:3,10.0.0.2:80:1
```

Distribution differs slightly by mode:

* **Userspace mode** does true **weighted round-robin** (strict rotation respecting weights).
* **`--NAT` mode** uses the kernel: the **nftables** backend does strict weighted round-robin (`numgen inc`); the **iptables** fallback does **weighted-random** (the `statistic` module has no strict weighted mode). Both converge to the configured ratio.

There is no health checking in either mode — backends are assumed up and traffic
is distributed blindly per the weights. A malformed list (missing port, bad
weight, etc.) is a clear startup error.

**Backends.** gost prefers **nftables** (its own table `gost_nat_<id>`) and falls back to
**iptables** (its own `GOST_*` chains). Force one with `--nat-backend=nftables|iptables` (default
`auto`). If neither tool is usable, gost refuses to start — it will **not** silently fall back to
userspace forwarding. Every rule is scoped exactly to its `-L` port/target (never a broad or
catch-all rule), so SSH and other traffic are never captured, and multiple `--NAT` services can
run on one host without colliding.

**Kernel tuning (global, raise-only).** In NAT mode gost raises — and never lowers —
`net.ipv4.ip_forward=1` (needed to forward to another host), `nf_conntrack_max` (floor 262144,
clamped to ~10% of RAM; override with `--nat-conntrack-max N`), and the conntrack hash size. These
are host-wide and persist until reboot (lowering them could break live connections or a sibling
service). conntrack timeouts are left alone unless you pass `--nat-tune-timeouts`.

**Install gost as a system command** (so `--nat-cleanup` and the systemd unit use the same binary).

Prebuilt Linux binaries (amd64/arm64) are published on the Releases page as
`.tar.gz` archives with `.sha256` checksums:

```bash
curl -fL https://github.com/Kup1ng/gost/releases/latest/download/gost-linux-amd64.tar.gz -o gost.tar.gz
tar -xzf gost.tar.gz                      # -> gost
sudo install -m 0755 gost /usr/local/bin/gost
gost -V
# arm64: swap gost-linux-amd64.tar.gz -> gost-linux-arm64.tar.gz
```

Or build from source:

```bash
cd gost/cmd/gost && go build
sudo install -m 0755 gost /usr/local/bin/gost
```

**Install a netfilter tool** (whichever your host is missing — gost only needs one):

```bash
sudo apt update && sudo apt install -y nftables   # preferred
# or
sudo apt update && sudo apt install -y iptables
```

Inspect the rules gost created:

```bash
sudo nft list ruleset | grep -A 20 gost_nat      # nftables backend
sudo iptables -t nat -S | grep GOST              # iptables backend
```

**Cleanup & safety.** gost removes its own rules (and flushes the matching conntrack entries) on
normal stop and on `SIGINT`/`SIGTERM` (Ctrl-C, `systemctl stop`). To cover crashes:

* On startup gost first clears any stale rules left by a previous crashed run of the **same** forward set (programming is an idempotent replace).
* Runtime rules are never persisted, so a reboot clears them.
* The rescue command removes **all** gost-created NAT rules if anything is ever stranded:

  ```bash
  sudo gost --nat-cleanup
  ```

  Scoped to specific forwards (used by the systemd unit below):

  ```bash
  sudo gost --nat-cleanup -L=tcp://:8080/1.2.3.4:80
  ```

**systemd** (recommended for production). `ExecStopPost` is a second cleanup layer that runs even
after a crash. The `-L` value contains `:` and `/`, so carry it via a per-instance
`EnvironmentFile`:

```ini
# /etc/systemd/system/gost-nat@.service
[Unit]
Description=gost NAT forward %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/gost-nat/%i.env          # contains e.g.: GOST_L=tcp://:8080/1.2.3.4:80
ExecStart=/usr/local/bin/gost --NAT -L=${GOST_L}
ExecStopPost=/usr/local/bin/gost --nat-cleanup -L=${GOST_L}
Restart=on-failure
RestartSec=2
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /etc/gost-nat
echo 'GOST_L=tcp://:8080/1.2.3.4:80' | sudo tee /etc/gost-nat/web.env
sudo systemctl enable --now gost-nat@web
```

**Limitations.** Multiple destinations are load-balanced per-connection (weighted; see above) with
no health checking; a hostname destination is
resolved once (restart to follow DNS changes); the destination sees the gost host's IP, not the
original client (MASQUERADE — disable with `--nat-no-snat` only when gost is on the return path);
on a host with a restrictive firewall in another table you may still need to allow the port there
(gost adds a scoped FORWARD accept by default — disable with `--nat-no-forward-rule`); forwarding
the SSH port is refused unless you pass `--nat-allow-ssh-port`.

#### Remote TCP port forwarding

```bash
gost -L=rtcp://:2222/192.168.1.1:22 [-F=... -F=socks5://172.24.10.1:1080]
```

The data on 172.24.10.1:2222 is forwarded to 192.168.1.1:22 (through the proxy chain). If the last node of the chain (the last -F parameter) is a SSH tunnel, then gost will use the remote port forwarding function of SSH directly:

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F forward+ssh://:2222
```

#### Remote UDP port forwarding

```bash
gost -L=rudp://:5353/192.168.1.1:53?ttl=60 [-F=... -F=socks5://172.24.10.1:1080]
```

The data on 172.24.10.1:5353 is forwarded to 192.168.1.1:53 (through the proxy chain).
Each forwarding channel has a timeout period. When this time is exceeded and there is no data interaction during this time period, the channel will be closed. The timeout value can be set by the `ttl` parameter. The default value is 60 seconds.

**NOTE:** When forwarding UDP data, if there is a proxy chain, the end of the chain (the last -F parameter) must be gost SOCKS5 proxy, gost will use UDP-over-TCP to forward data.

#### HTTP2

Gost HTTP2 supports two modes:

* As a standard HTTP2 proxy, and backwards-compatible with the HTTPS proxy.

* As a transport tunnel.

##### Standard proxy

Server:

```bash
gost -L=http2://:443
```

Client:

```bash
gost -L=:8080 -F=http2://server_ip:443?ping=30
```

##### Tunnel 

Server:

```bash
gost -L=h2://:443
```

Client:

```bash
gost -L=:8080 -F=h2://server_ip:443
```

#### QUIC

Support for QUIC is based on library [quic-go](https://github.com/quic-go/quic-go).

Server:

```bash
gost -L=quic://:6121
```

Client:

```bash
gost -L=:8080 -F=quic://server_ip:6121
```

**NOTE:** QUIC node can only be used as the first node of the proxy chain.

#### KCP
Support for KCP is based on libraries [kcp-go](https://github.com/xtaci/kcp-go) and [kcptun](https://github.com/xtaci/kcptun).

Server:

```bash
gost -L=kcp://:8388
```

Client:

```bash
gost -L=:8080 -F=kcp://server_ip:8388
```

Gost will automatically load kcp.json configuration file from current working directory if exists, 
or you can use the parameter to specify the path to the file.

```bash
gost -L=kcp://:8388?c=/path/to/conf/file
```

**NOTE:** KCP node can only be used as the first node of the proxy chain.

#### SSH

Gost SSH supports two modes:

* As a forward tunnel, used by local/remote TCP port forwarding.

* As a transport tunnel.


##### Forward tunnel

Server:

```bash
gost -L=forward+ssh://:2222
```

Client:

```bash
gost -L=rtcp://:1222/:22 -F=forward+ssh://server_ip:2222
```

##### Transport tunnel
Server:

```bash
gost -L=ssh://:2222
```
Client:

```bash
gost -L=:8080 -F=ssh://server_ip:2222?ping=60
```

The client supports the ping parameter to enable heartbeat detection (which is disabled by default). Parameter value represents heartbeat interval seconds.

#### Transparent proxy
Iptables-based transparent proxy

```bash
gost -L=redirect://:12345 -F=http2://server_ip:443
```


#### obfs4
Contributed by [@isofew](https://github.com/isofew).

Server:

```bash
gost -L=obfs4://:443
```

When the server is running normally, the console prints out the connection address for the client to use:

```bash
obfs4://:443/?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0
```

Client:

```bash
gost -L=:8888 -F='obfs4://server_ip:443?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0'
```

Encryption Mechanism
------

#### HTTP

For HTTP, you can use TLS to encrypt the entire communication process, the HTTPS proxy:

Server:

```bash
gost -L=http+tls://:443
```

Client:

```bash
gost -L=:8080 -F=http+tls://server_ip:443
```

#### HTTP2

Gost HTTP2 proxy mode only supports the use of TLS encrypted HTTP2 protocol, does not support plaintext HTTP2.

Gost HTTP2 tunnel mode supports both encryption (h2) and plaintext (h2c) modes.

#### SOCKS5

Gost supports the standard SOCKS5 protocol methods: no-auth (0x00) and user/pass (0x02), 
and extends two methods for data encryption: tls(0x80) and tls-auth(0x82).

Server:

```bash
gost -L=socks://:1080
```

Client:

```bash
gost -L=:8080 -F=socks://server_ip:1080
```

If both ends are gosts (as example above), the data transfer will be encrypted (using tls or tls-auth). 
Otherwise, use standard SOCKS5 for communication (no-auth or user/pass).

#### Shadowsocks
Support for shadowsocks is based on library [shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go).

Server:

```bash
gost -L=ss://aes-128-cfb:123456@:8338
```

Client:

```bash
gost -L=:8080 -F=ss://aes-128-cfb:123456@server_ip:8338
```

##### Shadowsocks UDP relay

Currently, only the server supports UDP Relay.

Server:

```bash
gost -L=ssu://aes-128-cfb:123456@:8338
```

#### TLS
There is built-in TLS certificate in gost, if you need to use other TLS certificate, there are two ways:

* Place two files cert.pem (public key) and key.pem (private key) in the current working directory, gost will automatically load them.

* Use the parameter to specify the path to the certificate file:

```bash
gost -L="http2://:443?cert=/path/to/my/cert/file&key=/path/to/my/key/file"
```

Client can specify `secure` parameter to perform server's certificate chain and host name verification:

```bash
gost -L=:8080 -F="http2://server_domain_name:443?secure=true"
```

Client can specify a CA certificate to allow for [Certificate Pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning):

```bash
gost -L=:8080 -F="http2://:443?ca=ca.pem"
```

Certificate Pinning is contributed by [@sheerun](https://github.com/sheerun).
