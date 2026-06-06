package gost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/go-log/log"
)

// NATForward describes a single in-kernel TCP/UDP port forward to be programmed
// as a netfilter DNAT rule when GOST runs in --NAT mode. It is pure data and is
// shared across platforms; the actual kernel programming lives in the
// platform-specific nat_linux.go / nat_other.go files.
type NATForward struct {
	Proto    string // "tcp" or "udp"
	BindAddr string // listen IP, empty means wildcard (all interfaces)
	LPort    int    // local listen port
	DestIP   net.IP // destination IP (already resolved to a literal IP)
	DestPort int    // destination port
}

// NATOptions holds the global, opt-in knobs for --NAT mode.
type NATOptions struct {
	Backend       string // "auto", "nftables" or "iptables"
	ConntrackMax  int    // 0 = use default floor; otherwise raise nf_conntrack_max to at least this
	NoSNAT        bool   // disable the scoped MASQUERADE (only for gateway/same-path topologies)
	NoForwardRule bool   // do not add the scoped FORWARD accept (filter table)
	AllowSSHPort  bool   // permit a -L listen port equal to 22 / the active SSH session port
	TuneTimeouts  bool   // additionally lower conntrack time_wait/fin_wait timeouts
}

// natTagPrefix marks every rule/comment GOST creates so the rescue cleanup can
// discover them without knowing the original ports.
const natTagPrefix = "gost-nat"

// natObjPrefix is the prefix for every nftables table / iptables chain GOST
// creates, so rescue cleanup can enumerate them by name.
const natObjPrefix = "gost_nat"

// wildcardLabel is the placeholder used in tags when -L binds all interfaces.
const wildcardLabel = "0.0.0.0"

// bindLabel returns the bind address as it appears in a rule tag.
func (f NATForward) bindLabel() string {
	if f.BindAddr == "" {
		return wildcardLabel
	}
	return f.BindAddr
}

// Wildcard reports whether the forward listens on all interfaces.
func (f NATForward) Wildcard() bool {
	return f.BindAddr == "" || f.BindAddr == wildcardLabel || f.BindAddr == "::"
}

// dest returns the "ip:port" destination string.
func (f NATForward) dest() string {
	return net.JoinHostPort(f.DestIP.String(), fmt.Sprintf("%d", f.DestPort))
}

// tag is the self-describing, exact identity of this forward, embedded in every
// rule comment and used for scoped cleanup. It is stable across restarts of the
// same forward (no PID, no random component) so a crashed instance's rules can
// be recognised and removed on the next startup.
//
//	gost-nat:<proto>:<bindaddr>:<lport>-><destip>:<dport>
func (f NATForward) tag() string {
	return fmt.Sprintf("%s:%s:%s:%d->%s:%d",
		natTagPrefix, f.Proto, f.bindLabel(), f.LPort, f.DestIP.String(), f.DestPort)
}

// instanceHash is a short, deterministic, collision-resistant id derived from
// the full set of forwards this process owns. Restarting with the same -L set
// yields the same hash (so programming is an idempotent replace), while any
// different set yields a different hash (so concurrent gost processes never
// collide). Used to name the per-instance nftables table / iptables chains.
func instanceHash(forwards []NATForward) string {
	tags := make([]string, 0, len(forwards))
	for _, f := range forwards {
		tags = append(tags, f.tag())
	}
	sort.Strings(tags)
	sum := sha256.Sum256([]byte(strings.Join(tags, ";")))
	return hex.EncodeToString(sum[:])[:8]
}

// ParseNATForward parses a single -L serve-node string into a NATForward,
// enforcing NAT-mode constraints: tcp/udp only, exactly one destination, and
// literal-or-resolved IPv4 addresses. The SSH-port guard is applied separately
// by the caller via IsProtectedSSHPort (it is a policy decision, not parsing).
func ParseNATForward(serveNode string) (NATForward, error) {
	node, err := ParseNode(serveNode)
	if err != nil {
		return NATForward{}, err
	}

	// Gate on the scheme/protocol, not the transport: GOST's ParseNode defaults
	// unknown transports to "tcp", so checking transport would let http://,
	// socks://, and bare :port forms through. NAT mode requires an explicit
	// tcp:// or udp:// raw forward.
	proto := node.Protocol
	if proto != "tcp" && proto != "udp" {
		scheme := proto
		if scheme == "" {
			scheme = "(none)"
		}
		return NATForward{}, fmt.Errorf("-L %q has scheme %q; NAT mode supports only explicit tcp:// or udp:// forwards", serveNode, scheme)
	}
	if node.Remote == "" {
		return NATForward{}, fmt.Errorf("-L %q has no destination; expected %s://[bind]:PORT/DESTIP:DESTPORT", serveNode, proto)
	}
	if strings.Contains(node.Remote, ",") {
		return NATForward{}, fmt.Errorf("-L %q has multiple destinations; NAT mode supports exactly one DESTIP:PORT per -L "+
			"(split into separate -L rules / services)", serveNode)
	}

	bindHost, bindPortStr, err := net.SplitHostPort(node.Addr)
	if err != nil {
		return NATForward{}, fmt.Errorf("bad listen address in -L %q: %v", serveNode, err)
	}
	lport, err := strconv.Atoi(bindPortStr)
	if err != nil || lport <= 0 || lport > 65535 {
		return NATForward{}, fmt.Errorf("bad listen port in -L %q", serveNode)
	}
	bindAddr, err := normalizeNATBindAddr(bindHost)
	if err != nil {
		return NATForward{}, fmt.Errorf("-L %q: %v", serveNode, err)
	}

	destHost, destPortStr, err := net.SplitHostPort(node.Remote)
	if err != nil {
		return NATForward{}, fmt.Errorf("bad destination in -L %q: %v", serveNode, err)
	}
	dport, err := strconv.Atoi(destPortStr)
	if err != nil || dport <= 0 || dport > 65535 {
		return NATForward{}, fmt.Errorf("bad destination port in -L %q", serveNode)
	}
	destIP, err := resolveNATDest(destHost)
	if err != nil {
		return NATForward{}, fmt.Errorf("-L %q: %v", serveNode, err)
	}

	return NATForward{Proto: proto, BindAddr: bindAddr, LPort: lport, DestIP: destIP, DestPort: dport}, nil
}

// normalizeNATBindAddr returns "" for a wildcard bind, or a validated literal
// IPv4 for a specific bind. IPv6 binds are rejected in v1.
func normalizeNATBindAddr(host string) (string, error) {
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "", nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("listen address %q must be a literal IP (or empty for all interfaces)", host)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("listen address %q is IPv6; --NAT currently supports IPv4 only", host)
	}
	return ip.To4().String(), nil
}

// resolveNATDest turns a destination host into a single literal IPv4. Hostnames
// are resolved once, here; the result is static (not re-resolved at runtime).
func resolveNATDest(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, fmt.Errorf("destination %q is IPv6; --NAT currently supports IPv4 only", host)
		}
		return ip.To4(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve destination %q: %v", host, err)
	}
	var v4 []net.IP
	for _, ip := range ips {
		if v := ip.To4(); v != nil {
			v4 = append(v4, v)
		}
	}
	if len(v4) == 0 {
		return nil, fmt.Errorf("destination %q has no IPv4 address", host)
	}
	if len(v4) > 1 {
		log.Logf("[nat] WARNING: %q resolves to %d IPv4 addresses; using %s (resolved once, not re-resolved at runtime)",
			host, len(v4), v4[0])
	}
	return v4[0], nil
}

// IsProtectedSSHPort reports whether lport is an SSH port we must refuse to
// forward (port 22, or the server port of the active SSH session), with a
// human-readable reason. Override via --nat-allow-ssh-port.
func IsProtectedSSHPort(lport int) (bool, string) {
	if lport == 22 {
		return true, "it is the default SSH port (22)"
	}
	if p := SSHServerPort(); p != 0 && lport == p {
		return true, fmt.Sprintf("it is the server port of your active SSH session (%d)", p)
	}
	return false, ""
}

// SSHServerPort returns the local sshd port of the current SSH session, parsed
// from $SSH_CONNECTION ("clientIP clientPort serverIP serverPort"), or 0.
func SSHServerPort() int {
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) >= 4 {
		if p, err := strconv.Atoi(f[3]); err == nil {
			return p
		}
	}
	return 0
}
