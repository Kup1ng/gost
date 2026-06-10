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

// NATDest is one (resolved IPv4) load-balancing destination of a NATForward,
// with its relative weight (>= 1). A forward with a single destination behaves
// exactly as before; two or more destinations enable weighted load-balancing.
type NATDest struct {
	IP     net.IP
	Port   int
	Weight int
}

// hostport returns the "ip:port" form.
func (d NATDest) hostport() string {
	return net.JoinHostPort(d.IP.String(), strconv.Itoa(d.Port))
}

// NATForward describes an in-kernel TCP/UDP port forward to be programmed as a
// netfilter DNAT rule when GOST runs in --NAT mode. With one Dest it is a plain
// DNAT; with several it is a per-connection weighted load-balancer. It is pure
// data and shared across platforms; the actual kernel programming lives in the
// platform-specific nat_linux.go / nat_other.go files.
type NATForward struct {
	Proto    string    // "tcp" or "udp"
	BindAddr string    // listen IP, empty means wildcard (all interfaces)
	LPort    int       // local listen port
	Dests    []NATDest // one or more weighted destinations
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

// single reports whether this forward has exactly one destination.
func (f NATForward) single() bool { return len(f.Dests) == 1 }

// totalWeight is the sum of destination weights (== nft `numgen mod N`).
func (f NATForward) totalWeight() int {
	n := 0
	for _, d := range f.Dests {
		n += d.Weight
	}
	return n
}

// destsLabel is a human-readable summary of the destinations, for logs.
func (f NATForward) destsLabel() string {
	if f.single() {
		return f.Dests[0].hostport()
	}
	parts := make([]string, len(f.Dests))
	for i, d := range f.Dests {
		parts[i] = fmt.Sprintf("%s(w%d)", d.hostport(), d.Weight)
	}
	return strings.Join(parts, ",") + " [weighted RR]"
}

// identity is the stable, exact identity of this forward; it feeds instanceHash
// (the per-instance table/chain name). It includes every destination AND weight
// so that changing any backend or weight yields a new table (idempotent replace)
// rather than silently reusing a stale one. For a single destination it is byte
// -identical to the original single-dest tag, so single-dest table names — and
// thus the proven cleanup path — are unchanged.
func (f NATForward) identity() string {
	if f.single() {
		d := f.Dests[0]
		return fmt.Sprintf("%s:%s:%s:%d->%s:%d", natTagPrefix, f.Proto, f.bindLabel(), f.LPort, d.IP.String(), d.Port)
	}
	parts := make([]string, len(f.Dests))
	for i, d := range f.Dests {
		parts[i] = fmt.Sprintf("%s:%d:%d", d.IP.String(), d.Port, d.Weight)
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s:%s:%s:%d->%s", natTagPrefix, f.Proto, f.bindLabel(), f.LPort, strings.Join(parts, ","))
}

// comment is the human-readable marker embedded in each rule. For a single
// destination it is the full proven form; for multiple it is the short listen
// identity (kept well under nft's 128-char comment limit; the backends are
// visible in the rule itself).
func (f NATForward) comment() string {
	if f.single() {
		d := f.Dests[0]
		return fmt.Sprintf("%s:%s:%s:%d->%s:%d", natTagPrefix, f.Proto, f.bindLabel(), f.LPort, d.IP.String(), d.Port)
	}
	return fmt.Sprintf("%s:%s:%s:%d", natTagPrefix, f.Proto, f.bindLabel(), f.LPort)
}

// instanceHash is a short, deterministic, collision-resistant id derived from
// the full set of forwards this process owns. Restarting with the same -L set
// yields the same hash (so programming is an idempotent replace), while any
// different set yields a different hash (so concurrent gost processes never
// collide). Used to name the per-instance nftables table / iptables chains.
func instanceHash(forwards []NATForward) string {
	ids := make([]string, 0, len(forwards))
	for _, f := range forwards {
		ids = append(ids, f.identity())
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, ";")))
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
		return NATForward{}, fmt.Errorf("-L %q has no destination; expected %s://[bind]:PORT/DESTIP:DESTPORT[:WEIGHT][,...]", serveNode, proto)
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

	// One or more weighted destinations. Each is resolved to a literal IPv4.
	parsed, err := ParseDestList(node.Remote)
	if err != nil {
		return NATForward{}, fmt.Errorf("-L %q: %v", serveNode, err)
	}
	dests := make([]NATDest, 0, len(parsed))
	for _, p := range parsed {
		ip, err := resolveNATDest(p.Host)
		if err != nil {
			return NATForward{}, fmt.Errorf("-L %q: %v", serveNode, err)
		}
		dests = append(dests, NATDest{IP: ip, Port: p.Port, Weight: p.Weight})
	}
	reduceNATWeights(dests)

	return NATForward{Proto: proto, BindAddr: bindAddr, LPort: lport, Dests: dests}, nil
}

// reduceNATWeights divides all weights by their GCD in place (e.g. 6:2 -> 3:1),
// keeping the nftables `numgen mod N` modulus and the conntrack-independent
// rotation state as small as possible. A no-op for one destination.
func reduceNATWeights(dests []NATDest) {
	if len(dests) < 2 {
		return
	}
	g := dests[0].Weight
	for _, d := range dests[1:] {
		g = gcdInt(g, d.Weight)
	}
	if g > 1 {
		for i := range dests {
			dests[i].Weight /= g
		}
	}
}

func gcdInt(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
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
