//go:build linux
// +build linux

package gost

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-log/log"
)

// natBackend is implemented by the nftables and iptables programmers. Exactly
// one backend is selected per process and used for both programming and
// cleanup; backends are never mixed for a single instance.
type natBackend interface {
	// name returns a short identifier ("nftables"/"iptables").
	name() string
	// available reports whether this backend can be used on this host.
	available() bool
	// program installs the DNAT/SNAT/FORWARD rules for forwards. It must be
	// idempotent: any pre-existing rules for this exact instance (e.g. left by
	// a crashed previous run with the same -L set) are removed first.
	program(forwards []NATForward, opts NATOptions) error
	// cleanup removes the rules belonging to exactly this instance (the set of
	// forwards). Deleting absent rules is a no-op.
	cleanup(forwards []NATForward, opts NATOptions) error
	// rescue removes every rule/table/chain GOST ever created on this host,
	// across all instances (the `gost --nat-cleanup` with no -L rescue path).
	rescue() error
}

// NATManager programs and tears down kernel NAT rules for a set of forwards.
type NATManager struct {
	forwards []NATForward
	opts     NATOptions
	backend  natBackend
}

// NewNATManager creates a manager for the given forwards and options. Backend
// selection and privilege checks happen in Setup.
func NewNATManager(forwards []NATForward, opts NATOptions) *NATManager {
	return &NATManager{forwards: forwards, opts: opts}
}

// BackendName returns the selected backend name, or "" before Setup.
func (m *NATManager) BackendName() string {
	if m.backend == nil {
		return ""
	}
	return m.backend.name()
}

// Setup performs the preflight checks, raises kernel limits, selects a backend
// and programs the rules. On any error nothing of consequence is left behind
// (programming itself is idempotent and self-cleaning).
func (m *NATManager) Setup() error {
	if len(m.forwards) == 0 {
		return errors.New("--NAT: no TCP/UDP forwards to program")
	}
	if err := preflightPrivileges(); err != nil {
		return err
	}
	if err := ensureConntrackLoaded(); err != nil {
		return err
	}

	backend, err := SelectNATBackend(m.opts.Backend)
	if err != nil {
		return err
	}
	m.backend = backend
	log.Logf("[nat] backend: %s", backend.name())

	tuneConntrack(m.opts)
	if err := ensureIPForward(m.forwards); err != nil {
		// not fatal on its own, but very likely required; warn loudly.
		log.Logf("[nat] WARNING: could not enable ip_forward: %s", err)
	}

	if err := backend.program(m.forwards, m.opts); err != nil {
		// best-effort rollback of whatever this instance may have added.
		_ = backend.cleanup(m.forwards, m.opts)
		return fmt.Errorf("[nat] program rules: %w", err)
	}
	for _, f := range m.forwards {
		log.Logf("[nat] %s :%d -> %s (in-kernel DNAT)", f.Proto, f.LPort, f.destsLabel())
	}
	return nil
}

// Teardown removes this instance's rules and flushes the matching conntrack
// entries. It is best-effort and safe to call multiple times.
func (m *NATManager) Teardown() error {
	if m.backend == nil {
		return nil
	}
	var errs []string
	if err := m.backend.cleanup(m.forwards, m.opts); err != nil {
		errs = append(errs, err.Error())
	}
	flushConntrack(m.forwards)
	log.Log("[nat] cleanup done")
	if len(errs) > 0 {
		return fmt.Errorf("[nat] teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SelectNATBackend resolves the backend for the requested mode
// ("auto"/""/"nftables"/"iptables").
func SelectNATBackend(mode string) (natBackend, error) {
	nft := newNftBackend()
	ipt := newIptablesBackend()

	switch mode {
	case "nftables", "nft":
		if nft.available() {
			return nft, nil
		}
		return nil, errors.New("--NAT: nftables backend requested but the `nft` command is not usable")
	case "iptables":
		if ipt.available() {
			return ipt, nil
		}
		return nil, errors.New("--NAT: iptables backend requested but the `iptables` command is not usable")
	case "", "auto":
		if nft.available() {
			return nft, nil
		}
		if ipt.available() {
			return ipt, nil
		}
		return nil, errors.New("--NAT: no usable kernel NAT backend found (neither `nft` nor `iptables` is available). " +
			"Install one: `apt install nftables` or `apt install iptables`. " +
			"Refusing to fall back to userspace forwarding")
	default:
		return nil, fmt.Errorf("--NAT: unknown --nat-backend %q (want auto|nftables|iptables)", mode)
	}
}

// availableBackends returns every backend usable on this host. Used by the
// cleanup paths, which must scrub rules regardless of which backend a previous
// run used.
func availableBackends() []natBackend {
	var bs []natBackend
	if nft := newNftBackend(); nft.available() {
		bs = append(bs, nft)
	}
	if ipt := newIptablesBackend(); ipt.available() {
		bs = append(bs, ipt)
	}
	return bs
}

// NATCleanup is the implementation of `gost --nat-cleanup`. With a non-empty
// forwards list it removes only those forwards' rules (used by the systemd
// ExecStopPost hook, scoped to one unit's -L). With an empty list it performs a
// host-wide rescue, removing every GOST-created NAT artifact. It scrubs every
// available backend, since a prior run may have used either.
func NATCleanup(forwards []NATForward, opts NATOptions) error {
	if err := preflightPrivileges(); err != nil {
		return err
	}
	backends := availableBackends()
	if len(backends) == 0 {
		return errors.New("--nat-cleanup: neither `nft` nor `iptables` is available, nothing to do")
	}
	var errs []string
	for _, b := range backends {
		if len(forwards) == 0 {
			if err := b.rescue(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s", b.name(), err))
			}
		} else {
			if err := b.cleanup(forwards, opts); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s", b.name(), err))
			}
		}
	}
	if len(forwards) > 0 {
		flushConntrack(forwards)
	}
	if len(errs) > 0 {
		return fmt.Errorf("--nat-cleanup: %s", strings.Join(errs, "; "))
	}
	log.Log("[nat] cleanup complete")
	return nil
}

// --- privilege preflight ---------------------------------------------------

const capNetAdmin = 12 // CAP_NET_ADMIN

// preflightPrivileges ensures the process can program netfilter and raise
// kernel limits, i.e. it is root or holds effective CAP_NET_ADMIN.
func preflightPrivileges() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if hasEffectiveCapNetAdmin() {
		return nil
	}
	return errors.New("--NAT requires root or CAP_NET_ADMIN to program DNAT/conntrack rules and raise nf_conntrack limits; " +
		"re-run with sudo, or grant the binary the capability " +
		"(`setcap cap_net_admin+ep /usr/local/bin/gost`, or systemd `AmbientCapabilities=CAP_NET_ADMIN`)")
}

// hasEffectiveCapNetAdmin parses /proc/self/status for the effective capability
// bitmask and tests the CAP_NET_ADMIN bit.
func hasEffectiveCapNetAdmin() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		field := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		v, err := strconv.ParseUint(field, 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<uint(capNetAdmin)) != 0
	}
	return false
}

// --- conntrack / ip_forward tuning (raise-only) ----------------------------

const (
	conntrackMaxPath  = "/proc/sys/net/netfilter/nf_conntrack_max"
	conntrackHashPath = "/sys/module/nf_conntrack/parameters/hashsize"
	ipForwardPath     = "/proc/sys/net/ipv4/ip_forward"

	// defaultConntrackFloor is the minimum nf_conntrack_max we ensure in NAT
	// mode (~90 MB of conntrack memory at ~360 bytes/entry).
	defaultConntrackFloor = 262144
	// bytesPerConntrackEntry is the rough kernel memory cost per entry, used to
	// clamp the table so we never plan to use more than ~10% of RAM.
	bytesPerConntrackEntry = 360
)

// ensureConntrackLoaded loads the nf_conntrack module if needed and verifies
// the conntrack sysctls are reachable.
func ensureConntrackLoaded() error {
	if _, err := os.Stat(conntrackMaxPath); err == nil {
		return nil
	}
	// best-effort: nf_conntrack is the unified module on modern kernels.
	_ = exec.Command("modprobe", "nf_conntrack").Run()
	if _, err := os.Stat(conntrackMaxPath); err != nil {
		return fmt.Errorf("--NAT: kernel connection tracking unavailable (%s missing); "+
			"this kernel does not support nf_conntrack", conntrackMaxPath)
	}
	return nil
}

// tuneConntrack raises nf_conntrack_max and hashsize, never lowering them.
// These are global, shared knobs; we ratchet up only so we can never shrink the
// table out from under live traffic (including the SSH session itself) or out
// from under a sibling gost --NAT instance. Failures are warnings, not fatal.
func tuneConntrack(opts NATOptions) {
	current := readSysctlInt(conntrackMaxPath)

	floor := defaultConntrackFloor
	if opts.ConntrackMax > 0 {
		floor = opts.ConntrackMax
	}
	if cap := memoryConntrackCap(); cap > 0 && floor > cap {
		log.Logf("[nat] clamping nf_conntrack_max target %d -> %d (memory limit)", floor, cap)
		floor = cap
	}

	target := floor
	if current > target {
		target = current // raise-only
	}
	if target > current {
		if err := writeSysctl(conntrackMaxPath, target); err != nil {
			log.Logf("[nat] WARNING: could not raise nf_conntrack_max: %s", err)
		} else {
			log.Logf("[nat] nf_conntrack_max %d -> %d", current, target)
		}
	}

	// hashsize: keep buckets at ~1/4 of max for short hash chains.
	wantHash := target / 4
	curHash := readSysctlInt(conntrackHashPath)
	if curHash > 0 && wantHash > curHash {
		if err := writeSysctl(conntrackHashPath, wantHash); err != nil {
			// EOPNOTSUPP/EPERM in containers / non-init netns — tolerate.
			log.Logf("[nat] note: could not raise nf_conntrack hashsize (%s); continuing", err)
		} else {
			log.Logf("[nat] nf_conntrack hashsize %d -> %d", curHash, wantHash)
		}
	}

	if opts.TuneTimeouts {
		// Only the safe-to-shorten timeouts; never the established timeout
		// (that can evict an idle SSH session's conntrack entry).
		for path, val := range map[string]int{
			"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait": 30,
			"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait":  30,
		} {
			if cur := readSysctlInt(path); cur > val {
				if err := writeSysctl(path, val); err != nil {
					log.Logf("[nat] note: could not set %s: %s", path, err)
				}
			}
		}
	}
}

// memoryConntrackCap returns the largest nf_conntrack_max we are willing to
// plan for (~10% of MemTotal), or 0 if it cannot be determined.
func memoryConntrackCap() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return int(kb * 1024 / 10 / bytesPerConntrackEntry)
	}
	return 0
}

// ensureIPForward enables net.ipv4.ip_forward when any forward targets a
// non-loopback (remote) destination. Raise-only: never reset to 0 on exit,
// since other forwarders/containers may depend on it.
func ensureIPForward(forwards []NATForward) error {
	needed := false
	for _, f := range forwards {
		for _, d := range f.Dests {
			if !d.IP.IsLoopback() {
				needed = true
				break
			}
		}
	}
	if !needed {
		return nil
	}
	if readSysctlInt(ipForwardPath) == 1 {
		return nil
	}
	if err := writeSysctl(ipForwardPath, 1); err != nil {
		return err
	}
	log.Log("[nat] enabled net.ipv4.ip_forward")
	return nil
}

// flushConntrack best-effort removes the conntrack entries for these forwards
// so already-established DNAT translations stop immediately (rule deletion
// alone leaves them alive until expiry). Uses the `conntrack` tool if present;
// otherwise it is skipped and the entries age out naturally.
func flushConntrack(forwards []NATForward) {
	bin, err := exec.LookPath("conntrack")
	if err != nil {
		if Debug {
			log.Log("[nat] conntrack tool not found; established flows will age out naturally")
		}
		return
	}
	for _, f := range forwards {
		// match by original-direction destination port (the -L listen port);
		// in NAT mode nothing else uses that port.
		_ = exec.Command(bin, "-D", "-p", f.Proto, "--dport", strconv.Itoa(f.LPort)).Run()
	}
}

// --- sysctl helpers --------------------------------------------------------

func readSysctlInt(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return n
}

func writeSysctl(path string, val int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(val)+"\n"), 0644)
}
