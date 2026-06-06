package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

// NAT-mode CLI flags. Registered in main.go's init() (before flag.Parse) so the
// ordering is correct; kept here to keep all --NAT logic in one place.
var (
	natCleanup      bool
	natBackend      string
	natConntrackMax int
	natNoSNAT       bool
	natNoForward    bool
	natAllowSSH     bool
	natTuneTO       bool
)

// natCleanupTimeout bounds in-process teardown so a wedged nft/iptables call
// can never hang shutdown.
const natCleanupTimeout = 15 * time.Second

func buildNATOptions() gost.NATOptions {
	return gost.NATOptions{
		Backend:       natBackend,
		ConntrackMax:  natConntrackMax,
		NoSNAT:        natNoSNAT,
		NoForwardRule: natNoForward,
		AllowSSHPort:  natAllowSSH,
		TuneTimeouts:  natTuneTO,
	}
}

// collectRoutes returns the base route plus any -C config routes.
func collectRoutes() []route {
	rs := make([]route, 0, 1+len(baseCfg.Routes))
	rs = append(rs, baseCfg.route)
	rs = append(rs, baseCfg.Routes...)
	return rs
}

func natChainsPresent() bool {
	for _, r := range collectRoutes() {
		if len(r.ChainNodes) > 0 {
			return true
		}
	}
	return false
}

func natServeNodesPresent() bool {
	for _, r := range collectRoutes() {
		if len(r.ServeNodes) > 0 {
			return true
		}
	}
	return false
}

// GenNATForwards converts this route's -L rules into NATForwards, enforcing the
// SSH-port guard. The per-rule parsing/validation lives in gost.ParseNATForward.
func (r *route) GenNATForwards(allowSSHPort bool) ([]gost.NATForward, error) {
	var forwards []gost.NATForward
	for _, ns := range r.ServeNodes {
		f, err := gost.ParseNATForward(ns)
		if err != nil {
			return nil, fmt.Errorf("--NAT: %v", err)
		}
		if !allowSSHPort {
			if blocked, why := gost.IsProtectedSSHPort(f.LPort); blocked {
				return nil, fmt.Errorf("--NAT: refusing to forward listen port %d because %s; "+
					"pass --nat-allow-ssh-port to override (you risk locking yourself out)", f.LPort, why)
			}
		}
		forwards = append(forwards, f)
	}
	return forwards, nil
}

// collectNATForwards parses every -L rule across the base and config routes.
func collectNATForwards(allowSSHPort bool) ([]gost.NATForward, error) {
	var forwards []gost.NATForward
	for _, r := range collectRoutes() {
		fwds, err := r.GenNATForwards(allowSSHPort)
		if err != nil {
			return nil, err
		}
		forwards = append(forwards, fwds...)
	}
	if len(forwards) == 0 {
		return nil, errors.New("--NAT: no -L TCP/UDP forward rules given")
	}
	return forwards, nil
}

// runNAT programs kernel DNAT for all -L rules and blocks until a signal,
// then removes the rules. Cleanup runs via the signal path AND the deferred
// stop(), so SIGINT/SIGTERM and normal exit are all covered.
func runNAT() int {
	gost.Debug = baseCfg.Debug

	if natChainsPresent() {
		log.Log("--NAT is incompatible with -F (SOCKS5 chaining); -F only works in userspace mode")
		return 1
	}

	forwards, err := collectNATForwards(natAllowSSH)
	if err != nil {
		log.Log(err)
		return 1
	}

	mgr := gost.NewNATManager(forwards, buildNATOptions())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := mgr.Setup(); err != nil {
		log.Log(err)
		return 1
	}
	log.Logf("gost %s NAT mode [%s]: %d forward(s) active; the data path is in-kernel. Send SIGINT/SIGTERM to stop.",
		gost.Version, mgr.BackendName(), len(forwards))

	<-ctx.Done()
	stop() // re-arm default signal handling: a second Ctrl-C now exits hard.
	log.Log("signal received; removing NAT rules...")

	done := make(chan error, 1)
	go func() { done <- mgr.Teardown() }()
	select {
	case err := <-done:
		if err != nil {
			log.Log(err)
			return 1
		}
		return 0
	case <-time.After(natCleanupTimeout):
		log.Logf("NAT cleanup timed out after %s; forcing exit. Run `gost --nat-cleanup` to recover.", natCleanupTimeout)
		return 1
	}
}

// runNATCleanup implements `gost --nat-cleanup`. With -L it removes only those
// forwards' rules (used by the systemd ExecStopPost hook); without -L it removes
// every gost NAT rule on the host (operator rescue).
func runNATCleanup() int {
	gost.Debug = baseCfg.Debug

	var forwards []gost.NATForward
	if natServeNodesPresent() {
		// Parse -L identically to setup (allow the SSH port here so cleanup can
		// never be blocked) so the computed identity matches the programmed one.
		fwds, err := collectNATForwards(true)
		if err != nil {
			log.Log(err)
			return 1
		}
		forwards = fwds
	}

	if err := gost.NATCleanup(forwards, buildNATOptions()); err != nil {
		log.Log(err)
		return 1
	}
	if len(forwards) == 0 {
		log.Log("removed all gost NAT rules")
	} else {
		log.Logf("removed NAT rules for %d forward(s)", len(forwards))
	}
	return 0
}
