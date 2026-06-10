//go:build linux
// +build linux

package gost

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/go-log/log"
)

// nftBackend programs kernel DNAT via the `nft` command. Each gost instance owns
// a dedicated table `gost_nat_<hash>` (the hash is derived from the full -L set,
// so it is stable across restarts and unique across concurrent instances).
// Cleanup is a single atomic `nft delete table`, which can never touch another
// table — including the admin's own firewall or a sibling gost instance.
type nftBackend struct {
	bin string
}

func newNftBackend() *nftBackend {
	bin, _ := exec.LookPath("nft")
	return &nftBackend{bin: bin}
}

func (b *nftBackend) name() string { return "nftables" }

func (b *nftBackend) available() bool {
	if b.bin == "" {
		return false
	}
	// `nft list tables` exercises the netlink path; if nf_tables is missing or
	// we lack permission this fails and we fall through to iptables.
	return exec.Command(b.bin, "list", "tables").Run() == nil
}

func (b *nftBackend) program(forwards []NATForward, opts NATOptions) error {
	table := nftTableName(forwards)
	// Idempotent replace: drop any stale table left by a crashed run with the
	// same -L set, then create the fresh one atomically.
	_ = b.deleteTable(table)

	doc := nftRuleset(table, forwards, opts)
	if Debug {
		log.Logf("[nat] nft ruleset:\n%s", doc)
	}
	cmd := exec.Command(b.bin, "-f", "-")
	cmd.Stdin = strings.NewReader(doc)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *nftBackend) cleanup(forwards []NATForward, _ NATOptions) error {
	return b.deleteTable(nftTableName(forwards))
}

// rescue deletes every ip table whose name carries the gost prefix.
func (b *nftBackend) rescue() error {
	out, err := exec.Command(b.bin, "list", "tables", "ip").Output()
	if err != nil {
		return fmt.Errorf("nft list tables: %w", err)
	}
	var failed []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// "table ip gost_nat_<hash>"
		if len(f) >= 3 && f[0] == "table" && f[1] == "ip" && strings.HasPrefix(f[2], natObjPrefix+"_") {
			if err := b.deleteTable(f[2]); err != nil {
				failed = append(failed, f[2])
			} else {
				log.Logf("[nat] removed nftables table %s", f[2])
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not delete tables: %s", strings.Join(failed, ", "))
	}
	return nil
}

// deleteTable removes a table, treating "not found" as success (idempotent).
func (b *nftBackend) deleteTable(name string) error {
	out, err := exec.Command(b.bin, "delete", "table", "ip", name).CombinedOutput()
	if err == nil {
		return nil
	}
	s := string(out)
	if strings.Contains(s, "No such file") || strings.Contains(s, "does not exist") {
		return nil
	}
	return fmt.Errorf("nft delete table ip %s: %v: %s", name, err, strings.TrimSpace(s))
}
