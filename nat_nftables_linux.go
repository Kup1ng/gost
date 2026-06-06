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

// tableName is the per-instance table, e.g. "gost_nat_1a2b3c4d".
func (b *nftBackend) tableName(forwards []NATForward) string {
	return natObjPrefix + "_" + instanceHash(forwards)
}

func (b *nftBackend) program(forwards []NATForward, opts NATOptions) error {
	table := b.tableName(forwards)
	// Idempotent replace: drop any stale table left by a crashed run with the
	// same -L set, then create the fresh one atomically.
	_ = b.deleteTable(table)

	doc := b.ruleset(table, forwards, opts)
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
	return b.deleteTable(b.tableName(forwards))
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

// ruleset renders the full nft document for `nft -f -`.
func (b *nftBackend) ruleset(table string, forwards []NATForward, opts NATOptions) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "table ip %s {\n", table)

	// prerouting DNAT
	sb.WriteString("\tchain pre {\n")
	sb.WriteString("\t\ttype nat hook prerouting priority -100; policy accept;\n")
	for _, f := range forwards {
		sb.WriteString("\t\t")
		if !f.Wildcard() {
			fmt.Fprintf(&sb, "ip daddr %s ", f.BindAddr)
		}
		fmt.Fprintf(&sb, "%s dport %d dnat to %s comment \"%s\"\n", f.Proto, f.LPort, f.dest(), f.tag())
	}
	sb.WriteString("\t}\n")

	// postrouting MASQUERADE, scoped to the DNAT'd flow only.
	sb.WriteString("\tchain post {\n")
	sb.WriteString("\t\ttype nat hook postrouting priority 100; policy accept;\n")
	if !opts.NoSNAT {
		for _, f := range forwards {
			fmt.Fprintf(&sb, "\t\tip daddr %s %s dport %d ct status dnat masquerade comment \"%s\"\n",
				f.DestIP.String(), f.Proto, f.DestPort, f.tag())
		}
	}
	sb.WriteString("\t}\n")

	// forward ACCEPT, scoped to the DNAT'd flow (+ established/related replies).
	// NOTE: the chain is named "forward" (not "fwd") because `fwd` is a reserved
	// nftables keyword (the fwd verdict statement) and is rejected as a chain
	// name; "forward" is a valid identifier (it is the chain name in Ubuntu's
	// default /etc/nftables.conf).
	if !opts.NoForwardRule {
		sb.WriteString("\tchain forward {\n")
		sb.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
		for _, f := range forwards {
			// accept both directions of this DNAT'd flow only.
			fmt.Fprintf(&sb, "\t\tip daddr %s %s dport %d ct status dnat accept comment \"%s\"\n",
				f.DestIP.String(), f.Proto, f.DestPort, f.tag())
			fmt.Fprintf(&sb, "\t\tip saddr %s %s sport %d ct status dnat accept comment \"%s\"\n",
				f.DestIP.String(), f.Proto, f.DestPort, f.tag())
		}
		sb.WriteString("\t}\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}
