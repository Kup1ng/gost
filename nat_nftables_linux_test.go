//go:build linux
// +build linux

package gost

import (
	"strings"
	"testing"
)

func TestNftRuleset(t *testing.T) {
	b := &nftBackend{bin: "nft"}
	forwards := []NATForward{
		mkFwd("tcp", "", 8080, "1.2.3.4", 80),
		mkFwd("udp", "10.0.0.5", 5353, "8.8.8.8", 53),
	}
	table := b.tableName(forwards)
	doc := b.ruleset(table, forwards, NATOptions{})

	// `fwd` is a reserved nftables keyword and is rejected as a chain name; the
	// forward chain must be named "forward".
	if strings.Contains(doc, "chain fwd ") || strings.Contains(doc, "chain fwd{") {
		t.Errorf("ruleset uses reserved keyword `fwd` as a chain name:\n%s", doc)
	}

	mustContain := []string{
		"table ip " + table + " {",
		"chain forward {",
		"type nat hook prerouting priority -100",
		"type nat hook postrouting priority 100",
		"type filter hook forward priority 0",
		// wildcard tcp DNAT has no daddr match
		"tcp dport 8080 dnat to 1.2.3.4:80 comment \"gost-nat:tcp:0.0.0.0:8080->1.2.3.4:80\"",
		// specific-bind udp DNAT includes daddr
		"ip daddr 10.0.0.5 udp dport 5353 dnat to 8.8.8.8:53",
		// scoped masquerade
		"ip daddr 1.2.3.4 tcp dport 80 ct status dnat masquerade",
		"ip daddr 8.8.8.8 udp dport 53 ct status dnat masquerade",
		// scoped forward accept, both directions
		"ip daddr 1.2.3.4 tcp dport 80 ct status dnat accept",
		"ip saddr 1.2.3.4 tcp sport 80 ct status dnat accept",
	}
	for _, s := range mustContain {
		if !strings.Contains(doc, s) {
			t.Errorf("ruleset missing %q\n---\n%s", s, doc)
		}
	}
}

func TestNftRulesetNoSNATNoForward(t *testing.T) {
	b := &nftBackend{bin: "nft"}
	forwards := []NATForward{mkFwd("tcp", "", 8080, "1.2.3.4", 80)}
	doc := b.ruleset(b.tableName(forwards), forwards, NATOptions{NoSNAT: true, NoForwardRule: true})

	if strings.Contains(doc, "masquerade") {
		t.Error("NoSNAT set but masquerade present")
	}
	if strings.Contains(doc, "hook forward") {
		t.Error("NoForwardRule set but forward chain present")
	}
	// DNAT must still be there.
	if !strings.Contains(doc, "dnat to 1.2.3.4:80") {
		t.Error("DNAT rule missing")
	}
}
