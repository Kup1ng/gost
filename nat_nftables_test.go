package gost

import (
	"strconv"
	"strings"
	"testing"
)

func TestNftRuleset(t *testing.T) {
	forwards := []NATForward{
		mkFwd("tcp", "", 8080, "1.2.3.4", 80),
		mkFwd("udp", "10.0.0.5", 5353, "8.8.8.8", 53),
	}
	table := nftTableName(forwards)
	doc := nftRuleset(table, forwards, NATOptions{})

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
	forwards := []NATForward{mkFwd("tcp", "", 8080, "1.2.3.4", 80)}
	doc := nftRuleset(nftTableName(forwards), forwards, NATOptions{NoSNAT: true, NoForwardRule: true})

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

func TestNftRulesetWeighted(t *testing.T) {
	forwards := []NATForward{
		mkFwdMulti("tcp", "", 8001, dst("1.1.1.1", 80, 3), dst("2.2.2.2", 80, 1)),
	}
	doc := nftRuleset(nftTableName(forwards), forwards, NATOptions{})

	mustContain := []string{
		// weighted DNAT via numgen inc, range keys, ip . port (NOT ip:port) values.
		`tcp dport 8001 dnat to numgen inc mod 4 map { 0-2 : 1.1.1.1 . 80, 3 : 2.2.2.2 . 80 } comment "gost-nat:tcp:0.0.0.0:8001"`,
		// masquerade + forward use the anonymous concatenation set.
		`ip daddr . tcp dport { 1.1.1.1 . 80, 2.2.2.2 . 80 } ct status dnat masquerade`,
		`ip daddr . tcp dport { 1.1.1.1 . 80, 2.2.2.2 . 80 } ct status dnat accept`,
		`ip saddr . tcp sport { 1.1.1.1 . 80, 2.2.2.2 . 80 } ct status dnat accept`,
	}
	for _, s := range mustContain {
		if !strings.Contains(doc, s) {
			t.Errorf("weighted ruleset missing:\n  %s\n---\n%s", s, doc)
		}
	}
	// colon-form ip:port is rejected inside an nft map; it must never appear there.
	if strings.Contains(doc, "1.1.1.1:80 .") || strings.Contains(doc, ": 1.1.1.1:80") {
		t.Errorf("map must use `ip . port`, not `ip:port`:\n%s", doc)
	}
}

// TestNftWeightedMapCoverage guards the highest-priority footgun: an incomplete
// `numgen inc mod N map {}` passes nft validation but silently drops the
// connections whose counter value is uncovered. Every key 0..N-1 must be
// covered exactly once.
func TestNftWeightedMapCoverage(t *testing.T) {
	cases := [][]NATDest{
		{dst("1.1.1.1", 80, 3), dst("2.2.2.2", 80, 1)},
		{dst("1.1.1.1", 80, 1), dst("2.2.2.2", 80, 1), dst("3.3.3.3", 80, 1)},
		{dst("1.1.1.1", 80, 5), dst("2.2.2.2", 8080, 2), dst("3.3.3.3", 80, 3)},
	}
	for _, dests := range cases {
		mapStr, n := nftWeightedMap(dests)
		total := 0
		for _, d := range dests {
			total += d.Weight
		}
		if n != total {
			t.Errorf("nftWeightedMap N=%d, want sum-of-weights %d", n, total)
		}
		covered := make([]bool, n)
		for _, entry := range strings.Split(mapStr, ", ") {
			key := strings.TrimSpace(strings.SplitN(entry, ":", 2)[0])
			lo, hi := 0, 0
			if strings.Contains(key, "-") {
				p := strings.SplitN(key, "-", 2)
				lo, _ = strconv.Atoi(p[0])
				hi, _ = strconv.Atoi(p[1])
			} else {
				lo, _ = strconv.Atoi(key)
				hi = lo
			}
			for k := lo; k <= hi; k++ {
				if k < 0 || k >= n {
					t.Fatalf("key %d out of range [0,%d): %q", k, n, mapStr)
				}
				if covered[k] {
					t.Fatalf("key %d covered twice: %q", k, mapStr)
				}
				covered[k] = true
			}
		}
		for k, c := range covered {
			if !c {
				t.Errorf("numgen map gap at key %d (would silently drop connections): %q", k, mapStr)
			}
		}
	}
}
