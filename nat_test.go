package gost

import (
	"net"
	"os"
	"testing"
)

func mkFwd(proto, bind string, lport int, dest string, dport int) NATForward {
	return NATForward{
		Proto:    proto,
		BindAddr: bind,
		LPort:    lport,
		Dests:    []NATDest{{IP: net.ParseIP(dest).To4(), Port: dport, Weight: 1}},
	}
}

func mkFwdMulti(proto, bind string, lport int, dests ...NATDest) NATForward {
	return NATForward{Proto: proto, BindAddr: bind, LPort: lport, Dests: dests}
}

func dst(ip string, port, weight int) NATDest {
	return NATDest{IP: net.ParseIP(ip).To4(), Port: port, Weight: weight}
}

func TestNATForwardIdentity(t *testing.T) {
	tests := []struct {
		f    NATForward
		want string
	}{
		{mkFwd("tcp", "", 8080, "1.2.3.4", 80), "gost-nat:tcp:0.0.0.0:8080->1.2.3.4:80"},
		{mkFwd("udp", "10.0.0.1", 5353, "8.8.8.8", 53), "gost-nat:udp:10.0.0.1:5353->8.8.8.8:53"},
	}
	for _, tt := range tests {
		// single-dest identity AND comment must be byte-identical to the proven
		// single-destination tag (so existing table names / rule comments don't move).
		if got := tt.f.identity(); got != tt.want {
			t.Errorf("identity() = %q, want %q", got, tt.want)
		}
		if got := tt.f.comment(); got != tt.want {
			t.Errorf("comment() = %q, want %q", got, tt.want)
		}
	}

	// multi-dest identity includes every backend + weight (feeds the table hash).
	m := mkFwdMulti("tcp", "", 8001, dst("1.1.1.1", 80, 3), dst("2.2.2.2", 80, 1))
	if got, want := m.identity(), "gost-nat:tcp:0.0.0.0:8001->1.1.1.1:80:3,2.2.2.2:80:1"; got != want {
		t.Errorf("multi identity() = %q, want %q", got, want)
	}
	// changing a weight must change the identity (=> new table, idempotent replace).
	m2 := mkFwdMulti("tcp", "", 8001, dst("1.1.1.1", 80, 2), dst("2.2.2.2", 80, 1))
	if m.identity() == m2.identity() {
		t.Error("changing a weight must change identity")
	}
}

func TestNATForwardWildcard(t *testing.T) {
	if !mkFwd("tcp", "", 80, "1.2.3.4", 80).Wildcard() {
		t.Error("empty bind should be wildcard")
	}
	if !mkFwd("tcp", "0.0.0.0", 80, "1.2.3.4", 80).Wildcard() {
		t.Error("0.0.0.0 bind should be wildcard")
	}
	if mkFwd("tcp", "10.0.0.1", 80, "1.2.3.4", 80).Wildcard() {
		t.Error("specific bind should not be wildcard")
	}
}

func TestInstanceHashStableAndUnique(t *testing.T) {
	a := []NATForward{
		mkFwd("tcp", "", 8080, "1.2.3.4", 80),
		mkFwd("udp", "", 5353, "8.8.8.8", 53),
	}
	// same set, different order -> same hash (deterministic identity).
	b := []NATForward{
		mkFwd("udp", "", 5353, "8.8.8.8", 53),
		mkFwd("tcp", "", 8080, "1.2.3.4", 80),
	}
	if instanceHash(a) != instanceHash(b) {
		t.Errorf("hash not order-independent: %s vs %s", instanceHash(a), instanceHash(b))
	}
	// different set -> different hash (no collision between concurrent instances).
	c := []NATForward{mkFwd("tcp", "", 9090, "1.2.3.4", 80)}
	if instanceHash(a) == instanceHash(c) {
		t.Error("different forward sets produced the same hash")
	}
	if len(instanceHash(a)) != 8 {
		t.Errorf("hash length = %d, want 8", len(instanceHash(a)))
	}
}

func TestParseNATForwardValid(t *testing.T) {
	f, err := ParseNATForward("tcp://:8080/1.2.3.4:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Proto != "tcp" || f.LPort != 8080 || f.BindAddr != "" || len(f.Dests) != 1 ||
		f.Dests[0].IP.String() != "1.2.3.4" || f.Dests[0].Port != 80 {
		t.Errorf("wrong forward: %+v", f)
	}

	f, err = ParseNATForward("udp://10.0.0.1:5353/8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Proto != "udp" || f.LPort != 5353 || f.BindAddr != "10.0.0.1" || len(f.Dests) != 1 ||
		f.Dests[0].IP.String() != "8.8.8.8" || f.Dests[0].Port != 53 {
		t.Errorf("wrong forward: %+v", f)
	}
}

func TestParseNATForwardMultiDest(t *testing.T) {
	f, err := ParseNATForward("tcp://:8001/1.1.1.1:80:3,2.2.2.2:80:1")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Dests) != 2 {
		t.Fatalf("want 2 dests, got %d", len(f.Dests))
	}
	if f.Dests[0].Weight != 3 || f.Dests[1].Weight != 1 {
		t.Errorf("weights = %d:%d, want 3:1", f.Dests[0].Weight, f.Dests[1].Weight)
	}
	if f.totalWeight() != 4 {
		t.Errorf("totalWeight = %d, want 4", f.totalWeight())
	}

	// equal weights default to 1
	f, _ = ParseNATForward("tcp://:8001/1.1.1.1:80,2.2.2.2:80,3.3.3.3:80")
	if len(f.Dests) != 3 || f.totalWeight() != 3 {
		t.Errorf("equal 3-dest: got %d dests, total %d", len(f.Dests), f.totalWeight())
	}

	// GCD reduction: 6:2 -> 3:1
	f, _ = ParseNATForward("tcp://:8001/1.1.1.1:80:6,2.2.2.2:80:2")
	if f.Dests[0].Weight != 3 || f.Dests[1].Weight != 1 {
		t.Errorf("GCD-reduced weights = %d:%d, want 3:1", f.Dests[0].Weight, f.Dests[1].Weight)
	}
}

func TestParseNATForwardRejections(t *testing.T) {
	cases := map[string]string{
		"non-tcp/udp transport": "http://:8080/1.2.3.4:80",
		"missing destination":   "tcp://:8080",
		"ipv6 destination":      "tcp://:8080/[2001:db8::1]:80",
		"bad weight zero":       "tcp://:8080/1.2.3.4:80:0",
		"missing port in list":  "tcp://:8080/1.2.3.4,2.2.2.2:80",
		"ipv6 in list":          "tcp://:8080/1.2.3.4:80,[2001:db8::1]:80",
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNATForward(l); err == nil {
				t.Errorf("%s: expected error, got nil", name)
			}
		})
	}
}

func TestNormalizeNATBindAddr(t *testing.T) {
	for _, in := range []string{"", "0.0.0.0", "::"} {
		if got, err := normalizeNATBindAddr(in); err != nil || got != "" {
			t.Errorf("normalizeNATBindAddr(%q) = %q,%v; want \"\",nil", in, got, err)
		}
	}
	if got, err := normalizeNATBindAddr("10.0.0.1"); err != nil || got != "10.0.0.1" {
		t.Errorf("normalizeNATBindAddr(10.0.0.1) = %q,%v", got, err)
	}
	if _, err := normalizeNATBindAddr("not-an-ip"); err == nil {
		t.Error("normalizeNATBindAddr(not-an-ip) should error")
	}
	if _, err := normalizeNATBindAddr("2001:db8::1"); err == nil {
		t.Error("normalizeNATBindAddr(ipv6) should error in v1")
	}
}

func TestResolveNATDest(t *testing.T) {
	ip, err := resolveNATDest("1.2.3.4")
	if err != nil || ip.String() != "1.2.3.4" {
		t.Errorf("resolveNATDest(1.2.3.4) = %v,%v", ip, err)
	}
	if _, err := resolveNATDest("2001:db8::1"); err == nil {
		t.Error("resolveNATDest(ipv6) should error in v1")
	}
}

func TestIsProtectedSSHPort(t *testing.T) {
	if blocked, _ := IsProtectedSSHPort(22); !blocked {
		t.Error("port 22 should be protected")
	}
	if blocked, _ := IsProtectedSSHPort(8080); blocked {
		t.Error("port 8080 should not be protected without SSH_CONNECTION")
	}
	old := os.Getenv("SSH_CONNECTION")
	defer os.Setenv("SSH_CONNECTION", old)
	os.Setenv("SSH_CONNECTION", "10.0.0.9 51000 10.0.0.1 2222")
	if blocked, _ := IsProtectedSSHPort(2222); !blocked {
		t.Error("active SSH session port 2222 should be protected")
	}
}
