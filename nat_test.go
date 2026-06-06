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
		DestIP:   net.ParseIP(dest).To4(),
		DestPort: dport,
	}
}

func TestNATForwardTag(t *testing.T) {
	tests := []struct {
		f    NATForward
		want string
	}{
		{mkFwd("tcp", "", 8080, "1.2.3.4", 80), "gost-nat:tcp:0.0.0.0:8080->1.2.3.4:80"},
		{mkFwd("udp", "10.0.0.1", 5353, "8.8.8.8", 53), "gost-nat:udp:10.0.0.1:5353->8.8.8.8:53"},
	}
	for _, tt := range tests {
		if got := tt.f.tag(); got != tt.want {
			t.Errorf("tag() = %q, want %q", got, tt.want)
		}
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
	if f.Proto != "tcp" || f.LPort != 8080 || f.BindAddr != "" ||
		f.DestIP.String() != "1.2.3.4" || f.DestPort != 80 {
		t.Errorf("wrong forward: %+v", f)
	}

	f, err = ParseNATForward("udp://10.0.0.1:5353/8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Proto != "udp" || f.LPort != 5353 || f.BindAddr != "10.0.0.1" ||
		f.DestIP.String() != "8.8.8.8" || f.DestPort != 53 {
		t.Errorf("wrong forward: %+v", f)
	}
}

func TestParseNATForwardRejections(t *testing.T) {
	cases := map[string]string{
		"non-tcp/udp transport": "http://:8080/1.2.3.4:80",
		"missing destination":   "tcp://:8080",
		"multiple destinations": "tcp://:8080/1.2.3.4:80,5.6.7.8:80",
		"ipv6 destination":      "tcp://:8080/[2001:db8::1]:80",
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
