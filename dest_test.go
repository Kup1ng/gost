package gost

import (
	"reflect"
	"testing"
)

func TestParseDestList(t *testing.T) {
	cases := []struct {
		in   string
		want []WeightedDest
	}{
		{"1.1.1.1:80", []WeightedDest{{"1.1.1.1", 80, 1}}},
		{"1.1.1.1:80,2.2.2.2:80,3.3.3.3:80", []WeightedDest{
			{"1.1.1.1", 80, 1}, {"2.2.2.2", 80, 1}, {"3.3.3.3", 80, 1},
		}},
		{"1.1.1.1:80:3,2.2.2.2:80:1", []WeightedDest{
			{"1.1.1.1", 80, 3}, {"2.2.2.2", 80, 1},
		}},
		{"example.com:8080:2", []WeightedDest{{"example.com", 8080, 2}}},
		{"[2001:db8::1]:80:3", []WeightedDest{{"2001:db8::1", 80, 3}}},
		{"[2001:db8::1]:80", []WeightedDest{{"2001:db8::1", 80, 1}}},
	}
	for _, c := range cases {
		got, err := ParseDestList(c.in)
		if err != nil {
			t.Errorf("ParseDestList(%q) error: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseDestList(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseDestListErrors(t *testing.T) {
	bad := []string{
		"",               // empty
		"1.1.1.1",        // missing port
		"1.1.1.1:0",      // invalid port
		"1.1.1.1:99999",  // port out of range
		"1.1.1.1:80:0",   // weight 0
		"1.1.1.1:80:-1",  // negative weight
		"1.1.1.1:80:abc", // non-integer weight
		"1.1.1.1:80:1:2", // too many fields
		"2001:db8::1:80", // unbracketed IPv6
		":80",            // missing host
	}
	for _, in := range bad {
		if _, err := ParseDestList(in); err == nil {
			t.Errorf("ParseDestList(%q) expected error, got nil", in)
		}
	}
}

func TestExpandWeightedDests(t *testing.T) {
	cases := map[string]string{
		// single unweighted -> unchanged (backward compat)
		"1.1.1.1:80": "1.1.1.1:80",
		// equal multi -> unchanged order
		"1.1.1.1:80,2.2.2.2:80": "1.1.1.1:80,2.2.2.2:80",
		// weighted 3:1 -> interleaved expansion A,B,A,A
		"1.1.1.1:80:3,2.2.2.2:80:1": "1.1.1.1:80,2.2.2.2:80,1.1.1.1:80,1.1.1.1:80",
	}
	for in, want := range cases {
		got, err := ExpandWeightedDests(in)
		if err != nil {
			t.Errorf("ExpandWeightedDests(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ExpandWeightedDests(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandWeightedDestsCounts(t *testing.T) {
	// weighted 3:1 over a full period should yield 3:1 occurrences.
	got, err := ExpandWeightedDests("1.1.1.1:80:3,2.2.2.2:80:1")
	if err != nil {
		t.Fatal(err)
	}
	a, b := 0, 0
	for _, s := range splitComma(got) {
		switch s {
		case "1.1.1.1:80":
			a++
		case "2.2.2.2:80":
			b++
		}
	}
	if a != 3 || b != 1 {
		t.Errorf("weighted 3:1 expansion counts = %d:%d, want 3:1", a, b)
	}
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
