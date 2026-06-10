package gost

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// WeightedDest is one parsed load-balancing destination from a -L rule's
// comma-separated destination list. Host may be an IP or (userspace only) a
// hostname. Weight defaults to 1 and is always >= 1.
type WeightedDest struct {
	Host   string
	Port   int
	Weight int
}

// Addr returns "host:port" (no weight), suitable for dialing.
func (d WeightedDest) Addr() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
}

// ParseDestList parses a comma-separated destination list where each element is
// HOST:PORT with an optional :WEIGHT suffix (a positive integer):
//
//	1.1.1.1:80,2.2.2.2:80              -> equal weights
//	1.1.1.1:80:3,2.2.2.2:80:1          -> weighted 3:1
//
// IPv6 hosts must be bracketed: [2001:db8::1]:80 or [2001:db8::1]:80:3.
// Returns a clear error for an empty list, a missing/invalid port, or an
// invalid weight.
func ParseDestList(s string) ([]WeightedDest, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty destination list")
	}
	var dests []WeightedDest
	for _, elem := range strings.Split(s, ",") {
		elem = strings.TrimSpace(elem)
		if elem == "" {
			continue
		}
		d, err := parseWeightedDest(elem)
		if err != nil {
			return nil, err
		}
		dests = append(dests, d)
	}
	if len(dests) == 0 {
		return nil, fmt.Errorf("no destinations in %q", s)
	}
	return dests, nil
}

// ExpandWeightedDests parses a destination list and returns a plain
// comma-separated "host:port" list with each backend repeated according to its
// weight, interleaved so the repetition is spread out rather than bursty. Fed
// to the userspace forward handler, whose round-robin selector then yields
// weighted round-robin. A single unweighted destination round-trips unchanged.
func ExpandWeightedDests(remote string) (string, error) {
	dests, err := ParseDestList(remote)
	if err != nil {
		return "", err
	}
	// Interleaved expansion: repeatedly walk the backends, emitting one slot for
	// each backend that still has weight left. {A:3,B:1} -> A,B,A,A.
	remaining := make([]int, len(dests))
	total := 0
	for i, d := range dests {
		remaining[i] = d.Weight
		total += d.Weight
	}
	out := make([]string, 0, total)
	for len(out) < total {
		for i, d := range dests {
			if remaining[i] > 0 {
				out = append(out, d.Addr())
				remaining[i]--
			}
		}
	}
	return strings.Join(out, ","), nil
}

func parseWeightedDest(e string) (WeightedDest, error) {
	host, rest, err := splitHostRest(e)
	if err != nil {
		return WeightedDest{}, err
	}
	if host == "" {
		return WeightedDest{}, fmt.Errorf("missing host in destination %q", e)
	}
	// rest is "PORT" or "PORT:WEIGHT".
	parts := strings.Split(rest, ":")
	if len(parts) > 2 {
		return WeightedDest{}, fmt.Errorf("bad destination %q: expected HOST:PORT[:WEIGHT] (bracket IPv6 as [addr]:port)", e)
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil || port <= 0 || port > 65535 {
		return WeightedDest{}, fmt.Errorf("bad port in destination %q", e)
	}
	weight := 1
	if len(parts) == 2 {
		w, err := strconv.Atoi(parts[1])
		if err != nil || w <= 0 {
			return WeightedDest{}, fmt.Errorf("bad weight in destination %q: weight must be a positive integer", e)
		}
		weight = w
	}
	return WeightedDest{Host: host, Port: port, Weight: weight}, nil
}

// splitHostRest splits an element into its host and the remaining
// "PORT[:WEIGHT]" tail, handling bracketed IPv6.
func splitHostRest(e string) (host, rest string, err error) {
	if strings.HasPrefix(e, "[") {
		end := strings.IndexByte(e, ']')
		if end < 0 {
			return "", "", fmt.Errorf("bad IPv6 destination %q: missing ']'", e)
		}
		tail := e[end+1:]
		if !strings.HasPrefix(tail, ":") {
			return "", "", fmt.Errorf("bad destination %q: expected [host]:PORT[:WEIGHT]", e)
		}
		return e[1:end], tail[1:], nil
	}
	i := strings.IndexByte(e, ':')
	if i < 0 {
		return "", "", fmt.Errorf("bad destination %q: missing :PORT", e)
	}
	return e[:i], e[i+1:], nil
}
