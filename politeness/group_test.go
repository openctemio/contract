package politeness

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func TestGroup(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		want    [][]string
	}{
		{"an address and its host:port are one host",
			[]string{"203.0.113.5", "198.51.100.7", "203.0.113.5:8443", "https://203.0.113.5/x"},
			[][]string{{"203.0.113.5", "203.0.113.5:8443", "https://203.0.113.5/x"}, {"198.51.100.7"}}},
		{"a name, its URL and its service are one host",
			[]string{"https://www.example.com/", "api.example.com", "www.example.com:443:tcp", "WWW.example.com."},
			[][]string{{"https://www.example.com/", "www.example.com:443:tcp", "WWW.example.com."}, {"api.example.com"}}},
		{"two addresses of one bucket stay apart",
			[]string{"203.0.113.5", "203.0.113.6"},
			[][]string{{"203.0.113.5"}, {"203.0.113.6"}}},
		{"a range joins the addresses of its buckets, either order",
			[]string{"203.0.113.5", "198.51.100.1", "203.0.113.0/25", "203.0.113.200"},
			[][]string{{"203.0.113.5", "203.0.113.0/25", "203.0.113.200"}, {"198.51.100.1"}}},
		{"transitive through a shared host",
			[]string{"10.0.0.1", "10.0.1.0/24", "http://10.0.0.1:8080", "10.0.1.9"},
			[][]string{{"10.0.0.1", "http://10.0.0.1:8080"}, {"10.0.1.0/24", "10.0.1.9"}}},
		{"a target without a host is alone",
			[]string{"", "  ", "www.example.com"},
			[][]string{{""}, {"  "}, {"www.example.com"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Group(c.targets, ""); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Group(%q)\n got  %q\n want %q", c.targets, got, c.want)
			}
		})
	}
}

func TestGroup_Empty(t *testing.T) {
	if got := Group(nil, ""); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

func TestGroup_Network(t *testing.T) {
	// Inside a network a private address is that network's host: the same
	// address and its URL are one group, a name too.
	got := Group([]string{"10.0.0.5", "http://10.0.0.5:8080/", "intranet.local", "intranet.local:22"}, "site-a")
	want := [][]string{{"10.0.0.5", "http://10.0.0.5:8080/"}, {"intranet.local", "intranet.local:22"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Every pair of targets in two different groups is conflict-free, and the
// groups cover every target exactly once.
func TestGroup_PartsNeverConflict(t *testing.T) {
	var targets []string
	for i := 0; i < 60; i++ {
		switch i % 5 {
		case 0:
			targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
		case 1:
			targets = append(targets, fmt.Sprintf("203.0.113.%d:443", i-1))
		case 2:
			targets = append(targets, fmt.Sprintf("h%d.example.com", i%7))
		case 3:
			targets = append(targets, fmt.Sprintf("https://h%d.example.com/", i%11))
		default:
			targets = append(targets, fmt.Sprintf("198.51.%d.0/24", i%3))
		}
	}
	groups := Group(targets, "")
	seen := 0
	for _, g := range groups {
		seen += len(g)
	}
	if seen != len(targets) {
		t.Fatalf("groups hold %d targets, want %d", seen, len(targets))
	}
	for a := range groups {
		for b := range groups {
			if a == b {
				continue
			}
			ka, kb := Keys(groups[a], ""), Keys(groups[b], "")
			cb := map[string]bool{}
			for _, k := range Conflicts(kb) {
				cb[k] = true
			}
			for _, k := range ka {
				if cb[k] {
					t.Fatalf("groups %q and %q conflict on %s", groups[a], groups[b], k)
				}
			}
		}
	}
}

func TestGroupKeys(t *testing.T) {
	keys := [][]string{
		{"a.example.com"},
		{"203.0.113.5", "in:203.0.113.0/24"},
		{"a.example.com", "203.0.113.5"}, // a name with an address it resolves to
		{"b.example.com"},
		nil,
	}
	want := [][]int{{0, 1, 2}, {3}, {4}}
	if got := GroupKeys(keys); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// GroupKeys equals the connected components of the pairwise conflict
// relation (brute force), on a mix of names, addresses, services and
// ranges sharing buckets.
func TestGroupKeys_MatchesPairwise(t *testing.T) {
	var targets []string
	for i := 0; i < 80; i++ {
		switch i % 6 {
		case 0:
			targets = append(targets, fmt.Sprintf("10.0.%d.%d", i%4, i%9))
		case 1:
			targets = append(targets, fmt.Sprintf("10.0.%d.%d:8080", i%4, i%9))
		case 2:
			targets = append(targets, fmt.Sprintf("10.0.%d.0/25", i%7))
		case 3:
			targets = append(targets, fmt.Sprintf("n%d.example.com", i%5))
		case 4:
			targets = append(targets, fmt.Sprintf("http://n%d.example.com:81/", i%13))
		default:
			targets = append(targets, fmt.Sprintf("10.0.%d.%d-10.0.%d.%d", i%5, 250, i%5+1, 3))
		}
	}
	keys := make([][]string, len(targets))
	for i, tg := range targets {
		keys[i] = TargetKeys(tg, "")
	}
	conflict := func(a, b int) bool {
		cb := map[string]bool{}
		for _, k := range Conflicts(keys[b]) {
			cb[k] = true
		}
		for _, k := range keys[a] {
			if cb[k] {
				return true
			}
		}
		return false
	}
	comp := make([]int, len(targets))
	for i := range comp {
		comp[i] = -1
	}
	var want [][]int
	for i := range targets {
		if comp[i] >= 0 {
			continue
		}
		g := len(want)
		stack, members := []int{i}, []int{}
		comp[i] = g
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			members = append(members, x)
			for y := range targets {
				if comp[y] < 0 && conflict(x, y) {
					comp[y] = g
					stack = append(stack, y)
				}
			}
		}
		slices.Sort(members)
		want = append(want, members)
	}
	if got := GroupKeys(keys); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}
