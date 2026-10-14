package politeness

// Groups of one host: the targets that must stay together when a job's
// targets are cut into parts (chunks of a step, waves of a running job), so
// that two parts never conflict with each other.

import "strings"

// GroupKeys partitions items by their keys: two items are in one group
// when one's keys share an element with the other's Conflicts, directly or
// through other items (the same name or address, an address and a range
// scan of its bucket). Two addresses of one bucket stay apart. keys[i] is
// the keys of item i; an item without keys is a group of its own. Groups
// are in the order of their first item, each item index ascending.
func GroupKeys(keys [][]string) [][]int {
	parent := make([]int, len(keys))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		switch {
		case ra == rb:
		case ra < rb:
			parent[rb] = ra
		default:
			parent[ra] = rb
		}
	}
	// owners is the items holding a key. A name, an address or a range key
	// conflicts with itself, so its holders are one group and the first
	// stands for all. A bucket marker does not (two addresses of one bucket
	// stay apart): its holders are kept until a range of the bucket joins
	// them. Conflicts is symmetric, so looking back from the later item of
	// each pair finds every pair.
	owners := map[string][]int{}
	for i, ks := range keys {
		for _, k := range ks {
			for _, c := range Conflicts([]string{k}) {
				os := owners[c]
				for _, o := range os {
					union(i, o)
				}
				if len(os) > 1 {
					owners[c] = os[:1] // now one group
				}
			}
		}
		for _, k := range ks {
			switch os := owners[k]; {
			case len(os) == 0, strings.HasPrefix(k, AddrInBucket) && os[len(os)-1] != i:
				owners[k] = append(os, i)
			}
		}
	}
	var out [][]int
	at := map[int]int{}
	for i := range keys {
		r := find(i)
		g, ok := at[r]
		if !ok {
			g = len(out)
			at[r] = g
			out = append(out, nil)
		}
		out[g] = append(out[g], i)
	}
	return out
}

// Group partitions targets in network ("" for the internet or a tenant's
// only network) into groups of one host (GroupKeys over TargetKeys): a URL,
// a service and a host:port of one name or address are one group with the
// name or address itself ("203.0.113.5", "203.0.113.5:8443" and
// "https://203.0.113.5/" are one host). A target that names no host is a
// group of its own. Groups are in the order of their first target.
func Group(targets []string, network string) [][]string {
	keys := make([][]string, len(targets))
	for i, t := range targets {
		keys[i] = TargetKeys(t, network)
	}
	idx := GroupKeys(keys)
	out := make([][]string, len(idx))
	for g, members := range idx {
		out[g] = make([]string, len(members))
		for j, i := range members {
			out[g][j] = targets[i]
		}
	}
	return out
}
