package addrscope

import (
	"net/netip"
	"testing"
)

func TestIsInternal(t *testing.T) {
	internal := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.1.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "172.31.255.255", "192.0.0.8", "192.168.1.1", "198.18.0.1", "198.19.255.255",
		"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fe80::1%eth0", "fec0::1", "fc00::1", "fd00:ec2::254", "ff02::1",
		"::ffff:10.0.0.1",                      // IPv4-mapped
		"::10.0.0.1",                           // IPv4-compatible
		"64:ff9b::a00:1",                       // NAT64 of 10.0.0.1
		"64:ff9b::a9fe:a9fe",                   // NAT64 of 169.254.169.254
		"64:ff9b:1:a00:0:100::",                // local-use NAT64 /48 of 10.0.0.1
		"2002:a00:1::1",                        // 6to4 of 10.0.0.1
		"2002:7f00:1::",                        // 6to4 of 127.0.0.1
		"2001:0:4136:e378:8000:63bf:f5ff:fffe", // Teredo, client 10.0.0.1 obfuscated
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.10", "198.51.100.1", "192.0.2.1", "100.128.0.1",
		"172.32.0.1", "192.0.1.1", "198.20.0.1", "2606:4700:4700::1111", "2001:db8::1",
		"::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
		"2001:0:4136:e378:8000:63bf:f7f7:f7f7", // Teredo, client 8.8.8.8 obfuscated
	}
	for _, s := range internal {
		if !IsInternal(netip.MustParseAddr(s)) {
			t.Errorf("%s: want internal", s)
		}
	}
	for _, s := range public {
		if IsInternal(netip.MustParseAddr(s)) {
			t.Errorf("%s: want public", s)
		}
	}
	if !IsInternal(netip.Addr{}) {
		t.Error("an invalid address must be internal (fail closed)")
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"64:ff9b::a00:1":                       "10.0.0.1",
		"64:ff9b:1:a00:0:100::":                "10.0.0.1",
		"2002:a00:1::1":                        "10.0.0.1",
		"2001:0:4136:e378:8000:63bf:f5ff:fffe": "10.0.0.1",
		"::10.0.0.1":                           "10.0.0.1",
	} {
		got, ok := EmbeddedIPv4(netip.MustParseAddr(in))
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("%s: got %v %v, want %s", in, got, ok, want)
		}
	}
	if _, ok := EmbeddedIPv4(netip.MustParseAddr("2606:4700::1")); ok {
		t.Error("an ordinary IPv6 address carries no IPv4 address")
	}
}

func TestIsInternalPrefix(t *testing.T) {
	for s, want := range map[string]bool{
		"10.0.0.0/8": true, "0.0.0.0/0": true, "8.8.8.0/24": false, "203.0.113.0/24": false,
		"169.254.169.254/32": true, "::/0": true, "2606:4700::/32": false, "64:ff9b::/96": true,
		"2002::/16": true, "2001::/32": true, "::ffff:10.0.0.0/104": true, "::ffff:8.8.8.0/120": false,
		"fd00::/8": true,
	} {
		if got := IsInternalPrefix(netip.MustParsePrefix(s)); got != want {
			t.Errorf("%s: got %v, want %v", s, got, want)
		}
	}
	if !IsInternalPrefix(netip.Prefix{}) {
		t.Error("an invalid prefix must be internal (fail closed)")
	}
}
