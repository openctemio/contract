// Package addrscope is the one definition of an internal network address:
// an address a scanner that serves several organizations from an
// operator's network must never reach. The platform checks job targets
// with it, and the sensor checks every address it connects to with the same
// function, so the two never disagree about what is internal.
//
// Internal means any address that is not ordinary public unicast:
//
//   - IPv4: 0.0.0.0/8 ("this network"), 10.0.0.0/8, 100.64.0.0/10 (CGNAT),
//     127.0.0.0/8, 169.254.0.0/16 (link-local, cloud metadata),
//     172.16.0.0/12, 192.0.0.0/24 (IETF protocol assignments),
//     192.168.0.0/16, 198.18.0.0/15 (benchmarking), 224.0.0.0/4
//     (multicast), 240.0.0.0/4 (reserved) and 255.255.255.255;
//   - IPv6: ::/128, ::1/128, fe80::/10, fc00::/7 (unique local, which holds
//     the metadata address fd00:ec2::254), ff00::/8 (multicast), and
//     fec0::/10 (deprecated site-local);
//   - an IPv6 address that carries an IPv4 address is judged by that IPv4
//     address: IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96), NAT64
//     (64:ff9b::/96 and the local-use 64:ff9b:1::/48), 6to4 (2002::/16)
//     and Teredo (2001::/32, client address obfuscated). A gateway in the
//     path would otherwise turn 64:ff9b::a00:1 into 10.0.0.1.
//
// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32) are not routable on the internet and are not listed as
// internal: examples and tests use them as public addresses.
//
// Names are never resolved here: resolve first, then check every answer.
package addrscope

import "net/netip"

var internalV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), // includes 255.255.255.255
}

var internalV6 = []netip.Prefix{
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nat64User = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour = netip.MustParsePrefix("2002::/16")
	teredo    = netip.MustParsePrefix("2001::/32")
	v4compat  = netip.MustParsePrefix("::/96")
)

// IsInternal reports whether a is internal (see the package comment). An
// invalid address is internal (fail closed). A zone is ignored.
func IsInternal(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.WithZone("").Unmap()
	if a.Is4() {
		return inAny(a, internalV4)
	}
	if inAny(a, internalV6) {
		return true
	}
	if v4, ok := EmbeddedIPv4(a); ok {
		return IsInternal(v4)
	}
	return false
}

// EmbeddedIPv4 returns the IPv4 address an IPv6 address carries through
// NAT64, 6to4, Teredo or IPv4-compatible notation (IPv4-mapped addresses are
// unmapped by IsInternal before this).
func EmbeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case nat64User.Contains(a):
		// RFC 6052 with a /48 prefix: the IPv4 address is bytes 6-7 and
		// 9-10 (byte 8 is the reserved "u" octet).
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case teredo.Contains(a):
		// The client's public address, XOR-obfuscated, in the last 32 bits.
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	case v4compat.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// IsInternalPrefix reports whether any address of p is internal: p overlaps
// an internal range or is (or lies inside) an IPv6 range that carries IPv4.
// An invalid prefix is internal (fail closed).
func IsInternalPrefix(p netip.Prefix) bool {
	if !p.IsValid() {
		return true
	}
	p = p.Masked()
	addr := p.Addr().WithZone("")
	if addr.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
		addr = p.Addr()
	}
	if addr.Is4() {
		return overlapsAny(p, internalV4)
	}
	for _, carrier := range []netip.Prefix{nat64, nat64User, sixToFour, teredo, v4compat, netip.MustParsePrefix("::ffff:0:0/96")} {
		if p.Overlaps(carrier) {
			return true
		}
	}
	return overlapsAny(p, internalV6)
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func overlapsAny(p netip.Prefix, ps []netip.Prefix) bool {
	for _, q := range ps {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}
