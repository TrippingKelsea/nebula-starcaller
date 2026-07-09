package cert

import (
	"net"
	"strings"
)

// anyContainsCIDR returns true if any of the parent CIDRs is a supernet of
// (or equal to) child. Also returns true if child is a host IP that falls
// within any parent CIDR.
func anyContainsCIDR(parents []string, child string) bool {
	// Try parse child as CIDR first, then as IP.
	if ip, childNet, err := net.ParseCIDR(child); err == nil {
		for _, p := range parents {
			_, pn, err := net.ParseCIDR(strings.TrimSpace(p))
			if err != nil {
				continue
			}
			if cidrContains(pn, childNet, ip) {
				return true
			}
		}
		return false
	}
	// Not a CIDR — try as bare IP
	if ip := net.ParseIP(child); ip != nil {
		for _, p := range parents {
			_, pn, err := net.ParseCIDR(strings.TrimSpace(p))
			if err != nil {
				continue
			}
			if pn.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// cidrContains returns true if parent contains the child network.
// If either mask is invalid, falls back to IP containment on `ip`.
func cidrContains(parent, child *net.IPNet, ip net.IP) bool {
	// Same or supernet: parent's prefix len is <= child's, and parent contains
	// child's network address.
	pOnes, pBits := parent.Mask.Size()
	cOnes, cBits := child.Mask.Size()
	if pBits != cBits {
		return false
	}
	if pOnes > cOnes {
		return false
	}
	return parent.Contains(child.IP) && parent.Contains(ip)
}
