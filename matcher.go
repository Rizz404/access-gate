package main

import (
	"errors"
	"net/netip"
	"strings"
	"time"
)

// ParseCIDR accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::/32"; a bare IP becomes a host prefix.
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("IP/CIDR kosong")
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("pakai notasi IPv4 biasa, bukan ::ffff:")
	}
	return p.Masked(), nil
}

// Allowed reports whether ip is covered by an active entry of the site.
// Unknown/disabled site, bad IP, or store error -> false (fail-closed).
func (s *Store) Allowed(site, ip string, now time.Time) (bool, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil
	}
	a = a.Unmap()
	cidrs, err := s.activeCIDRs(site, now)
	if err != nil {
		return false, err
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true, nil
		}
	}
	return false, nil
}
