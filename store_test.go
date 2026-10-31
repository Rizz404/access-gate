package main

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func siteID(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	if err := s.AddSite(name, ""); err != nil {
		t.Fatal(err)
	}
	sites, _ := s.ListSites()
	for _, x := range sites {
		if x.Name == name {
			return x.ID
		}
	}
	t.Fatal("site not found")
	return 0
}

func TestAllowed(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := siteID(t, s, "omniroute")
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AddEntry(id, "203.0.113.5", "host", nil))
	must(s.AddEntry(id, "198.51.100.0/24", "net", nil))
	must(s.AddEntry(id, "2001:db8::/32", "v6", nil))
	must(s.AddEntry(id, "192.0.2.1", "expired", &past))
	must(s.AddEntry(id, "192.0.2.2", "temp", &future))

	cases := []struct {
		site, ip string
		want     bool
	}{
		{"omniroute", "203.0.113.5", true},
		{"omniroute", "203.0.113.6", false},
		{"omniroute", "198.51.100.77", true},
		{"omniroute", "198.51.101.1", false},
		{"omniroute", "2001:db8::1", true},
		{"omniroute", "2001:db9::1", false},
		{"omniroute", "::ffff:203.0.113.5", true}, // v4-mapped
		{"omniroute", "192.0.2.1", false},         // expired
		{"omniroute", "192.0.2.2", true},          // not yet expired
		{"omniroute", "not-an-ip", false},
		{"omniroute", "", false},
		{"unknown", "203.0.113.5", false}, // unknown site
	}
	for _, c := range cases {
		got, err := s.Allowed(c.site, c.ip, now)
		if err != nil || got != c.want {
			t.Errorf("Allowed(%q,%q)=%v,%v want %v", c.site, c.ip, got, err, c.want)
		}
	}

	must(s.SetSiteEnabled(id, false))
	if ok, _ := s.Allowed("omniroute", "203.0.113.5", now); ok {
		t.Error("disabled site must deny")
	}
}

func TestParseCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":        "1.2.3.4/32",
		"1.2.3.9/24":     "1.2.3.0/24",
		"2001:db8::1":    "2001:db8::1/128",
		"::ffff:1.2.3.4": "1.2.3.4/32",
		" 10.0.0.0/8 ":   "10.0.0.0/8",
	} {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseCIDR(%q)=%v,%v want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "1.2.3.4/33", "::ffff:1.2.3.0/120"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("ParseCIDR(%q) should fail", bad)
		}
	}
}

func TestDeniedKeepsLastN(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < deniedKeep+50; i++ {
		if err := s.LogDenied("x", "1.1.1.1", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.RecentDenied(1000)
	if len(got) != deniedKeep {
		t.Errorf("len=%d", len(got))
	}
}
