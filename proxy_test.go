package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestProxyHandler(t *testing.T) {
	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("X-Got-Host", r.Host)
		w.Header().Set("X-Got-Site", r.Header.Get("X-Site"))
		w.Header().Set("X-Got-XFF", r.Header.Get("X-Forwarded-For"))
		io.WriteString(w, "upstream:"+r.URL.Path)
	}))
	defer up.Close()

	s := newTestStore(t)
	if err := s.AddSite("omniroute", up.URL); err != nil {
		t.Fatal(err)
	}
	sites, _ := s.ListSites()
	if err := s.AddEntry(sites[0].ID, "203.0.113.5", "me", nil); err != nil {
		t.Fatal(err)
	}
	app := &App{Store: s, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}

	do := func(xreal string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://route-gateway.example/v1/chat", strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Site", "omniroute")
		r.Header.Set("X-Real-IP", xreal)
		r.Header.Set("X-Forwarded-For", "203.0.113.5")
		w := httptest.NewRecorder()
		app.proxyHandler(w, r)
		return w
	}

	w := do("203.0.113.5")
	if w.Code != 200 || w.Body.String() != "upstream:/v1/chat" {
		t.Fatalf("allowed: %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Got-Host") != "route-gateway.example" {
		t.Errorf("Host not preserved: %q", w.Header().Get("X-Got-Host"))
	}
	if w.Header().Get("X-Got-Site") != "" {
		t.Error("X-Site must not reach upstream")
	}
	if w.Header().Get("X-Got-XFF") == "" {
		t.Error("X-Forwarded-For must be passed through")
	}

	before := hits
	if w := do("198.51.100.9"); w.Code != 403 || hits != before {
		t.Errorf("denied: code=%d upstream hit=%v", w.Code, hits != before)
	}

	// site without upstream -> 502, not an open redirect/loop
	if err := s.AddSite("noup", ""); err != nil {
		t.Fatal(err)
	}
	sites, _ = s.ListSites()
	for _, x := range sites {
		if x.Name == "noup" {
			s.AddEntry(x.ID, "203.0.113.5", "", nil)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Site", "noup")
	r.Header.Set("X-Real-IP", "203.0.113.5")
	rec := httptest.NewRecorder()
	app.proxyHandler(rec, r)
	if rec.Code != 502 {
		t.Errorf("no upstream: %d want 502", rec.Code)
	}
}

func TestAddSiteRejectsBadUpstream(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{"ftp://x", "127.0.0.1:20138", "http://"} {
		if err := s.AddSite("a"+bad, bad); err == nil {
			t.Errorf("upstream %q should be rejected", bad)
		}
	}
}
