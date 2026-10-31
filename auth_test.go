package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func authReq(app *App, peer, site, xreal string) int {
	r := httptest.NewRequest("GET", "/auth", nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Site", site)
	if xreal != "" {
		r.Header.Set("X-Real-IP", xreal)
	}
	// a client-supplied Cloudflare header must never be used
	r.Header.Set("CF-Connecting-IP", "203.0.113.5")
	w := httptest.NewRecorder()
	app.authHandler(w, r)
	return w.Code
}

func TestAuthHandler(t *testing.T) {
	s := newTestStore(t)
	id := siteID(t, s, "omniroute")
	if err := s.AddEntry(id, "203.0.113.5", "me", nil); err != nil {
		t.Fatal(err)
	}
	app := &App{Store: s, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}

	cases := []struct {
		name, peer, site, xreal string
		want                    int
	}{
		{"allowed via trusted X-Real-IP", "127.0.0.1:1234", "omniroute", "203.0.113.5", 204},
		{"denied other ip", "127.0.0.1:1234", "omniroute", "198.51.100.9", 403},
		{"untrusted peer cannot spoof X-Real-IP", "198.51.100.9:1", "omniroute", "203.0.113.5", 403},
		{"CF header ignored", "127.0.0.1:1234", "omniroute", "", 403},
		{"unknown site", "127.0.0.1:1234", "nope", "203.0.113.5", 403},
		{"missing site", "127.0.0.1:1234", "", "203.0.113.5", 403},
	}
	for _, c := range cases {
		if got := authReq(app, c.peer, c.site, c.xreal); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}

	d, _ := s.RecentDenied(10)
	if len(d) != 5 {
		t.Errorf("denied logged=%d want 5", len(d))
	}
}

func TestAuthFailClosedOnStoreError(t *testing.T) {
	s := newTestStore(t)
	s.Close()
	app := &App{Store: s, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	if got := authReq(app, "127.0.0.1:1", "omniroute", "203.0.113.5"); got != http.StatusInternalServerError {
		t.Errorf("got %d want 500 (nginx treats non-2xx as deny)", got)
	}
}
