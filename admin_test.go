package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func newTestAdmin(t *testing.T) (*Admin, http.Handler) {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Store: newTestStore(t), Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	a := NewAdmin(app, h, false)
	return a, a.Routes()
}

func do(h http.Handler, method, path string, form url.Values, cookie *http.Cookie, xreal string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xreal != "" {
		r.Header.Set("X-Real-IP", xreal)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, a *Admin, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	w := do(h, "POST", "/login", url.Values{"password": {"secret"}}, nil, "198.51.100.7")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login code=%d", w.Code)
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Error("cookie must be HttpOnly + SameSite=Strict")
	}
	return c, a.sessions[c.Value].csrf
}

func TestLoginRequiredAndWrongPassword(t *testing.T) {
	_, h := newTestAdmin(t)
	if w := do(h, "GET", "/", nil, nil, ""); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("unauthenticated dashboard: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "POST", "/login", url.Values{"password": {"nope"}}, nil, "198.51.100.7"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password code=%d", w.Code)
	}
}

func TestLoginLockout(t *testing.T) {
	_, h := newTestAdmin(t)
	for i := 0; i < maxFails; i++ {
		do(h, "POST", "/login", url.Values{"password": {"bad"}}, nil, "198.51.100.7")
	}
	if w := do(h, "POST", "/login", url.Values{"password": {"secret"}}, nil, "198.51.100.7"); w.Code != http.StatusTooManyRequests {
		t.Errorf("correct password while locked: %d want 429", w.Code)
	}
	if w := do(h, "POST", "/login", url.Values{"password": {"secret"}}, nil, "198.51.100.8"); w.Code != http.StatusSeeOther {
		t.Errorf("other ip must not be locked: %d", w.Code)
	}
}

func TestCSRFRequired(t *testing.T) {
	a, h := newTestAdmin(t)
	c, _ := login(t, a, h)
	if w := do(h, "POST", "/site/add", url.Values{"name": {"x"}}, c, ""); w.Code != http.StatusForbidden {
		t.Errorf("missing csrf code=%d want 403", w.Code)
	}
	if sites, _ := a.Store.ListSites(); len(sites) != 0 {
		t.Error("site must not be created without csrf")
	}
}

func TestWhitelistMyIPFlow(t *testing.T) {
	a, h := newTestAdmin(t)
	c, csrf := login(t, a, h)
	if w := do(h, "POST", "/site/add", url.Values{"name": {"omniroute"}, "csrf": {csrf}}, c, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("site add: %d", w.Code)
	}
	sites, _ := a.Store.ListSites()
	sid := sites[0].ID

	if ok, _ := a.Store.Allowed("omniroute", "198.51.100.7", a.now()); ok {
		t.Fatal("must be denied before whitelisting")
	}
	form := url.Values{"id": {"1"}, "csrf": {csrf}}
	do(h, "POST", "/entry/me", form, c, "198.51.100.7")
	if ok, _ := a.Store.Allowed("omniroute", "198.51.100.7", a.now()); !ok {
		t.Error("my IP must be allowed after /entry/me")
	}
	es, _ := a.Store.ListEntries(sid)
	if len(es) != 1 || es[0].ExpiresAt == nil {
		t.Errorf("entry/me should default to a 24h expiry: %+v", es)
	}

	do(h, "POST", "/entry/delete", url.Values{"id": {"1"}, "csrf": {csrf}}, c, "")
	if ok, _ := a.Store.Allowed("omniroute", "198.51.100.7", a.now()); ok {
		t.Error("must be denied after delete")
	}

	if w := do(h, "GET", "/", nil, c, "198.51.100.7"); w.Code != 200 || !strings.Contains(w.Body.String(), "omniroute") {
		t.Errorf("dashboard render: %d", w.Code)
	}
}

func TestBadCIDRRejected(t *testing.T) {
	a, h := newTestAdmin(t)
	c, csrf := login(t, a, h)
	do(h, "POST", "/site/add", url.Values{"name": {"s"}, "csrf": {csrf}}, c, "")
	w := do(h, "POST", "/entry/add", url.Values{"id": {"1"}, "cidr": {"garbage"}, "csrf": {csrf}}, c, "")
	if !strings.Contains(w.Header().Get("Location"), "msg=") {
		t.Errorf("expected error message redirect, got %q", w.Header().Get("Location"))
	}
}

func TestStaticAndDeniedFragment(t *testing.T) {
	a, h := newTestAdmin(t)
	if w := do(h, "GET", "/static/htmx.min.js", nil, nil, ""); w.Code != 200 || w.Body.Len() < 1000 {
		t.Errorf("htmx asset: %d len=%d", w.Code, w.Body.Len())
	}
	if w := do(h, "GET", "/denied", nil, nil, ""); w.Code != http.StatusSeeOther {
		t.Errorf("denied fragment must require login: %d", w.Code)
	}
	c, _ := login(t, a, h)
	a.Store.LogDenied("x", "9.9.9.9", a.now())
	if w := do(h, "GET", "/denied", nil, c, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "9.9.9.9") || strings.Contains(w.Body.String(), "<html") {
		t.Errorf("denied fragment: %d %q", w.Code, w.Body.String())
	}
}
