package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html static/*
var tplFS embed.FS

var tpl = template.Must(template.ParseFS(tplFS, "templates/*.html"))

const (
	sessionTTL  = 12 * time.Hour
	maxFails    = 5
	lockoutTime = 15 * time.Minute
	cookieName  = "gate_session"
)

type session struct {
	csrf    string
	expires time.Time
}

type failInfo struct {
	n     int
	until time.Time
}

// Admin serves the management UI. shortcut: sessions and login-fail counters live in memory
// (lost on restart, single instance only); upgrade if admin ever needs persistence or HA.
type Admin struct {
	*App
	Hash   []byte
	Secure bool // set Secure flag on cookie (use when served over HTTPS)

	mu       sync.Mutex
	sessions map[string]session
	fails    map[string]failInfo
}

func NewAdmin(app *App, hash []byte, secure bool) *Admin {
	return &Admin{App: app, Hash: hash, Secure: secure, sessions: map[string]session{}, fails: map[string]failInfo{}}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (a *Admin) Routes() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /static/", http.FileServerFS(tplFS))
	m.HandleFunc("GET /login", a.loginPage)
	m.HandleFunc("POST /login", a.loginPost)
	m.HandleFunc("POST /logout", a.authed(a.logout))
	m.HandleFunc("GET /{$}", a.authed(a.dashboard))
	m.HandleFunc("GET /denied", a.authed(a.deniedFragment))
	m.HandleFunc("POST /site/add", a.authed(a.siteAdd))
	m.HandleFunc("POST /site/delete", a.authed(a.siteDelete))
	m.HandleFunc("POST /site/toggle", a.authed(a.siteToggle))
	m.HandleFunc("POST /entry/add", a.authed(a.entryAdd))
	m.HandleFunc("POST /entry/delete", a.authed(a.entryDelete))
	m.HandleFunc("POST /entry/me", a.authed(a.entryMe))
	return m
}

func (a *Admin) current(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || a.now().After(s.expires) {
		delete(a.sessions, c.Value)
		return "", session{}, false
	}
	return c.Value, s, true
}

// authed requires a valid session; every POST additionally requires the session's CSRF token.
func (a *Admin) authed(h func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, s, ok := a.current(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "csrf", http.StatusForbidden)
				return
			}
		}
		h(w, r, s)
	}
}

func (a *Admin) loginPage(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": ""})
}

func (a *Admin) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := realIP(r, a.Trusted)
	now := a.now()
	a.mu.Lock()
	f := a.fails[ip]
	locked := f.n >= maxFails && now.Before(f.until)
	a.mu.Unlock()
	if locked {
		w.WriteHeader(http.StatusTooManyRequests)
		tpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": "Terlalu banyak percobaan, coba lagi nanti."})
		return
	}
	if bcrypt.CompareHashAndPassword(a.Hash, []byte(r.FormValue("password"))) != nil {
		a.mu.Lock()
		if f.n >= maxFails { // lockout expired, start over
			f.n = 0
		}
		f.n++
		f.until = now.Add(lockoutTime)
		a.fails[ip] = f
		a.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		tpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": "Password salah."})
		return
	}
	tok := randHex(32)
	a.mu.Lock()
	delete(a.fails, ip)
	a.sessions[tok] = session{csrf: randHex(16), expires: now.Add(sessionTTL)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: a.Secure, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request, _ session) {
	if tok, _, ok := a.current(r); ok {
		a.mu.Lock()
		delete(a.sessions, tok)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type siteView struct {
	Site
	Entries []Entry
}

func (a *Admin) dashboard(w http.ResponseWriter, r *http.Request, s session) {
	sites, err := a.Store.ListSites()
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]siteView, 0, len(sites))
	for _, st := range sites {
		es, err := a.Store.ListEntries(st.ID)
		if err != nil {
			a.fail(w, err)
			return
		}
		views = append(views, siteView{st, es})
	}
	denied, err := a.Store.RecentDenied(50)
	if err != nil {
		a.fail(w, err)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", map[string]any{
		"CSRF": s.csrf, "Sites": views, "Denied": denied, "MyIP": realIP(r, a.Trusted), "Msg": r.URL.Query().Get("msg"),
	})
}

// deniedFragment is polled by htmx to refresh the denied-requests table in place.
func (a *Admin) deniedFragment(w http.ResponseWriter, r *http.Request, _ session) {
	denied, err := a.Store.RecentDenied(50)
	if err != nil {
		a.fail(w, err)
		return
	}
	tpl.ExecuteTemplate(w, "denied", map[string]any{"Denied": denied})
}

func (a *Admin) fail(w http.ResponseWriter, err error) {
	log.Printf("admin: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (a *Admin) done(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Redirect(w, r, "/?msg="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func id(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	return n
}

// expiry parses the "hours" form field: empty/0 = never expires.
func (a *Admin) expiry(r *http.Request) *time.Time {
	h, _ := strconv.Atoi(r.FormValue("hours"))
	if h <= 0 {
		return nil
	}
	t := a.now().Add(time.Duration(h) * time.Hour)
	return &t
}

func (a *Admin) siteAdd(w http.ResponseWriter, r *http.Request, _ session) {
	a.done(w, r, a.Store.AddSite(r.FormValue("name"), r.FormValue("upstream")))
}

func (a *Admin) siteDelete(w http.ResponseWriter, r *http.Request, _ session) {
	a.done(w, r, a.Store.DeleteSite(id(r)))
}

func (a *Admin) siteToggle(w http.ResponseWriter, r *http.Request, _ session) {
	a.done(w, r, a.Store.SetSiteEnabled(id(r), r.FormValue("enabled") == "1"))
}

func (a *Admin) entryAdd(w http.ResponseWriter, r *http.Request, _ session) {
	a.done(w, r, a.Store.AddEntry(id(r), r.FormValue("cidr"), r.FormValue("label"), a.expiry(r)))
}

func (a *Admin) entryDelete(w http.ResponseWriter, r *http.Request, _ session) {
	a.done(w, r, a.Store.DeleteEntry(id(r)))
}

// entryMe whitelists the admin's own current IP on a site (default 24h).
func (a *Admin) entryMe(w http.ResponseWriter, r *http.Request, _ session) {
	exp := a.expiry(r)
	if exp == nil && r.FormValue("hours") == "" {
		t := a.now().Add(24 * time.Hour)
		exp = &t
	}
	a.done(w, r, a.Store.AddEntry(id(r), realIP(r, a.Trusted), "IP saya", exp))
}
