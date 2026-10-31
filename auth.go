package main

import (
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type App struct {
	Store   *Store
	Trusted []netip.Prefix // peers allowed to set X-Real-IP (our own nginx)
	Now     func() time.Time
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// realIP returns the client IP. X-Real-IP is only honored when the direct peer is a trusted
// proxy; Cloudflare/forwarded headers are deliberately ignored here (nginx real_ip resolves
// them and writes X-Real-IP, so a client cannot inject its own value).
func realIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	peer = peer.Unmap()
	for _, p := range trusted {
		if p.Contains(peer) {
			if v := r.Header.Get("X-Real-IP"); v != "" {
				return v
			}
			break
		}
	}
	return peer.String()
}

// authHandler is the nginx auth_request target: 204 = allow, 403 = deny, 500 = error (nginx denies).
func (a *App) authHandler(w http.ResponseWriter, r *http.Request) {
	site, ip := r.Header.Get("X-Site"), realIP(r, a.Trusted)
	ok, err := a.Store.Allowed(site, ip, a.now())
	if err != nil {
		log.Printf("auth: store error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if !ok {
		if err := a.Store.LogDenied(site, ip, a.now()); err != nil {
			log.Printf("auth: log denied: %v", err)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
