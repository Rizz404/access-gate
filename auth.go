package main

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
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

// statusDrop is nginx's "close the connection without a response" code. In proxy mode a denied
// client gets no hint it was blocked: nginx maps 444 to `return 444`, and through Cloudflare the
// visitor just sees a generic origin error (520) instead of "forbidden".
const statusDrop = 444

// allowed decides the request; on deny/error it writes the response (denyCode/500) and returns false.
func (a *App) allowed(w http.ResponseWriter, r *http.Request, denyCode int) bool {
	site, ip := r.Header.Get("X-Site"), realIP(r, a.Trusted)
	ok, err := a.Store.Allowed(site, ip, a.now())
	if err != nil {
		log.Printf("auth: store error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return false
	}
	if !ok {
		if err := a.Store.LogDenied(site, ip, a.now()); err != nil {
			log.Printf("auth: log denied: %v", err)
		}
		if denyCode == http.StatusForbidden {
			http.Error(w, "forbidden", denyCode)
		} else {
			w.WriteHeader(denyCode) // no body, no hint
		}
	}
	return ok
}

// authHandler is the nginx auth_request target: 204 = allow, 403 = deny, 500 = error (nginx denies).
func (a *App) authHandler(w http.ResponseWriter, r *http.Request) {
	if a.allowed(w, r, http.StatusForbidden) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// proxyHandler checks the IP, then reverse-proxies to the site's upstream (for nginx builds
// without auth_request). Streaming (SSE) is flushed immediately; WebSocket upgrades pass through.
func (a *App) proxyHandler(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(w, r, statusDrop) {
		return
	}
	up, err := a.Store.Upstream(r.Header.Get("X-Site"))
	target, perr := url.Parse(up)
	if err != nil || up == "" || perr != nil {
		http.Error(w, "no upstream", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto"} { // Rewrite strips these by default
				if v := pr.In.Header[h]; v != nil {
					pr.Out.Header[h] = v
				}
			}
			pr.Out.Header.Del("X-Site")
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: %v", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}
