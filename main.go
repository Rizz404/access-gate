package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	// `access-gate hash` reads a password on stdin and prints a bcrypt hash for GATE_ADMIN_HASH.
	if len(os.Args) > 1 && os.Args[1] == "hash" {
		pw, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		h, err := bcrypt.GenerateFromPassword([]byte(strings.TrimRight(pw, "\r\n")), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(h))
		return
	}

	hash := os.Getenv("GATE_ADMIN_HASH")
	if hash == "" {
		log.Fatal("GATE_ADMIN_HASH kosong; buat dengan: echo -n 'password' | access-gate hash")
	}
	var trusted []netip.Prefix
	for _, c := range strings.Split(env("GATE_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"), ",") {
		p, err := ParseCIDR(c)
		if err != nil {
			log.Fatalf("GATE_TRUSTED_PROXIES: %v", err)
		}
		trusted = append(trusted, p)
	}
	store, err := OpenStore(env("GATE_DB", "access-gate.db"))
	if err != nil {
		log.Fatal(err)
	}
	app := &App{Store: store, Trusted: trusted}
	admin := NewAdmin(app, []byte(hash), env("GATE_COOKIE_SECURE", "") == "1")
	if secret := os.Getenv("GATE_WEBHOOK_SECRET"); secret != "" {
		repo := os.Getenv("GATE_UPDATE_REPO")
		if repo == "" {
			log.Fatal("GATE_UPDATE_REPO (owner/name) wajib jika GATE_WEBHOOK_SECRET diisi")
		}
		exe, _ := os.Executable()
		up := &Updater{Secret: []byte(secret), Repo: repo, Exe: exe, Fetch: httpFetch, Retry: 15 * time.Second,
			Dir: env("GATE_STAGE_DIR", filepath.Dir(env("GATE_DB", "access-gate.db"))), Exit: func() { os.Exit(0) }}
		admin.Hook = http.HandlerFunc(up.Handler)
		log.Printf("webhook update enabled for %s", repo)
	}

	// /auth listens on its own address (loopback by default) so only the local nginx can reach it.
	authMux := http.NewServeMux()
	authMux.HandleFunc("/auth", app.authHandler)
	authAddr, adminAddr := env("GATE_ADDR_AUTH", "127.0.0.1:9181"), env("GATE_ADDR_ADMIN", "127.0.0.1:9180")
	go func() {
		srv := &http.Server{Addr: authAddr, Handler: authMux, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(srv.ListenAndServe())
	}()
	// proxy mode for nginx builds without auth_request; no write timeout so streaming responses can run long.
	proxyAddr := env("GATE_ADDR_PROXY", "127.0.0.1:9182")
	go func() {
		srv := &http.Server{Addr: proxyAddr, Handler: http.HandlerFunc(app.proxyHandler), ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServe())
	}()
	log.Printf("auth on %s, proxy on %s, admin on %s", authAddr, proxyAddr, adminAddr)
	srv := &http.Server{Addr: adminAddr, Handler: admin.Routes(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
