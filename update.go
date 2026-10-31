package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	assetName = "access-gate-linux-amd64"
	maxAsset  = 64 << 20
)

// Updater is a GitHub-webhook-driven self-update. On a signed `workflow_run` success event for
// the main branch it downloads the release asset of Repo (fixed URL, never taken from the
// payload), verifies its sha256, stages it in Dir as "access-gate.new" and exits; systemd
// (Restart=always + ExecStartPre) installs the staged binary and starts it.
// shortcut: sha256 comes from the same release as the binary, so it guards corruption, not a
// compromised repo; trust = GitHub repo access. Upgrade to signed artifacts if that matters.
type Updater struct {
	Secret []byte
	Repo   string // owner/name
	Dir    string // writable staging dir
	Exe    string // running binary, to skip no-op updates
	Fetch  func(url string) ([]byte, error)
	Exit   func()
	Go     func(func()) // test hook; default runs in a goroutine
	Retry  time.Duration
}

func validSig(secret, body []byte, header string) bool {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	want := "sha256=" + hex.EncodeToString(m.Sum(nil))
	return hmac.Equal([]byte(want), []byte(header))
}

func httpFetch(url string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAsset+1))
	if err == nil && len(b) > maxAsset {
		err = errors.New("asset too large")
	}
	return b, err
}

func (u *Updater) Handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || !validSig(u.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	switch r.Header.Get("X-GitHub-Event") {
	case "ping":
		io.WriteString(w, "pong\n")
	case "workflow_run":
		var p struct {
			Action      string `json:"action"`
			WorkflowRun struct {
				Conclusion string `json:"conclusion"`
				HeadBranch string `json:"head_branch"`
			} `json:"workflow_run"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if json.Unmarshal(body, &p) != nil || p.Action != "completed" || p.WorkflowRun.Conclusion != "success" ||
			p.WorkflowRun.HeadBranch != "main" || !strings.EqualFold(p.Repository.FullName, u.Repo) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		run := func() { u.update() }
		if u.Go != nil {
			u.Go(run)
		} else {
			go run()
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// update fetches and stages the latest release binary, then exits so systemd swaps it in.
func (u *Updater) update() {
	var err error
	for i := 0; i < 3; i++ { // release CDN can lag right after upload
		if err = u.stage(); err == nil || errors.Is(err, errUpToDate) {
			break
		}
		log.Printf("update attempt %d: %v", i+1, err)
		time.Sleep(u.Retry)
	}
	switch {
	case errors.Is(err, errUpToDate):
		log.Print("update: already running the latest binary")
	case err != nil:
		log.Printf("update failed: %v", err)
	default:
		log.Print("update: staged new binary, restarting")
		u.Exit()
	}
}

var errUpToDate = errors.New("up to date")

func (u *Updater) stage() error {
	base := "https://github.com/" + u.Repo + "/releases/download/latest/" + assetName
	bin, err := u.Fetch(base)
	if err != nil {
		return err
	}
	sumFile, err := u.Fetch(base + ".sha256")
	if err != nil {
		return err
	}
	f := strings.Fields(string(sumFile))
	got := sha256.Sum256(bin)
	if len(f) == 0 || !strings.EqualFold(f[0], hex.EncodeToString(got[:])) {
		return errors.New("sha256 mismatch")
	}
	if cur, err := os.ReadFile(u.Exe); err == nil && sha256.Sum256(cur) == got {
		return errUpToDate
	}
	tmp := filepath.Join(u.Dir, "access-gate.new.tmp")
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.Dir, "access-gate.new"))
}
