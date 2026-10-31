package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func sumHex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type fixture struct {
	u       *Updater
	dir     string
	exited  bool
	fetched []string
}

func newFixture(t *testing.T, bin []byte, sha string) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir()}
	exe := filepath.Join(f.dir, "running")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	f.u = &Updater{
		Secret: []byte("s3cret"), Repo: "Rizz404/access-gate", Dir: f.dir, Exe: exe, Retry: time.Millisecond,
		Go:   func(fn func()) { fn() },
		Exit: func() { f.exited = true },
		Fetch: func(url string) ([]byte, error) {
			f.fetched = append(f.fetched, url)
			if strings.HasSuffix(url, ".sha256") {
				return []byte(sha + "  " + assetName + "\n"), nil
			}
			return bin, nil
		},
	}
	return f
}

func post(u *Updater, event, body, sig string) int {
	r := httptest.NewRequest("POST", "/hooks/github", strings.NewReader(body))
	r.Header.Set("X-GitHub-Event", event)
	r.Header.Set("X-Hub-Signature-256", sig)
	w := httptest.NewRecorder()
	u.Handler(w, r)
	return w.Code
}

const okBody = `{"action":"completed","workflow_run":{"conclusion":"success","head_branch":"main"},"repository":{"full_name":"Rizz404/access-gate"}}`

func TestWebhookSignatureAndFilters(t *testing.T) {
	bin := []byte("new binary")
	f := newFixture(t, bin, sumHex(bin))

	if c := post(f.u, "workflow_run", okBody, "sha256=deadbeef"); c != http.StatusUnauthorized {
		t.Errorf("bad sig: %d", c)
	}
	if c := post(f.u, "workflow_run", okBody, ""); c != http.StatusUnauthorized {
		t.Errorf("missing sig: %d", c)
	}
	if c := post(f.u, "ping", "{}", sign("s3cret", "{}")); c != 200 {
		t.Errorf("ping: %d", c)
	}
	for name, body := range map[string]string{
		"other branch":  strings.Replace(okBody, `"main"`, `"dev"`, 1),
		"failed run":    strings.Replace(okBody, `"success"`, `"failure"`, 1),
		"other repo":    strings.Replace(okBody, "Rizz404/access-gate", "evil/fork", 1),
		"not completed": strings.Replace(okBody, `"completed"`, `"requested"`, 1),
	} {
		if c := post(f.u, "workflow_run", body, sign("s3cret", body)); c != http.StatusNoContent {
			t.Errorf("%s: %d want 204", name, c)
		}
	}
	if f.exited || len(f.fetched) != 0 {
		t.Fatal("filtered events must not trigger an update")
	}
}

func TestWebhookUpdateStagesAndExits(t *testing.T) {
	bin := []byte("new binary")
	f := newFixture(t, bin, sumHex(bin))
	if c := post(f.u, "workflow_run", okBody, sign("s3cret", okBody)); c != http.StatusAccepted {
		t.Fatalf("code %d", c)
	}
	got, err := os.ReadFile(filepath.Join(f.dir, "access-gate.new"))
	if err != nil || string(got) != "new binary" || !f.exited {
		t.Fatalf("staged=%q err=%v exited=%v", got, err, f.exited)
	}
	if f.fetched[0] != "https://github.com/Rizz404/access-gate/releases/download/latest/"+assetName {
		t.Errorf("unexpected url %s", f.fetched[0])
	}
}

func TestUpdateRejectsBadSumAndSkipsSame(t *testing.T) {
	bad := newFixture(t, []byte("new binary"), strings.Repeat("0", 64))
	bad.u.update()
	if bad.exited {
		t.Error("sha mismatch must not restart")
	}
	if _, err := os.Stat(filepath.Join(bad.dir, "access-gate.new")); err == nil {
		t.Error("sha mismatch must not stage")
	}

	same := newFixture(t, []byte("old binary"), sumHex([]byte("old binary")))
	same.u.update()
	if same.exited {
		t.Error("identical binary must not restart (webhook redelivery loop)")
	}

	fail := newFixture(t, nil, "")
	fail.u.Fetch = func(string) ([]byte, error) { return nil, errors.New("404") }
	fail.u.update()
	if fail.exited {
		t.Error("fetch failure must not restart")
	}
}
