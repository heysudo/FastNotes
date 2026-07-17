package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// newTestDB opens a throwaway bolt db and resets the auth-state globals so each
// test starts unconfigured. Returns a cleanup func.
func newTestDB(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	var err error
	db, err = bolt.Open(dir+"/t.db", 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bNotes, bImages, bMeta} {
			if _, e := tx.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("init buckets: %v", err)
	}
	authStateMu.Lock()
	authHash, authKnown = nil, false
	authStateMu.Unlock()
	return func() { db.Close() }
}

func b64token(n int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, n))
}

// ---- clientIP: X-Forwarded-For must only be honored from trusted proxies ----

func TestClientIP_IgnoresSpoofedXFFFromUntrustedPeer(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	initTrustedProxies()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:5555" // public, NOT a trusted proxy
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("spoofed XFF honored: got %q, want the real peer 203.0.113.9", got)
	}
}

func TestClientIP_HonorsXFFFromTrustedProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	initTrustedProxies()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:443" // the trusted proxy
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("got %q, want client 198.51.100.7", got)
	}
}

func TestClientIP_WalksPastChainedTrustedProxies(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	initTrustedProxies()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	// client, spoof, then two trusted hops appended on the right
	r.Header.Set("X-Forwarded-For", "5.5.5.5, 198.51.100.7, 10.0.0.9")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("chain walk wrong: got %q, want 198.51.100.7", got)
	}
}

func TestClientIP_NoTrustedProxiesUsesPeer(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	initTrustedProxies()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.50:9000"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "192.0.2.50" {
		t.Fatalf("got %q, want 192.0.2.50", got)
	}
}

// ---- rate limiter: prunes empty buckets, caps at 10 per 5 min ----

func TestRateLimited_PrunesAndCaps(t *testing.T) {
	authMu.Lock()
	failures = map[string][]int64{}
	authMu.Unlock()

	ip := "9.9.9.9"
	for i := 0; i < 9; i++ {
		recordFailure(ip)
	}
	if rateLimited(ip) {
		t.Fatal("9 failures should not be rate limited")
	}
	recordFailure(ip)
	if !rateLimited(ip) {
		t.Fatal("10 failures should be rate limited")
	}

	// stale entries prune to nothing and the key is dropped
	authMu.Lock()
	failures["old"] = []int64{time.Now().Unix() - 1000}
	authMu.Unlock()
	if rateLimited("old") {
		t.Fatal("stale bucket should not be limited")
	}
	authMu.Lock()
	_, present := failures["old"]
	authMu.Unlock()
	if present {
		t.Fatal("empty bucket was not pruned — map can grow unbounded")
	}
}

// ---- SSE ticket: expiry, tamper, and identity binding ----

func TestVerifyTicket(t *testing.T) {
	sseSecret = make([]byte, 32)
	setAuth([]byte("identity-A"))

	good := signTicket(time.Now().Add(time.Hour).Unix())
	if !verifyTicket(good) {
		t.Fatal("fresh ticket should verify")
	}
	if verifyTicket(signTicket(time.Now().Add(-time.Hour).Unix())) {
		t.Fatal("expired ticket must not verify")
	}
	if verifyTicket(good + "x") {
		t.Fatal("tampered ticket must not verify")
	}
	// rotating the identity invalidates outstanding tickets
	setAuth([]byte("identity-B"))
	if verifyTicket(good) {
		t.Fatal("ticket must not survive an identity change")
	}
}

// ---- setup: token gate, single-registration, and no in-memory divergence ----

func doSetup(token, authToken string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"salt": "c2FsdA==", "iters": 600000, "auth_token": authToken, "setup_token": token,
	})
	r := httptest.NewRequest("POST", "/api/setup", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	handleSetup(w, r)
	return w
}

func TestSetup_TokenGate(t *testing.T) {
	defer newTestDB(t)()
	t.Setenv("SETUP_TOKEN", "s3cr3t")

	if w := doSetup("", b64token(16)); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing setup token: got %d, want 401", w.Code)
	}
	if w := doSetup("wrong", b64token(16)); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong setup token: got %d, want 401", w.Code)
	}
	if w := doSetup("s3cr3t", b64token(16)); w.Code != http.StatusOK {
		t.Fatalf("correct setup token: got %d, want 200", w.Code)
	}
	if !authKnownSafe() {
		t.Fatal("auth should be configured after successful setup")
	}
	// second attempt is rejected once configured
	if w := doSetup("s3cr3t", b64token(16)); w.Code != http.StatusConflict {
		t.Fatalf("second setup: got %d, want 409", w.Code)
	}
}

// TestSetup_ConcurrentNoDivergence proves the takeover-race fix: many setups run
// at once, exactly one persists, and the cached in-memory hash always equals the
// one on disk (the losers never overwrite it).
func TestSetup_ConcurrentNoDivergence(t *testing.T) {
	defer newTestDB(t)()

	const n = 24
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// distinct auth token per racer
			raw := make([]byte, 16)
			raw[0] = byte(i + 1)
			codes[i] = doSetup("", base64.StdEncoding.EncodeToString(raw)).Code
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		} else if c != http.StatusConflict {
			t.Fatalf("unexpected setup status %d", c)
		}
	}
	if ok != 1 {
		t.Fatalf("expected exactly one winning setup, got %d", ok)
	}

	// in-memory hash must equal the persisted hash — no divergence
	var stored []byte
	db.View(func(tx *bolt.Tx) error {
		stored = append([]byte(nil), tx.Bucket(bMeta).Get([]byte("auth_hash"))...)
		return nil
	})
	mem := getAuthHash()
	if len(mem) != sha256.Size || string(mem) != string(stored) {
		t.Fatalf("in-memory auth hash diverged from disk: mem=%x disk=%x", mem, stored)
	}
}
