// FastNotes — zero-knowledge encrypted notes server.
// Stores only ciphertext blobs; all encryption/decryption happens in the browser.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

//go:embed web
var webFS embed.FS

var (
	db       *bolt.DB
	bNotes   = []byte("notes")  // id -> json{blob, updated_at, deleted}
	bImages  = []byte("images") // id -> raw encrypted bytes
	bMeta    = []byte("meta")   // config: salt, auth_hash, kdf_iters
	authMu   sync.Mutex
	failures = map[string][]int64{} // ip -> unix seconds of recent auth failures

	authStateMu sync.RWMutex // guards authHash / authKnown
	authHash    []byte       // cached sha256 of auth token
	authKnown   bool

	trustedProxies []*net.IPNet // peers whose X-Forwarded-For header we honor
)

type noteRec struct {
	ID        string `json:"id"`
	Blob      string `json:"blob,omitempty"` // base64 ciphertext
	UpdatedAt int64  `json:"updated_at"`     // unix ms, server-assigned
	Deleted   bool   `json:"deleted,omitempty"`
	Version   int    `json:"version"` // monotonic per-note; drives optimistic concurrency
}

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	var err error
	db, err = bolt.Open(dataDir+"/fastnotes.db", 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bNotes, bImages, bMeta} {
			if _, e := tx.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	loadAuthHash()
	initTrustedProxies()
	initEvents()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/bootstrap", handleBootstrap)
	mux.HandleFunc("POST /api/setup", handleSetup)
	mux.HandleFunc("GET /api/notes", auth(handleListNotes))
	mux.HandleFunc("PUT /api/notes/{id}", auth(handlePutNote))
	mux.HandleFunc("DELETE /api/notes/{id}", auth(handleDeleteNote))
	mux.HandleFunc("GET /api/images/{id}", auth(handleGetImage))
	mux.HandleFunc("PUT /api/images/{id}", auth(handlePutImage))
	mux.HandleFunc("DELETE /api/images/{id}", auth(handleDeleteImage))
	mux.HandleFunc("GET /api/export", auth(handleExport))
	mux.HandleFunc("POST /api/ai/cover", auth(handleAICover))
	mux.HandleFunc("POST /api/events/ticket", auth(handleEventTicket))
	mux.HandleFunc("GET /api/events", handleEvents) // auth via ticket query param (EventSource can't set headers)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	// Static frontend (embedded).
	sub, _ := fs.Sub(webFS, "web")
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			p = "index.html" // SPA fallback
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "vendor/") || strings.HasPrefix(p, "icons/") || strings.HasPrefix(p, "fonts/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8000"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("FastNotes listening on %s (data: %s)", addr, dataDir)
	log.Fatal(srv.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; worker-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// ---------- auth ----------

func loadAuthHash() {
	db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bMeta).Get([]byte("auth_hash")); v != nil {
			setAuth(v)
		}
		return nil
	})
}

// authKnownSafe / getAuthHash / setAuth serialize all access to the auth-state
// globals, which are read on every request and written during setup.
func authKnownSafe() bool {
	authStateMu.RLock()
	defer authStateMu.RUnlock()
	return authKnown
}

func getAuthHash() []byte {
	authStateMu.RLock()
	defer authStateMu.RUnlock()
	return authHash
}

func setAuth(h []byte) {
	authStateMu.Lock()
	defer authStateMu.Unlock()
	authHash = append([]byte(nil), h...)
	authKnown = true
}

// initTrustedProxies parses TRUSTED_PROXIES (comma-separated IPs/CIDRs). Only
// requests whose direct peer is in this set have their X-Forwarded-For honored;
// for every other connection the header is ignored, so it cannot be spoofed to
// defeat the per-IP rate limiter or to grow the failures map without bound.
func initTrustedProxies() {
	trustedProxies = nil
	for _, c := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			trustedProxies = append(trustedProxies, n)
		} else {
			log.Printf("TRUSTED_PROXIES: ignoring invalid entry %q: %v", c, err)
		}
	}
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the address used for rate-limiting. X-Forwarded-For is
// consulted ONLY when the direct connection comes from a configured trusted
// proxy; the value used is the right-most XFF entry that is not itself a trusted
// proxy (i.e. the address our proxy actually observed). This prevents a client
// from spoofing the header to evade the limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isTrustedProxy(net.ParseIP(host)) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		s := strings.TrimSpace(parts[i])
		ip := net.ParseIP(s)
		if ip == nil || isTrustedProxy(ip) {
			continue
		}
		return s
	}
	return host
}

func rateLimited(ip string) bool {
	authMu.Lock()
	defer authMu.Unlock()
	now := time.Now().Unix()
	recent := failures[ip][:0]
	for _, t := range failures[ip] {
		if now-t < 300 {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(failures, ip) // don't retain empty buckets
		return false
	}
	failures[ip] = recent
	return len(recent) >= 10 // 10 failures per 5 min
}

func recordFailure(ip string) {
	authMu.Lock()
	defer authMu.Unlock()
	failures[ip] = append(failures[ip], time.Now().Unix())
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authKnownSafe() {
			http.Error(w, `{"error":"not configured"}`, http.StatusForbidden)
			return
		}
		ip := clientIP(r)
		if rateLimited(ip) {
			http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		raw, err := base64.StdEncoding.DecodeString(tok)
		if err != nil || len(raw) == 0 {
			recordFailure(ip)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h := sha256.Sum256(raw)
		if subtle.ConstantTimeCompare(h[:], getAuthHash()) != 1 {
			recordFailure(ip)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---------- handlers ----------

func handleBootstrap(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"configured": authKnownSafe(), "ai": aiEnabled()}
	db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(bMeta)
		if s := m.Get([]byte("kdf_salt")); s != nil {
			resp["salt"] = string(s)
		}
		if it := m.Get([]byte("kdf_iters")); it != nil {
			n, _ := strconv.Atoi(string(it))
			resp["iters"] = n
		}
		return nil
	})
	writeJSON(w, resp)
}

// handleSetup registers the master password artifacts. Only allowed once.
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if authKnownSafe() {
		http.Error(w, `{"error":"already configured"}`, http.StatusConflict)
		return
	}
	var req struct {
		Salt       string `json:"salt"`        // base64, client-generated
		Iters      int    `json:"iters"`       // PBKDF2 iterations
		AuthToken  string `json:"auth_token"`  // base64 HKDF-derived token
		SetupToken string `json:"setup_token"` // optional; required when SETUP_TOKEN is set
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil ||
		req.Salt == "" || req.AuthToken == "" || req.Iters < 100000 {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	// Optional guard against first-run (trust-on-first-use) takeover on a
	// publicly-reachable setup endpoint: if the operator set SETUP_TOKEN, the
	// very first registration must present it.
	if want := os.Getenv("SETUP_TOKEN"); want != "" {
		if subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(want)) != 1 {
			http.Error(w, `{"error":"setup token required"}`, http.StatusUnauthorized)
			return
		}
	}
	raw, err := base64.StdEncoding.DecodeString(req.AuthToken)
	if err != nil || len(raw) < 16 {
		http.Error(w, `{"error":"bad token"}`, http.StatusBadRequest)
		return
	}
	h := sha256.Sum256(raw)
	wrote := false
	err = db.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(bMeta)
		if m.Get([]byte("auth_hash")) != nil {
			return nil // configured concurrently — never overwrite an existing hash
		}
		if e := m.Put([]byte("kdf_salt"), []byte(req.Salt)); e != nil {
			return e
		}
		if e := m.Put([]byte("kdf_iters"), []byte(strconv.Itoa(req.Iters))); e != nil {
			return e
		}
		if e := m.Put([]byte("auth_hash"), h[:]); e != nil {
			return e
		}
		wrote = true
		return nil
	})
	if err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	// Only adopt the in-memory hash if THIS request actually persisted it, so a
	// racing setup can't diverge the cached hash from what's on disk.
	if !wrote {
		http.Error(w, `{"error":"already configured"}`, http.StatusConflict)
		return
	}
	setAuth(h[:])
	log.Printf("setup: master password registered")
	writeJSON(w, map[string]any{"ok": true})
}

func handleListNotes(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	out := []noteRec{}
	db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bNotes).ForEach(func(k, v []byte) error {
			var n noteRec
			if json.Unmarshal(v, &n) == nil && n.UpdatedAt > since {
				out = append(out, n)
			}
			return nil
		})
	})
	writeJSON(w, map[string]any{"notes": out, "now": time.Now().UnixMilli()})
}

func handlePutNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	var req struct {
		Blob        string `json:"blob"`
		BaseVersion int    `json:"base_version"` // version this edit was based on
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil || req.Blob == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	var saved noteRec
	var conflict *noteRec
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bNotes)
		var cur noteRec
		if v := b.Get([]byte(id)); v != nil {
			json.Unmarshal(v, &cur)
		}
		// Optimistic concurrency: only accept a write based on the current version.
		if cur.Version != req.BaseVersion {
			c := cur
			conflict = &c
			return nil
		}
		saved = noteRec{ID: id, Blob: req.Blob, UpdatedAt: time.Now().UnixMilli(), Version: cur.Version + 1}
		return b.Put([]byte(id), mustJSON(saved))
	})
	if err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	if conflict != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "conflict", "note": conflict})
		return
	}
	events.broadcast(id, saved.Version, r.Header.Get("X-Client-Id"))
	writeJSON(w, map[string]any{"ok": true, "version": saved.Version, "updated_at": saved.UpdatedAt})
}

func handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	var ver int
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bNotes)
		var cur noteRec
		if v := b.Get([]byte(id)); v != nil {
			json.Unmarshal(v, &cur)
		}
		ver = cur.Version + 1
		// Delete is an explicit user action — it always wins (bumps version, tombstones).
		return b.Put([]byte(id), mustJSON(noteRec{ID: id, UpdatedAt: time.Now().UnixMilli(), Deleted: true, Version: ver}))
	}); err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	events.broadcast(id, ver, r.Header.Get("X-Client-Id"))
	writeJSON(w, map[string]any{"ok": true})
}

func handleGetImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	var data []byte
	db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bImages).Get([]byte(id)); v != nil {
			data = append([]byte(nil), v...)
		}
		return nil
	})
	if data == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Write(data)
}

func handlePutImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 16<<20)) // 16 MB cap
	if err != nil || len(data) == 0 {
		http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
		return
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bImages).Put([]byte(id), data)
	}); err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func handleDeleteImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bImages).Delete([]byte(id))
	}); err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleExport streams every ciphertext record as one JSON document (encrypted backup).
func handleExport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=fastnotes-encrypted-backup.json")
	type img struct {
		ID   string `json:"id"`
		Data string `json:"data"`
	}
	out := struct {
		Version int       `json:"version"`
		Salt    string    `json:"salt"`
		Iters   string    `json:"iters"`
		Notes   []noteRec `json:"notes"`
		Images  []img     `json:"images"`
	}{Version: 1}
	db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(bMeta)
		out.Salt = string(m.Get([]byte("kdf_salt")))
		out.Iters = string(m.Get([]byte("kdf_iters")))
		tx.Bucket(bNotes).ForEach(func(k, v []byte) error {
			var n noteRec
			if json.Unmarshal(v, &n) == nil && !n.Deleted {
				out.Notes = append(out.Notes, n)
			}
			return nil
		})
		return tx.Bucket(bImages).ForEach(func(k, v []byte) error {
			out.Images = append(out.Images, img{ID: string(k), Data: base64.StdEncoding.EncodeToString(v)})
			return nil
		})
	})
	json.NewEncoder(w).Encode(out)
}

// ---------- helpers ----------

func validID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
