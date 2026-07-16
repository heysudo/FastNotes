// FastNotes — zero-knowledge encrypted notes server.
// Stores only ciphertext blobs; all encryption/decryption happens in the browser.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
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
	db        *bolt.DB
	bNotes    = []byte("notes")  // id -> json{blob, updated_at, deleted}
	bImages   = []byte("images") // id -> raw encrypted bytes
	bMeta     = []byte("meta")   // config: salt, auth_hash, kdf_iters
	authMu    sync.Mutex
	failures  = map[string][]int64{} // ip -> unix seconds of recent auth failures
	authHash  []byte                 // cached sha256 of auth token
	authKnown bool
)

type noteRec struct {
	ID        string `json:"id"`
	Blob      string `json:"blob,omitempty"` // base64 ciphertext
	UpdatedAt int64  `json:"updated_at"`     // unix ms, server-assigned
	Deleted   bool   `json:"deleted,omitempty"`
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
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; worker-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// ---------- auth ----------

func loadAuthHash() {
	db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bMeta).Get([]byte("auth_hash"))
		if v != nil {
			authHash = append([]byte(nil), v...)
			authKnown = true
		}
		return nil
	})
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
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
		if !authKnown {
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
		if subtle.ConstantTimeCompare(h[:], authHash) != 1 {
			recordFailure(ip)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---------- handlers ----------

func handleBootstrap(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"configured": authKnown, "ai": aiEnabled()}
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
	if authKnown {
		http.Error(w, `{"error":"already configured"}`, http.StatusConflict)
		return
	}
	var req struct {
		Salt      string `json:"salt"`       // base64, client-generated
		Iters     int    `json:"iters"`      // PBKDF2 iterations
		AuthToken string `json:"auth_token"` // base64 HKDF-derived token
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil ||
		req.Salt == "" || req.AuthToken == "" || req.Iters < 100000 {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.AuthToken)
	if err != nil || len(raw) < 16 {
		http.Error(w, `{"error":"bad token"}`, http.StatusBadRequest)
		return
	}
	h := sha256.Sum256(raw)
	err = db.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(bMeta)
		if m.Get([]byte("auth_hash")) != nil {
			return nil
		}
		m.Put([]byte("kdf_salt"), []byte(req.Salt))
		m.Put([]byte("kdf_iters"), []byte(strconv.Itoa(req.Iters)))
		return m.Put([]byte("auth_hash"), h[:])
	})
	if err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	authHash = h[:]
	authKnown = true
	log.Printf("setup: master password registered (hash %s…)", hex.EncodeToString(h[:4]))
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
		Blob string `json:"blob"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil || req.Blob == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	n := noteRec{ID: id, Blob: req.Blob, UpdatedAt: time.Now().UnixMilli()}
	buf, _ := json.Marshal(n)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bNotes).Put([]byte(id), buf)
	}); err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "updated_at": n.UpdatedAt})
}

func handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	n := noteRec{ID: id, UpdatedAt: time.Now().UnixMilli(), Deleted: true}
	buf, _ := json.Marshal(n)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bNotes).Put([]byte(id), buf) // tombstone for sync
	}); err != nil {
		http.Error(w, `{"error":"db"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func handleGetImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bImages).Delete([]byte(id))
	})
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
