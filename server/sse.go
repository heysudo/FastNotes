// Server-Sent Events hub for near-real-time sync.
// On every note write the server broadcasts {id, version, origin} to all
// connected clients; a client debounces these into a normal delta pull and
// ignores events tagged with its own origin id. No note content crosses the
// SSE channel — only the fact that something changed.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxSSEClients = 1024 // bound concurrent event streams

type eventHub struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

var (
	events    *eventHub
	sseSecret []byte
)

func initEvents() {
	events = &eventHub{subs: make(map[chan string]struct{})}
	sseSecret = make([]byte, 32)
	rand.Read(sseSecret)
}

func (h *eventHub) subscribe() (chan string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= maxSSEClients {
		return nil, false
	}
	ch := make(chan string, 16)
	h.subs[ch] = struct{}{}
	return ch, true
}

func (h *eventHub) unsubscribe(ch chan string) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *eventHub) broadcast(id string, version int, origin string) {
	if h == nil {
		return
	}
	msg, _ := json.Marshal(map[string]any{"id": id, "version": version, "origin": origin})
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- string(msg):
		default: // slow consumer — drop; its periodic poll will catch up
		}
	}
	h.mu.Unlock()
}

// ---- tickets: EventSource can't send Authorization headers, so an
// authenticated request mints a short-lived signed ticket used as a query param. ----

func ticketMAC(msg string) []byte {
	mac := hmac.New(sha256.New, sseSecret)
	mac.Write([]byte(msg))
	mac.Write(getAuthHash()) // bind the ticket to the current identity
	return mac.Sum(nil)
}

func signTicket(expUnix int64) string {
	msg := strconv.FormatInt(expUnix, 10)
	return msg + "." + hex.EncodeToString(ticketMAC(msg))
}

func verifyTicket(t string) bool {
	parts := strings.SplitN(t, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := hex.EncodeToString(ticketMAC(parts[0]))
	return hmac.Equal([]byte(want), []byte(parts[1]))
}

func handleEventTicket(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"ticket": signTicket(time.Now().Add(time.Hour).Unix())})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	if !verifyTicket(r.URL.Query().Get("ticket")) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, ok := events.subscribe()
	if !ok {
		http.Error(w, `{"error":"too many connections"}`, http.StatusServiceUnavailable)
		return
	}
	defer events.unsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx/NPM response buffering
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n") // client reconnect backoff
	flusher.Flush()

	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n") // comment line keeps the connection warm
			flusher.Flush()
		}
	}
}
