// AI cover generation, BYOK multi-provider.
//
// LLM step (writes the image prompt from the note text) — first configured wins,
// or force with LLM_PROVIDER=anthropic|openai|gemini:
//   ANTHROPIC_API_KEY  -> Claude (LLM_MODEL, default claude-haiku-4-5)
//   OPENAI_API_KEY     -> OpenAI (LLM_MODEL, default gpt-4o-mini)
//   GEMINI_API_KEY     -> Gemini (LLM_MODEL, default gemini-2.5-flash)
//
// Image step — first configured wins, or force with IMAGE_PROVIDER=higgsfield|openai|gemini|worker:
//   HF_API_KEY+HF_API_SECRET -> Higgsfield platform API (IMAGE_MODEL endpoint)
//   OPENAI_API_KEY           -> OpenAI images (IMAGE_MODEL, default gpt-image-1)
//   GEMINI_API_KEY           -> Gemini image out (IMAGE_MODEL, default gemini-2.5-flash-image)
//   AI_WORKER_URL            -> Claude Code + Higgsfield MCP sidecar
//
// PRIVACY: this is the one deliberate exception to the zero-knowledge model —
// the client sends this note's title/text in plaintext to /api/ai/cover, which
// forwards it to the configured LLM. Nothing is stored or logged; the image
// returns to the client and is encrypted there like any upload. The feature is
// completely off unless keys are configured.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const promptSystem = `You write prompts for an AI image generator. Given a note's title and text, produce ONE image prompt for the note's cover, in the style of clean corporate cards:
- If the note is about one or more identifiable brands/companies/products (e.g. HSBC, Kotak, Singapore Airlines, Aadhaar), the prompt must be: that brand's logo (or a small tasteful collection of the logos), centered, flat vector style, on a PLAIN SOLID background in the brand's primary color.
- If no brand is present, choose one simple iconic flat symbol representing the topic (e.g. an aeroplane, a shopping basket, a key) on a plain solid muted background color that fits the topic.
- Always minimal: no scenery, no people, no gradients unless the brand uses one, no extra text.
Reply with ONLY the image prompt on a single line, nothing else.`

var (
	aiHTTP     = &http.Client{Timeout: 120 * time.Second}
	hfEndpoint string
	hfMu       sync.Mutex
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hfCreds() string {
	if c := os.Getenv("HF_CREDENTIALS"); c != "" {
		return c
	}
	k, s := os.Getenv("HF_API_KEY"), os.Getenv("HF_API_SECRET")
	if k != "" && s != "" {
		return k + ":" + s
	}
	return ""
}

func workerURL() string { return os.Getenv("AI_WORKER_URL") }

func llmProvider() string {
	if p := os.Getenv("LLM_PROVIDER"); p != "" {
		return p
	}
	switch {
	case os.Getenv("ANTHROPIC_API_KEY") != "":
		return "anthropic"
	case os.Getenv("OPENAI_API_KEY") != "":
		return "openai"
	case os.Getenv("GEMINI_API_KEY") != "":
		return "gemini"
	}
	return ""
}

func imageProvider() string {
	if p := os.Getenv("IMAGE_PROVIDER"); p != "" {
		return p
	}
	switch {
	case hfCreds() != "":
		return "higgsfield"
	case os.Getenv("OPENAI_API_KEY") != "":
		return "openai"
	case os.Getenv("GEMINI_API_KEY") != "":
		return "gemini"
	case workerURL() != "":
		return "worker"
	}
	return ""
}

func aiEnabled() bool { return llmProvider() != "" && imageProvider() != "" }

// ---------- HTTP handler ----------

func handleAICover(w http.ResponseWriter, r *http.Request) {
	if !aiEnabled() {
		http.Error(w, `{"error":"ai not configured"}`, http.StatusNotImplemented)
		return
	}
	var req struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(req.Title + "\n" + req.Text)
	if len(note) < 8 {
		http.Error(w, `{"error":"note too short"}`, http.StatusBadRequest)
		return
	}
	if len(note) > 4000 {
		note = note[:4000]
	}

	prompt, err := llmPrompt(note)
	if err != nil {
		log.Printf("ai: prompt generation failed (%s): %v", llmProvider(), err)
		http.Error(w, `{"error":"prompt generation failed"}`, http.StatusBadGateway)
		return
	}
	data, mime, err := generateImage(prompt)
	if err != nil {
		log.Printf("ai: image generation failed (%s): %v", imageProvider(), err)
		http.Error(w, `{"error":"image generation failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{
		"prompt": prompt,
		"mime":   mime,
		"image":  base64.StdEncoding.EncodeToString(data),
	})
}

// ---------- LLM providers ----------

func llmPrompt(note string) (string, error) {
	switch llmProvider() {
	case "anthropic":
		return anthropicPrompt(note)
	case "openai":
		return openaiPrompt(note)
	case "gemini":
		return geminiPrompt(note)
	}
	return "", fmt.Errorf("no llm provider configured")
}

func anthropicPrompt(note string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      env("LLM_MODEL", "claude-haiku-4-5"),
		"max_tokens": 200,
		"system":     promptSystem,
		"messages":   []map[string]any{{"role": "user", "content": note}},
	})
	rq, _ := http.NewRequest("POST", strings.TrimRight(env("ANTHROPIC_BASE_URL", "https://api.anthropic.com"), "/")+"/v1/messages", bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
	rq.Header.Set("anthropic-version", "2023-06-01")
	raw, err := doJSON(rq)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Content) == 0 {
		return "", fmt.Errorf("anthropic: unexpected response")
	}
	return nonEmpty(out.Content[0].Text)
}

func openaiPrompt(note string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": env("LLM_MODEL", "gpt-4o-mini"),
		"messages": []map[string]any{
			{"role": "system", "content": promptSystem},
			{"role": "user", "content": note},
		},
		"max_tokens": 200,
	})
	rq, _ := http.NewRequest("POST", strings.TrimRight(env("OPENAI_BASE_URL", "https://api.openai.com"), "/")+"/v1/chat/completions", bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_API_KEY"))
	raw, err := doJSON(rq)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: unexpected response")
	}
	return nonEmpty(out.Choices[0].Message.Content)
}

func geminiPrompt(note string) (string, error) {
	model := env("LLM_MODEL", "gemini-2.5-flash")
	body, _ := json.Marshal(map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]any{{"text": promptSystem}}},
		"contents":           []map[string]any{{"parts": []map[string]any{{"text": note}}}},
	})
	url := strings.TrimRight(env("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com"), "/") +
		"/v1beta/models/" + model + ":generateContent"
	rq, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("x-goog-api-key", os.Getenv("GEMINI_API_KEY"))
	raw, err := doJSON(rq)
	if err != nil {
		return "", err
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: unexpected response")
	}
	return nonEmpty(out.Candidates[0].Content.Parts[0].Text)
}

// ---------- image providers ----------

func generateImage(prompt string) ([]byte, string, error) {
	switch imageProvider() {
	case "higgsfield":
		url, err := higgsfieldImage(prompt)
		if err != nil {
			return nil, "", err
		}
		return fetchImage(url)
	case "openai":
		return openaiImage(prompt)
	case "gemini":
		return geminiImage(prompt)
	case "worker":
		url, err := workerImage(prompt)
		if err != nil {
			return nil, "", err
		}
		return fetchImage(url)
	}
	return nil, "", fmt.Errorf("no image provider configured")
}

func fetchImage(url string) ([]byte, string, error) {
	resp, err := aiHTTP.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("image fetch %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", err
	}
	mime := resp.Header.Get("Content-Type")
	if mime == "" {
		mime = "image/png"
	}
	return data, mime, nil
}

func openaiImage(prompt string) ([]byte, string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":  env("IMAGE_MODEL", "gpt-image-1"),
		"prompt": prompt,
		"size":   "1536x1024",
		"n":      1,
	})
	rq, _ := http.NewRequest("POST", strings.TrimRight(env("OPENAI_BASE_URL", "https://api.openai.com"), "/")+"/v1/images/generations", bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_API_KEY"))
	raw, err := doJSON(rq)
	if err != nil {
		return nil, "", err
	}
	var out struct {
		Data []struct {
			B64  string `json:"b64_json"`
			URL  string `json:"url"`
			Mime string `json:"mime_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Data) == 0 {
		return nil, "", fmt.Errorf("openai images: unexpected response")
	}
	if out.Data[0].B64 != "" {
		data, err := base64.StdEncoding.DecodeString(out.Data[0].B64)
		return data, "image/png", err
	}
	if out.Data[0].URL != "" {
		return fetchImage(out.Data[0].URL)
	}
	return nil, "", fmt.Errorf("openai images: no image in response")
}

func geminiImage(prompt string) ([]byte, string, error) {
	model := env("IMAGE_MODEL", "gemini-2.5-flash-image")
	body, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{{"parts": []map[string]any{{"text": prompt}}}},
	})
	url := strings.TrimRight(env("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com"), "/") +
		"/v1beta/models/" + model + ":generateContent"
	rq, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	rq.Header.Set("x-goog-api-key", os.Getenv("GEMINI_API_KEY"))
	raw, err := doJSON(rq)
	if err != nil {
		return nil, "", err
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					InlineData *struct {
						MimeType string `json:"mimeType"`
						Data     string `json:"data"`
					} `json:"inlineData"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Candidates) == 0 {
		return nil, "", fmt.Errorf("gemini image: unexpected response %.200s", raw)
	}
	for _, p := range out.Candidates[0].Content.Parts {
		if p.InlineData != nil && p.InlineData.Data != "" {
			data, err := base64.StdEncoding.DecodeString(p.InlineData.Data)
			mime := p.InlineData.MimeType
			if mime == "" {
				mime = "image/png"
			}
			return data, mime, err
		}
	}
	return nil, "", fmt.Errorf("gemini image: no inline image in response")
}

// higgsfieldImage submits a text-to-image job on the Higgsfield platform API
// and polls until an image URL is ready.
func higgsfieldImage(prompt string) (string, error) {
	base := env("HF_BASE_URL", "https://platform.higgsfield.ai")
	endpoints := candidateEndpoints()
	input := map[string]any{"prompt": prompt, "aspect_ratio": "3:2"}

	var lastErr error
	for _, ep := range endpoints {
		url := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(ep, "/")
		for _, body := range []map[string]any{{"input": input}, input} {
			b, _ := json.Marshal(body)
			rq, _ := http.NewRequest("POST", url, bytes.NewReader(b))
			rq.Header.Set("Content-Type", "application/json")
			rq.Header.Set("Authorization", "Key "+hfCreds())
			resp, err := aiHTTP.Do(rq)
			if err != nil {
				lastErr = err
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == 404 || resp.StatusCode == 405 {
				lastErr = fmt.Errorf("endpoint %s: %d", ep, resp.StatusCode)
				break
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return "", fmt.Errorf("higgsfield auth failed (%d): check HF keys", resp.StatusCode)
			}
			if resp.StatusCode >= 400 {
				lastErr = fmt.Errorf("endpoint %s: %d %.300s", ep, resp.StatusCode, raw)
				continue
			}
			var job struct {
				RequestID string `json:"request_id"`
				StatusURL string `json:"status_url"`
			}
			if err := json.Unmarshal(raw, &job); err != nil || (job.StatusURL == "" && job.RequestID == "") {
				lastErr = fmt.Errorf("endpoint %s: unparseable job response %.200s", ep, raw)
				continue
			}
			statusURL := job.StatusURL
			if statusURL == "" {
				statusURL = strings.TrimRight(base, "/") + "/requests/" + job.RequestID + "/status"
			}
			hfMu.Lock()
			if hfEndpoint != ep {
				hfEndpoint = ep
				log.Printf("ai: higgsfield endpoint in use: %s", ep)
			}
			hfMu.Unlock()
			return hfPoll(statusURL)
		}
	}
	return "", fmt.Errorf("no working higgsfield endpoint: %v", lastErr)
}

func candidateEndpoints() []string {
	if ep := os.Getenv("IMAGE_MODEL"); ep != "" && imageProvider() == "higgsfield" && strings.Contains(ep, "/") {
		return []string{ep}
	}
	if ep := os.Getenv("HF_IMAGE_ENDPOINT"); ep != "" {
		return []string{ep}
	}
	hfMu.Lock()
	cached := hfEndpoint
	hfMu.Unlock()
	list := []string{
		"gpt-image-2/text-to-image",
		"openai/gpt-image-2/text-to-image",
		"gpt-image/text-to-image",
		"v1/text2image/gpt-image-2",
		"flux-pro/kontext/max/text-to-image", // known-good fallback
	}
	if cached != "" {
		return append([]string{cached}, list...)
	}
	return list
}

func hfPoll(statusURL string) (string, error) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		rq, _ := http.NewRequest("GET", statusURL, nil)
		rq.Header.Set("Authorization", "Key "+hfCreds())
		resp, err := aiHTTP.Do(rq)
		if err != nil {
			return "", err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var st struct {
			Status string `json:"status"`
			Images []struct {
				URL string `json:"url"`
			} `json:"images"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			return "", fmt.Errorf("status parse: %.200s", raw)
		}
		switch st.Status {
		case "completed":
			if len(st.Images) > 0 && st.Images[0].URL != "" {
				return st.Images[0].URL, nil
			}
			return "", fmt.Errorf("completed but no image url")
		case "failed", "nsfw", "canceled":
			return "", fmt.Errorf("generation %s", st.Status)
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("generation timed out")
}

// workerImage asks the sidecar (Claude Code + Higgsfield MCP) for an image URL.
func workerImage(prompt string) (string, error) {
	body, _ := json.Marshal(map[string]string{"prompt": prompt})
	rq, _ := http.NewRequest("POST", strings.TrimRight(workerURL(), "/")+"/generate", bytes.NewReader(body))
	rq.Header.Set("Content-Type", "application/json")
	resp, err := aiHTTP.Do(rq)
	if err != nil {
		return "", fmt.Errorf("worker unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		URL   string `json:"url"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("worker: unparseable response %.200s", raw)
	}
	if resp.StatusCode != 200 || out.URL == "" {
		return "", fmt.Errorf("worker: %s", out.Error)
	}
	return out.URL, nil
}

// ---------- helpers ----------

func doJSON(rq *http.Request) ([]byte, error) {
	resp, err := aiHTTP.Do(rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %d %.300s", rq.URL.Host, resp.StatusCode, raw)
	}
	return raw, nil
}

func nonEmpty(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty llm response")
	}
	return s, nil
}
