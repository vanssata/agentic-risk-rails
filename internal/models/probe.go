package models

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Provider API flavours.
const (
	Anthropic  = "anthropic"
	OpenAI     = "openai"
	OpenRouter = "openrouter"
)

// AccountHash identifies the credential or profile a cache entry belongs to.
func AccountHash(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(s[:6])
}

// HTTPProber confirms each candidate with one max_tokens:1 completion (DES §4.3.2).
// The list endpoint is not used: filtering by key is unproven (models.md).
type HTTPProber struct {
	Kind    string // Anthropic | OpenAI | OpenRouter
	BaseURL string
	Key     string
	Client  *http.Client
	Now     func() time.Time
}

func (p HTTPProber) Runtime() string { return p.Kind }

func (p HTTPProber) Probe(ctx context.Context, candidates []string) ([]core.ProbeResult, error) {
	cl := p.Client
	if cl == nil {
		// Never follow redirects: x-api-key / Authorization must not reach another host.
		cl = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	var out []core.ProbeResult
	for _, m := range candidates {
		r := core.ProbeResult{Model: m, ProbedAt: now()}
		r.State, r.Error = p.one(ctx, cl, m)
		out = append(out, r)
	}
	return out, nil
}

func (p HTTPProber) one(ctx context.Context, cl *http.Client, model string) (core.ModelState, string) {
	body := map[string]any{"model": model, "max_tokens": 1, "messages": []map[string]string{{"role": "user", "content": "ok"}}}
	path := "/v1/messages"
	switch p.Kind {
	case OpenAI:
		path = "/v1/chat/completions"
		delete(body, "max_tokens")
		body["max_completion_tokens"] = 1
	case OpenRouter:
		path = "/api/v1/chat/completions"
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.BaseURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return core.ModelUnknown, "request"
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Kind == Anthropic {
		req.Header.Set("x-api-key", p.Key)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else {
		req.Header.Set("Authorization", "Bearer "+p.Key)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return core.ModelUnknown, "network"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	st, typ := Classify(p.Kind, resp.StatusCode, raw)
	if len(typ) > 128 {
		typ = typ[:128] // the type comes from the remote body
	}
	return st, typ
}

// Classify maps an HTTP answer to a state by error type, falling back to the
// status only when the type is absent or unknown (DES §4.3.2). Anything not
// recognised as success or unavailability is UNKNOWN, never PASS.
func Classify(kind string, status int, body []byte) (core.ModelState, string) {
	if status >= 200 && status < 300 {
		// PASS needs a real completion: valid JSON, no top-level error, and the provider's completion field.
		var o map[string]json.RawMessage
		field := "choices"
		if kind == Anthropic {
			field = "content"
		}
		if json.Unmarshal(body, &o) != nil || o["error"] != nil || o[field] == nil {
			return core.ModelUnknown, "bad_success_body"
		}
		return core.ModelPass, ""
	}
	var e struct {
		Error struct {
			Type string `json:"type"`
			Code any    `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	typ := e.Error.Type
	if c, ok := e.Error.Code.(string); ok && typ == "" {
		typ = c
	}
	switch typ {
	case "permission_error", "not_found_error", "model_not_found", "authentication_error":
		return core.ModelFail, typ
	case "rate_limit_error", "overloaded_error", "insufficient_quota":
		return core.ModelUnknown, typ
	}
	if typ == "" {
		typ = fmt.Sprintf("http_%d", status)
	}
	switch status {
	case 401, 403, 404:
		return core.ModelFail, typ
	}
	return core.ModelUnknown, typ
}

// CLIProber probes a subscription runtime by running `<bin> -p ok --model <m> --max-turns 1
// --output-format json` (~100 tokens per model, DES §4.3.3g). Exit 0 and a model
// that answered matching m ⇒ PASS; another model answered ⇒ FAIL model_substituted
// (claude 2.1.317 runs Sonnet for `--model haiku` on a subscription login); the
// "issue with the selected model" / "restricted by your organization" wording ⇒
// FAIL; else UNKNOWN.
type CLIProber struct {
	Name string
	Bin  string
	Now  func() time.Time
}

func (p CLIProber) Runtime() string { return p.Name }

func (p CLIProber) Probe(ctx context.Context, candidates []string) ([]core.ProbeResult, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	// `-p` means "print" only for claude; for codex it selects a profile.
	if p.Name != "claude" {
		return nil, fmt.Errorf("cli probe supports only runtime claude, not %q", p.Name)
	}
	if strings.HasPrefix(p.Bin, "-") {
		return nil, fmt.Errorf("invalid binary %q", p.Bin)
	}
	for _, m := range candidates {
		if strings.HasPrefix(m, "-") {
			return nil, fmt.Errorf("invalid model %q", m)
		}
	}
	dir, err := os.MkdirTemp("", "rr-probe-") // a repo-local .claude/settings must not apply
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	var out []core.ProbeResult
	for _, m := range candidates {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		c := exec.CommandContext(cctx, p.Bin, "-p", "ok", "--model", m, "--max-turns", "1", "--output-format", "json", "--no-session-persistence")
		c.Dir = dir
		var stdout, stderr bytes.Buffer
		c.Stdout, c.Stderr = &stdout, &stderr
		err := c.Run()
		cancel()
		r := core.ProbeResult{Model: m, ProbedAt: now()}
		low := strings.ToLower(stdout.String() + stderr.String())
		switch {
		case err == nil:
			r.State, r.Error = answeredBy(stdout.Bytes(), m)
		case strings.Contains(low, "issue with the selected model") || strings.Contains(low, "restricted by your organization"):
			r.State, r.Error = core.ModelFail, "model_unavailable"
		default:
			r.State, r.Error = core.ModelUnknown, "cli_error"
		}
		out = append(out, r)
	}
	return out, nil
}

// answeredBy is PASS when a model in the result's modelUsage is m or carries
// the alias m in its ID; unparsable output is UNKNOWN, never PASS.
func answeredBy(out []byte, m string) (core.ModelState, string) {
	var res struct {
		ModelUsage map[string]json.RawMessage `json:"modelUsage"`
	}
	if json.Unmarshal(out, &res) != nil || len(res.ModelUsage) == 0 {
		return core.ModelUnknown, "no_model_usage"
	}
	for id := range res.ModelUsage {
		if id == m || strings.Contains(id, m) {
			return core.ModelPass, ""
		}
	}
	return core.ModelFail, "model_substituted"
}

// ProfileProber is the install profile of a subscription runtime (DES §4.3.3b):
// every candidate is PASS unless excluded (e.g. --exclude fable).
type ProfileProber struct {
	Name    string
	Exclude []string
	Now     func() time.Time
}

func (p ProfileProber) Runtime() string { return p.Name }

func (p ProfileProber) Probe(_ context.Context, candidates []string) ([]core.ProbeResult, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	var out []core.ProbeResult
	for _, m := range candidates {
		r := core.ProbeResult{Model: m, State: core.ModelPass, ProbedAt: now()}
		for _, x := range p.Exclude {
			if x == m {
				r.State, r.Error = core.ModelFail, "excluded_by_profile"
			}
		}
		out = append(out, r)
	}
	return out, nil
}
