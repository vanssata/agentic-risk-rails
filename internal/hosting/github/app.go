package github

// GitHub App authentication (DES §8.2: the runner pushes and opens PRs as an App,
// so the code owner is not the pusher). Facts: docs/research/verified/github.md.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TokenFor returns the token for remote ("owner/repo"): with RR_GITHUB_APP_ID (client
// or app id) and RR_GITHUB_APP_KEY (path of the App's PEM private key) an
// installation token limited to that one repository, else TokenFromEnv. Half an App
// configuration is an error, never a fallback to the personal token.
func TokenFor(ctx context.Context, remote, baseURL string) (string, error) {
	id, key := os.Getenv("RR_GITHUB_APP_ID"), os.Getenv("RR_GITHUB_APP_KEY")
	if id == "" && key == "" {
		return TokenFromEnv(), nil
	}
	if id == "" || key == "" {
		return "", errors.New("github: RR_GITHUB_APP_ID and RR_GITHUB_APP_KEY are set together or not at all")
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return "", errors.New("github: API base URL must be https")
	}
	return appToken(ctx, &http.Client{Timeout: 30 * time.Second}, baseURL, id, key, remote)
}

// runnerPermissions narrow the installation token to what rr uses, whatever else
// the App holds: push rr/* branches, open draft PRs, read the ruleset with its
// bypass actors (GitHub returns them only with administration write).
var runnerPermissions = map[string]string{"contents": "write", "pull_requests": "write", "administration": "write", "metadata": "read"}

// appToken signs an App JWT, finds the App's installation on remote and mints an
// installation token for that repository only (valid 1 hour).
func appToken(ctx context.Context, hc *http.Client, base, id, keyPath, remote string) (string, error) {
	owner, repo, ok := strings.Cut(remote, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("github: remote %q is not owner/repo", remote)
	}
	jwt, err := appJWT(id, keyPath, time.Now())
	if err != nil {
		return "", err
	}
	var inst struct {
		ID int64 `json:"id"`
	}
	if err := appCall(ctx, hc, http.MethodGet, base+"/repos/"+owner+"/"+repo+"/installation", jwt, nil, &inst); err != nil {
		return "", fmt.Errorf("github: App installation on %s: %w", remote, err)
	}
	body, _ := json.Marshal(map[string]any{"repositories": []string{repo}, "permissions": runnerPermissions})
	var tok struct {
		Token string `json:"token"`
	}
	if err := appCall(ctx, hc, http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", base, inst.ID), jwt, body, &tok); err != nil {
		return "", fmt.Errorf("github: App installation token: %w", err)
	}
	if tok.Token == "" {
		return "", errors.New("github: App installation token: empty")
	}
	return tok.Token, nil
}

// appJWT: RS256, iat 60 s in the past (clock drift), exp 9 minutes ahead (max 10).
func appJWT(id, keyPath string, now time.Time) (string, error) {
	raw, err := os.ReadFile(keyPath) //nolint:gosec // RR_GITHUB_APP_KEY is the operator's own key file
	if err != nil {
		return "", fmt.Errorf("github: App key: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return "", errors.New("github: App key: no PEM block")
	}
	var key *rsa.PrivateKey
	if key, err = x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
		k, perr := x509.ParsePKCS8PrivateKey(blk.Bytes)
		var isRSA bool
		if key, isRSA = k.(*rsa.PrivateKey); perr != nil || !isRSA {
			return "", errors.New("github: App key: not an RSA private key")
		}
	}
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": id})
	signed := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("github: App JWT: %w", err)
	}
	return signed + "." + enc.EncodeToString(sig), nil
}

func appCall(ctx context.Context, hc *http.Client, method, url, jwt string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d", method, url, resp.StatusCode) // the body may echo the request
	}
	return json.Unmarshal(b, out)
}
