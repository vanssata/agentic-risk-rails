package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func appKey(t *testing.T) (*rsa.PrivateKey, string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "app.pem")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600))
	return k, p
}

// appServer is GitHub's App API: it checks the JWT like GitHub does (RS256 with the
// app's public key, iss, at most 10 minutes) and records the token request body.
func appServer(t *testing.T, pub *rsa.PublicKey, body *string) *httptest.Server {
	checkJWT := func(r *http.Request) bool {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(tok, ".")
		if !ok || len(parts) != 3 {
			return false
		}
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		c, _ := base64.RawURLEncoding.DecodeString(parts[1])
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		var hdr struct{ Alg string }
		var cl struct {
			Iat, Exp int64
			Iss      string
		}
		_ = json.Unmarshal(h, &hdr)
		_ = json.Unmarshal(c, &cl)
		now := time.Now().Unix()
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil && hdr.Alg == "RS256" &&
			cl.Iss == "Iv1.abc" && cl.Iat <= now && cl.Exp > now && cl.Exp-now <= 600
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/shop/installation", func(w http.ResponseWriter, r *http.Request) {
		if !checkJWT(r) {
			http.Error(w, "bad jwt", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"id":42}`)
	})
	mux.HandleFunc("POST /app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if !checkJWT(r) {
			http.Error(w, "bad jwt", http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		*body = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"ghs_test","expires_at":"2099-01-01T00:00:00Z"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// errata #54: the runner pushes and opens PRs as a GitHub App (DES §8.2), so the
// code owner is not the pusher and can approve.
func TestAppInstallationTokenForOneRepo(t *testing.T) {
	k, keyPath := appKey(t)
	var body string
	srv := appServer(t, &k.PublicKey, &body)
	tok, _, err := appToken(t.Context(), srv.Client(), srv.URL, "Iv1.abc", keyPath, "acme/shop")
	require.NoError(t, err)
	assert.Equal(t, "ghs_test", tok)
	assert.JSONEq(t, `{"repositories":["shop"],"permissions":{"contents":"write","pull_requests":"write","administration":"write","metadata":"read"}}`,
		body, "the token reaches only the pinned repo, with only what the runner uses, whatever else the App was granted")

	_, _, err = appToken(t.Context(), srv.Client(), srv.URL, "Iv1.abc", keyPath, "acme/other")
	assert.Error(t, err, "no installation on that repo")
	_, _, err = appToken(t.Context(), srv.Client(), srv.URL, "Iv1.wrong", keyPath, "acme/shop")
	assert.Error(t, err, "GitHub refuses a JWT for another app")
	bad := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not a key"), 0o600))
	_, _, err = appToken(t.Context(), srv.Client(), srv.URL, "Iv1.abc", bad, "acme/shop")
	assert.Error(t, err)
}

func TestTokenForChoosesTheAppOrTheToken(t *testing.T) {
	t.Setenv("RR_GITHUB_TOKEN", "pat")
	t.Setenv("RR_GITHUB_APP_ID", "")
	t.Setenv("RR_GITHUB_APP_KEY", "")
	tok, err := TokenFor(t.Context(), "acme/shop", "")
	require.NoError(t, err)
	assert.Equal(t, "pat", tok)

	t.Setenv("RR_GITHUB_APP_ID", "Iv1.abc")
	_, err = TokenFor(t.Context(), "acme/shop", "")
	assert.Error(t, err, "an App id without its key fails closed, no fallback to the PAT")
	t.Setenv("RR_GITHUB_APP_ID", "")
	t.Setenv("RR_GITHUB_APP_KEY", "/x.pem")
	_, err = TokenFor(t.Context(), "acme/shop", "")
	assert.Error(t, err)
	t.Setenv("RR_GITHUB_APP_ID", "Iv1.abc")
	_, err = TokenFor(t.Context(), "acme/shop", "http://api.example")
	assert.Error(t, err, "a JWT is never sent in clear text")
}
