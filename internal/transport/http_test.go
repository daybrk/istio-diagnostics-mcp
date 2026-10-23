package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

func TestHTTPIdentityAndSessionIsolation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "one", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer issuer.Close()
	cfg := core.Config{Transport: "streamable_http", Kube: core.KubeConfig{Contexts: []core.Scope{{Context: "c", Namespaces: []string{"n"}}}}, HTTP: &core.HTTPConfig{Listen: "127.0.0.1:0", PublicURL: "https://diagnostics.example/mcp", AllowedOrigins: []string{"https://client.example"}, Auth: core.AuthConfig{Mode: "oidc", Issuer: issuer.URL, Audience: "diag", Bindings: []core.Binding{{Subject: "alice", AstraProjects: []string{"p1"}, Contexts: []core.Scope{{Context: "c", Namespaces: []string{"n", "forbidden"}}}}, {Subject: "bob"}}}}}
	seen := make(chan core.Principal, 4)
	h, err := newHTTPHandler(handlerFunc(func(_ context.Context, p core.Principal, _ string, _ json.RawMessage) (core.Envelope, error) {
		seen <- p
		return core.Fail("TEST", "test"), nil
	}), cfg, issuer.Client())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(sub, aud string, expires time.Time) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Issuer: issuer.URL, Subject: sub, Audience: jwt.ClaimStrings{aud}, ExpiresAt: jwt.NewNumericDate(expires)})
		token.Header["kid"] = "one"
		s, _ := token.SignedString(key)
		return s
	}

	signClaims := func(method jwt.SigningMethod, claims jwt.RegisteredClaims, signingKey any) string {
		token := jwt.NewWithClaims(method, claims)
		token.Header["kid"] = "one"
		s, err := token.SignedString(signingKey)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	validClaims := jwt.RegisteredClaims{Issuer: issuer.URL, Subject: "alice", Audience: jwt.ClaimStrings{"diag"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	wrongIssuer := validClaims
	wrongIssuer.Issuer = "https://other-issuer.example"
	noExpiry := validClaims
	noExpiry.ExpiresAt = nil
	future := validClaims
	future.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
	foreignKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	alice := sign("alice", "diag", time.Now().Add(time.Hour))
	bob := sign("bob", "diag", time.Now().Add(time.Hour))
	request := func(token, session, origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://diagnostics.example/mcp", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:42"
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("MCP-Protocol-Version", "2025-06-18")
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	for name, token := range map[string]string{"unsigned": "bad", "wrong_signature": signClaims(jwt.SigningMethodRS256, validClaims, foreignKey), "wrong_issuer": signClaims(jwt.SigningMethodRS256, wrongIssuer, key), "missing_expiry": signClaims(jwt.SigningMethodRS256, noExpiry, key), "future": signClaims(jwt.SigningMethodRS256, future, key), "algorithm_confusion": signClaims(jwt.SigningMethodHS256, validClaims, []byte("secret")), "audience": sign("alice", "other", time.Now().Add(time.Hour)), "expired": sign("alice", "diag", time.Now().Add(-time.Hour)), "unbound": sign("mallory", "diag", time.Now().Add(time.Hour))} {
		t.Run(name, func(t *testing.T) {
			w := request(token, "", "", init)
			if w.Code != 401 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
	if w := request(alice, "", "https://evil.example", init); w.Code != 403 {
		t.Fatalf("origin=%d", w.Code)
	}
	w := request(alice, "", "https://client.example", init)
	if w.Code != 200 {
		t.Fatalf("initialize %d %s", w.Code, w.Body)
	}
	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("missing session")
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_capabilities","arguments":{}}}`
	if w = request(sign("alice", "diag", time.Now().Add(-time.Hour)), sid, "", call); w.Code != 401 {
		t.Fatalf("expired session token=%d", w.Code)
	}
	if w = request(bob, sid, "", call); w.Code != 403 {
		t.Fatalf("session hijack %d %s", w.Code, w.Body)
	}
	if w = request(alice, sid, "", call); w.Code != 200 {
		t.Fatalf("call %d %s", w.Code, w.Body)
	}
	select {
	case p := <-seen:
		if p.AstraCredentialScope || len(p.AstraProjects) != 1 || p.AstraProjects[0] != "p1" {
			t.Fatalf("HTTP inherited credential-wide access or lost binding: %+v", p)
		}
		if p.ID != "alice" || !p.Allows("c", "n") || p.Allows("c", "forbidden") {
			t.Fatalf("scope=%#v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("handler not called")
	}
	hostSpoof := httptest.NewRequest("POST", "https://evil.example/mcp", strings.NewReader(init))
	hostSpoof.RemoteAddr = "127.0.0.1:42"
	hostSpoof.Header.Set("Authorization", "Bearer "+alice)
	hostResponse := httptest.NewRecorder()
	h.ServeHTTP(hostResponse, hostSpoof)
	if hostResponse.Code != 403 {
		t.Fatalf("spoofed host=%d", hostResponse.Code)
	}
	r := httptest.NewRequest("POST", "http://diagnostics.example/mcp", strings.NewReader(init))
	r.RemoteAddr = "192.0.2.3:42"
	r.Header.Set("Authorization", "Bearer "+alice)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("plain remote=%d", w.Code)
	}
}
