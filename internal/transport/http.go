package transport

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPHandler requires verified OIDC RS256 access tokens. Plain HTTP is accepted
// only from an actual loopback peer, for a local TLS reverse proxy. Forwarded
// headers do not bypass this boundary. PublicURL and the issuer must use HTTPS.
func HTTPHandler(h core.Handler, c core.Config) (http.Handler, error) {
	return newHTTPHandler(h, c, &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect})
}
func noRedirect(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") }
func newHTTPHandler(h core.Handler, c core.Config, client *http.Client) (http.Handler, error) {
	if c.HTTP == nil || c.HTTP.Auth.Mode != "oidc" || c.HTTP.Auth.Audience == "" || !core.HTTPSURL(c.HTTP.PublicURL) || !core.HTTPSURL(c.HTTP.Auth.Issuer) || len(c.HTTP.Auth.Bindings) == 0 {
		return nil, fmt.Errorf("HTTP requires HTTPS public URL, OIDC issuer, audience and subject bindings")
	}
	seen := map[string]bool{}
	for _, b := range c.HTTP.Auth.Bindings {
		if b.Subject == "" || seen[b.Subject] {
			return nil, fmt.Errorf("OIDC subjects must be unique and nonempty")
		}
		seen[b.Subject] = true
	}
	clientCopy := *client
	clientCopy.CheckRedirect = noRedirect
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > 10*time.Second {
		clientCopy.Timeout = 10 * time.Second
	}
	publicURL, _ := url.Parse(c.HTTP.PublicURL)
	verifier := &oidcVerifier{cfg: c, client: &clientCopy}
	s := newServer(h, c, true)
	ttl := time.Duration(c.Limits.SessionIdleTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	inner := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{JSONResponse: true, SessionTimeout: ttl, MaxRequestBodyBytes: 1 << 20, DisableLocalhostProtection: true})
	authenticated := auth.RequireBearerToken(verifier.verify, nil)(inner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An explicit public Host allowlist provides DNS rebinding protection and
		// permits a loopback TLS proxy to preserve the external Host header.
		if !strings.EqualFold(r.Host, publicURL.Host) {
			http.Error(w, "host forbidden", http.StatusForbidden)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if r.TLS == nil && (err != nil || ip == nil || !ip.IsLoopback()) {
			http.Error(w, "TLS required", http.StatusForbidden)
			return
		}
		if len(r.Header.Values("Origin")) > 1 {
			http.Error(w, "origin forbidden", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			allowed := false
			for _, v := range c.HTTP.AllowedOrigins {
				if origin == v {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "origin forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		authenticated.ServeHTTP(w, r)
	}), nil
}

type oidcVerifier struct {
	cfg     core.Config
	client  *http.Client
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	expires time.Time
}

func (v *oidcVerifier) verify(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	if len(raw) > 16<<10 {
		return nil, auth.ErrInvalidToken
	}
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, auth.ErrInvalidToken
		}
		return v.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.cfg.HTTP.Auth.Issuer), jwt.WithAudience(v.cfg.HTTP.Auth.Audience), jwt.WithExpirationRequired())
	if err != nil || !token.Valid || claims.Subject == "" {
		return nil, auth.ErrInvalidToken
	}
	for _, b := range v.cfg.HTTP.Auth.Bindings {
		if b.Subject == claims.Subject {
			projects := []string{}
			for _, p := range b.AstraProjects {
				if v.cfg.Astra.ProjectAllowed(p) {
					projects = append(projects, p)
				}
			}
			principal := core.Principal{ID: claims.Subject, Scopes: core.IntersectScopes(b.Contexts, v.cfg.Kube.Contexts), AstraProjects: projects}
			return &auth.TokenInfo{UserID: claims.Subject, Expiration: claims.ExpiresAt.Time, Extra: map[string]any{"principal": principal}}, nil
		}
	}
	return nil, auth.ErrInvalidToken
}
func (v *oidcVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Now().Before(v.expires) {
		if k := v.keys[kid]; k != nil {
			return k, nil
		}
		return nil, auth.ErrInvalidToken
	}
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, strings.TrimRight(v.cfg.HTTP.Auth.Issuer, "/")+"/.well-known/openid-configuration", &discovery); err != nil {
		return nil, err
	}
	if discovery.Issuer != v.cfg.HTTP.Auth.Issuer || !core.HTTPSURL(discovery.JWKS) {
		return nil, auth.ErrInvalidToken
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E string
			KeyOps                   []string `json:"key_ops"`
		} `json:"keys"`
	}
	if err := v.getJSON(ctx, discovery.JWKS, &set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Kid == "" || (j.Use != "" && j.Use != "sig") || (j.Alg != "" && j.Alg != "RS256") {
			continue
		}
		if len(j.KeyOps) > 0 {
			verify := false
			for _, op := range j.KeyOps {
				if op == "verify" {
					verify = true
				}
			}
			if !verify {
				continue
			}
		}
		n, ne := base64.RawURLEncoding.DecodeString(j.N)
		e, ee := base64.RawURLEncoding.DecodeString(j.E)
		if ne != nil || ee != nil || len(e) == 0 || len(e) > 4 || len(n) < 256 || len(n) > 1024 {
			continue
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 || exp%2 == 0 {
			continue
		}
		if keys[j.Kid] != nil {
			return nil, auth.ErrInvalidToken
		}
		keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	v.keys = keys
	v.expires = time.Now().Add(5 * time.Minute)
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, auth.ErrInvalidToken
}
func (v *oidcVerifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return auth.ErrInvalidToken
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, (256<<10)+1))
	if err != nil || len(b) > 256<<10 {
		return auth.ErrInvalidToken
	}
	return json.Unmarshal(b, out)
}
