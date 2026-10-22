package diagnostics

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

func InspectTLS(raw Object, at time.Time) (Report, error) {
	d, err := parse(raw)
	if err != nil {
		return newReport(at), err
	}
	return inspectTLS(d, at), nil
}

func inspectTLS(d dump, at time.Time) Report {
	r := newReport(at)
	r.Summary = "Validity audit of locally available public certificates; remote peer certificates and handshake success are not established."
	secrets := map[string]bool{}
	for _, s := range d.Secrets {
		secrets[name(s.Value)] = true
	}
	active := append(append(append([]item{}, d.Secrets...), d.Listeners...), d.Clusters...)
	count := 0
	for _, x := range active {
		walk(x.Value, x.Path, func(o Object, p string) {
			for _, k := range []string{"tls_certificate_sds_secret_configs", "validation_context_sds_secret_config"} {
				var refs []any
				if k == "tls_certificate_sds_secret_configs" {
					refs = arr(get(o, k))
				} else if v := get(o, k); v != nil {
					refs = []any{v}
				}
				for _, ref := range refs {
					n := name(obj(ref))
					if n == "" {
						continue
					}
					if !secrets[n] {
						r.unknown("SDS_SECRET_UNAVAILABLE", "Referenced secret is not available in this dump: "+n, p)
					} else {
						r.add("SDS_SECRET_PRESENT", "PASS", "info", "Referenced secret is present.", p, n, "")
					}
				}
			}
			for _, k := range []string{"certificate_chain", "trusted_ca"} {
				ds := obj(get(o, k))
				if len(ds) == 0 {
					continue
				}
				count++
				path := child(p, o, k)
				data := []byte(field(ds, "inline_string"))
				if b := field(ds, "inline_bytes"); b != "" {
					decoded, err := base64.StdEncoding.DecodeString(b)
					if err != nil {
						r.add("CERTIFICATE_PARSE_ERROR", "UNKNOWN", "warning", "Invalid base64 certificate data.", path, "Unable to decode public certificate.", "")
						continue
					}
					data = decoded
				}
				if len(data) == 0 {
					r.unknown("CERTIFICATE_BYTES_UNAVAILABLE", "Certificate is file-backed, redacted or omitted; no files are read from dump paths.", path)
					continue
				}
				found := 0
				for len(data) > 0 {
					block, rest := pem.Decode(data)
					if block == nil {
						break
					}
					data = rest
					if block.Type != "CERTIFICATE" {
						continue
					}
					found++
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						r.unknown("CERTIFICATE_PARSE_ERROR", "Cannot parse X.509 certificate.", path)
						continue
					}
					obs := fmt.Sprintf("serial=%s not_before=%s not_after=%s", cert.SerialNumber.Text(16), cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
					switch {
					case at.Before(cert.NotBefore):
						r.add("CERTIFICATE_NOT_YET_VALID", "FAIL", "error", "A local certificate is not yet valid at the evaluation time.", path, obs, "Check certificate issuance and clock synchronization.")
					case !at.Before(cert.NotAfter):
						r.add("CERTIFICATE_EXPIRED", "FAIL", "error", "A local certificate has expired at the evaluation time.", path, obs, "Rotate the certificate and confirm the proxy loaded the new serial number.")
					case cert.NotAfter.Sub(at) < 7*24*time.Hour:
						r.add("CERTIFICATE_EXPIRING", "PASS", "warning", "A local certificate expires within seven days.", path, obs, "Check certificate renewal and SDS rotation.")
					default:
						r.add("CERTIFICATE_TIME_VALID", "PASS", "info", "Certificate validity interval includes the evaluation time.", path, obs, "")
					}
				}
				if found == 0 {
					r.unknown("CERTIFICATE_PARSE_ERROR", "No PEM certificate found; a hidden or malformed certificate cannot be assessed.", path)
				}
			}
		})
	}
	if count == 0 {
		r.unknown("CERTIFICATES_NOT_COLLECTED", "No inspectable local certificate sources were found.", "")
	}
	r.Limitations = append(r.Limitations, "Certificate time checks do not validate remote trust chains, SAN/SNI, revocation, negotiated TLS, or prove this certificate was used by the failed request.")
	return r
}

// Redact removes private keys and credential fields from collected snapshots.
// This is deliberately independent from certificate parsing: no private key is needed.
func Redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := Object{}
		for k, v := range x {
			n := key(k)
			if strings.Contains(n, "privatekey") || n == "password" || n == "token" || n == "authorization" || n == "clientsecret" || n == "sessionticketkeys" {
				o[k] = "[REDACTED]"
			} else {
				o[k] = Redact(v)
			}
		}
		return o
	case []any:
		a := make([]any, len(x))
		for i, v := range x {
			a[i] = Redact(v)
		}
		return a
	default:
		return v
	}
}
