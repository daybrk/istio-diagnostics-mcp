package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func NewID(prefix string) string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func ResolveWindow(w *TimeWindow, now time.Time) (ResolvedWindow, error) {
	var start, end time.Time
	var err error
	if w == nil {
		w = &TimeWindow{LookbackSeconds: 900}
	}
	if w.LookbackSeconds > 0 {
		if w.Start != "" || w.End != "" || int64(w.LookbackSeconds) > int64((1<<63-1)/int64(time.Second)) {
			return ResolvedWindow{}, fmt.Errorf("invalid relative window")
		}
		end = now
		start = now.Add(-time.Duration(w.LookbackSeconds) * time.Second)
	} else {
		start, err = time.Parse(time.RFC3339Nano, w.Start)
		if err != nil {
			return ResolvedWindow{}, err
		}
		end, err = time.Parse(time.RFC3339Nano, w.End)
		if err != nil {
			return ResolvedWindow{}, err
		}
	}
	if !start.Before(end) || end.After(now) {
		return ResolvedWindow{}, fmt.Errorf("expected start < end <= now")
	}
	return ResolvedWindow{Start: Timestamp(start), End: Timestamp(end)}, nil
}

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)

func ValidName(s string) bool { return len(s) > 0 && len(s) <= 253 && namePattern.MatchString(s) }

var bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
var secretPattern = regexp.MustCompile(`(?i)(["']?(?:authorization|cookie|set-cookie|password|token|access_token|refresh_token|client_secret|private_key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,}]+)`)
var keyPattern = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----.*?-----END (?:[A-Z ]*PRIVATE KEY)-----`)

func RedactString(s string) string {
	s = keyPattern.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	s = bearerPattern.ReplaceAllString(s, "${1}[REDACTED]")
	return secretPattern.ReplaceAllString(s, "${1}[REDACTED]")
}
func RedactObject(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			l := strings.ToLower(k)
			if l == "env" || l == "envfrom" || strings.Contains(l, "private_key") || strings.Contains(l, "privatekey") || strings.Contains(l, "password") || l == "token" || l == "authorization" || l == "cookie" || l == "set-cookie" || l == "client_secret" {
				out[k] = "[REDACTED]"
			} else {
				out[k] = RedactObject(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = RedactObject(v)
		}
		return out
	case string:
		return RedactString(x)
	default:
		return v
	}
}
