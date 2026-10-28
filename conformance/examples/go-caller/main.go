// SPDX-License-Identifier: Apache-2.0
// A small, standalone Go caller for AI Passport Revocation Check v1 (draft.1).
// Conformance adapter protocol: one JSON input and one JSON output per line.
// This example is not an HTTP gateway, signer, identity provider, or authorization engine.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const clockSkew = 5 * time.Minute
const irreversibleReuse = 5 * time.Second

type object = map[string]any

// jsonObject rejects duplicate members at every depth rather than silently
// letting the last copy replace the first. UseNumber keeps boolean and integer
// semantics unambiguous for state versions and revision floors.
func jsonObject(data []byte) (object, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := valueStrict(d)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing JSON value")
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return result, nil
}

func valueStrict(d *json.Decoder) (any, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		out := make(object)
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("non-string object key")
			}
			if _, exists := out[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member")
			}
			out[key], err = valueStrict(d)
			if err != nil {
				return nil, err
			}
		}
		_, err := d.Token()
		return out, err
	case '[':
		var out []any
		for d.More() {
			item, err := valueStrict(d)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		_, err := d.Token()
		return out, err
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}

func obj(v any) object {
	x, _ := v.(map[string]any)
	return x
}

func nonnegativeInt(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	raw := string(n)
	if raw == "" || strings.ContainsAny(raw, ".eE+-") {
		return 0, false
	}
	result, err := strconv.ParseUint(raw, 10, 64)
	return result, err == nil
}

func timestamp(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func validAnswer(b object) bool {
	if b == nil {
		return false
	}
	if _, ok := b["subject"]; !ok {
		return false
	}
	if b["subject"] != nil {
		if _, ok := b["subject"].(string); !ok {
			return false
		}
	}
	if _, ok := b["revoked"]; !ok {
		return false
	}
	if _, ok := b["revoked_scopes"]; !ok {
		return false
	}
	if _, ok := nonnegativeInt(b["min_required_revision"]); !ok {
		return false
	}
	if _, ok := nonnegativeInt(b["state_version"]); !ok {
		return false
	}
	_, ok := timestamp(b["evaluated_at"])
	return ok
}

func header(headers object, name string) any {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// A missing/unparseable max-age allows a newly fetched answer to be applied
// once, never reused. First max-age wins; no-store/no-cache forbid reuse.
func lifetime(v any) (uint64, bool) {
	raw, ok := v.(string)
	if !ok {
		return 0, false
	}
	var lifetime uint64
	found := false
	for _, part := range strings.Split(strings.ToLower(raw), ",") {
		directive := strings.TrimSpace(part)
		if directive == "no-cache" || directive == "no-store" {
			return 0, true
		}
		if strings.HasPrefix(directive, "max-age=") && !found {
			seconds := strings.TrimPrefix(directive, "max-age=")
			n, err := strconv.ParseUint(seconds, 10, 64)
			if err != nil || seconds == "" {
				return 0, false
			}
			lifetime, found = n, true
		}
	}
	return lifetime, found
}

func age(v any) (uint64, bool) {
	if v == nil {
		return 0, true
	}
	s := fmt.Sprint(v)
	if s == "" || strings.ContainsAny(s, ".eE+-") {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func caller(input object) string {
	received := obj(input["received"])
	if received == nil || received["error"] != nil {
		return "deny"
	}
	status, ok := nonnegativeInt(received["status"])
	if !ok || status != 200 {
		return "deny"
	}

	body := obj(received["body"])
	if txt, exists := received["body_text"]; exists {
		s, ok := txt.(string)
		if !ok {
			return "deny"
		}
		parsed, err := jsonObject([]byte(s))
		if err != nil {
			return "deny"
		}
		body = parsed
	}
	if !validAnswer(body) {
		return "deny"
	}
	if expired, _ := received["cache_expired"].(bool); expired {
		return "deny"
	}

	// The synthetic adapter has optional cache state; a production caller
	// must additionally track the response's actual residence time itself.
	_, hasHeaders := received["headers"]
	reused, _ := received["reused"].(bool)
	if hasHeaders || reused {
		headers := obj(received["headers"])
		maxAge, hasLifetime := lifetime(header(headers, "Cache-Control"))
		if reused && !hasLifetime {
			return "deny"
		}
		if sentAge := header(headers, "Age"); sentAge != nil {
			n, valid := age(sentAge)
			if !valid || (hasLifetime && n >= maxAge) || (!hasLifetime && n != 0) {
				return "deny"
			}
		}
		if t, hasNow := timestamp(input["now"]); hasNow {
			evaluated, _ := timestamp(body["evaluated_at"])
			ageOfAnswer := t.Sub(evaluated)
			if ageOfAnswer > time.Duration(maxAge)*time.Second+clockSkew {
				return "deny"
			}
			if reused {
				if irreversible, _ := received["irreversible"].(bool); irreversible &&
					ageOfAnswer > irreversibleReuse {
					return "deny"
				}
			}
		} else if reused {
			irreversible, _ := received["irreversible"].(bool)
			if irreversible {
				return "deny"
			}
		}
	}

	previous := obj(input["previously_applied"])
	previousExpired, _ := input["previously_applied_expired"].(bool)
	if previous != nil && body["subject"] == previous["subject"] {
		version, _ := nonnegativeInt(body["state_version"])
		oldVersion, oldOK := nonnegativeInt(previous["state_version"])
		if oldOK && version < oldVersion {
			if previousExpired || !validAnswer(previous) {
				return "deny"
			}
			body = previous
		} else if oldOK && version == oldVersion && !previousExpired {
			if !validAnswer(previous) {
				return "deny"
			}
			priorFloor, _ := nonnegativeInt(previous["min_required_revision"])
			floor, _ := nonnegativeInt(body["min_required_revision"])
			if priorFloor > floor {
				body["min_required_revision"] = json.Number(strconv.FormatUint(priorFloor, 10))
			}
			if previous["revoked"] != false || body["revoked"] != false {
				body["revoked"] = true
			}
			pastScopes, _ := previous["revoked_scopes"].([]any)
			currentScopes, _ := body["revoked_scopes"].([]any)
			body["revoked_scopes"] = append(append([]any{}, pastScopes...), currentScopes...)
		}
	}

	if body["subject"] == nil {
		return "deny"
	}
	asked := obj(input["asked"])
	if asked != nil && asked["subject"] != nil && body["subject"] != asked["subject"] {
		return "deny"
	}
	held := obj(input["holds_passport"])
	if held != nil {
		if held["issuer"] != nil && received["issuer"] != nil && held["issuer"] != received["issuer"] {
			return "deny"
		}
		if body["subject"] != held["subject"] {
			return "deny"
		}
	}
	if body["revoked"] != false {
		return "deny"
	}
	scopes, isArray := body["revoked_scopes"].([]any)
	if !isArray || len(scopes) != 0 {
		return "deny"
	}
	if held != nil {
		revision, ok := nonnegativeInt(held["revision"])
		if !ok {
			return "deny"
		}
		floor, _ := nonnegativeInt(body["min_required_revision"])
		if revision < floor {
			return "refetch"
		}
	}
	return "proceed"
}

// httpCaller obtains an actual revocation answer, refusing redirects. A 3xx,
// timeout or other non-200 response cannot be upgraded into permission.
// The tool only runs against the loopback mock service during conformance.
func httpCaller(message object) string {
	rawURL, ok := message["revocation_url"].(string)
	if !ok {
		return "deny"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "deny"
	}
	seconds := 2.0
	if n, ok := message["timeout_seconds"].(json.Number); ok {
		if parsedSeconds, err := strconv.ParseFloat(n.String(), 64); err == nil && parsedSeconds > 0 && parsedSeconds <= 120 {
			seconds = parsedSeconds
		}
	}
	client := http.Client{
		Timeout: time.Duration(seconds * float64(time.Second)),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Get(rawURL)
	if err != nil {
		return "deny"
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "deny"
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil || len(payload) > 4*1024*1024 {
		return "deny"
	}
	headers := object{}
	for name, values := range response.Header {
		if len(values) > 0 {
			headers[name] = strings.Join(values, ", ")
		}
	}
	received := object{
		"status":    json.Number("200"),
		"body_text": string(payload),
		"headers":   headers,
	}
	input := object{
		"received":           received,
		"holds_passport":     message["holds_passport"],
		"previously_applied": nil,
		"now":                time.Now().UTC().Format(time.RFC3339),
	}
	if subject := parsed.Query().Get("subject"); subject != "" {
		input["asked"] = object{"subject": subject}
	}
	return caller(input)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		outcome := "deny"
		if message, err := jsonObject(line); err == nil && message["role"] == "caller" {
			if message["mode"] == "http" {
				outcome = httpCaller(message)
			} else {
				outcome = caller(obj(message["input"]))
			}
		}
		output, err := json.Marshal(object{"outcome": outcome})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(writer, string(output))
		writer.Flush()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
