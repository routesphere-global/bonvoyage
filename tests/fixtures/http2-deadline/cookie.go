package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type cookieObservation struct {
	Protocol string   `json:"protocol"`
	Cookies  []string `json:"cookies"`
}

func registerCookieUpstream(mux *http.ServeMux) {
	var requests atomic.Uint64
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cookieObservation{r.Proto, r.Header.Values("Cookie")})
	})
	mux.HandleFunc("/cookie-count", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(requests.Load())
	})
}

func cookieCount() (uint64, error) {
	data, err := fetch("http://upstream:8081/cookie-count")
	if err != nil {
		return 0, err
	}
	var count uint64
	err = json.Unmarshal(data, &count)
	return count, err
}

func expectCookies(p *peer, id uint32, expected []string) error {
	s := p.stream(id)
	if err := p.wait(time.Now().Add(2*time.Second), func() bool { return s.End || s.Reset != nil }); err != nil {
		return err
	}
	if s.Reset != nil || s.Status != "200" {
		return fmt.Errorf("cookie stream %d: status=%s reset=%v", id, s.Status, s.Reset)
	}
	var observed cookieObservation
	if err := json.Unmarshal(s.body, &observed); err != nil {
		return err
	}
	if observed.Protocol != "HTTP/1.1" || !reflect.DeepEqual(observed.Cookies, expected) {
		return fmt.Errorf("upstream cookie mismatch: protocol=%s got=%.128q wanted=%.128q (stream %d)", observed.Protocol, observed.Cookies, expected, id)
	}
	return nil
}

func cookieLimitRejected(s *response) bool {
	if s.Reset != nil {
		return *s.Reset == http2.ErrCodeEnhanceYourCalm
	}
	return s.End && s.Status == "431"
}

func runCookieCases() error {
	field := func(value string) hpack.HeaderField { return hpack.HeaderField{Name: "cookie", Value: value} }
	cases := []struct {
		name   string
		fields []hpack.HeaderField
		want   []string
	}{
		{"none", nil, nil},
		{"single", []hpack.HeaderField{field("session=abc")}, []string{"session=abc"}},
		{"split-session", []hpack.HeaderField{field("session=abc"), field("theme=dark")}, []string{"session=abc; theme=dark"}},
		{"interleaved", []hpack.HeaderField{field("session=abc"), {Name: "x-other", Value: "ok"}, field("theme=dark"), field("lang=en")}, []string{"session=abc; theme=dark; lang=en"}},
		{"same-name-order", []hpack.HeaderField{field("session=first"), field("session=second")}, []string{"session=first; session=second"}},
		{"prejoined", []hpack.HeaderField{field("a=1; b=2"), field("c=3")}, []string{"a=1; b=2; c=3"}},
		{"empty-value", []hpack.HeaderField{field("a="), field("b=2")}, []string{"a=; b=2"}},
		{"bounded-large", []hpack.HeaderField{field("a=" + strings.Repeat("x", 15000)), field("b=" + strings.Repeat("y", 15000))}, []string{"a=" + strings.Repeat("x", 15000) + "; b=" + strings.Repeat("y", 15000)}},
	}
	results := []result{}
	for _, tc := range cases {
		results = append(results, runCase("cookie-"+tc.name, func(r *result) error {
			p, err := dial(65535, 0, true)
			if err != nil {
				return err
			}
			r.p = p
			if err = p.requestFields(1, "GET", "/cookies", 0, tc.fields); err != nil {
				return err
			}
			if err = expectCookies(p, 1, tc.want); err != nil {
				return err
			}
			r.Observations["cookie_fields_sent"] = len(tc.fields)
			r.Observations["upstream_protocol"] = "HTTP/1.1"
			r.Observations["ordered_cookie_value_verified"] = true
			// Reuse the same connection and route without cookies to catch leakage.
			if err = p.request(3, "GET", "/cookies", 0); err != nil {
				return err
			}
			return expectCookies(p, 3, nil)
		}))
	}
	results = append(results, runCase("cookie-header-limit", func(r *result) error {
		before, err := cookieCount()
		if err != nil {
			return err
		}
		p, err := dial(65535, 0, true)
		if err != nil {
			return err
		}
		r.p = p
		if err = p.requestFields(1, "GET", "/cookies", 0, []hpack.HeaderField{field("a=" + strings.Repeat("x", 17000)), field("b=" + strings.Repeat("y", 17000))}); err != nil {
			return err
		}
		s := p.stream(1)
		if err = p.wait(time.Now().Add(2*time.Second), func() bool { return s.End || s.Reset != nil }); err != nil {
			return err
		}
		if !cookieLimitRejected(s) {
			return errors.New("oversized cookie list was not rejected")
		}
		after, err := cookieCount()
		if err != nil {
			return err
		}
		if after != before {
			return errors.New("oversized cookie request reached upstream")
		}
		r.Observations["rejected_before_upstream"] = true
		if err = p.requestFields(3, "GET", "/cookies", 0, []hpack.HeaderField{field("recovery=ok")}); err != nil {
			return err
		}
		if err = expectCookies(p, 3, []string{"recovery=ok"}); err != nil {
			return err
		}
		// Cross the original request budget to detect delayed dispatch after reset.
		time.Sleep(requestTimeout + 100*time.Millisecond)
		m, err := snapshot("cookie-limit-post-recovery")
		if err != nil {
			return err
		}
		if !drained(m) {
			return errors.New("cookie rejection/recovery resources did not drain")
		}
		after, err = cookieCount()
		if err != nil {
			return err
		}
		if after != before+1 {
			return fmt.Errorf("expected only one recovery upstream request, got %d", after-before)
		}
		r.Observations["upstream_requests_before"] = before
		r.Observations["upstream_requests_after_recovery"] = after
		return nil
	}))
	pass := true
	for _, r := range results {
		pass = pass && r.Pass
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "cookie", "pass": pass, "cases": results}); err != nil {
		return err
	}
	if !pass {
		return errors.New("cookie translation regression failed")
	}
	return nil
}
