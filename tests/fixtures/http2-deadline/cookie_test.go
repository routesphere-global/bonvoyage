package main

import (
	"encoding/json"
	"testing"

	"golang.org/x/net/http2"
)

func TestCookieOracleRejectsLossAndWrongJoin(t *testing.T) {
	want := []string{"session=abc; theme=dark"}
	for _, tc := range []struct {
		name    string
		proto   string
		cookies []string
		pass    bool
	}{
		{"intact", "HTTP/1.1", want, true},
		{"lost-session", "HTTP/1.1", []string{"theme=dark"}, false},
		{"comma", "HTTP/1.1", []string{"session=abc,theme=dark"}, false},
		{"reversed", "HTTP/1.1", []string{"theme=dark; session=abc"}, false},
		{"still-split", "HTTP/1.1", []string{"session=abc", "theme=dark"}, false},
		{"wrong-protocol", "HTTP/2.0", want, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(cookieObservation{tc.proto, tc.cookies})
			if err != nil {
				t.Fatal(err)
			}
			p := &peer{streams: map[uint32]*response{1: {Status: "200", End: true, body: body}}}
			if err = expectCookies(p, 1, want); (err == nil) != tc.pass {
				t.Fatalf("pass=%t, got %v", tc.pass, err)
			}
		})
	}
}

func TestCookieLimitRequiresSpecificRejection(t *testing.T) {
	for _, code := range []http2.ErrCode{http2.ErrCodeNo, http2.ErrCodeProtocol, http2.ErrCodeInternal, http2.ErrCodeCancel, http2.ErrCodeEnhanceYourCalm} {
		if got := cookieLimitRejected(&response{Reset: &code}); got != (code == http2.ErrCodeEnhanceYourCalm) {
			t.Fatalf("reset %v accepted=%t", code, got)
		}
	}
	for _, s := range []response{{Status: "431"}, {Status: "200", End: true}, {Status: "503", End: true}} {
		if cookieLimitRejected(&s) {
			t.Fatalf("wrong status or incomplete error accepted: %+v", s)
		}
	}
	if !cookieLimitRejected(&response{Status: "431", End: true}) {
		t.Fatal("complete 431 not accepted")
	}
}
