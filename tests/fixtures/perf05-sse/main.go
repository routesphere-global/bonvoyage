package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	semanticEventCount = 6
	requestTimeout     = 800 * time.Millisecond
	cleanupBound       = 2 * time.Second
	metricPrefix       = "bonvoyage_bonvoyage_gateway_"
)

var (
	mode        = flag.String("mode", "client", "client, upstream, ready, or metrics")
	caPath      = flag.String("ca", "/secrets/ca.pem", "fixture CA")
	metricsURL  = flag.String("metrics", "http://gateway:9090/metrics", "gateway metrics URL")
	readyURL    = flag.String("ready", "http://gateway:9901/health/ready", "gateway readiness URL")
	upstreamURL = flag.String("upstream", "http://upstream:8081", "controlled upstream URL")
)

type scenarioCounter struct {
	Started   uint64 `json:"started"`
	Active    uint64 `json:"active"`
	Completed uint64 `json:"completed"`
	Canceled  uint64 `json:"canceled"`
	Failed    uint64 `json:"failed"`
}

type upstreamState struct {
	mu       sync.Mutex
	counters map[string]*scenarioCounter
}

func newUpstreamState() *upstreamState {
	return &upstreamState{counters: map[string]*scenarioCounter{}}
}

func (s *upstreamState) begin(name string) func(string) {
	s.mu.Lock()
	counter := s.counters[name]
	if counter == nil {
		counter = &scenarioCounter{}
		s.counters[name] = counter
	}
	counter.Started++
	counter.Active++
	s.mu.Unlock()
	return func(outcome string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		counter.Active--
		switch outcome {
		case "completed":
			counter.Completed++
		case "canceled":
			counter.Canceled++
		default:
			counter.Failed++
		}
	}
}

func (s *upstreamState) snapshot() map[string]scenarioCounter {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]scenarioCounter, len(s.counters))
	for name, counter := range s.counters {
		result[name] = *counter
	}
	return result
}

func scenarioName(path string) string {
	return strings.TrimPrefix(path, "/sse/")
}

func writeSSE(w http.ResponseWriter, value string) error {
	if _, err := io.WriteString(w, value); err != nil {
		return err
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return errors.New("controlled upstream lacks flush support")
	}
	flusher.Flush()
	return nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func serveScenario(state *upstreamState, w http.ResponseWriter, r *http.Request) {
	name := scenarioName(r.URL.Path)
	finish := state.begin(name)
	outcome := "failed"
	defer func() {
		if r.Context().Err() != nil {
			outcome = "canceled"
		}
		finish(outcome)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Perf05-SSE-Scenario", name)
	w.WriteHeader(http.StatusOK)
	if err := writeSSE(w, ": fixture-ready\n\n"); err != nil {
		return
	}

	message := func(sequence int, padding string) error {
		payload, _ := json.Marshal(map[string]any{
			"sequence": sequence,
			"padding":  padding,
		})
		return writeSSE(w, formatSSE("message", strconv.Itoa(sequence), string(payload)))
	}

	switch name {
	case "healthy":
		for sequence := 1; sequence <= semanticEventCount; sequence++ {
			if err := waitContext(r.Context(), 40*time.Millisecond); err != nil {
				return
			}
			if sequence%2 == 0 {
				if err := writeSSE(w, ": heartbeat\n\n"); err != nil {
					return
				}
			}
			if err := message(sequence, ""); err != nil {
				return
			}
		}
		if err := writeSSE(w, formatSSE("done", "", `{"completed":true}`)); err != nil {
			return
		}
		outcome = "completed"
	case "terminal-error":
		if err := message(1, ""); err != nil {
			return
		}
		if err := writeSSE(w, formatSSE("error", "", `{"code":"fixture_error"}`)); err != nil {
			return
		}
		outcome = "completed"
	case "missing-terminal":
		for sequence := 1; sequence <= 3; sequence++ {
			if err := message(sequence, ""); err != nil {
				return
			}
		}
		outcome = "completed"
	case "cancel":
		for sequence := 1; ; sequence++ {
			if err := message(sequence, ""); err != nil {
				return
			}
			if err := waitContext(r.Context(), 25*time.Millisecond); err != nil {
				return
			}
		}
	case "stall":
		if err := message(1, ""); err != nil {
			return
		}
		if err := waitContext(r.Context(), 5*time.Second); err != nil {
			return
		}
		if err := writeSSE(w, formatSSE("done", "", `{"completed":true}`)); err != nil {
			return
		}
		outcome = "completed"
	case "slow":
		padding := strings.Repeat("x", 4096)
		for sequence := 1; sequence <= 16384; sequence++ {
			if err := message(sequence, padding); err != nil {
				return
			}
		}
		if err := writeSSE(w, formatSSE("done", "", `{"completed":true}`)); err != nil {
			return
		}
		outcome = "completed"
	default:
		http.Error(w, "unknown fixture scenario", http.StatusNotFound)
	}
}

func runUpstream() error {
	state := newUpstreamState()
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.snapshot())
	})
	mux.HandleFunc("/sse/", func(w http.ResponseWriter, r *http.Request) {
		serveScenario(state, w, r)
	})
	server := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       3 * time.Second,
	}
	return server.ListenAndServe()
}

type metrics map[string]float64

var requiredMetrics = []string{
	"active_requests",
	"active_route_requests",
	"active_upstream_requests",
	"active_upstream_http1_requests",
	"active_http2_streams",
	"request_timeouts_total",
	"http2_request_cancellations_total",
}

func fetch(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 4<<20))
}

func gatewayMetrics() (metrics, error) {
	body, err := fetch(*metricsURL, time.Second)
	if err != nil {
		return nil, err
	}
	all := metrics{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], metricPrefix) {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(fields[0], metricPrefix), "{")
		value, parseErr := strconv.ParseFloat(fields[1], 64)
		if parseErr != nil {
			return nil, parseErr
		}
		all[name] += value
	}
	result := metrics{}
	for _, name := range requiredMetrics {
		value, ok := all[name]
		if !ok {
			return nil, fmt.Errorf("missing gateway metric %s", name)
		}
		result[name] = value
	}
	return result, nil
}

func upstreamMetrics() (map[string]scenarioCounter, error) {
	body, err := fetch(*upstreamURL+"/stats", time.Second)
	if err != nil {
		return nil, err
	}
	result := map[string]scenarioCounter{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func requestsDrained(value metrics) bool {
	for _, name := range []string{
		"active_requests", "active_route_requests", "active_upstream_requests",
		"active_upstream_http1_requests", "active_http2_streams",
	} {
		if value[name] != 0 {
			return false
		}
	}
	return true
}

func waitDrained(scenario string) (metrics, scenarioCounter, time.Duration, error) {
	started := time.Now()
	deadline := started.Add(cleanupBound)
	for {
		gateway, gatewayErr := gatewayMetrics()
		upstream, upstreamErr := upstreamMetrics()
		if gatewayErr != nil {
			return nil, scenarioCounter{}, 0, gatewayErr
		}
		if upstreamErr != nil {
			return nil, scenarioCounter{}, 0, upstreamErr
		}
		counter := upstream[scenario]
		if requestsDrained(gateway) && counter.Active == 0 {
			return gateway, counter, time.Since(started), nil
		}
		if time.Now().After(deadline) {
			return gateway, counter, time.Since(started),
				fmt.Errorf("%s did not drain within %s", scenario, cleanupBound)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type protocolClient struct {
	name    string
	baseURL string
	client  *http.Client
	close   func()
}

func clients() ([]protocolClient, error) {
	certificate, err := os.ReadFile(*caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("fixture CA is invalid")
	}
	http1TLS := &tls.Config{
		RootCAs: roots, ServerName: "api.example.test",
		MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
	}
	http1Transport := &http.Transport{
		TLSClientConfig: http1TLS, ForceAttemptHTTP2: false,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	http2Transport := &http2.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "api.example.test",
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	}}
	return []protocolClient{
		{name: "https-http1", baseURL: "https://api.example.test:8443",
			client: &http.Client{Transport: http1Transport},
			close:  http1Transport.CloseIdleConnections},
		{name: "https-http2", baseURL: "https://api.example.test:8444",
			client: &http.Client{Transport: http2Transport},
			close:  http2Transport.CloseIdleConnections},
	}, nil
}

type observedEvent struct {
	Event     sseEvent `json:"event"`
	ArrivalMS float64  `json:"arrival_ms"`
}

type caseResult struct {
	Name              string          `json:"name"`
	Protocol          string          `json:"protocol"`
	ExpectedOutcome   string          `json:"expected_outcome"`
	Pass              bool            `json:"pass"`
	Errors            []string        `json:"errors,omitempty"`
	HTTPStatus        int             `json:"http_status,omitempty"`
	ResponseProtocol  string          `json:"response_protocol,omitempty"`
	TTFBMS            float64         `json:"ttfb_ms,omitempty"`
	FirstSemanticMS   float64         `json:"first_semantic_ms,omitempty"`
	CompletionMS      float64         `json:"completion_ms,omitempty"`
	MaximumEventGapMS float64         `json:"maximum_event_gap_ms,omitempty"`
	SemanticEvents    int             `json:"semantic_events"`
	Heartbeats        int             `json:"heartbeats"`
	TerminalEvent     string          `json:"terminal_event,omitempty"`
	LogicalSuccess    bool            `json:"logical_success"`
	CleanupMS         float64         `json:"cleanup_ms,omitempty"`
	GatewayBefore     metrics         `json:"gateway_before,omitempty"`
	GatewayAfter      metrics         `json:"gateway_after,omitempty"`
	UpstreamAfter     scenarioCounter `json:"upstream_after,omitempty"`
	Events            []observedEvent `json:"events,omitempty"`
}

func (r *caseResult) check(err error) {
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
}

func openStream(client protocolClient, scenario string) (*http.Response,
	context.CancelFunc, time.Time, float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.baseURL+"/sse/"+scenario, nil)
	if err != nil {
		cancel()
		return nil, nil, time.Time{}, 0, err
	}
	request.Header.Set("Accept", "text/event-stream")
	started := time.Now()
	response, err := client.client.Do(request)
	ttfb := float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		cancel()
		return nil, nil, started, ttfb, err
	}
	return response, cancel, started, ttfb, nil
}

func recordStream(result *caseResult, response *http.Response, started time.Time,
	stopAfter int) error {
	lastArrival := 0.0
	return parseSSE(response.Body, func(event sseEvent) error {
		arrival := float64(time.Since(started).Microseconds()) / 1000
		if lastArrival > 0 && arrival-lastArrival > result.MaximumEventGapMS {
			result.MaximumEventGapMS = arrival - lastArrival
		}
		lastArrival = arrival
		result.Events = append(result.Events, observedEvent{event, arrival})
		if event.Heartbeat {
			result.Heartbeats++
			return nil
		}
		switch event.Event {
		case "message":
			result.SemanticEvents++
			if result.FirstSemanticMS == 0 {
				result.FirstSemanticMS = arrival
			}
		case "done", "error":
			result.TerminalEvent = event.Event
		}
		if stopAfter > 0 && result.SemanticEvents >= stopAfter {
			return errStopReading
		}
		return nil
	})
}

var errStopReading = errors.New("fixture requested reader stop")

func expectedProtocol(name string) string {
	if name == "https-http2" {
		return "HTTP/2.0"
	}
	return "HTTP/1.1"
}

func beginCase(client protocolClient, scenario, expected string) caseResult {
	result := caseResult{
		Name: scenario, Protocol: client.name, ExpectedOutcome: expected,
	}
	before, err := gatewayMetrics()
	result.check(err)
	result.GatewayBefore = before
	if err == nil && !requestsDrained(before) {
		result.check(errors.New("case started with active gateway work"))
	}
	return result
}

func finishCase(result *caseResult, scenario string) {
	gateway, upstream, elapsed, err := waitDrained(scenario)
	result.check(err)
	result.GatewayAfter = gateway
	result.UpstreamAfter = upstream
	result.CleanupMS = float64(elapsed.Microseconds()) / 1000
	result.Pass = len(result.Errors) == 0
}

func runCompletedCase(client protocolClient, scenario, expected string) caseResult {
	result := beginCase(client, scenario, expected)
	response, cancel, started, ttfb, err := openStream(client, scenario)
	result.TTFBMS = ttfb
	if err == nil {
		result.HTTPStatus = response.StatusCode
		result.ResponseProtocol = response.Proto
		if response.StatusCode != http.StatusOK ||
			response.Header.Get("Content-Type") != "text/event-stream" ||
			response.Header.Get("X-Perf05-SSE-Scenario") != scenario ||
			response.Proto != expectedProtocol(client.name) {
			result.check(fmt.Errorf("unexpected response metadata: status=%d proto=%s content-type=%q scenario=%q",
				response.StatusCode, response.Proto,
				response.Header.Get("Content-Type"),
				response.Header.Get("X-Perf05-SSE-Scenario")))
		}
		result.check(recordStream(&result, response, started, 0))
		result.CompletionMS = float64(time.Since(started).Microseconds()) / 1000
		_ = response.Body.Close()
		cancel()
	} else {
		result.check(err)
	}
	client.close()

	switch scenario {
	case "healthy":
		result.LogicalSuccess = result.TerminalEvent == "done" &&
			result.SemanticEvents == semanticEventCount
		if !result.LogicalSuccess {
			result.check(fmt.Errorf("healthy stream lacked exact semantic completion: events=%d terminal=%q",
				result.SemanticEvents, result.TerminalEvent))
		}
		if result.FirstSemanticMS <= 0 ||
			result.FirstSemanticMS >= result.CompletionMS-100 {
			result.check(fmt.Errorf("healthy stream was not observably incremental: first=%.3fms completion=%.3fms",
				result.FirstSemanticMS, result.CompletionMS))
		}
	case "terminal-error":
		result.LogicalSuccess = false
		if result.TerminalEvent != "error" || result.SemanticEvents != 1 {
			result.check(errors.New("terminal error was not classified distinctly"))
		}
	case "missing-terminal":
		result.LogicalSuccess = false
		if result.TerminalEvent != "" || result.SemanticEvents != 3 {
			result.check(errors.New("missing terminal event was misclassified"))
		}
	}
	finishCase(&result, scenario)
	return result
}

func runCancelCase(client protocolClient) caseResult {
	const scenario = "cancel"
	result := beginCase(client, scenario, "client-cancellation")
	response, cancel, started, ttfb, err := openStream(client, scenario)
	result.TTFBMS = ttfb
	if err == nil {
		result.HTTPStatus = response.StatusCode
		result.ResponseProtocol = response.Proto
		err = recordStream(&result, response, started, 2)
		if !errors.Is(err, errStopReading) {
			result.check(fmt.Errorf("cancellation setup did not observe two events: %w", err))
		}
		cancel()
		_ = response.Body.Close()
	} else {
		result.check(err)
	}
	client.close()
	result.LogicalSuccess = false
	finishCase(&result, scenario)
	if result.UpstreamAfter.Canceled == 0 {
		result.check(errors.New("client cancellation did not reach the controlled upstream"))
	}
	result.Pass = len(result.Errors) == 0
	return result
}

func runStallCase(client protocolClient) caseResult {
	const scenario = "stall"
	result := beginCase(client, scenario, "gateway-deadline")
	response, cancel, started, ttfb, err := openStream(client, scenario)
	result.TTFBMS = ttfb
	if err == nil {
		result.HTTPStatus = response.StatusCode
		result.ResponseProtocol = response.Proto
		readErr := recordStream(&result, response, started, 0)
		if readErr == nil && result.TerminalEvent == "done" {
			result.check(errors.New("stalled stream completed instead of timing out"))
		}
		_ = response.Body.Close()
		cancel()
	} else {
		result.check(err)
	}
	client.close()
	result.CompletionMS = float64(time.Since(started).Microseconds()) / 1000
	result.LogicalSuccess = false
	finishCase(&result, scenario)
	if result.GatewayAfter != nil &&
		result.GatewayAfter["request_timeouts_total"] <=
			result.GatewayBefore["request_timeouts_total"] {
		result.check(errors.New("stalled stream did not increment request timeout"))
	}
	if result.UpstreamAfter.Canceled == 0 {
		result.check(errors.New("stalled upstream request was not canceled"))
	}
	result.Pass = len(result.Errors) == 0
	return result
}

func runSlowCase(client protocolClient) caseResult {
	const scenario = "slow"
	result := beginCase(client, scenario, "bounded-slow-consumer")
	response, cancel, started, ttfb, err := openStream(client, scenario)
	result.TTFBMS = ttfb
	if err == nil {
		result.HTTPStatus = response.StatusCode
		result.ResponseProtocol = response.Proto
		err = recordStream(&result, response, started, 1)
		if !errors.Is(err, errStopReading) {
			result.check(fmt.Errorf("slow-reader setup did not observe an event: %w", err))
		}
		time.Sleep(requestTimeout + 300*time.Millisecond)
		_ = response.Body.Close()
		cancel()
	} else {
		result.check(err)
	}
	client.close()
	result.LogicalSuccess = false
	finishCase(&result, scenario)
	if result.UpstreamAfter.Canceled == 0 {
		result.check(errors.New("slow consumer did not cancel bounded upstream work"))
	}
	result.Pass = len(result.Errors) == 0
	return result
}

func runClient() error {
	protocols, err := clients()
	if err != nil {
		return err
	}
	results := []caseResult{}
	for _, client := range protocols {
		results = append(results,
			runCompletedCase(client, "healthy", "logical-success"),
			runCompletedCase(client, "terminal-error", "logical-error"),
			runCompletedCase(client, "missing-terminal", "logical-incomplete"),
			runCancelCase(client),
			runStallCase(client),
			runSlowCase(client),
		)
	}
	pass := true
	for _, result := range results {
		pass = pass && result.Pass
	}
	output := map[string]any{
		"schema_version":     1,
		"profile":            "P5-S01",
		"pass":               pass,
		"request_timeout_ms": requestTimeout.Milliseconds(),
		"cleanup_bound_ms":   cleanupBound.Milliseconds(),
		"cases":              results,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}
	if !pass {
		return errors.New("PERF-05 SSE local preflight failed")
	}
	return nil
}

func run() error {
	flag.Parse()
	switch *mode {
	case "upstream":
		return runUpstream()
	case "ready":
		_, err := fetch(*readyURL, time.Second)
		return err
	case "metrics":
		value, err := gatewayMetrics()
		if err != nil {
			return err
		}
		if !requestsDrained(value) {
			return fmt.Errorf("gateway work remains active: %v", value)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	case "client":
		return runClient()
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
