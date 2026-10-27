// A bounded frame-level client: withheld stream credit is independent of TCP
// backpressure, and HPACK decoding remains owned by x/net/http2.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"gopkg.in/yaml.v3"
)

const requestTimeout = 400 * time.Millisecond
const resetBound = 2 * time.Second
const connectionWindow = 32 << 20
const metricPrefix = "bonvoyage_bonvoyage_gateway_"

var errObservationDeadline = errors.New("observation deadline exceeded")
var metricNames = []string{
	"active_requests", "active_route_requests", "active_http2_streams",
	"active_upstream_requests", "active_connections", "active_http2_connections",
	"request_timeouts_total", "http2_request_cancellations_total",
	"http2_stream_resets_total", "route_overload_rejections_total",
}

var mode = flag.String("mode", "flow-control", "flow-control, transport, cookie, generate, upstream, ready, or metrics")
var address = flag.String("addr", "api.example.test:8443", "gateway TLS address")
var caPath = flag.String("ca", "/secrets/server-chain.pem", "fixture CA")
var metricsURL = flag.String("metrics", "http://gateway:9090/metrics", "metrics endpoint")
var readyURL = flag.String("ready", "http://gateway:9901/health/ready", "readiness endpoint")
var evidence = flag.String("evidence", "/evidence", "evidence directory")

type response struct {
	Status string         `json:"status"`
	Bytes  int            `json:"bytes"`
	End    bool           `json:"end_stream"`
	Reset  *http2.ErrCode `json:"reset_code,omitempty"`
	AtMS   int64          `json:"last_frame_ms"`
	body   []byte
}

type event struct {
	id       uint32
	status   string
	data     []byte
	end      bool
	reset    *http2.ErrCode
	ping     uint64
	settings bool
	ack      bool
	err      error
}

type peer struct {
	conn              *tls.Conn
	framer            *http2.Framer
	mu                sync.Mutex
	events            chan event
	done              chan struct{}
	started           time.Time
	streams           map[uint32]*response
	settings, ack     bool
	pingSent, pingACK uint64
	closed            bool
}

func (p *peer) write(fn func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	return fn()
}

func dial(window uint32, receiveBuffer int, background bool) (*peer, error) {
	cert, err := os.ReadFile(*caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return nil, errors.New("invalid fixture CA")
	}
	raw, err := net.DialTimeout("tcp", *address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if receiveBuffer > 0 {
		if err = raw.(*net.TCPConn).SetReadBuffer(receiveBuffer); err != nil {
			raw.Close()
			return nil, err
		}
	}
	c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "api.example.test", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err = c.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		raw.Close()
		return nil, err
	}
	if err = c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		raw.Close()
		return nil, errors.New("ALPN did not select h2")
	}
	p := &peer{conn: c, framer: http2.NewFramer(c, c), events: make(chan event, 64), done: make(chan struct{}), started: time.Now(), streams: map[uint32]*response{}}
	p.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	p.framer.MaxHeaderListSize = 32768
	err = p.write(func() error {
		if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
			return err
		}
		if err := p.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window}, http2.Setting{ID: http2.SettingEnablePush, Val: 0}); err != nil {
			return err
		}
		return p.framer.WriteWindowUpdate(0, connectionWindow-65535)
	})
	if err != nil {
		p.close()
		return nil, err
	}
	if background {
		go func() {
			for {
				e := p.read()
				select {
				case p.events <- e:
				case <-p.done:
					return
				}
				if e.err != nil {
					return
				}
			}
		}()
		err = p.wait(time.Now().Add(time.Second), func() bool { return p.settings && p.ack })
	} else {
		for !p.settings || !p.ack {
			if err = p.accept(p.read()); err != nil {
				break
			}
		}
	}
	if err != nil {
		p.close()
		return nil, err
	}
	p.started = time.Now()
	return p, nil
}

func (p *peer) close() {
	if !p.closed {
		p.closed = true
		close(p.done)
		p.conn.NetConn().Close()
	}
}

func (p *peer) read() event {
	f, err := p.framer.ReadFrame()
	if err != nil {
		return event{err: err}
	}
	e := event{id: f.Header().StreamID}
	switch f := f.(type) {
	case *http2.SettingsFrame:
		e.ack, e.settings = f.IsAck(), !f.IsAck()
		if !f.IsAck() {
			e.err = p.write(p.framer.WriteSettingsAck)
		}
	case *http2.PingFrame:
		if f.IsAck() {
			e.ping = binary.BigEndian.Uint64(f.Data[:])
		} else {
			e.err = p.write(func() error { return p.framer.WritePing(true, f.Data) })
		}
	case *http2.MetaHeadersFrame:
		if f.Truncated {
			e.err = errors.New("truncated response headers")
		}
		for _, field := range f.Fields {
			if field.Name == ":status" {
				e.status = field.Value
			}
		}
		e.end = f.StreamEnded()
	case *http2.DataFrame:
		e.data, e.end = bytes.Clone(f.Data()), f.StreamEnded()
	case *http2.RSTStreamFrame:
		code := f.ErrCode
		e.reset = &code
	case *http2.GoAwayFrame:
		e.err = fmt.Errorf("connection GOAWAY: %v %q", f.ErrCode, f.DebugData())
	}
	return e
}

func (p *peer) accept(e event) error {
	if e.err != nil {
		return e.err
	}
	p.settings = p.settings || e.settings
	p.ack = p.ack || e.ack
	if e.ping > p.pingSent {
		return errors.New("unexpected PING acknowledgement")
	}
	if e.ping > p.pingACK {
		p.pingACK = e.ping
	}
	if e.id != 0 {
		s := p.stream(e.id)
		if e.status != "" {
			s.Status = e.status
		}
		s.body = append(s.body, e.data...)
		s.Bytes += len(e.data)
		s.End = s.End || e.end
		if e.reset != nil {
			s.Reset = e.reset
		}
		s.AtMS = time.Since(p.started).Milliseconds()
	}
	return nil
}

func (p *peer) stream(id uint32) *response {
	if p.streams[id] == nil {
		p.streams[id] = &response{}
	}
	return p.streams[id]
}

func (p *peer) ping() error {
	p.pingSent++
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], p.pingSent)
	return p.write(func() error { return p.framer.WritePing(false, data) })
}

func (p *peer) wait(deadline time.Time, condition func() bool) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if !time.Now().Before(deadline) {
			return errObservationDeadline
		}
		if condition() {
			return nil
		}
		select {
		case e := <-p.events:
			if err := p.accept(e); err != nil {
				return err
			}
		case <-tick.C:
			if err := p.ping(); err != nil {
				return err
			}
		case <-timer.C:
			return errObservationDeadline
		}
	}
}

func (p *peer) request(id uint32, method, path string, credit uint32) error {
	return p.requestFields(id, method, path, credit, nil)
}

func (p *peer) requestFields(id uint32, method, path string, credit uint32, extra []hpack.HeaderField) error {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "api.example.test"}, {Name: ":path", Value: path}}
	for _, field := range append(fields, extra...) {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	return p.write(func() error {
		encoded := block.Bytes()
		first := min(len(encoded), 16384)
		if err := p.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: encoded[:first], EndStream: true, EndHeaders: first == len(encoded)}); err != nil {
			return err
		}
		for offset := first; offset < len(encoded); {
			end := min(offset+16384, len(encoded))
			if err := p.framer.WriteContinuation(id, end == len(encoded), encoded[offset:end]); err != nil {
				return err
			}
			offset = end
		}
		if credit > 0 {
			return p.framer.WriteWindowUpdate(id, credit)
		}
		return nil
	})
}

func (p *peer) expect(id uint32, body []byte, deadline time.Time) error {
	s := p.stream(id)
	if err := p.wait(deadline, func() bool { return s.End || s.Reset != nil }); err != nil {
		return err
	}
	if s.Reset != nil || s.Status != "200" || !bytes.Equal(s.body, body) {
		return fmt.Errorf("stream %d: status=%s bytes=%d reset=%v, expected 200/%d bytes", id, s.Status, s.Bytes, s.Reset, len(body))
	}
	return nil
}

type metrics map[string]float64

func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: time.Second}
	r, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("%s: status %d", url, r.StatusCode)
	}
	return io.ReadAll(io.LimitReader(r.Body, 4<<20))
}

func snapshot(name string) (metrics, error) {
	body, err := fetch(*metricsURL)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(*evidence, name+".prom"), body, 0600); err != nil {
		return nil, err
	}
	all := metrics{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], metricPrefix) {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(fields[0], metricPrefix), "{")
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, err
		}
		all[name] += v
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	m := metrics{}
	for _, name := range metricNames {
		v, ok := all[name]
		if !ok {
			return nil, fmt.Errorf("missing metric %s", name)
		}
		m[name] = v
	}
	return m, nil
}

func drained(m metrics) bool {
	for _, name := range []string{"active_requests", "active_route_requests", "active_http2_streams", "active_upstream_requests"} {
		if m[name] != 0 {
			return false
		}
	}
	return true
}

func quiescent(m metrics) bool {
	return drained(m) && m["active_connections"] == 0 && m["active_http2_connections"] == 0
}

type result struct {
	Name         string               `json:"name"`
	Pass         bool                 `json:"pass"`
	Errors       []string             `json:"errors,omitempty"`
	Observations map[string]any       `json:"observations"`
	Streams      map[uint32]*response `json:"streams,omitempty"`
	Before       metrics              `json:"metrics_before,omitempty"`
	OpenAfter    metrics              `json:"metrics_while_client_open,omitempty"`
	After        metrics              `json:"metrics_after_close,omitempty"`
	p            *peer
}

func (r *result) check(err error) {
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
}

func runCase(name string, test func(*result) error) result {
	r := result{Name: name, Observations: map[string]any{}}
	var err error
	r.Before, err = snapshot(name + "-before")
	if err == nil && !quiescent(r.Before) {
		err = errors.New("case did not start with quiescent request/stream/route/connection gauges")
	}
	r.check(err)
	if err == nil {
		r.check(test(&r))
	}
	r.OpenAfter, err = snapshot(name + "-open-after")
	r.check(err)
	if r.p != nil {
		r.Streams = r.p.streams
		r.Observations["ping_sent"] = r.p.pingSent
		r.Observations["ping_ack"] = r.p.pingACK
		r.Observations["client_closed_before_final_observation"] = r.p.closed
		r.p.close()
	}
	for deadline := time.Now().Add(time.Second); ; {
		r.After, err = snapshot(name + "-after-close")
		if err != nil || quiescent(r.After) || time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.check(err)
	if err == nil && !quiescent(r.After) {
		r.check(errors.New("gauges did not drain after client close"))
	}
	r.Pass = len(r.Errors) == 0
	return r
}

func flow(r *result, path string, cancel bool) error {
	p, err := dial(0, 0, true)
	if err != nil {
		return err
	}
	r.p = p
	if err = p.request(1, "GET", path, 0); err != nil {
		return err
	}
	if err = p.wait(p.started.Add(300*time.Millisecond), func() bool { return p.stream(1).Status != "" }); err != nil {
		return fmt.Errorf("blocked response headers: %w", err)
	}
	if p.stream(1).Status != "200" {
		return fmt.Errorf("blocked response status %s", p.stream(1).Status)
	}
	if err = p.request(3, "HEAD", "/healthy", 0); err != nil {
		return err
	}
	if err = p.expect(3, nil, p.started.Add(350*time.Millisecond)); err != nil {
		return fmt.Errorf("HEAD canary before timeout: %w", err)
	}
	r.Observations["head_before_timeout_ms"] = time.Since(p.started).Milliseconds()
	during, err := snapshot(r.Name + "-blocked")
	if err != nil {
		return err
	}
	r.Observations["blocked_metrics"] = during
	if during["active_http2_streams"] != 1 {
		return errors.New("expected exactly one blocked active stream")
	}
	if during["active_requests"] != 1 || during["active_route_requests"] != 1 {
		r.check(errors.New("queued response released its request/route slot before terminal output"))
	}
	if cancel {
		if time.Since(p.started) >= requestTimeout {
			return errors.New("peer cancellation setup exceeded the request deadline")
		}
		if err = p.write(func() error { return p.framer.WriteRSTStream(1, http2.ErrCodeCancel) }); err != nil {
			return err
		}
		r.Observations["peer_reset_ms"] = time.Since(p.started).Milliseconds()
	} else {
		if err = p.wait(p.started.Add(resetBound), func() bool { return p.stream(1).Reset != nil || p.stream(1).End }); err != nil {
			return fmt.Errorf("no timeout RST_STREAM within 2s: %w", err)
		}
		s := p.stream(1)
		r.Observations["timeout_reset_ms"] = s.AtMS
		if s.Reset == nil || *s.Reset == http2.ErrCodeNo || s.End || s.Bytes != 0 {
			return fmt.Errorf("expected error reset with no DATA/END_STREAM: %+v", s)
		}
		if s.AtMS < 250 || s.AtMS > 2000 {
			return fmt.Errorf("reset outside request deadline envelope: %dms", s.AtMS)
		}
		if p.pingACK == 0 {
			return errors.New("no PING ACK while stream credit withheld")
		}
	}
	// Observe permit release without granting credit to the stalled stream.
	for deadline := p.started.Add(resetBound); ; {
		m, err := snapshot(r.Name + "-drained-open")
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("request/stream/route gauges retained while peer is open: %v", m)
		}
		if drained(m) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = p.request(5, "GET", "/healthy", 65535); err != nil {
		return err
	}
	if err = p.expect(5, []byte("ok\n"), time.Now().Add(350*time.Millisecond)); err != nil {
		return fmt.Errorf("GET canary after release: %w", err)
	}
	if err = p.request(7, "HEAD", path, 0); err != nil {
		return err
	}
	if err = p.expect(7, nil, time.Now().Add(350*time.Millisecond)); err != nil {
		return fmt.Errorf("same-route HEAD admission recovery: %w", err)
	}
	// In cancellation controls, cross the original deadline with the same peer
	// still live, so a timer left armed cannot hide behind immediate close.
	until := p.started.Add(requestTimeout + 150*time.Millisecond)
	if cancel && time.Now().Before(until) {
		err = p.wait(until, func() bool { return false })
		if err != nil && !errors.Is(err, errObservationDeadline) {
			return err
		}
	}
	if p.stream(1).Bytes != 0 || p.stream(1).End {
		return errors.New("zero-window stream received DATA or a successful END_STREAM")
	}
	if err = p.ping(); err != nil {
		return err
	}
	if err = p.wait(time.Now().Add(300*time.Millisecond), func() bool { return p.pingACK == p.pingSent }); err != nil {
		return fmt.Errorf("connection not reusable: %w", err)
	}
	m, err := snapshot(r.Name + "-verified-open")
	if err != nil {
		return err
	}
	wantTimeout := float64(1)
	if cancel {
		wantTimeout = 0
	}
	delta := m["request_timeouts_total"] - r.Before["request_timeouts_total"]
	r.Observations["timeout_delta"] = delta
	r.Observations["cancellation_delta"] = m["http2_request_cancellations_total"] - r.Before["http2_request_cancellations_total"]
	if delta != wantTimeout {
		return fmt.Errorf("timeout delta %g, expected %g", delta, wantTimeout)
	}
	if cancel && m["http2_request_cancellations_total"]-r.Before["http2_request_cancellations_total"] != 1 {
		return errors.New("peer RST must record exactly one cancellation")
	}
	if !drained(m) || m["active_http2_connections"] != 1 || m["active_connections"] != 1 {
		return errors.New("gauges not drained on the still-live connection")
	}
	return nil
}

func normal(r *result, path string) error {
	p, err := dial(1<<20, 0, true)
	if err != nil {
		return err
	}
	r.p = p
	if err = p.request(1, "GET", path, 0); err != nil {
		return err
	}
	want := bytes.Repeat([]byte("x"), 512<<10)
	if err = p.expect(1, want, p.started.Add(resetBound)); err != nil {
		return err
	}
	r.Observations["sha256"] = fmt.Sprintf("%x", sha256.Sum256(p.stream(1).body))
	r.Observations["completed_ms"] = time.Since(p.started).Milliseconds()
	if err = p.wait(p.started.Add(requestTimeout+150*time.Millisecond), func() bool { return false }); !errors.Is(err, errObservationDeadline) {
		return fmt.Errorf("normal connection did not survive the original deadline: %w", err)
	}
	m, err := snapshot(r.Name + "-verified-open")
	if err != nil {
		return err
	}
	if !drained(m) || p.stream(1).Reset != nil || m["request_timeouts_total"] != r.Before["request_timeouts_total"] {
		return errors.New("normal transfer timed out or retained active gauges")
	}
	return nil
}

func transport(r *result) error {
	// No background reader: after response headers, no more TLS/TCP bytes are
	// consumed until metrics have proved cleanup (or the bounded test fails).
	p, err := dial(connectionWindow, 1024, false)
	if err != nil {
		return err
	}
	r.p = p
	if err = p.conn.SetReadDeadline(p.started.Add(resetBound)); err != nil {
		return err
	}
	if err = p.request(1, "GET", "/payload/16M", 0); err != nil {
		return err
	}
	for p.stream(1).Status == "" {
		if err = p.accept(p.read()); err != nil {
			return err
		}
	}
	if p.stream(1).Status != "200" {
		return fmt.Errorf("nonreader status %s", p.stream(1).Status)
	}
	r.Observations["stopped_reading_ms"] = time.Since(p.started).Milliseconds()
	r.Observations["receive_buffer_requested"] = 1024
	r.Observations["initial_stream_window"] = connectionWindow
	r.Observations["connection_window"] = connectionWindow
	r.Observations["upstream_body_bytes"] = 16 << 20
	seenActive := false
	for {
		m, err := snapshot(r.Name + "-while-not-reading")
		if err != nil {
			return err
		}
		if time.Since(p.started) >= resetBound {
			return fmt.Errorf("nonreader did not drain by 2s while client remained open (active observed=%t): %v", seenActive, m)
		}
		if !drained(m) && !seenActive {
			seenActive = true
			r.Observations["blocked_metrics"] = m
			if _, err = snapshot(r.Name + "-blocked"); err != nil {
				return err
			}
		}
		if seenActive && drained(m) && m["active_connections"] == 0 && m["active_http2_connections"] == 0 && m["request_timeouts_total"]-r.Before["request_timeouts_total"] == 1 {
			r.Observations["drained_while_not_reading_ms"] = time.Since(p.started).Milliseconds()
			if time.Since(p.started) < 250*time.Millisecond {
				return errors.New("nonreader closed before the request deadline envelope")
			}
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func generate() error {
	type object = map[string]any
	routes := []object{}
	for _, item := range []struct {
		name, path string
		size       int
	}{{"small", "/small", 64 << 10}, {"large", "/large", 512 << 10}, {"healthy", "/healthy", 0}} {
		body := strings.Repeat("x", item.size)
		if item.name == "healthy" {
			body = "ok\n"
		}
		routes = append(routes, object{"name": item.name, "match": object{"path_exact": item.path}, "max_concurrent_requests_per_shard": 1, "fixed_response": object{"status_code": 200, "body": body, "content_type": "application/octet-stream"}})
	}
	for _, size := range []string{"512K", "16M"} {
		routes = append(routes, object{"name": "upstream-" + size, "match": object{"path_exact": "/payload/" + size}, "cluster": "upstream", "max_concurrent_requests_per_shard": 1})
	}
	routes = append(routes, object{"name": "cookies", "match": object{"path_exact": "/cookies"}, "cluster": "upstream"})
	doc := object{
		"server":         object{"node_id": "http2-deadline", "admin_addr": "0.0.0.0:9901", "metrics_addr": "0.0.0.0:9090"},
		"snapshot":       object{"schema_version": 1, "snapshot_id": "http2-deadline", "generation": 1, "minimum_dataplane_version": "0.2.0"},
		"listeners":      []object{{"name": "h2", "address": "0.0.0.0", "port": 8443, "protocol": "http2", "virtual_hosts": []string{"api"}, "downstream_tls": object{"certificate_chain_secret": "server-chain.pem", "private_key_secret": "server-key.pem"}}},
		"virtual_hosts":  []object{{"name": "api", "domains": []string{"api.example.test"}, "routes": routes}},
		"clusters":       []object{{"name": "upstream", "load_balancing_policy": "round_robin", "connect_timeout_ms": 200, "max_connections_per_shard": 4, "max_pending_requests_per_shard": 4, "endpoints": []object{{"name": "controlled", "address": "upstream", "port": 8081}}}},
		"runtime_limits": object{"max_downstream_connections_per_shard": 32, "max_request_header_bytes": 32768, "max_request_body_bytes": 1048576, "max_upstream_response_header_bytes": 32768, "max_upstream_chunk_metadata_bytes": 32768, "request_timeout_ms": 400, "downstream_idle_timeout_ms": 2500},
	}
	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(doc)
}

func upstream() error {
	mux := http.NewServeMux()
	registerCookieUpstream(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		size := 0
		switch r.URL.Path {
		case "/payload/512K":
			size = 512 << 10
		case "/payload/16M":
			size = 16 << 20
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if r.Method != "HEAD" {
			_, _ = w.Write(bytes.Repeat([]byte("x"), size))
		}
	})
	server := &http.Server{Addr: ":8081", Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 3 * time.Second}
	return server.ListenAndServe()
}

func run() error {
	flag.Parse()
	switch *mode {
	case "generate":
		return generate()
	case "upstream":
		return upstream()
	case "ready":
		_, err := fetch(*readyURL)
		return err
	case "metrics":
		m, err := snapshot("metrics")
		if err == nil && !quiescent(m) {
			return fmt.Errorf("final request/stream/route/connection gauges not quiescent: %v", m)
		}
		return err
	case "cookie":
		return runCookieCases()
	case "flow-control", "transport":
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
	if err := os.MkdirAll(*evidence, 0700); err != nil {
		return err
	}
	results := []result{}
	if *mode == "transport" {
		results = append(results, runCase("tcp-nonreader", transport))
	} else {
		for _, path := range []string{"/small", "/large"} {
			results = append(results, runCase("zero-window"+strings.ReplaceAll(path, "/", "-"), func(r *result) error { return flow(r, path, false) }))
		}
		for _, path := range []string{"/small", "/large"} {
			results = append(results, runCase("peer-reset"+strings.ReplaceAll(path, "/", "-"), func(r *result) error { return flow(r, path, true) }))
		}
		for _, path := range []string{"/large", "/payload/512K"} {
			results = append(results, runCase("normal"+strings.ReplaceAll(path, "/", "-"), func(r *result) error { return normal(r, path) }))
		}
	}
	pass := true
	for _, r := range results {
		pass = pass && r.Pass
	}
	output := map[string]any{"mode": *mode, "pass": pass, "request_timeout_ms": 400, "idle_timeout_ms": 2500, "reset_bound_ms": 2000, "cases": results}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}
	if !pass {
		return errors.New("HTTP/2 deadline regression failed; see client JSON and per-case metrics")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
