package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/proto"
)

const (
	maximumRouteCount    = 100_000
	maximumSnapshotBytes = 16 * 1024 * 1024
)

type snapshotMetadata struct {
	Bytes       int    `json:"bytes"`
	RouteCount  int    `json:"route_count"`
	SHA256      string `json:"sha256"`
	SnapshotID  string `json:"snapshot_id"`
	Output      string `json:"output"`
	MaximumConn uint32 `json:"max_downstream_connections_per_shard"`
	IdleMS      uint32 `json:"downstream_idle_timeout_ms"`
}

type heldConnection struct {
	connection net.Conn
}

type holderState struct {
	mu             sync.Mutex
	connections    []heldConnection
	target         int
	opened         int
	openDurationMS int64
	released       bool
}

type holderSummary struct {
	Target         int   `json:"target"`
	Opened         int   `json:"opened"`
	OpenDurationMS int64 `json:"open_duration_ms"`
	Released       bool  `json:"released"`
}

func main() {
	if len(os.Args) < 2 {
		exitError(errors.New("usage: phase3-scale-fixture snapshot|hold [options]"))
	}

	var err error
	switch os.Args[1] {
	case "snapshot":
		err = runSnapshot(os.Args[2:])
	case "hold":
		err = runHolder(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		exitError(err)
	}
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func runSnapshot(args []string) error {
	flags := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	routeCount := flags.Int("routes", 0, "number of exact routes")
	output := flags.String("output", "", "snapshot output path")
	port := flags.Uint("port", 8080, "listener port")
	maximumConnections := flags.Uint("max-connections", 20_000, "downstream connections per shard")
	idleTimeoutMS := flags.Uint("idle-timeout-ms", 600_000, "downstream idle timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *routeCount < 1 || *routeCount > maximumRouteCount {
		return fmt.Errorf("routes must be between 1 and %d", maximumRouteCount)
	}
	if *output == "" {
		return errors.New("output is required")
	}
	if *port < 1 || *port > 65_535 {
		return errors.New("port must be between 1 and 65535")
	}
	if *maximumConnections < 1 || *maximumConnections > 1_000_000 {
		return errors.New("max-connections must be between 1 and 1000000")
	}
	if *idleTimeoutMS < 1 || *idleTimeoutMS > 3_600_000 {
		return errors.New("idle-timeout-ms must be between 1 and 3600000")
	}

	snapshot := buildSnapshot(
		*routeCount,
		uint32(*port),
		uint32(*maximumConnections),
		uint32(*idleTimeoutMS),
	)
	serialized, err := (proto.MarshalOptions{Deterministic: true}).Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("marshal deterministic snapshot: %w", err)
	}
	if len(serialized) > maximumSnapshotBytes {
		return fmt.Errorf("snapshot is %d bytes; runtime limit is %d", len(serialized), maximumSnapshotBytes)
	}
	if err := writeAtomic(*output, serialized); err != nil {
		return err
	}
	digest := sha256.Sum256(serialized)
	metadata := snapshotMetadata{
		Bytes:       len(serialized),
		RouteCount:  *routeCount,
		SHA256:      hex.EncodeToString(digest[:]),
		SnapshotID:  snapshot.GetSnapshotId(),
		Output:      *output,
		MaximumConn: uint32(*maximumConnections),
		IdleMS:      uint32(*idleTimeoutMS),
	}
	return json.NewEncoder(os.Stdout).Encode(metadata)
}

func buildSnapshot(routeCount int, port, maximumConnections, idleTimeoutMS uint32) *bonvoyagev1.Snapshot {
	routes := make([]*bonvoyagev1.Route, 0, routeCount)
	for index := 0; index < routeCount; index++ {
		identity := fmt.Sprintf("r%06d", index)
		routes = append(routes, &bonvoyagev1.Route{
			Name: identity,
			Match: &bonvoyagev1.RouteMatch{
				PathMatch: &bonvoyagev1.RouteMatch_PathExact{
					PathExact: "/r/" + identity[1:],
				},
			},
			FixedResponse: &bonvoyagev1.FixedResponse{
				StatusCode:  200,
				Body:        identity + "\n",
				ContentType: "text/plain",
			},
		})
	}

	return &bonvoyagev1.Snapshot{
		SnapshotId:              fmt.Sprintf("phase3-route-scale-%d", routeCount),
		Generation:              1,
		MinimumDataplaneVersion: "0.2.0",
		SchemaVersion:           1,
		Listeners: []*bonvoyagev1.Listener{{
			Name:             "route-scale-http1",
			Address:          "0.0.0.0",
			Port:             port,
			Protocol:         bonvoyagev1.Protocol_PROTOCOL_HTTP1,
			VirtualHostNames: []string{"route-scale"},
		}},
		VirtualHosts: []*bonvoyagev1.VirtualHost{{
			Name:    "route-scale",
			Domains: []string{"scale.example.test"},
			Routes:  routes,
		}},
		RuntimeLimits: &bonvoyagev1.RuntimeLimits{
			MaxRequestHeaderBytes:            32 * 1024,
			MaxRequestBodyBytes:              10 * 1024 * 1024,
			MaxUpstreamResponseHeaderBytes:   32 * 1024,
			MaxUpstreamChunkMetadataBytes:    32 * 1024,
			RequestTimeoutMs:                 15_000,
			DownstreamIdleTimeoutMs:          idleTimeoutMS,
			MaxDownstreamConnectionsPerShard: maximumConnections,
		},
	}
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".phase3-scale-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set snapshot permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("activate snapshot file: %w", err)
	}
	return nil
}

func runHolder(args []string) error {
	flags := flag.NewFlagSet("hold", flag.ContinueOnError)
	address := flags.String("address", "", "gateway host:port")
	host := flags.String("host", "scale.example.test", "HTTP Host value")
	path := flags.String("path", "/r/000000", "request path")
	expectedBody := flags.String("expected-body", "r000000\n", "expected response body")
	connectionCount := flags.Int("connections", 0, "connections to open and hold")
	workers := flags.Int("workers", 128, "parallel connection workers")
	controlAddress := flags.String("control-address", "0.0.0.0:8090", "control listener")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "per-connection open deadline")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *address == "" {
		return errors.New("address is required")
	}
	if *connectionCount < 1 || *connectionCount > 1_000_000 {
		return errors.New("connections must be between 1 and 1000000")
	}
	if *workers < 1 || *workers > 4096 {
		return errors.New("workers must be between 1 and 4096")
	}

	state := &holderState{target: *connectionCount}
	started := time.Now()
	connections, err := openConnections(
		*address,
		*host,
		*path,
		*expectedBody,
		*connectionCount,
		*workers,
		*dialTimeout,
	)
	if err != nil {
		return err
	}
	state.mu.Lock()
	state.connections = connections
	state.opened = len(connections)
	state.openDurationMS = time.Since(started).Milliseconds()
	state.mu.Unlock()
	if err := json.NewEncoder(os.Stdout).Encode(state.summary()); err != nil {
		state.release()
		return fmt.Errorf("encode holder summary: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/ready", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(writer).Encode(state.summary())
	})
	mux.HandleFunc("/summary", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(state.summary())
	})
	mux.HandleFunc("/release", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(writer, "POST required", http.StatusMethodNotAllowed)
			return
		}
		state.release()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(state.summary())
	})

	server := &http.Server{
		Addr:              *controlAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case received := <-signals:
		fmt.Fprintf(os.Stderr, "received signal %s\n", received)
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			state.release()
			return fmt.Errorf("control listener: %w", err)
		}
	}

	state.release()
	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(context); err != nil {
		return fmt.Errorf("stop control listener: %w", err)
	}
	return nil
}

func openConnections(address, host, path, expectedBody string, count, workers int, timeout time.Duration) ([]heldConnection, error) {
	if workers > count {
		workers = count
	}
	tasks := make(chan int)
	results := make(chan struct {
		connection heldConnection
		err        error
	}, workers)

	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for range tasks {
				connection, err := openConnection(address, host, path, expectedBody, timeout)
				results <- struct {
					connection heldConnection
					err        error
				}{connection: connection, err: err}
			}
		}()
	}
	go func() {
		for index := 0; index < count; index++ {
			tasks <- index
		}
		close(tasks)
		group.Wait()
		close(results)
	}()

	connections := make([]heldConnection, 0, count)
	var firstError error
	for result := range results {
		if result.err != nil {
			if firstError == nil {
				firstError = result.err
			}
			continue
		}
		connections = append(connections, result.connection)
	}
	if firstError != nil || len(connections) != count {
		for _, connection := range connections {
			_ = connection.connection.Close()
		}
		return nil, fmt.Errorf("opened %d of %d connections: %w", len(connections), count, firstError)
	}
	return connections, nil
}

func openConnection(address, host, path, expectedBody string, timeout time.Duration) (heldConnection, error) {
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return heldConnection{}, fmt.Errorf("dial gateway: %w", err)
	}
	fail := func(err error) (heldConnection, error) {
		_ = connection.Close()
		return heldConnection{}, err
	}
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fail(fmt.Errorf("set request deadline: %w", err))
	}
	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
		path,
		host,
	)
	if _, err := io.WriteString(connection, request); err != nil {
		return fail(fmt.Errorf("write request: %w", err))
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		return fail(fmt.Errorf("read response: %w", err))
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return fail(fmt.Errorf("read response body: %w", readErr))
	}
	if closeErr != nil {
		return fail(fmt.Errorf("close response body: %w", closeErr))
	}
	if response.StatusCode != http.StatusOK || string(body) != expectedBody {
		return fail(fmt.Errorf("unexpected response status=%d body=%q", response.StatusCode, string(body)))
	}
	if response.Close {
		return fail(errors.New("gateway response disabled keep-alive"))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("clear request deadline: %w", err))
	}
	return heldConnection{connection: connection}, nil
}

func (state *holderState) summary() holderSummary {
	state.mu.Lock()
	defer state.mu.Unlock()
	return holderSummary{
		Target:         state.target,
		Opened:         state.opened,
		OpenDurationMS: state.openDurationMS,
		Released:       state.released,
	}
}

func (state *holderState) release() {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.released {
		return
	}
	for _, connection := range state.connections {
		_ = connection.connection.Close()
	}
	state.connections = nil
	state.released = true
}
