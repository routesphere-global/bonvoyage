package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxFixtureBodyBytes = 1 << 20

type observations struct {
	mu                sync.Mutex
	connections       map[string]struct{}
	requests          uint64
	activeRequests    uint64
	maximumConcurrent uint64
}

func newObservations() *observations {
	return &observations{connections: make(map[string]struct{})}
}

func (o *observations) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.connections[r.RemoteAddr] = struct{}{}
		o.requests++
		o.activeRequests++
		if o.activeRequests > o.maximumConcurrent {
			o.maximumConcurrent = o.activeRequests
		}
		o.mu.Unlock()

		defer func() {
			o.mu.Lock()
			o.activeRequests--
			o.mu.Unlock()
		}()
		next.ServeHTTP(w, r)
	})
}

func (o *observations) writeJSON(w http.ResponseWriter) {
	o.mu.Lock()
	result := struct {
		UniqueConnections int    `json:"unique_connections"`
		Requests          uint64 `json:"requests"`
		ActiveRequests    uint64 `json:"active_requests"`
		MaximumConcurrent uint64 `json:"maximum_concurrent"`
	}{
		UniqueConnections: len(o.connections),
		Requests:          o.requests,
		ActiveRequests:    o.activeRequests,
		MaximumConcurrent: o.maximumConcurrent,
	}
	o.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("write observations: %v", err)
	}
}

func boundedSize(path, prefix string) (int, error) {
	value := strings.TrimPrefix(path, prefix)
	size, err := strconv.Atoi(value)
	if err != nil || size < 0 || size > maxFixtureBodyBytes {
		return 0, fmt.Errorf("size must be between 0 and %d", maxFixtureBodyBytes)
	}
	return size, nil
}

func main() {
	certificate := strings.TrimSpace(os.Getenv("BONVOYAGE_UPSTREAM_TLS_CERTIFICATE"))
	privateKey := strings.TrimSpace(os.Getenv("BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY"))
	if certificate == "" || privateKey == "" {
		log.Fatal("BONVOYAGE_UPSTREAM_TLS_CERTIFICATE and BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY are required")
	}

	observed := newObservations()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/protocol", func(w http.ResponseWriter, r *http.Request) {
		negotiated := ""
		if r.TLS != nil {
			negotiated = r.TLS.NegotiatedProtocol
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"alpn":     negotiated,
			"protocol": r.Proto,
		})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxFixtureBodyBytes+1))
		if err != nil || len(body) > maxFixtureBodyBytes {
			http.Error(w, "request body exceeds fixture limit", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
		size, err := boundedSize(r.URL.Path, "/stream/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming is unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 4096))
		for remaining := size; remaining > 0; {
			count := min(remaining, len(chunk))
			if _, err := w.Write(chunk[:count]); err != nil {
				return
			}
			flusher.Flush()
			remaining -= count
		}
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "grpc-status")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "trailer-body\n")
		w.Header().Set("grpc-status", "0")
	})
	mux.HandleFunc("/slow/", func(w http.ResponseWriter, r *http.Request) {
		delay, err := boundedSize(r.URL.Path, "/slow/")
		if err != nil || delay > 5000 {
			http.Error(w, "delay must be between 0 and 5000 milliseconds", http.StatusBadRequest)
			return
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "slow-ok\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		observed.writeJSON(w)
	})

	shutdownComplete := make(chan struct{})
	var shutdownOnce sync.Once
	server := &http.Server{
		Addr:              ":8443",
		Handler:           observed.observe(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
		},
	}
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "draining\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		shutdownOnce.Do(func() {
			go func() {
				time.Sleep(50 * time.Millisecond)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := server.Shutdown(ctx); err != nil {
					log.Printf("graceful shutdown: %v", err)
				}
				close(shutdownComplete)
			}()
		})
	})

	err := server.ListenAndServeTLS(certificate, privateKey)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownComplete
		return
	}
	log.Fatal(err)
}
