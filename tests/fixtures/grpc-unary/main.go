package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const unaryMethod = "/bonvoyage.test.v1.Echo/Unary"

type echoService interface {
	Unary(context.Context, *wrapperspb.StringValue) (*wrapperspb.StringValue, error)
}

type observationSnapshot struct {
	Requests               uint64   `json:"requests"`
	Successes              uint64   `json:"successes"`
	ApplicationErrors      uint64   `json:"application_errors"`
	Cancellations          uint64   `json:"cancellations"`
	MaximumConcurrent      uint64   `json:"maximum_concurrent"`
	Active                 uint64   `json:"active"`
	LastDeadlineMillis     int64    `json:"last_deadline_millis"`
	LastASCIIValues        []string `json:"last_ascii_values"`
	LastCookieValues       []string `json:"last_cookie_values"`
	LastBinaryValuesBase64 []string `json:"last_binary_values_base64"`
}

type observations struct {
	mu       sync.Mutex
	snapshot observationSnapshot
}

func (o *observations) begin(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.snapshot.Requests++
	o.snapshot.Active++
	if o.snapshot.Active > o.snapshot.MaximumConcurrent {
		o.snapshot.MaximumConcurrent = o.snapshot.Active
	}
	if deadline, ok := ctx.Deadline(); ok {
		o.snapshot.LastDeadlineMillis = time.Until(deadline).Milliseconds()
	} else {
		o.snapshot.LastDeadlineMillis = -1
	}
	if values, ok := metadata.FromIncomingContext(ctx); ok {
		o.snapshot.LastASCIIValues = append([]string(nil), values.Get("x-test-ascii")...)
		o.snapshot.LastCookieValues = append([]string(nil), values.Get("cookie")...)
		o.snapshot.LastBinaryValuesBase64 = o.snapshot.LastBinaryValuesBase64[:0]
		for _, value := range values.Get("x-test-bin") {
			o.snapshot.LastBinaryValuesBase64 = append(
				o.snapshot.LastBinaryValuesBase64,
				base64.StdEncoding.EncodeToString([]byte(value)))
		}
	}
}

func (o *observations) finish(success, applicationError, cancellation bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.snapshot.Active > 0 {
		o.snapshot.Active--
	}
	if success {
		o.snapshot.Successes++
	}
	if applicationError {
		o.snapshot.ApplicationErrors++
	}
	if cancellation {
		o.snapshot.Cancellations++
	}
}

func (o *observations) read() observationSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := o.snapshot
	result.LastASCIIValues = append([]string(nil), result.LastASCIIValues...)
	result.LastCookieValues = append([]string(nil), result.LastCookieValues...)
	result.LastBinaryValuesBase64 = append(
		[]string(nil), result.LastBinaryValuesBase64...)
	return result
}

type echoServer struct {
	observations *observations
}

func (s *echoServer) Unary(
	ctx context.Context,
	request *wrapperspb.StringValue,
) (*wrapperspb.StringValue, error) {
	s.observations.begin(ctx)
	success := false
	applicationError := false
	cancellation := false
	defer func() {
		s.observations.finish(success, applicationError, cancellation)
	}()

	if err := grpc.SendHeader(ctx, metadata.Pairs(
		"x-upstream", "grpc-unary-fixture",
	)); err != nil {
		return nil, status.Error(codes.Internal, "initial metadata failed")
	}
	grpc.SetTrailer(ctx, metadata.Pairs(
		"x-trace-id", "trace-1",
		"trace-bin", string([]byte{4, 5, 6}),
		"x-repeat", "one",
		"x-repeat", "two",
	))

	switch request.Value {
	case "error":
		applicationError = true
		grpc.SetTrailer(ctx, metadata.Pairs("x-error", "declined"))
		detailed, err := status.New(codes.InvalidArgument, "declined").WithDetails(
			wrapperspb.String("detail-1"),
		)
		if err != nil {
			return nil, status.Error(codes.Internal, "status details failed")
		}
		return nil, detailed.Err()
	case "slow":
		select {
		case <-time.After(2 * time.Second):
			success = true
			return wrapperspb.String("echo:slow"), nil
		case <-ctx.Done():
			cancellation = true
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	case "concurrent":
		select {
		case <-time.After(100 * time.Millisecond):
			success = true
			return wrapperspb.String("echo:concurrent"), nil
		case <-ctx.Done():
			cancellation = true
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	case "large":
		success = true
		return wrapperspb.String(strings.Repeat("x", 128*1024)), nil
	default:
		success = true
		return wrapperspb.String("echo:" + request.Value), nil
	}
}

func unaryHandler(
	service any,
	ctx context.Context,
	decode func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	request := new(wrapperspb.StringValue)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return service.(echoService).Unary(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: unaryMethod}
	handler := func(ctx context.Context, request any) (any, error) {
		return service.(echoService).Unary(ctx, request.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, request, info, handler)
}

var echoServiceDescription = grpc.ServiceDesc{
	ServiceName: "bonvoyage.test.v1.Echo",
	HandlerType: (*echoService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Unary",
		Handler:    unaryHandler,
	}},
}

func loadTLSConfig(certificateFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
		ServerName:   serverName,
	}
	if caFile == "" {
		return config, nil
	}
	contents, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return nil, errors.New("CA bundle contains no certificates")
	}
	config.RootCAs = pool
	return config, nil
}

func runServer(arguments []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	grpcAddress := flags.String("grpc-address", ":8443", "gRPC listen address")
	adminAddress := flags.String("admin-address", ":8081", "admin listen address")
	certificate := flags.String("certificate", "/secrets/server-chain.pem", "TLS certificate")
	key := flags.String("key", "/secrets/server-key.pem", "TLS key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	tlsConfig, err := loadTLSConfig(*certificate, *key, "", "")
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *grpcAddress)
	if err != nil {
		return err
	}
	observationStore := new(observations)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	server.RegisterService(&echoServiceDescription, &echoServer{
		observations: observationStore,
	})

	admin := &http.Server{
		Addr:              *adminAddress,
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/healthz" {
				response.WriteHeader(http.StatusNoContent)
				return
			}
			if request.URL.Path != "/observations" {
				http.NotFound(response, request)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(observationStore.read())
		}),
	}
	adminError := make(chan error, 1)
	go func() {
		adminError <- admin.ListenAndServe()
	}()
	grpcError := make(chan error, 1)
	go func() {
		grpcError <- server.Serve(listener)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-signals:
	case err := <-grpcError:
		return err
	case err := <-adminError:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	server.GracefulStop()
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return admin.Shutdown(shutdown)
}

type clientResult struct {
	Case               string   `json:"case"`
	Code               string   `json:"code"`
	ResponseBytes      int      `json:"response_bytes,omitempty"`
	InitialMetadata    []string `json:"initial_metadata,omitempty"`
	TraceMetadata      []string `json:"trace_metadata,omitempty"`
	BinaryMetadata     []string `json:"binary_metadata_base64,omitempty"`
	RepeatedMetadata   []string `json:"repeated_metadata,omitempty"`
	SuccessfulRequests int      `json:"successful_requests,omitempty"`
}

type clientOptions struct {
	target     string
	caFile     string
	serverName string
	testCase   string
}

func parseClientOptions(arguments []string) (clientOptions, error) {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	options := clientOptions{}
	flags.StringVar(&options.target, "target", "gateway:8443", "gRPC target")
	flags.StringVar(&options.caFile, "ca", "/secrets/ca.pem", "trusted CA")
	flags.StringVar(&options.serverName, "server-name", "api.example.test", "TLS server name")
	flags.StringVar(&options.testCase, "case", "success", "test case")
	return options, flags.Parse(arguments)
}

func clientTLS(options clientOptions) (*tls.Config, error) {
	contents, err := os.ReadFile(options.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return nil, errors.New("client CA bundle contains no certificates")
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: options.serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}, nil
}

func invoke(
	ctx context.Context,
	connection *grpc.ClientConn,
	value string,
) (*wrapperspb.StringValue, metadata.MD, metadata.MD, error) {
	response := new(wrapperspb.StringValue)
	var header metadata.MD
	var trailer metadata.MD
	err := connection.Invoke(ctx, unaryMethod, wrapperspb.String(value), response,
		grpc.Header(&header), grpc.Trailer(&trailer))
	return response, header, trailer, err
}

func requireValues(values []string, expected string) error {
	if strings.Join(values, ",") != expected {
		return fmt.Errorf("metadata changed: got %q, want %q", values, expected)
	}
	return nil
}

func runGRPCCase(options clientOptions, connection *grpc.ClientConn) (clientResult, error) {
	result := clientResult{Case: options.testCase, Code: codes.OK.String()}
	switch options.testCase {
	case "success":
		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
			"x-test-ascii", "alpha",
			"cookie", "session=abc",
			"cookie", "theme=dark",
			"x-test-bin", string([]byte{1, 2, 3}),
		))
		response, header, trailer, err := invoke(ctx, connection, "ok")
		if err != nil {
			return result, err
		}
		if response.Value != "echo:ok" {
			return result, fmt.Errorf("response changed: %q", response.Value)
		}
		if err := requireValues(header.Get("x-upstream"), "grpc-unary-fixture"); err != nil {
			return result, err
		}
		if err := requireValues(trailer.Get("x-trace-id"), "trace-1"); err != nil {
			return result, err
		}
		if err := requireValues(trailer.Get("x-repeat"), "one,two"); err != nil {
			return result, err
		}
		binary := trailer.Get("trace-bin")
		if len(binary) != 1 || !bytes.Equal([]byte(binary[0]), []byte{4, 5, 6}) {
			return result, fmt.Errorf("binary trailer changed: %q", binary)
		}
		result.ResponseBytes = len(response.Value)
		result.InitialMetadata = header.Get("x-upstream")
		result.TraceMetadata = trailer.Get("x-trace-id")
		result.RepeatedMetadata = trailer.Get("x-repeat")
		result.BinaryMetadata = []string{base64.StdEncoding.EncodeToString([]byte(binary[0]))}
	case "error":
		_, _, trailer, err := invoke(context.Background(), connection, "error")
		if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "declined" {
			return result, fmt.Errorf("application status changed: %v", err)
		}
		if err := requireValues(trailer.Get("x-error"), "declined"); err != nil {
			return result, err
		}
		if len(status.Convert(err).Details()) != 1 {
			return result, errors.New("grpc-status-details-bin was not preserved")
		}
		result.Code = codes.InvalidArgument.String()
	case "deadline":
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, _, _, err := invoke(ctx, connection, "slow")
		if status.Code(err) != codes.DeadlineExceeded {
			return result, fmt.Errorf("deadline status changed: %v", err)
		}
		result.Code = codes.DeadlineExceeded.String()
	case "cancel":
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		_, _, _, err := invoke(ctx, connection, "slow")
		if status.Code(err) != codes.Canceled {
			return result, fmt.Errorf("cancellation status changed: %v", err)
		}
		result.Code = codes.Canceled.String()
	case "large":
		response, _, _, err := invoke(context.Background(), connection, "large")
		if err != nil {
			return result, err
		}
		if len(response.Value) != 128*1024 {
			return result, fmt.Errorf("large response changed: %d", len(response.Value))
		}
		result.ResponseBytes = len(response.Value)
	case "concurrent":
		const requests = 16
		errorsChannel := make(chan error, requests)
		var group sync.WaitGroup
		for index := 0; index < requests; index++ {
			group.Add(1)
			go func() {
				defer group.Done()
				response, _, _, err := invoke(context.Background(), connection, "concurrent")
				if err == nil && response.Value != "echo:concurrent" {
					err = fmt.Errorf("concurrent response changed: %q", response.Value)
				}
				errorsChannel <- err
			}()
		}
		group.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			if err != nil {
				return result, err
			}
			result.SuccessfulRequests++
		}
	default:
		return result, fmt.Errorf("unknown native gRPC case %q", options.testCase)
	}
	return result, nil
}

func grpcFrame(payload []byte) []byte {
	result := make([]byte, 5+len(payload))
	length := uint32(len(payload))
	result[1] = byte(length >> 24)
	result[2] = byte(length >> 16)
	result[3] = byte(length >> 8)
	result[4] = byte(length)
	copy(result[5:], payload)
	return result
}

func runRawCase(options clientOptions, tlsConfig *tls.Config) (clientResult, error) {
	validMessage := grpcFrame([]byte{0x0a, 0x02, 'o', 'k'})
	body := validMessage
	timeout := "1S"
	includeTE := true
	switch options.testCase {
	case "raw-multiple":
		body = append(append([]byte(nil), validMessage...), validMessage...)
	case "raw-truncated":
		body = []byte{0, 0, 0, 0, 4, 0x0a, 0x02}
	case "raw-timeout":
		timeout = "invalid"
	case "raw-missing-te":
		includeTE = false
	default:
		return clientResult{}, fmt.Errorf("unknown raw case %q", options.testCase)
	}
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: tlsConfig}}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://"+options.target+unaryMethod,
		bytes.NewReader(body),
	)
	if err != nil {
		return clientResult{}, err
	}
	request.Host = options.serverName
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("grpc-timeout", timeout)
	if includeTE {
		request.Header.Set("TE", "trailers")
	}
	response, err := client.Do(request)
	if err != nil {
		return clientResult{}, err
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		return clientResult{}, err
	}
	grpcStatus := response.Header.Get("grpc-status")
	if grpcStatus == "" {
		grpcStatus = response.Trailer.Get("grpc-status")
	}
	if response.StatusCode != http.StatusOK || grpcStatus != "3" {
		return clientResult{}, fmt.Errorf(
			"raw rejection changed: HTTP %d grpc-status %q",
			response.StatusCode,
			grpcStatus,
		)
	}
	return clientResult{Case: options.testCase, Code: codes.InvalidArgument.String()}, nil
}

func runClient(arguments []string) error {
	options, err := parseClientOptions(arguments)
	if err != nil {
		return err
	}
	tlsConfig, err := clientTLS(options)
	if err != nil {
		return err
	}
	var result clientResult
	if strings.HasPrefix(options.testCase, "raw-") {
		result, err = runRawCase(options, tlsConfig)
	} else {
		connection, dialErr := grpc.NewClient(
			options.target,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		)
		if dialErr != nil {
			return dialErr
		}
		defer connection.Close()
		result, err = runGRPCCase(options, connection)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: grpc-unary-fixture server|client [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
