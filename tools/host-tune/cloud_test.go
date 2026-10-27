package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCollectAWSIdentityUsesIMDSv2AndBindsHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest/api/token":
			if request.Method != http.MethodPut ||
				request.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "60" {
				http.Error(writer, "invalid token request", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte("fixture-token"))
		case "/latest/dynamic/instance-identity/document":
			if request.Header.Get("X-aws-ec2-metadata-token") != "fixture-token" {
				http.Error(writer, "missing token", http.StatusUnauthorized)
				return
			}
			_, _ = writer.Write([]byte(`{
			  "architecture":"x86_64",
			  "availabilityZone":"ap-southeast-1a",
			  "imageId":"ami-11111111111111111",
			  "instanceId":"i-11111111111111111",
			  "instanceType":"c7a.16xlarge",
  "privateIp":"10.42.0.12",
  "region":"ap-southeast-1"
}`))
		case "/latest/meta-data/placement/host-id":
			_, _ = writer.Write([]byte("h-11111111111111111\n"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	identity, err := collectAWSIdentity(server.URL)
	if err != nil {
		t.Fatalf("collectAWSIdentity returned an error: %v", err)
	}
	if identity.Provider != "aws" || identity.InstanceID != "i-11111111111111111" ||
		identity.InstanceType != "c7a.16xlarge" ||
		identity.ImageID != "ami-11111111111111111" ||
		identity.PrivateIPv4 != "10.42.0.12" ||
		identity.AvailabilityZone != "ap-southeast-1a" ||
		identity.Region != "ap-southeast-1" || identity.Architecture != "x86_64" ||
		identity.HostID != "h-11111111111111111" {
		t.Fatalf("unexpected AWS identity: %+v", identity)
	}
}

func TestCollectAWSIdentityAllowsDefaultTenancyAndRejectsIMDSv1Fallback(t *testing.T) {
	t.Run("default tenancy", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/latest/api/token":
				_, _ = writer.Write([]byte("fixture-token"))
			case "/latest/dynamic/instance-identity/document":
				_, _ = writer.Write([]byte(`{"architecture":"x86_64","availabilityZone":"ap-southeast-1a","imageId":"ami-11111111111111111","instanceId":"i-11111111111111111","instanceType":"c7a.16xlarge","privateIp":"10.42.0.11","region":"ap-southeast-1"}`))
			case "/latest/meta-data/placement/host-id":
				http.NotFound(writer, request)
			default:
				http.NotFound(writer, request)
			}
		}))
		defer server.Close()
		identity, err := collectAWSIdentity(server.URL)
		if err != nil || identity.HostID != "" {
			t.Fatalf("default-tenancy identity = %+v, %v", identity, err)
		}
	})

	t.Run("no IMDSv1 fallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			http.Error(writer, "token disabled", http.StatusForbidden)
		}))
		defer server.Close()
		if _, err := collectAWSIdentity(server.URL); err == nil {
			t.Fatal("expected an IMDSv2 token failure")
		}
	})

	t.Run("trailing identity data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/latest/api/token":
				_, _ = writer.Write([]byte("fixture-token"))
			case "/latest/dynamic/instance-identity/document":
				_, _ = writer.Write([]byte(`{"architecture":"x86_64","availabilityZone":"ap-southeast-1a","imageId":"ami-11111111111111111","instanceId":"i-11111111111111111","instanceType":"c7a.16xlarge","privateIp":"10.42.0.11","region":"ap-southeast-1"} altered`))
			default:
				http.NotFound(writer, request)
			}
		}))
		defer server.Close()
		if _, err := collectAWSIdentity(server.URL); err == nil {
			t.Fatal("expected trailing instance identity data to be rejected")
		}
	})
}
