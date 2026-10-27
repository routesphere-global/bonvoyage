package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const awsMetadataEndpoint = "http://169.254.169.254"

const metadataResponseLimit = 64 * 1024

type awsIdentityDocument struct {
	Architecture     string `json:"architecture"`
	AvailabilityZone string `json:"availabilityZone"`
	ImageID          string `json:"imageId"`
	InstanceID       string `json:"instanceId"`
	InstanceType     string `json:"instanceType"`
	PrivateIP        string `json:"privateIp"`
	Region           string `json:"region"`
}

func collectAWSIdentity(endpoint string) (cloudIdentity, error) {
	client := &http.Client{
		// Metadata traffic must remain link-local even when the host exports proxy settings.
		Transport: &http.Transport{Proxy: nil},
		Timeout:   3 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("AWS metadata redirects are prohibited")
		},
	}
	tokenRequest, err := http.NewRequest(
		http.MethodPut,
		strings.TrimRight(endpoint, "/")+"/latest/api/token",
		nil,
	)
	if err != nil {
		return cloudIdentity{}, err
	}
	tokenRequest.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	token, status, err := metadataRequest(client, tokenRequest, 4*1024)
	if err != nil {
		return cloudIdentity{}, fmt.Errorf("request IMDSv2 token: %w", err)
	}
	if status != http.StatusOK || strings.TrimSpace(string(token)) == "" {
		return cloudIdentity{}, fmt.Errorf("IMDSv2 token returned HTTP %d", status)
	}

	request := func(resource string) ([]byte, int, error) {
		metadataURL := strings.TrimRight(endpoint, "/") + resource
		request, requestErr := http.NewRequest(http.MethodGet, metadataURL, nil)
		if requestErr != nil {
			return nil, 0, requestErr
		}
		request.Header.Set("X-aws-ec2-metadata-token", strings.TrimSpace(string(token)))
		return metadataRequest(client, request, metadataResponseLimit)
	}

	documentBytes, status, err := request("/latest/dynamic/instance-identity/document")
	if err != nil {
		return cloudIdentity{}, fmt.Errorf("request instance identity: %w", err)
	}
	if status != http.StatusOK {
		return cloudIdentity{}, fmt.Errorf("instance identity returned HTTP %d", status)
	}
	var document awsIdentityDocument
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		return cloudIdentity{}, fmt.Errorf("decode instance identity: %w", err)
	}
	if !validAWSIdentity(document) {
		return cloudIdentity{}, errors.New("instance identity is incomplete or invalid")
	}

	hostID := ""
	hostBytes, hostStatus, err := request("/latest/meta-data/placement/host-id")
	if err != nil {
		return cloudIdentity{}, fmt.Errorf("request placement host ID: %w", err)
	}
	if hostStatus == http.StatusOK {
		hostID = strings.TrimSpace(string(hostBytes))
		if !strings.HasPrefix(hostID, "h-") || len(hostID) < 10 {
			return cloudIdentity{}, errors.New("placement host ID is malformed")
		}
	} else if hostStatus != http.StatusNotFound {
		return cloudIdentity{}, fmt.Errorf("placement host ID returned HTTP %d", hostStatus)
	}

	return cloudIdentity{
		Provider:         "aws",
		InstanceID:       document.InstanceID,
		InstanceType:     document.InstanceType,
		ImageID:          document.ImageID,
		PrivateIPv4:      document.PrivateIP,
		AvailabilityZone: document.AvailabilityZone,
		Region:           document.Region,
		Architecture:     document.Architecture,
		HostID:           hostID,
	}, nil
}

func metadataRequest(
	client *http.Client,
	request *http.Request,
	limit int64,
) ([]byte, int, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if int64(len(data)) > limit {
		return nil, response.StatusCode, errors.New("AWS metadata response exceeded limit")
	}
	return data, response.StatusCode, nil
}

func validAWSIdentity(document awsIdentityDocument) bool {
	return strings.HasPrefix(document.InstanceID, "i-") &&
		document.InstanceType != "" &&
		strings.HasPrefix(document.ImageID, "ami-") &&
		net.ParseIP(document.PrivateIP) != nil &&
		strings.Count(document.PrivateIP, ":") == 0 &&
		document.AvailabilityZone != "" &&
		document.Region != "" &&
		document.Architecture == "x86_64"
}
