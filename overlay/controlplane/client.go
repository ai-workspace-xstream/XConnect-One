// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

const apiPrefixV1 = "/api/overlay/v1"

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type RegisterDeviceRequest struct {
	DeviceID           string `json:"device_id"`
	Name               string `json:"name,omitempty"`
	Platform           string `json:"platform,omitempty"`
	Hostname           string `json:"hostname,omitempty"`
	NetworkID          string `json:"network_id,omitempty"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

type RegisterDeviceResponse struct {
	Device  model.Device  `json:"device"`
	Network model.Network `json:"network"`
}

type ConfigRequest struct {
	DeviceID  string
	NetworkID string
	NodeID    string
}

type ConfigAckRequest struct {
	DeviceID  string    `json:"device_id"`
	NetworkID string    `json:"network_id,omitempty"`
	Revision  string    `json:"revision"`
	Digest    string    `json:"digest,omitempty"`
	AppliedAt time.Time `json:"applied_at"`
}

type ConfigAckResponse struct {
	Acked      bool      `json:"acked"`
	DeviceID   string    `json:"device_id"`
	NetworkID  string    `json:"network_id"`
	Revision   string    `json:"revision"`
	ReceivedAt time.Time `json:"received_at"`
}

func New(baseURL, token string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fault.New(fault.CodeInvalidInput, "create control plane client", err)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{
		baseURL:    parsed,
		token:      strings.TrimSpace(token),
		httpClient: httpClient,
	}, nil
}

func (c *Client) RegisterDevice(ctx context.Context, request RegisterDeviceRequest) (RegisterDeviceResponse, error) {
	var response RegisterDeviceResponse
	err := c.doJSON(ctx, http.MethodPost, apiPrefixV1+"/devices/register", nil, request, &response, nil)
	return response, err
}

func (c *Client) GetConfig(ctx context.Context, request ConfigRequest) (model.Config, error) {
	query := url.Values{}
	query.Set("device_id", request.DeviceID)
	if request.NetworkID != "" {
		query.Set("network_id", request.NetworkID)
	}
	if request.NodeID != "" {
		query.Set("node_id", request.NodeID)
	}
	var config model.Config
	var responseHeader http.Header
	err := c.doJSON(ctx, http.MethodGet, apiPrefixV1+"/config", query, nil, &config, &responseHeader)
	if err != nil {
		return model.Config{}, err
	}
	config.ETag = responseHeader.Get("ETag")
	return config, nil
}

func (c *Client) AckConfig(ctx context.Context, request ConfigAckRequest) (ConfigAckResponse, error) {
	var response ConfigAckResponse
	err := c.doJSON(ctx, http.MethodPost, apiPrefixV1+"/config/ack", nil, request, &response, nil)
	return response, err
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	query url.Values,
	payload any,
	result any,
	responseHeader *http.Header,
) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawQuery = query.Encode()

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fault.New(fault.CodeInvalidInput, "encode control plane request", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fault.New(fault.CodeInvalidInput, "create control plane request", err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fault.New(fault.CodeControlPlaneUnavailable, "request control plane", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return statusError(resp.StatusCode)
	}
	if responseHeader != nil {
		*responseHeader = resp.Header.Clone()
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fault.New(fault.CodeInvalidResponse, "decode control plane response", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fault.New(fault.CodeInvalidResponse, "decode control plane response", err)
	}
	return nil
}

func statusError(statusCode int) error {
	code := fault.CodeControlPlaneRejected
	switch statusCode {
	case http.StatusUnauthorized:
		code = fault.CodeAuthenticationFailed
	case http.StatusForbidden:
		code = fault.CodeAccessDenied
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		code = fault.CodeControlPlaneUnavailable
	}
	return fault.New(code, fmt.Sprintf("control plane HTTP %d", statusCode), nil)
}
