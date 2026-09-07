// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
)

var adminIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type CreateJoinTokenRequest struct {
	NetworkID        string `json:"network_id"`
	DeviceID         string `json:"device_id,omitempty"`
	Platform         string `json:"platform,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

type JoinToken struct {
	ID            string    `json:"id"`
	JoinURI       string    `json:"join_uri"`
	NetworkID     string    `json:"network_id"`
	DeviceID      string    `json:"device_id"`
	Platform      string    `json:"platform"`
	RemainingUses int       `json:"remaining_uses"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type CreateJoinTokenResponse struct {
	JoinToken JoinToken `json:"join_token"`
}

type PolicyWarning struct {
	Code    string `json:"Code"`
	RuleID  string `json:"RuleID"`
	Message string `json:"Message"`
}

type PolicyMetadata struct {
	NetworkID       string          `json:"network_id"`
	Revision        uint64          `json:"revision"`
	Name            string          `json:"name"`
	ArtifactSHA256  string          `json:"artifact_sha256"`
	CompilerVersion string          `json:"compiler_version"`
	Warnings        []PolicyWarning `json:"warnings"`
	Status          string          `json:"status"`
	Generation      uint64          `json:"generation"`
	CreatedAt       time.Time       `json:"created_at"`
	ValidatedAt     *time.Time      `json:"validated_at"`
	ActivatedAt     *time.Time      `json:"activated_at"`
}

type PolicyExplainRequest struct {
	NetworkID   string `json:"network_id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
}

type PolicyExplanation struct {
	Action                     string   `json:"action"`
	RuleID                     string   `json:"rule_id,omitempty"`
	Reason                     string   `json:"reason"`
	Protected                  bool     `json:"protected"`
	ResolvedSourceDevices      []string `json:"resolved_source_devices,omitempty"`
	ResolvedDestinationDevices []string `json:"resolved_destination_devices,omitempty"`
}

type PolicyExplainResult struct {
	NetworkID                  string   `json:"network_id"`
	Revision                   uint64   `json:"revision"`
	Generation                 uint64   `json:"generation"`
	Action                     string   `json:"action"`
	RuleID                     string   `json:"rule_id,omitempty"`
	Reason                     string   `json:"reason"`
	Protected                  bool     `json:"protected"`
	ResolvedSourceDevices      []string `json:"resolved_source_devices,omitempty"`
	ResolvedDestinationDevices []string `json:"resolved_destination_devices,omitempty"`
}

func (c *Client) CreateJoinToken(ctx context.Context, request CreateJoinTokenRequest) (CreateJoinTokenResponse, error) {
	request.NetworkID = strings.TrimSpace(request.NetworkID)
	request.DeviceID = strings.TrimSpace(request.DeviceID)
	request.Platform = strings.TrimSpace(request.Platform)
	if !adminIDPattern.MatchString(request.NetworkID) || request.DeviceID != "" && !adminIDPattern.MatchString(request.DeviceID) || request.Platform != "" && !validInvitePlatform(request.Platform) || request.ExpiresInSeconds < 1 || request.ExpiresInSeconds > 86400 {
		return CreateJoinTokenResponse{}, fault.New(fault.CodeInvalidInput, "create join invite", nil)
	}
	_, headers, raw, err := c.doContract(ctx, http.MethodPost, apiPrefixV1+"/join-tokens", nil, request, nil, false)
	if err != nil {
		return CreateJoinTokenResponse{}, err
	}
	if !headerContainsToken(headers.Values("Cache-Control"), "no-store") {
		return CreateJoinTokenResponse{}, fault.New(fault.CodeInvalidResponse, "validate join invite cache policy", nil)
	}
	response, decodeErr := strictContractDecode[CreateJoinTokenResponse](raw)
	now := time.Now().UTC()
	maximumExpiry := now.Add(time.Duration(request.ExpiresInSeconds)*time.Second + time.Minute)
	if decodeErr != nil || !adminIDPattern.MatchString(response.JoinToken.ID) || response.JoinToken.NetworkID != request.NetworkID || response.JoinToken.DeviceID != "" && !adminIDPattern.MatchString(response.JoinToken.DeviceID) || response.JoinToken.Platform != "" && !validInvitePlatform(response.JoinToken.Platform) || request.DeviceID != "" && response.JoinToken.DeviceID != request.DeviceID || request.Platform != "" && response.JoinToken.Platform != request.Platform || response.JoinToken.RemainingUses != 1 || response.JoinToken.ExpiresAt.IsZero() || !response.JoinToken.ExpiresAt.After(now.Add(-time.Minute)) || response.JoinToken.ExpiresAt.After(maximumExpiry) {
		return CreateJoinTokenResponse{}, fault.New(fault.CodeInvalidResponse, "decode join invite", nil)
	}
	allowLocalhost := c.baseURL.Scheme == "http" && (c.baseURL.Hostname() == "localhost" || c.baseURL.Hostname() == "127.0.0.1")
	target, parseErr := invite.Parse(response.JoinToken.JoinURI, allowLocalhost)
	if parseErr != nil || strings.TrimRight(target.Controller, "/") != strings.TrimRight(c.baseURL.String(), "/") {
		return CreateJoinTokenResponse{}, fault.New(fault.CodeInvalidResponse, "validate join invite", nil)
	}
	return response, nil
}

func validInvitePlatform(value string) bool {
	switch value {
	case "linux", "darwin", "windows", "ios", "android":
		return true
	default:
		return false
	}
}

func (c *Client) ExplainPolicy(ctx context.Context, revision uint64, request PolicyExplainRequest) (PolicyExplainResult, error) {
	request.NetworkID = strings.TrimSpace(request.NetworkID)
	request.Source = strings.TrimSpace(request.Source)
	request.Destination = strings.TrimSpace(request.Destination)
	request.Protocol = strings.ToLower(strings.TrimSpace(request.Protocol))
	if revision == 0 || !adminIDPattern.MatchString(request.NetworkID) || !validPolicyQuery(request) {
		return PolicyExplainResult{}, fault.New(fault.CodeInvalidInput, "explain overlay policy", nil)
	}
	query := url.Values{"network_id": []string{request.NetworkID}}
	_, _, metadataRaw, err := c.doContract(ctx, http.MethodGet, apiPrefixV1+"/policies/"+strconv.FormatUint(revision, 10), query, nil, nil, false)
	if err != nil {
		return PolicyExplainResult{}, err
	}
	metadata, decodeErr := strictContractDecode[PolicyMetadata](metadataRaw)
	if decodeErr != nil || metadata.NetworkID != request.NetworkID || metadata.Revision != revision || metadata.CompilerVersion != "xconnect-acl-v1alpha1.1" || !validPolicyMetadataState(metadata) {
		return PolicyExplainResult{}, fault.New(fault.CodeInvalidResponse, "decode policy metadata", nil)
	}
	_, _, raw, err := c.doContract(ctx, http.MethodPost, apiPrefixV1+"/policies/"+strconv.FormatUint(revision, 10)+"/explain", nil, request, nil, false)
	if err != nil {
		return PolicyExplainResult{}, err
	}
	explanation, decodeErr := strictContractDecode[PolicyExplanation](raw)
	if decodeErr != nil || !validExplanation(explanation) {
		return PolicyExplainResult{}, fault.New(fault.CodeInvalidResponse, "decode policy explanation", nil)
	}
	return PolicyExplainResult{
		NetworkID: request.NetworkID, Revision: revision, Generation: metadata.Generation,
		Action: explanation.Action, RuleID: explanation.RuleID, Reason: explanation.Reason,
		Protected:                  explanation.Protected,
		ResolvedSourceDevices:      append([]string(nil), explanation.ResolvedSourceDevices...),
		ResolvedDestinationDevices: append([]string(nil), explanation.ResolvedDestinationDevices...),
	}, nil
}

func validPolicyMetadataState(metadata PolicyMetadata) bool {
	switch metadata.Status {
	case "active":
		return metadata.Generation > 0
	case "draft":
		return metadata.Generation == 0
	default:
		return false
	}
}

func validPolicyQuery(request PolicyExplainRequest) bool {
	if request.Source == "" || request.Destination == "" || strings.Contains(request.Source, "@") || strings.Contains(request.Destination, "@") {
		return false
	}
	if request.Protocol != "tcp" && request.Protocol != "udp" && request.Protocol != "icmp" {
		return false
	}
	if request.Protocol == "icmp" {
		return request.Port == 0
	}
	return request.Port >= 1 && request.Port <= 65535
}

func validExplanation(value PolicyExplanation) bool {
	if value.Action != "accept" && value.Action != "deny" {
		return false
	}
	switch value.Reason {
	case "protected control-plane flow":
		if !value.Protected || value.Action != "accept" || value.RuleID != "_xconnect_control_plane" {
			return false
		}
	case "matched canonical rule":
		if value.Protected || value.RuleID == "" {
			return false
		}
	case "default deny":
		if value.Protected || value.Action != "deny" || value.RuleID != "" || len(value.ResolvedSourceDevices) != 0 || len(value.ResolvedDestinationDevices) != 0 {
			return false
		}
	default:
		return false
	}
	if value.RuleID != "" && !adminIDPattern.MatchString(value.RuleID) {
		return false
	}
	for _, devices := range [][]string{value.ResolvedSourceDevices, value.ResolvedDestinationDevices} {
		seen := map[string]bool{}
		for index, device := range devices {
			if index > 0 && devices[index-1] >= device {
				return false
			}
			if !adminIDPattern.MatchString(device) || strings.Contains(device, "@") || seen[device] {
				return false
			}
			seen[device] = true
		}
	}
	return true
}
