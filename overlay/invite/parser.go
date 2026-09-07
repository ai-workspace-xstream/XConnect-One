// Modified for XConnect-One: standalone module imports.
package invite

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const joinTokenPrefix = "xjt_"

// Target is the non-persistent result of parsing an XConnect-One invite URL.
// JoinToken must remain in memory and must never be included in errors/logs.
type Target struct {
	Controller string
	JoinToken  string
}

// Parse validates the canonical v1 invite URL. Mobile callers must keep
// allowInsecureLocalhost false; the flag exists only for explicit CLI dev use.
func Parse(value string, allowInsecureLocalhost bool) (Target, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return Target{}, invalid()
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "xconnect" || parsed.Host != "join" ||
		parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.Port() != "" {
		return Target{}, invalid()
	}
	query := parsed.Query()
	if len(query) != 1 || len(query["controller"]) != 1 {
		return Target{}, invalid()
	}
	joinToken := strings.TrimPrefix(parsed.Path, "/")
	if parsed.Path != "/"+joinToken || parsed.EscapedPath() != parsed.Path || !validToken(joinToken) {
		return Target{}, invalid()
	}
	controller, err := parseController(query.Get("controller"), allowInsecureLocalhost)
	if err != nil {
		return Target{}, err
	}
	return Target{Controller: controller, JoinToken: joinToken}, nil
}

func parseController(value string, allowInsecureLocalhost bool) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", invalid()
	}
	secure := parsed.Scheme == "https"
	localDev := parsed.Scheme == "http" &&
		(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1") &&
		allowInsecureLocalhost
	if !secure && !localDev {
		return "", invalid()
	}
	return strings.TrimRight(value, "/"), nil
}

func validToken(value string) bool {
	if !strings.HasPrefix(value, joinTokenPrefix) {
		return false
	}
	raw := strings.TrimPrefix(value, joinTokenPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}

func invalid() error {
	return fault.New(fault.CodeJoinInviteInvalid, "parse join invite", nil)
}
