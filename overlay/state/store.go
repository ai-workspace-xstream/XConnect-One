// Modified for XConnect-One: standalone module imports.
package state

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const SchemaVersion = 1

var ErrNotFound = errors.New("overlay state not found")

var registrationIDPattern = regexp.MustCompile(`^xreg_[A-Za-z0-9_-]{1,123}$`)

type Phase string

const (
	PhaseStarted          Phase = "started"
	PhaseDeviceRegistered Phase = "device_registered"
	PhaseConfigFetched    Phase = "config_fetched"
	PhaseRuntimeApplied   Phase = "runtime_applied"
	PhaseAcknowledged     Phase = "acknowledged"
)

type Checkpoint struct {
	SchemaVersion       int           `json:"schema_version"`
	Server              string        `json:"server"`
	DeviceID            string        `json:"device_id"`
	DeviceName          string        `json:"device_name,omitempty"`
	Platform            string        `json:"platform,omitempty"`
	Hostname            string        `json:"hostname,omitempty"`
	NetworkID           string        `json:"network_id,omitempty"`
	NodeID              string        `json:"node_id,omitempty"`
	WireGuardPrivateKey string        `json:"wireguard_private_key"`
	WireGuardPublicKey  string        `json:"wireguard_public_key"`
	Phase               Phase         `json:"phase"`
	Config              *model.Config `json:"config,omitempty"`
	ConfigContract      string        `json:"config_contract,omitempty"`
	SignedConfigID      string        `json:"signed_config_id,omitempty"`
	SignedGeneration    uint64        `json:"signed_generation,omitempty"`
	InviteEnrollment    bool          `json:"invite_enrollment,omitempty"`
	EnrollmentExpiresAt time.Time     `json:"enrollment_expires_at,omitempty"`
	LastErrorCode       string        `json:"last_error_code,omitempty"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

type LastKnown struct {
	SchemaVersion       int          `json:"schema_version"`
	Server              string       `json:"server"`
	DeviceID            string       `json:"device_id"`
	NetworkID           string       `json:"network_id"`
	NodeID              string       `json:"node_id,omitempty"`
	WireGuardPrivateKey string       `json:"wireguard_private_key"`
	WireGuardPublicKey  string       `json:"wireguard_public_key"`
	Phase               Phase        `json:"phase"`
	Config              model.Config `json:"config"`
	ConfigContract      string       `json:"config_contract,omitempty"`
	SignedConfigID      string       `json:"signed_config_id,omitempty"`
	SignedGeneration    uint64       `json:"signed_generation,omitempty"`
	UpdatedAt           time.Time    `json:"updated_at"`
}

type Store struct {
	dir string
}

type ContractBinding struct {
	Controller        string    `json:"controller"`
	DeviceID          string    `json:"device_id"`
	NetworkID         string    `json:"network_id"`
	SignedLocked      bool      `json:"signed_locked"`
	HighestGeneration uint64    `json:"highest_generation"`
	ConfigID          string    `json:"config_id"`
	PayloadSHA256     string    `json:"payload_sha256"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ContractState struct {
	SchemaVersion int               `json:"schema_version"`
	Bindings      []ContractBinding `json:"bindings"`
}

type SigningKeyCache struct {
	SchemaVersion int                      `json:"schema_version"`
	Controller    string                   `json:"controller"`
	DeviceID      string                   `json:"device_id"`
	ETag          string                   `json:"etag"`
	Keys          signedconfig.SigningKeys `json:"keys"`
	FetchedAt     time.Time                `json:"fetched_at"`
}

// EnrollmentSecret is the only local artifact allowed to contain the
// short-lived enrollment bearer. It is deliberately separate from checkpoint
// and last-known state so status and diagnostics never need to decode it.
type EnrollmentSecret struct {
	SchemaVersion      int                      `json:"schema_version"`
	Controller         string                   `json:"controller"`
	DeviceID           string                   `json:"device_id"`
	NetworkID          string                   `json:"network_id"`
	Platform           string                   `json:"platform"`
	WireGuardPublicKey string                   `json:"wireguard_public_key"`
	EnrollmentToken    string                   `json:"enrollment_token"`
	ExpiresAt          time.Time                `json:"expires_at"`
	Scope              []string                 `json:"scope"`
	Device             model.Device             `json:"device"`
	Network            model.Network            `json:"network"`
	SigningKeys        signedconfig.SigningKeys `json:"signing_keys"`
	CreatedAt          time.Time                `json:"created_at"`
}

// RegistrationState is the private, resumable handoff for One self-registration.
// It is never included in status or diagnostic output. Approved contains the
// existing enrollment exchange response so a consumed registration token can
// still resume the signed-config/apply/ACK phases after a local crash.
type RegistrationState struct {
	SchemaVersion       int                   `json:"schema_version"`
	Controller          string                `json:"controller"`
	RegistrationID      string                `json:"registration_id,omitempty"`
	RegistrationToken   string                `json:"registration_token,omitempty"`
	Status              string                `json:"status"`
	ExpiresAt           time.Time             `json:"expires_at,omitempty"`
	Interval            int                   `json:"interval,omitempty"`
	DeviceID            string                `json:"device_id"`
	DeviceName          string                `json:"device_name,omitempty"`
	NetworkID           string                `json:"network_id"`
	Platform            string                `json:"platform"`
	Hostname            string                `json:"hostname,omitempty"`
	WireGuardPrivateKey string                `json:"wireguard_private_key"`
	WireGuardPublicKey  string                `json:"wireguard_public_key"`
	CreatedAt           time.Time             `json:"created_at"`
	UpdatedAt           time.Time             `json:"updated_at"`
	Approved            *RegistrationExchange `json:"approved,omitempty"`
}

type RegistrationExchange struct {
	EnrollmentToken  string                       `json:"enrollment_token"`
	TokenType        string                       `json:"token_type"`
	ExpiresAt        time.Time                    `json:"expires_at"`
	Scope            []string                     `json:"scope"`
	DeviceCredential RegistrationDeviceCredential `json:"device_credential"`
	Device           model.Device                 `json:"device"`
	Network          model.Network                `json:"network"`
	SigningKeys      signedconfig.SigningKeys     `json:"signing_keys"`
}

type RegistrationDeviceCredential struct {
	CredentialID string    `json:"credential_id"`
	Credential   string    `json:"credential"`
	TokenType    string    `json:"token_type"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        []string  `json:"scope"`
}

func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) Directory() string { return s.dir }

func (s *Store) CheckpointPath() string {
	return filepath.Join(s.dir, "join-checkpoint.json")
}

func (s *Store) LastKnownPath() string {
	return filepath.Join(s.dir, "state.json")
}

func (s *Store) ContractStatePath() string {
	return filepath.Join(s.dir, "config-contract.json")
}

func (s *Store) SigningKeyCachePath() string {
	return filepath.Join(s.dir, "signing-keys.json")
}

func (s *Store) EnrollmentSecretPath() string {
	return filepath.Join(s.dir, "enrollment-secret.json")
}

func (s *Store) RegistrationPath() string {
	return filepath.Join(s.dir, "registration.json")
}

func (s *Store) LoadRegistration() (RegistrationState, error) {
	var registration RegistrationState
	if err := readJSON(s.RegistrationPath(), &registration); err != nil {
		return RegistrationState{}, err
	}
	if err := validateRegistrationState(registration); err != nil {
		return RegistrationState{}, err
	}
	return registration, nil
}

func (s *Store) SaveRegistration(registration RegistrationState) error {
	registration.SchemaVersion = SchemaVersion
	if err := validateRegistrationState(registration); err != nil {
		return err
	}
	return writeJSON0600(s.RegistrationPath(), registration)
}

func (s *Store) ClearRegistration() error {
	err := os.Remove(s.RegistrationPath())
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fault.New(fault.CodeStateIO, "clear registration state", err)
}

func (s *Store) LoadCheckpoint() (Checkpoint, error) {
	var checkpoint Checkpoint
	if err := readJSON(s.CheckpointPath(), &checkpoint); err != nil {
		return Checkpoint{}, err
	}
	if checkpoint.SchemaVersion != SchemaVersion {
		return Checkpoint{}, fault.New(fault.CodeStateIO, "load join checkpoint", nil)
	}
	return checkpoint, nil
}

func (s *Store) SaveCheckpoint(checkpoint Checkpoint) error {
	checkpoint.SchemaVersion = SchemaVersion
	return writeJSON0600(s.CheckpointPath(), checkpoint)
}

func (s *Store) ClearCheckpoint() error {
	err := os.Remove(s.CheckpointPath())
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fault.New(fault.CodeStateIO, "clear join checkpoint", err)
}

func (s *Store) LoadLastKnown() (LastKnown, error) {
	var lastKnown LastKnown
	if err := readJSON(s.LastKnownPath(), &lastKnown); err != nil {
		return LastKnown{}, err
	}
	if lastKnown.SchemaVersion != SchemaVersion {
		return LastKnown{}, fault.New(fault.CodeStateIO, "load last-known state", nil)
	}
	return lastKnown, nil
}

func (s *Store) SaveLastKnown(lastKnown LastKnown) error {
	lastKnown.SchemaVersion = SchemaVersion
	return writeJSON0600(s.LastKnownPath(), lastKnown)
}

func (s *Store) LoadContractState() (ContractState, error) {
	var contractState ContractState
	if err := readJSON(s.ContractStatePath(), &contractState); err != nil {
		return ContractState{}, err
	}
	if contractState.SchemaVersion != SchemaVersion {
		return ContractState{}, fault.New(fault.CodeStateIO, "load config-contract state", nil)
	}
	return contractState, nil
}

func (s *Store) IsSignedLocked(controller, deviceID, networkID string) (bool, error) {
	contractState, err := s.LoadContractState()
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, binding := range contractState.Bindings {
		if binding.Controller == controller && binding.DeviceID == deviceID && binding.NetworkID == networkID {
			return binding.SignedLocked, nil
		}
	}
	return false, nil
}

func (s *Store) AcceptSignedConfig(controller, deviceID, networkID, configID, payloadSHA256 string, generation uint64, now time.Time) error {
	digest, digestErr := hex.DecodeString(payloadSHA256)
	if strings.TrimSpace(controller) == "" || strings.TrimSpace(deviceID) == "" || strings.TrimSpace(networkID) == "" || strings.TrimSpace(configID) == "" || generation == 0 || digestErr != nil || len(digest) != 32 || payloadSHA256 != strings.ToLower(payloadSHA256) {
		return fault.New(fault.CodeStateIO, "validate signed config floor", nil)
	}
	contractState, err := s.LoadContractState()
	if errors.Is(err, ErrNotFound) {
		contractState = ContractState{SchemaVersion: SchemaVersion}
	} else if err != nil {
		return err
	}
	for index := range contractState.Bindings {
		binding := &contractState.Bindings[index]
		if binding.Controller != controller || binding.DeviceID != deviceID || binding.NetworkID != networkID {
			continue
		}
		// ConfigID is the authoritative identity for a configuration generation.
		// Accounts may re-sign that exact configuration to renew its issued/expiry
		// window, which changes the signed payload digest without changing the
		// generation or ConfigID. Reject a different configuration identity at the
		// same generation, but accept and retain a renewed signature.
		if generation < binding.HighestGeneration || generation == binding.HighestGeneration && binding.ConfigID != configID {
			return fault.New(fault.CodeConfigReplay, "accept signed config generation", nil)
		}
		if generation > binding.HighestGeneration {
			binding.HighestGeneration = generation
			binding.ConfigID = configID
			binding.PayloadSHA256 = payloadSHA256
		} else if binding.PayloadSHA256 != payloadSHA256 {
			binding.PayloadSHA256 = payloadSHA256
		}
		binding.SignedLocked = true
		binding.UpdatedAt = now.UTC()
		contractState.SchemaVersion = SchemaVersion
		return writeJSON0600(s.ContractStatePath(), contractState)
	}
	contractState.Bindings = append(contractState.Bindings, ContractBinding{
		Controller: controller, DeviceID: deviceID, NetworkID: networkID,
		SignedLocked: true, HighestGeneration: generation, ConfigID: configID, PayloadSHA256: payloadSHA256, UpdatedAt: now.UTC(),
	})
	contractState.SchemaVersion = SchemaVersion
	return writeJSON0600(s.ContractStatePath(), contractState)
}

// ValidateSignedConfigFloor performs the replay check without changing durable
// state. Consumers use it while staging a v2 config and policy before runtime
// apply/readback; the floor is advanced only after that boundary succeeds.
func (s *Store) ValidateSignedConfigFloor(controller, deviceID, networkID, configID, payloadSHA256 string, generation uint64) error {
	digest, digestErr := hex.DecodeString(payloadSHA256)
	if strings.TrimSpace(controller) == "" || strings.TrimSpace(deviceID) == "" || strings.TrimSpace(networkID) == "" || strings.TrimSpace(configID) == "" || generation == 0 || digestErr != nil || len(digest) != 32 || payloadSHA256 != strings.ToLower(payloadSHA256) {
		return fault.New(fault.CodeStateIO, "validate signed config floor", nil)
	}
	contractState, err := s.LoadContractState()
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, binding := range contractState.Bindings {
		if binding.Controller == controller && binding.DeviceID == deviceID && binding.NetworkID == networkID && (generation < binding.HighestGeneration || generation == binding.HighestGeneration && binding.ConfigID != configID) {
			return fault.New(fault.CodeConfigReplay, "validate signed config generation", nil)
		}
	}
	return nil
}

func (s *Store) LoadSigningKeyCache(controller, deviceID string) (SigningKeyCache, error) {
	var cache SigningKeyCache
	if err := readJSON(s.SigningKeyCachePath(), &cache); err != nil {
		return SigningKeyCache{}, err
	}
	if cache.Controller != controller || cache.DeviceID != deviceID {
		return SigningKeyCache{}, ErrNotFound
	}
	if cache.SchemaVersion != SchemaVersion || strings.TrimSpace(cache.ETag) == "" {
		return SigningKeyCache{}, fault.New(fault.CodeStateIO, "load signing-key cache", nil)
	}
	if err := cache.Keys.Validate(); err != nil {
		return SigningKeyCache{}, fault.New(fault.CodeStateIO, "validate signing-key cache", err)
	}
	cache.Keys.ETag = cache.ETag
	return cache, nil
}

func (s *Store) SaveSigningKeyCache(cache SigningKeyCache) error {
	cache.SchemaVersion = SchemaVersion
	cache.Keys.ETag = ""
	return writeJSON0600(s.SigningKeyCachePath(), cache)
}

func (s *Store) LoadEnrollmentSecret(controller, deviceID, wireGuardPublicKey string) (EnrollmentSecret, error) {
	var secret EnrollmentSecret
	if err := readJSON(s.EnrollmentSecretPath(), &secret); err != nil {
		return EnrollmentSecret{}, err
	}
	if secret.Controller != controller || secret.DeviceID != deviceID || secret.WireGuardPublicKey != wireGuardPublicKey {
		return EnrollmentSecret{}, fault.New(fault.CodeStateConflict, "load enrollment secret binding", nil)
	}
	if err := validateEnrollmentSecret(secret); err != nil {
		return EnrollmentSecret{}, err
	}
	return secret, nil
}

func (s *Store) SaveEnrollmentSecret(secret EnrollmentSecret) error {
	secret.SchemaVersion = SchemaVersion
	secret.SigningKeys.ETag = ""
	if err := validateEnrollmentSecret(secret); err != nil {
		return err
	}
	return writeJSON0600(s.EnrollmentSecretPath(), secret)
}

func (s *Store) ClearEnrollmentSecret() error {
	err := os.Remove(s.EnrollmentSecretPath())
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fault.New(fault.CodeStateIO, "clear enrollment secret", err)
}

// ValidateEnrollmentSecret validates a staged enrollment response without
// writing it. Registration uses this before caching an approved handoff.
func ValidateEnrollmentSecret(secret EnrollmentSecret) error {
	return validateEnrollmentSecret(secret)
}

func validateEnrollmentSecret(secret EnrollmentSecret) error {
	tokenRaw, tokenErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(secret.EnrollmentToken, "xenr_"))
	publicKey, publicKeyErr := base64.StdEncoding.DecodeString(secret.WireGuardPublicKey)
	if secret.SchemaVersion != SchemaVersion || strings.TrimSpace(secret.Controller) == "" || strings.TrimSpace(secret.DeviceID) == "" || strings.TrimSpace(secret.NetworkID) == "" || strings.TrimSpace(secret.Platform) == "" || !strings.HasPrefix(secret.EnrollmentToken, "xenr_") || tokenErr != nil || len(tokenRaw) != 32 || publicKeyErr != nil || len(publicKey) != 32 || secret.CreatedAt.IsZero() || secret.ExpiresAt.IsZero() || !secret.ExpiresAt.After(secret.CreatedAt) || secret.ExpiresAt.Location() != time.UTC || secret.Device.ID != secret.DeviceID || secret.Device.NetworkID != secret.NetworkID || secret.Device.Platform != secret.Platform || secret.Device.WireGuardPublicKey != secret.WireGuardPublicKey || secret.Network.ID != secret.NetworkID || !validEnrollmentScope(secret.Scope) {
		return fault.New(fault.CodeStateIO, "validate enrollment secret", nil)
	}
	if err := secret.SigningKeys.Validate(); err != nil {
		return fault.New(fault.CodeStateIO, "validate enrollment signing keys", err)
	}
	return nil
}

func validateRegistrationState(registration RegistrationState) error {
	parsed, parseErr := url.Parse(registration.Controller)
	privateKey, privateErr := base64.StdEncoding.DecodeString(registration.WireGuardPrivateKey)
	publicKey, publicErr := base64.StdEncoding.DecodeString(registration.WireGuardPublicKey)
	if registration.SchemaVersion != SchemaVersion || parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || registration.DeviceID == "" || registration.NetworkID == "" || registration.Platform == "" || privateErr != nil || len(privateKey) != 32 || publicErr != nil || len(publicKey) != 32 || base64.StdEncoding.EncodeToString(privateKey) != registration.WireGuardPrivateKey || base64.StdEncoding.EncodeToString(publicKey) != registration.WireGuardPublicKey || registration.CreatedAt.IsZero() || registration.UpdatedAt.IsZero() || registration.CreatedAt.Location() != time.UTC || registration.UpdatedAt.Location() != time.UTC || registration.UpdatedAt.Before(registration.CreatedAt) {
		return fault.New(fault.CodeStateIO, "validate registration state", nil)
	}
	if registration.Status != "creating" && registration.Status != "pending" && registration.Status != "approved" {
		return fault.New(fault.CodeStateIO, "validate registration state", nil)
	}
	if registration.Status == "creating" {
		if registration.RegistrationID != "" || registration.RegistrationToken != "" || !registration.ExpiresAt.IsZero() || registration.Interval != 0 || registration.Approved != nil {
			return fault.New(fault.CodeStateIO, "validate registration state", nil)
		}
	} else if !registrationIDPattern.MatchString(registration.RegistrationID) || !validRegistrationToken(registration.RegistrationToken) || registration.ExpiresAt.IsZero() || registration.ExpiresAt.Location() != time.UTC || registration.Interval < 5 || registration.Interval > 30 {
		return fault.New(fault.CodeStateIO, "validate registration state", nil)
	}
	if registration.Status == "approved" && registration.Approved == nil || registration.Status != "approved" && registration.Approved != nil {
		return fault.New(fault.CodeStateIO, "validate registration state", nil)
	}
	return nil
}

func validRegistrationToken(value string) bool {
	if value != strings.TrimSpace(value) || !strings.HasPrefix(value, "xrt_") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "xrt_"))
	return err == nil && len(raw) == 32
}

func validEnrollmentScope(values []string) bool {
	if len(values) != 2 && len(values) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "overlay:config:read" && value != "overlay:config:ack" && value != "overlay:device:revoke" || seen[value] {
			return false
		}
		seen[value] = true
	}
	if !seen["overlay:config:read"] || !seen["overlay:config:ack"] {
		return false
	}
	return len(values) == 2 || seen["overlay:device:revoke"]
}

func readJSON(path string, target any) error {
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return ErrNotFound
	}
	if statErr != nil || !privateStateRegular(path, info) {
		return fault.New(fault.CodeStateIO, "validate overlay state permissions", statErr)
	}
	file, err := os.Open(path)
	if err != nil {
		return fault.New(fault.CodeStateIO, "open overlay state", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fault.New(fault.CodeStateIO, "decode overlay state", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fault.New(fault.CodeStateIO, "decode overlay state", err)
	}
	return nil
}

func writeJSON0600(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fault.New(fault.CodeStateIO, "create overlay state directory", err)
	}
	if err := secureStateDirectory(dir); err != nil {
		return fault.New(fault.CodeStateIO, "secure overlay state directory", err)
	}
	temporary, err := os.CreateTemp(dir, ".xconnect-state-*")
	if err != nil {
		return fault.New(fault.CodeStateIO, "create overlay state file", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := secureStateFile(temporaryPath); err != nil {
		return fault.New(fault.CodeStateIO, "secure overlay state file", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fault.New(fault.CodeStateIO, "encode overlay state", err)
	}
	if err := temporary.Sync(); err != nil {
		return fault.New(fault.CodeStateIO, "sync overlay state", err)
	}
	if err := temporary.Close(); err != nil {
		return fault.New(fault.CodeStateIO, "close overlay state", err)
	}
	if err := replaceStateFile(temporaryPath, path); err != nil {
		return fault.New(fault.CodeStateIO, "commit overlay state", err)
	}
	if err := secureStateFile(path); err != nil {
		return fault.New(fault.CodeStateIO, "secure committed overlay state", err)
	}
	committed = true
	return nil
}

func ValidatePermissions(path string, expected os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	got := info.Mode().Perm()
	if !statePermissionOK(path, info, expected) {
		return fmt.Errorf("permissions are %04o, want %04o", got, expected)
	}
	return nil
}
