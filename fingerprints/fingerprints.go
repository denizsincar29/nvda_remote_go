// github.com/denizsincar29/nvda_remote_go/fingerprints/fingerprints.go
package fingerprints

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const KNOWN_HOSTS_FILENAME = "known_hosts.json"

// Error types (consider exporting if needed externally)
// ... (ErrUnknownFingerprint, ErrFingerprintMismatch - maybe simplify or keep internal)

// FingerprintManager handles loading and saving known host fingerprints.
type FingerprintManager struct {
	filePath string
	mu       sync.RWMutex
	// Map structure: "host:port" -> "sha256_fingerprint_hex"
	fingerprints map[string]string
}

// Config struct for initialization options
type Config struct {
	// Directory to store the known_hosts.json file.
	// If empty, uses OS default config dir + appName or fallback to ".".
	Directory string
	// Application name used for creating a subdirectory in the OS config dir.
	AppName string // e.g., "MyNVDARemoteApp"
}

// NewFingerprintManager creates and loads a fingerprint manager.
func NewFingerprintManager(cfg Config) (*FingerprintManager, error) {
	configDir := cfg.Directory
	appName := cfg.AppName
	if appName == "" {
		appName = "NVDA" // Provide a default app name
	}

	if configDir == "" {
		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			configDir = "." // Fallback to current directory
		} else {
			configDir = filepath.Join(userConfigDir, appName)
			err = os.MkdirAll(configDir, 0700) // Ensure directory exists
			if err != nil {
				return nil, fmt.Errorf("failed to create config directory %s: %w", configDir, err)
			}
		}
	}

	filePath := filepath.Join(configDir, KNOWN_HOSTS_FILENAME)
	fm := &FingerprintManager{
		filePath:     filePath,
		fingerprints: make(map[string]string),
	}

	err := fm.load()
	// It's okay if the file doesn't exist initially
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load known hosts from %s: %w", filePath, err)
	}
	return fm, nil
}

func (fm *FingerprintManager) load() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	data, err := os.ReadFile(fm.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		fm.fingerprints = make(map[string]string)
		return nil
	}
	err = json.Unmarshal(data, &fm.fingerprints)
	if err != nil {
		return fmt.Errorf("failed to unmarshal known hosts: %w", err)
	}
	return nil
}

func (fm *FingerprintManager) save() error {
	fm.mu.RLock()
	data, err := json.MarshalIndent(fm.fingerprints, "", "  ")
	fm.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to marshal known hosts: %w", err)
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()
	err = os.WriteFile(fm.filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write known hosts file %s: %w", fm.filePath, err)
	}
	return nil
}

// Get retrieves the known fingerprint for a host:port.
func (fm *FingerprintManager) Get(hostPort string) (string, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	fp, ok := fm.fingerprints[hostPort]
	return fp, ok
}

// Add stores a fingerprint for a host:port and saves the file.
func (fm *FingerprintManager) Add(hostPort, fingerprint string) error {
	fm.mu.Lock()
	fm.fingerprints[hostPort] = strings.ToLower(fingerprint) // Store consistently lowercased
	fm.mu.Unlock()
	return fm.save()
}

// CalculateSha256Fingerprint computes the SHA-256 hash of the certificate's DER encoding.
func CalculateSha256Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
