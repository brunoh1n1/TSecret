// Package crypto provides encryption and decryption for TSecret values.
//
// Supported algorithms:
//   - XChaCha20-Poly1305: 256-bit key, 192-bit nonce (recommended — side-channel resistant,
//     large nonce space eliminates nonce-reuse risk, no hardware dependency)
//   - ChaCha20-Poly1305: 256-bit key, 96-bit nonce (IETF standard, fast on all platforms)
//
// AES is intentionally NOT supported. XChaCha20-Poly1305 is the default and recommended
// algorithm because:
//   - Resistant to timing side-channel attacks by design (constant-time without hardware)
//   - 192-bit nonce makes random nonce generation safe even at massive scale
//   - No dependency on AES-NI hardware instructions
//   - Used by NordPass, Cloudflare, WireGuard, age encryption, and libsodium
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// AlgorithmXChaCha20Poly is the recommended algorithm: XChaCha20-Poly1305.
	// 256-bit key, 192-bit nonce, 128-bit auth tag.
	AlgorithmXChaCha20Poly = "xchacha20-poly1305"

	// AlgorithmChaCha20Poly is the IETF ChaCha20-Poly1305.
	// 256-bit key, 96-bit nonce, 128-bit auth tag.
	AlgorithmChaCha20Poly = "chacha20-poly1305"

	// CiphertextPrefix identifies TSecret encrypted values.
	CiphertextPrefix = "tsecret:"

	// KeySize is the required key size for both algorithms (32 bytes / 256 bits).
	KeySize = chacha20poly1305.KeySize
)

// SupportedAlgorithms returns the list of supported algorithm identifiers.
func SupportedAlgorithms() []string {
	return []string{AlgorithmXChaCha20Poly, AlgorithmChaCha20Poly}
}

// IsSupported checks if an algorithm identifier is supported.
func IsSupported(algorithm string) bool {
	return algorithm == AlgorithmXChaCha20Poly || algorithm == AlgorithmChaCha20Poly
}

// Encrypt encrypts plaintext using the specified algorithm and key.
// Returns base64-encoded ciphertext with format: tsecret:<algorithm>:<nonce>:<ciphertext+tag>
//
// The nonce is generated from crypto/rand and is unique per operation.
func Encrypt(plaintext []byte, key []byte, algorithm string) (string, error) {
	aead, err := newAEAD(key, algorithm)
	if err != nil {
		return "", err
	}

	// Generate cryptographically random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate (ciphertext includes the Poly1305 tag)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Wire format: tsecret:<algorithm>:<base64(nonce)>:<base64(ciphertext+tag)>
	encoded := fmt.Sprintf("%s%s:%s:%s",
		CiphertextPrefix,
		algorithm,
		base64.RawStdEncoding.EncodeToString(nonce),
		base64.RawStdEncoding.EncodeToString(ciphertext),
	)

	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}

// Decrypt decrypts a TSecret encrypted value.
// The algorithm is embedded in the ciphertext — the correct AEAD is selected automatically.
func Decrypt(encryptedValue string, key []byte) ([]byte, error) {
	algorithm, nonce, ciphertext, err := parseEncryptedValue(encryptedValue)
	if err != nil {
		return nil, err
	}

	aead, err := newAEAD(key, algorithm)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error — wrong key or tampered data): %w", err)
	}

	return plaintext, nil
}

// IsValidEncryptedValue checks if a value has the expected TSecret encrypted format
// without performing actual decryption.
func IsValidEncryptedValue(value string) bool {
	algorithm, _, _, err := parseEncryptedValue(value)
	if err != nil {
		return false
	}
	return IsSupported(algorithm)
}

// newAEAD creates the appropriate AEAD cipher for the given algorithm and key.
func newAEAD(key []byte, algorithm string) (interface {
	NonceSize() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%s requires %d-byte key, got %d", algorithm, KeySize, len(key))
	}

	switch algorithm {
	case AlgorithmXChaCha20Poly:
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
		}
		return aead, nil

	case AlgorithmChaCha20Poly:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
		}
		return aead, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s (supported: %v)", algorithm, SupportedAlgorithms())
	}
}

// parseEncryptedValue decodes and parses the wire format.
func parseEncryptedValue(encryptedValue string) (algorithm string, nonce []byte, ciphertext []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode outer base64: %w", err)
	}

	value := string(raw)
	if !strings.HasPrefix(value, CiphertextPrefix) {
		return "", nil, nil, fmt.Errorf("invalid ciphertext format: missing prefix %q", CiphertextPrefix)
	}

	parts := strings.SplitN(value[len(CiphertextPrefix):], ":", 3)
	if len(parts) != 3 {
		return "", nil, nil, fmt.Errorf("invalid ciphertext format: expected 3 parts after prefix, got %d", len(parts))
	}

	algorithm = parts[0]

	nonce, err = base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return algorithm, nonce, ciphertext, nil
}
