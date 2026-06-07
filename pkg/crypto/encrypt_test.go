package crypto

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptXChaCha20(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("my-secret-password-123")

	encrypted, err := Encrypt(plaintext, key, AlgorithmXChaCha20Poly)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !IsValidEncryptedValue(encrypted) {
		t.Fatal("IsValidEncryptedValue returned false for valid encrypted value")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted value mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptChaCha20(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("another-secret-value")

	encrypted, err := Encrypt(plaintext, key, AlgorithmChaCha20Poly)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !IsValidEncryptedValue(encrypted) {
		t.Fatal("IsValidEncryptedValue returned false for valid encrypted value")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted value mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestXChaCha20LargeNonce(t *testing.T) {
	// XChaCha20 uses 24-byte (192-bit) nonce — verify it's embedded correctly
	key := make([]byte, KeySize)
	rand.Read(key)

	plaintext := []byte("test-large-nonce")
	encrypted, err := Encrypt(plaintext, key, AlgorithmXChaCha20Poly)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt should work
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("Mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("secret")
	encrypted, _ := Encrypt(plaintext, key1, AlgorithmXChaCha20Poly)

	_, err := Decrypt(encrypted, key2)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key")
	}
}

func TestInvalidAlgorithm(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)

	_, err := Encrypt([]byte("test"), key, "aes-256-gcm")
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm (AES is not supported)")
	}

	_, err = Encrypt([]byte("test"), key, "invalid-algo")
	if err == nil {
		t.Fatal("Expected error for invalid algorithm")
	}
}

func TestIsValidEncryptedValue_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not-base64!!!",
		"aGVsbG8=", // "hello" in base64 — no prefix
	}

	for _, c := range cases {
		if IsValidEncryptedValue(c) {
			t.Errorf("IsValidEncryptedValue(%q) should be false", c)
		}
	}
}

func TestUniqueNonce(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)

	plaintext := []byte("same-value")

	enc1, _ := Encrypt(plaintext, key, AlgorithmXChaCha20Poly)
	enc2, _ := Encrypt(plaintext, key, AlgorithmXChaCha20Poly)

	if enc1 == enc2 {
		t.Fatal("Two encryptions of the same value should produce different ciphertexts (unique nonce)")
	}
}

func TestWrongKeySize(t *testing.T) {
	shortKey := make([]byte, 16) // 128-bit — too short
	rand.Read(shortKey)

	_, err := Encrypt([]byte("test"), shortKey, AlgorithmXChaCha20Poly)
	if err == nil {
		t.Fatal("Expected error for wrong key size")
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	algos := SupportedAlgorithms()
	if len(algos) != 2 {
		t.Fatalf("Expected 2 supported algorithms, got %d", len(algos))
	}
	if !IsSupported(AlgorithmXChaCha20Poly) {
		t.Fatal("XChaCha20 should be supported")
	}
	if !IsSupported(AlgorithmChaCha20Poly) {
		t.Fatal("ChaCha20 should be supported")
	}
	if IsSupported("aes-256-gcm") {
		t.Fatal("AES should NOT be supported")
	}
}
