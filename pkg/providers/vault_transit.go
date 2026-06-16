package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TransitDecrypt unwraps a data encryption key using Vault Transit.
func (p *VaultProvider) TransitDecrypt(ctx context.Context, transitKey, ciphertext string) ([]byte, error) {
	if transitKey == "" {
		return nil, fmt.Errorf("transit key name is required")
	}
	if ciphertext == "" {
		return nil, fmt.Errorf("ciphertext is required")
	}

	path := fmt.Sprintf("transit/decrypt/%s", transitKey)
	var result struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}

	if err := p.transitRequest(ctx, http.MethodPost, path, map[string]string{
		"ciphertext": ciphertext,
	}, &result); err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transit plaintext: %w", err)
	}
	return plaintext, nil
}

// TransitEncrypt wraps a data encryption key using Vault Transit.
func (p *VaultProvider) TransitEncrypt(ctx context.Context, transitKey string, plaintext []byte) (string, error) {
	if transitKey == "" {
		return "", fmt.Errorf("transit key name is required")
	}
	if len(plaintext) == 0 {
		return "", fmt.Errorf("plaintext is required")
	}

	path := fmt.Sprintf("transit/encrypt/%s", transitKey)
	var result struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}

	if err := p.transitRequest(ctx, http.MethodPost, path, map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, &result); err != nil {
		return "", err
	}

	if result.Data.Ciphertext == "" {
		return "", fmt.Errorf("vault transit returned empty ciphertext")
	}
	return result.Data.Ciphertext, nil
}

func (p *VaultProvider) transitRequest(ctx context.Context, method, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal transit request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s", p.server, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create transit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("X-Vault-Token", p.token)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault transit request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault transit returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode transit response: %w", err)
	}
	return nil
}
