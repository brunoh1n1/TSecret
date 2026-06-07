package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// VaultProvider implements Provider for HashiCorp Vault.
type VaultProvider struct {
	server string
	path   string
	token  string
	client *http.Client
}

// NewVaultProvider creates a new Vault provider.
func NewVaultProvider(config *v1alpha1.VaultProvider) (*VaultProvider, error) {
	if config.Server == "" {
		return nil, fmt.Errorf("vault server URL is required")
	}

	return &VaultProvider{
		server: strings.TrimRight(config.Server, "/"),
		path:   config.Path,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// SetToken sets the Vault token for authentication.
func (p *VaultProvider) SetToken(token string) {
	p.token = token
}

// ConfigureVaultAuth loads credentials from Kubernetes and configures the provider.
func ConfigureVaultAuth(
	ctx context.Context,
	c client.Reader,
	namespace string,
	provider Provider,
	auth v1alpha1.VaultAuth,
) error {
	vp, ok := provider.(*VaultProvider)
	if !ok {
		return fmt.Errorf("provider is not a Vault provider")
	}

	if auth.TokenSecretRef != nil {
		ref := auth.TokenSecretRef
		secretNS := namespace
		if ref.Namespace != "" {
			secretNS = ref.Namespace
		}

		secret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: secretNS}, secret); err != nil {
			return fmt.Errorf("failed to read vault token secret %s/%s: %w", secretNS, ref.Name, err)
		}

		token, ok := secret.Data[ref.Key]
		if !ok {
			return fmt.Errorf("key %q not found in secret %s/%s", ref.Key, secretNS, ref.Name)
		}

		vp.SetToken(string(token))
		return nil
	}

	return fmt.Errorf("no supported vault auth method configured")
}

func (p *VaultProvider) kvReadPath(key string) string {
	if p.path == "" {
		return key
	}

	mount := strings.Trim(strings.TrimRight(p.path, "/"), "/")
	// Accept both "secret" and the common misconfiguration "secret/data".
	if strings.HasSuffix(mount, "/data") {
		mount = strings.TrimSuffix(mount, "/data")
		mount = strings.TrimRight(mount, "/")
	}

	return fmt.Sprintf("%s/data/%s", mount, strings.TrimLeft(key, "/"))
}

// GetSecret retrieves a secret from Vault KV v2.
func (p *VaultProvider) GetSecret(ctx context.Context, key string, property string) (string, error) {
	path := p.kvReadPath(key)

	url := fmt.Sprintf("%s/v1/%s", p.server, path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if p.token != "" {
		req.Header.Set("X-Vault-Token", p.token)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secret not found in vault: %s", key)
	}
	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("vault permission denied for: %s", key)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse KV v2 response
	var result struct {
		Data struct {
			Data     map[string]interface{} `json:"data"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode vault response: %w", err)
	}

	if property != "" {
		val, ok := result.Data.Data[property]
		if !ok {
			return "", fmt.Errorf("property %q not found in vault secret %q", property, key)
		}
		return fmt.Sprintf("%v", val), nil
	}

	// Return entire data as JSON if no property specified
	data, err := json.Marshal(result.Data.Data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal vault secret data: %w", err)
	}
	return string(data), nil
}

// HealthCheck verifies Vault connectivity via /v1/sys/health.
func (p *VaultProvider) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/v1/sys/health", p.server)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// Vault health endpoint accepts standby codes
	req.URL.RawQuery = "standbyok=true&sealedcode=200&uninitcode=200"

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	defer resp.Body.Close()

	// 200 = initialized, unsealed, active
	// 429 = unsealed, standby (acceptable)
	// 472 = DR secondary
	// 473 = performance standby
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("vault unhealthy: HTTP %d: %s", resp.StatusCode, string(body))
}

// Close releases resources.
func (p *VaultProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
