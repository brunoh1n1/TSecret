package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// OracleProvider implements Provider for Oracle Cloud Infrastructure (OCI) Vault.
type OracleProvider struct {
	vaultID string
	region  string
	client  *http.Client
}

// NewOracleProvider creates a new Oracle Vault provider.
func NewOracleProvider(config *v1alpha1.OracleProvider) (*OracleProvider, error) {
	if config.VaultID == "" {
		return nil, fmt.Errorf("Oracle Vault OCID is required")
	}
	if config.Region == "" {
		return nil, fmt.Errorf("Oracle region is required")
	}

	return &OracleProvider{
		vaultID: config.VaultID,
		region:  config.Region,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSecret retrieves a secret from OCI Vault Secrets service.
func (p *OracleProvider) GetSecret(ctx context.Context, key string, property string) (string, error) {
	endpoint := fmt.Sprintf("https://secrets.vaults.%s.oci.oraclecloud.com", p.region)
	url := fmt.Sprintf("%s/20190301/secretbundles/%s?stage=CURRENT", endpoint, key)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OCI request: %w", err)
	}

	if err := p.signRequest(req); err != nil {
		return "", err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OCI Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secret %q not found in OCI Vault", key)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OCI Vault returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		SecretBundleContent struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"secretBundleContent"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode OCI response: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.SecretBundleContent.Content)
	if err != nil {
		return "", fmt.Errorf("failed to decode OCI secret content: %w", err)
	}

	if property != "" {
		var data map[string]interface{}
		if err := json.Unmarshal(decoded, &data); err != nil {
			return "", fmt.Errorf("OCI secret %q is not JSON, cannot extract property %q", key, property)
		}
		val, ok := data[property]
		if !ok {
			return "", fmt.Errorf("property %q not found in OCI secret %q", property, key)
		}
		return fmt.Sprintf("%v", val), nil
	}

	return string(decoded), nil
}

// HealthCheck verifies OCI Vault connectivity.
func (p *OracleProvider) HealthCheck(ctx context.Context) error {
	endpoint := fmt.Sprintf("https://vaults.%s.oci.oraclecloud.com", p.region)
	url := fmt.Sprintf("%s/20180608/vaults/%s", endpoint, p.vaultID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	if err := p.signRequest(req); err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("OCI Vault health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("OCI auth failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

func (p *OracleProvider) signRequest(req *http.Request) error {
	if os.Getenv("OCI_RESOURCE_PRINCIPAL_VERSION") != "" {
		return nil
	}

	return fmt.Errorf("OCI request signing requires oci-go-sdk — configure instance/resource principal")
}

// Close releases resources.
func (p *OracleProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
