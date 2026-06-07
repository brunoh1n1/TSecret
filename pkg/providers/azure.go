package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// AzureProvider implements Provider for Azure Key Vault.
// Uses the Azure Key Vault REST API with managed identity or service principal auth.
type AzureProvider struct {
	vaultURL string
	tenantID string
	clientID string
	client   *http.Client
	token    string
}

// NewAzureProvider creates a new Azure Key Vault provider.
func NewAzureProvider(config *v1alpha1.AzureProvider) (*AzureProvider, error) {
	if config.VaultURL == "" {
		return nil, fmt.Errorf("Azure Key Vault URL is required")
	}

	return &AzureProvider{
		vaultURL: strings.TrimRight(config.VaultURL, "/"),
		tenantID: config.TenantID,
		clientID: config.Auth.ClientID,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSecret retrieves a secret from Azure Key Vault.
// API: GET {vaultBaseUrl}/secrets/{secret-name}?api-version=7.4
func (p *AzureProvider) GetSecret(ctx context.Context, key string, property string) (string, error) {
	if err := p.ensureToken(ctx); err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/secrets/%s?api-version=7.4", p.vaultURL, key)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Azure Key Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secret %q not found in Azure Key Vault", key)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Azure Key Vault returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value string `json:"value"`
		ID    string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode Azure response: %w", err)
	}

	if property != "" {
		// Try to parse value as JSON
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(result.Value), &data); err != nil {
			return "", fmt.Errorf("Azure secret %q is not JSON, cannot extract property %q", key, property)
		}
		val, ok := data[property]
		if !ok {
			return "", fmt.Errorf("property %q not found in Azure secret %q", property, key)
		}
		return fmt.Sprintf("%v", val), nil
	}

	return result.Value, nil
}

// HealthCheck verifies Azure Key Vault connectivity.
func (p *AzureProvider) HealthCheck(ctx context.Context) error {
	if err := p.ensureToken(ctx); err != nil {
		return fmt.Errorf("Azure auth failed: %w", err)
	}

	// List secrets with maxresults=1 as health check
	url := fmt.Sprintf("%s/secrets?api-version=7.4&maxresults=1", p.vaultURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("Azure Key Vault health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Azure Key Vault auth failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// ensureToken obtains an Azure AD token via managed identity or environment credentials.
func (p *AzureProvider) ensureToken(ctx context.Context) error {
	if p.token != "" {
		return nil
	}

	// Try managed identity (IMDS endpoint)
	imdsURL := "http://169.254.169.254/metadata/identity/oauth2/token"
	params := fmt.Sprintf("?api-version=2019-08-01&resource=https://vault.azure.net")
	if p.clientID != "" {
		params += "&client_id=" + p.clientID
	}

	req, err := http.NewRequestWithContext(ctx, "GET", imdsURL+params, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Metadata", "true")

	resp, err := p.client.Do(req)
	if err != nil {
		// Fallback: check for AZURE_CLIENT_SECRET in env (service principal)
		return p.tokenFromServicePrincipal(ctx)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return p.tokenFromServicePrincipal(ctx)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode IMDS token response: %w", err)
	}

	p.token = tokenResp.AccessToken
	return nil
}

func (p *AzureProvider) tokenFromServicePrincipal(ctx context.Context) error {
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if clientSecret == "" || p.tenantID == "" || p.clientID == "" {
		return fmt.Errorf("Azure auth: no managed identity and no service principal credentials configured")
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", p.tenantID)
	body := fmt.Sprintf(
		"grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https://vault.azure.net/.default",
		p.clientID, clientSecret,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("Azure token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Azure token request returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	p.token = tokenResp.AccessToken
	return nil
}

// Close releases resources.
func (p *AzureProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
