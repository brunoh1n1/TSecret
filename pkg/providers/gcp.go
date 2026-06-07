package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// GCPProvider implements Provider for GCP Secret Manager.
// Uses the REST API with metadata server token (workload identity) or service account JSON.
type GCPProvider struct {
	projectID string
	client    *http.Client
	token     string
}

// NewGCPProvider creates a new GCP Secret Manager provider.
func NewGCPProvider(config *v1alpha1.GCPProvider) (*GCPProvider, error) {
	if config.ProjectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}

	return &GCPProvider{
		projectID: config.ProjectID,
		client:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSecret retrieves a secret from GCP Secret Manager.
func (p *GCPProvider) GetSecret(ctx context.Context, key string, property string) (string, error) {
	if err := p.ensureToken(ctx); err != nil {
		return "", err
	}

	version := "latest"
	if strings.Contains(key, "/versions/") {
		parts := strings.SplitN(key, "/versions/", 2)
		key = parts[0]
		version = parts[1]
	}

	url := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/%s:access",
		p.projectID, key, version,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create GCP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GCP Secret Manager request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secret %q not found in GCP project %s", key, p.projectID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GCP Secret Manager returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode GCP response: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode GCP secret data: %w", err)
	}

	if property != "" {
		var data map[string]interface{}
		if err := json.Unmarshal(decoded, &data); err != nil {
			return "", fmt.Errorf("GCP secret %q is not JSON, cannot extract property %q", key, property)
		}
		val, ok := data[property]
		if !ok {
			return "", fmt.Errorf("property %q not found in GCP secret %q", property, key)
		}
		return fmt.Sprintf("%v", val), nil
	}

	return string(decoded), nil
}

// HealthCheck verifies GCP connectivity.
func (p *GCPProvider) HealthCheck(ctx context.Context) error {
	if err := p.ensureToken(ctx); err != nil {
		return fmt.Errorf("GCP auth failed: %w", err)
	}

	url := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets?pageSize=1",
		p.projectID,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("GCP health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("GCP auth failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

func (p *GCPProvider) ensureToken(ctx context.Context) error {
	if p.token != "" {
		return nil
	}

	// Try GKE metadata server (workload identity)
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err == nil && tokenResp.AccessToken != "" {
			p.token = tokenResp.AccessToken
			return nil
		}
	}

	credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credFile == "" {
		return fmt.Errorf("GCP auth: no workload identity and GOOGLE_APPLICATION_CREDENTIALS not set")
	}

	return fmt.Errorf("GCP service account JSON auth not yet implemented — use workload identity")
}

// Close releases resources.
func (p *GCPProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
