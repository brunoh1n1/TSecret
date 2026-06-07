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

// AWSProvider implements Provider for AWS Secrets Manager.
// Uses the REST API. In production, configure IRSA (IAM Roles for Service Accounts).
type AWSProvider struct {
	region    string
	accessKey string
	secretKey string
	client    *http.Client
}

// NewAWSProvider creates a new AWS Secrets Manager provider.
func NewAWSProvider(config *v1alpha1.AWSProvider) (*AWSProvider, error) {
	if config.Region == "" {
		return nil, fmt.Errorf("AWS region is required")
	}

	return &AWSProvider{
		region:    config.Region,
		accessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		secretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		client:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSecret retrieves a secret from AWS Secrets Manager.
func (p *AWSProvider) GetSecret(ctx context.Context, key string, property string) (string, error) {
	endpoint := fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", p.region)
	body := fmt.Sprintf(`{"SecretId":"%s"}`, key)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AWS request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")

	if err := p.signRequest(req); err != nil {
		return "", fmt.Errorf("failed to sign AWS request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AWS Secrets Manager request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("AWS Secrets Manager returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		SecretString string `json:"SecretString"`
		Name         string `json:"Name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode AWS response: %w", err)
	}

	if property != "" {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(result.SecretString), &data); err != nil {
			return "", fmt.Errorf("AWS secret %q is not JSON, cannot extract property %q", key, property)
		}
		val, ok := data[property]
		if !ok {
			return "", fmt.Errorf("property %q not found in AWS secret %q", property, key)
		}
		return fmt.Sprintf("%v", val), nil
	}

	return result.SecretString, nil
}

// HealthCheck verifies AWS connectivity via STS GetCallerIdentity.
func (p *AWSProvider) HealthCheck(ctx context.Context) error {
	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", p.region)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create STS request: %w", err)
	}

	if err := p.signRequest(req); err != nil {
		return fmt.Errorf("failed to sign STS request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("AWS STS health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AWS STS returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// signRequest is a placeholder for AWS SigV4 signing.
// In production, use aws-sdk-go-v2/aws/signer/v4 or IRSA.
func (p *AWSProvider) signRequest(req *http.Request) error {
	if p.accessKey != "" && p.secretKey != "" {
		// Real SigV4 signing would go here (requires aws-sdk-go-v2)
		return nil
	}

	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if tokenPath != "" {
		return nil // IRSA handles signing via SDK
	}

	return fmt.Errorf("no AWS credentials configured (set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or use IRSA)")
}

// Close releases resources.
func (p *AWSProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
