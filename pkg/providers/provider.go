// Package providers defines the interface for external secret providers.
package providers

import (
	"context"
	"fmt"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// Provider is the interface that all secret provider backends must implement.
type Provider interface {
	// GetSecret retrieves a secret value from the provider.
	// key is the secret path/name, property is an optional sub-key for JSON secrets.
	GetSecret(ctx context.Context, key string, property string) (string, error)

	// HealthCheck verifies connectivity to the provider.
	HealthCheck(ctx context.Context) error

	// Close releases any resources held by the provider.
	Close() error
}

// Factory creates Provider instances from store configuration.
type Factory interface {
	// NewProvider creates a new provider from the given configuration.
	NewProvider(config v1alpha1.SecretStoreProvider) (Provider, error)
}

// DefaultFactory is the default provider factory.
type DefaultFactory struct{}

// NewProvider creates a provider based on the configuration.
func (f *DefaultFactory) NewProvider(config v1alpha1.SecretStoreProvider) (Provider, error) {
	if config.Vault != nil {
		return NewVaultProvider(config.Vault)
	}
	if config.AWS != nil {
		return NewAWSProvider(config.AWS)
	}
	if config.Azure != nil {
		return NewAzureProvider(config.Azure)
	}
	if config.GCP != nil {
		return NewGCPProvider(config.GCP)
	}
	if config.Oracle != nil {
		return NewOracleProvider(config.Oracle)
	}
	return nil, fmt.Errorf("no provider configured")
}
