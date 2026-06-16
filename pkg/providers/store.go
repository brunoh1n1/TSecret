package providers

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

// ResolveVaultStore loads a TSecretStore or ClusterTSecretStore spec.
func ResolveVaultStore(
	ctx context.Context,
	c client.Reader,
	ref v1alpha1.SecretStoreRef,
	namespace string,
) (*v1alpha1.TSecretStoreSpec, error) {
	switch ref.Kind {
	case "TSecretStore", "":
		store := &v1alpha1.TSecretStore{}
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, store); err != nil {
			return nil, fmt.Errorf("TSecretStore %s/%s not found: %w", namespace, ref.Name, err)
		}
		if store.Spec.Provider.Vault == nil {
			return nil, fmt.Errorf("TSecretStore %s/%s is not a Vault store", namespace, ref.Name)
		}
		return &store.Spec, nil

	case "ClusterTSecretStore":
		store := &v1alpha1.ClusterTSecretStore{}
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name}, store); err != nil {
			return nil, fmt.Errorf("ClusterTSecretStore %s not found: %w", ref.Name, err)
		}
		if store.Spec.Provider.Vault == nil {
			return nil, fmt.Errorf("ClusterTSecretStore %s is not a Vault store", ref.Name)
		}
		return &store.Spec, nil

	default:
		return nil, fmt.Errorf("unsupported store kind: %s", ref.Kind)
	}
}

// NewAuthenticatedVaultProvider builds a Vault provider using store auth configuration.
func NewAuthenticatedVaultProvider(
	ctx context.Context,
	c client.Reader,
	storeSpec *v1alpha1.TSecretStoreSpec,
	namespace string,
) (*VaultProvider, error) {
	if storeSpec.Provider.Vault == nil {
		return nil, fmt.Errorf("vault provider is not configured")
	}

	provider, err := NewVaultProvider(storeSpec.Provider.Vault)
	if err != nil {
		return nil, err
	}
	if err := ConfigureVaultAuth(ctx, c, namespace, provider, storeSpec.Provider.Vault.Auth); err != nil {
		return nil, err
	}
	return provider, nil
}
