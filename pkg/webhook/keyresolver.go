package webhook

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/crypto"
	"github.com/brunoh1n1/tsecret/pkg/providers"
)

// KeyResolver resolves encryption keys for decryption.
type KeyResolver interface {
	ResolveKey(ctx context.Context, ref v1alpha1.EncryptionRef, namespace string) ([]byte, error)
}

// DefaultKeyResolver resolves encryption keys from Kubernetes Secrets or Vault Transit.
type DefaultKeyResolver struct {
	Client client.Client
	Log    logr.Logger
}

// ResolveKey returns the encryption key for the given EncryptionRef.
func (r *DefaultKeyResolver) ResolveKey(ctx context.Context, ref v1alpha1.EncryptionRef, namespace string) ([]byte, error) {
	switch ref.Provider {
	case "sealed-secret":
		ns := ref.Namespace
		if ns == "" {
			ns = namespace
		}
		return r.resolveFromSecret(ctx, ref.Name, ns)

	case "vault-transit":
		return r.resolveFromVaultTransit(ctx, ref, namespace)

	case "aws-kms", "azure-keyvault", "gcp-kms", "vault-transit-legacy":
		return nil, fmt.Errorf("provider %q is not implemented yet", ref.Provider)

	default:
		return nil, fmt.Errorf("unsupported key provider: %s", ref.Provider)
	}
}

func (r *DefaultKeyResolver) resolveFromVaultTransit(
	ctx context.Context,
	ref v1alpha1.EncryptionRef,
	namespace string,
) ([]byte, error) {
	if ref.VaultTransit == nil {
		return nil, fmt.Errorf("vault-transit requires encryptionRef.vaultTransit")
	}
	if ref.Name == "" {
		return nil, fmt.Errorf("vault-transit requires encryptionRef.name (Transit key name)")
	}

	wrapped := ref.VaultTransit.WrappedKeySecret
	wrappedNS := wrapped.Namespace
	if wrappedNS == "" {
		wrappedNS = namespace
	}

	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: wrapped.Name, Namespace: wrappedNS}, secret); err != nil {
		return nil, fmt.Errorf("failed to get wrapped DEK secret %s/%s: %w", wrappedNS, wrapped.Name, err)
	}

	ciphertext, ok := secret.Data[wrapped.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain key %q", wrappedNS, wrapped.Name, wrapped.Key)
	}

	storeSpec, err := providers.ResolveVaultStore(ctx, r.Client, ref.VaultTransit.StoreRef, namespace)
	if err != nil {
		return nil, err
	}

	vaultProvider, err := providers.NewAuthenticatedVaultProvider(ctx, r.Client, storeSpec, namespace)
	if err != nil {
		return nil, fmt.Errorf("configure vault provider: %w", err)
	}
	defer vaultProvider.Close()

	dek, err := vaultProvider.TransitDecrypt(ctx, ref.Name, string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: %w", err)
	}
	if len(dek) != crypto.KeySize {
		return nil, fmt.Errorf("transit decrypted DEK has wrong size: got %d bytes, need %d", len(dek), crypto.KeySize)
	}
	return dek, nil
}

// resolveFromSecret reads the encryption key from a Kubernetes Secret.
func (r *DefaultKeyResolver) resolveFromSecret(ctx context.Context, name, namespace string) ([]byte, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: name, Namespace: namespace}

	if err := r.Client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get encryption key secret %s/%s: %w", namespace, name, err)
	}

	keyData, ok := secret.Data["encryption-key"]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain 'encryption-key' field", namespace, name)
	}

	if len(keyData) != crypto.KeySize {
		return nil, fmt.Errorf("encryption key in %s/%s has wrong size: got %d bytes, need %d",
			namespace, name, len(keyData), crypto.KeySize)
	}

	return keyData, nil
}
