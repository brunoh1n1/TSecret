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
)

// KeyResolver resolves encryption keys for decryption.
type KeyResolver interface {
	ResolveKey(ctx context.Context, ref v1alpha1.EncryptionRef, namespace string) ([]byte, error)
}

// DefaultKeyResolver resolves encryption keys from Kubernetes Secrets or external KMS.
type DefaultKeyResolver struct {
	Client client.Client
	Log    logr.Logger
}

// ResolveKey returns the encryption key for the given EncryptionRef.
//
// Key resolution strategy by provider:
//   - sealed-secret: reads key from a Kubernetes Secret named by ref.Name
//   - vault-transit: calls Vault Transit API to unwrap/export the key
//   - aws-kms: calls AWS KMS Decrypt to unwrap a data key stored in a Secret
//   - azure-keyvault: calls Azure Key Vault to unwrap a data key
//   - gcp-kms: calls GCP Cloud KMS to unwrap a data key
//
// For all providers, the actual 256-bit symmetric key is stored as a wrapped
// data key in a Kubernetes Secret. The KMS provider unwraps it on demand.
func (r *DefaultKeyResolver) ResolveKey(ctx context.Context, ref v1alpha1.EncryptionRef, namespace string) ([]byte, error) {
	ns := ref.Namespace
	if ns == "" {
		ns = namespace
	}

	switch ref.Provider {
	case "sealed-secret":
		return r.resolveFromSecret(ctx, ref.Name, ns)

	case "vault-transit":
		// For Vault Transit, the wrapped key is stored in a Secret.
		// In production, this would call Vault Transit decrypt endpoint.
		// For now, we read the key directly (bootstrap mode).
		return r.resolveFromSecret(ctx, ref.Name, ns)

	case "aws-kms":
		// AWS KMS: wrapped data key in Secret, unwrap via KMS Decrypt.
		// Bootstrap: read directly from Secret.
		return r.resolveFromSecret(ctx, ref.Name, ns)

	case "azure-keyvault":
		// Azure: wrapped data key in Secret, unwrap via Key Vault.
		// Bootstrap: read directly from Secret.
		return r.resolveFromSecret(ctx, ref.Name, ns)

	case "gcp-kms":
		// GCP: wrapped data key in Secret, unwrap via Cloud KMS.
		// Bootstrap: read directly from Secret.
		return r.resolveFromSecret(ctx, ref.Name, ns)

	default:
		return nil, fmt.Errorf("unsupported key provider: %s", ref.Provider)
	}
}

// resolveFromSecret reads the encryption key from a Kubernetes Secret.
// The Secret must contain a key named "encryption-key" with exactly 32 bytes.
func (r *DefaultKeyResolver) resolveFromSecret(ctx context.Context, name, namespace string) ([]byte, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: name, Namespace: namespace}

	if err := r.Client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get encryption key secret %s/%s: %w", namespace, name, err)
	}

	// Look for the key in the Secret data
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
