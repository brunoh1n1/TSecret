// Package certs handles TLS certificate generation and rotation for the webhook,
// following the same self-signed CA pattern used by Kyverno.
//
// Flow:
//  1. On startup, check if the CA Secret exists in the operator namespace.
//  2. If not, generate a self-signed CA (valid 10 years) and store it.
//  3. Generate a serving certificate signed by the CA (valid 1 year).
//  4. Patch the MutatingWebhookConfiguration with the CA bundle.
//  5. Periodically check certificate expiry and rotate before expiration.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CASecretName is the name of the Secret holding the CA key pair.
	CASecretName = "tsecret-ca"

	// ServingCertSecretName is the name of the Secret holding the serving cert.
	ServingCertSecretName = "tsecret-webhook-certs"

	// WebhookConfigName is the MutatingWebhookConfiguration name.
	WebhookConfigName = "tsecret-mutating-webhook"

	// CAValidityDuration is how long the CA certificate is valid.
	CAValidityDuration = 10 * 365 * 24 * time.Hour // 10 years

	// ServingCertValidityDuration is how long the serving certificate is valid.
	ServingCertValidityDuration = 365 * 24 * time.Hour // 1 year

	// RenewalThreshold — renew when less than this time remains.
	RenewalThreshold = 30 * 24 * time.Hour // 30 days
)

// CertManager handles certificate lifecycle.
type CertManager struct {
	Client    client.Client
	Log       logr.Logger
	Namespace string
	Service   string // webhook service name (e.g., "tsecret-webhook")
}

// EnsureCerts ensures CA and serving certificates exist and are valid.
// Returns the path where certs are written for the webhook server.
func (cm *CertManager) EnsureCerts(ctx context.Context) error {
	log := cm.Log.WithName("certs")

	// 1. Ensure CA
	caKey, caCert, err := cm.ensureCA(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to ensure CA: %w", err)
	}

	// 2. Ensure serving cert
	if err := cm.ensureServingCert(ctx, log, caKey, caCert); err != nil {
		return fmt.Errorf("failed to ensure serving cert: %w", err)
	}

	// 3. Patch webhook configuration with CA bundle
	if err := cm.patchWebhookCABundle(ctx, log, caCert); err != nil {
		return fmt.Errorf("failed to patch webhook CA bundle: %w", err)
	}

	log.Info("TLS certificates are ready")
	return nil
}

// NeedsRenewal checks if the serving certificate needs renewal.
func (cm *CertManager) NeedsRenewal(ctx context.Context) (bool, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: ServingCertSecretName, Namespace: cm.Namespace}

	if err := cm.Client.Get(ctx, key, secret); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}

	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return true, nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, nil
	}

	remaining := time.Until(cert.NotAfter)
	return remaining < RenewalThreshold, nil
}

func (cm *CertManager) ensureCA(ctx context.Context, log logr.Logger) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: CASecretName, Namespace: cm.Namespace}

	err := cm.Client.Get(ctx, key, secret)
	if err == nil {
		// CA exists — parse and return
		return parseCAFromSecret(secret)
	}

	if !errors.IsNotFound(err) {
		return nil, nil, err
	}

	// Generate new CA
	log.Info("Generating new CA certificate")

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "TSecret CA",
			Organization: []string{"TSecret"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(CAValidityDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, err
	}

	// Store in Secret
	keyPEM, err := marshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CASecretName,
			Namespace: cm.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "tsecret-operator",
				"app.kubernetes.io/component":  "ca",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}

	if err := cm.Client.Create(ctx, caSecret); err != nil {
		return nil, nil, fmt.Errorf("failed to create CA secret: %w", err)
	}

	log.Info("CA certificate created", "notAfter", caCert.NotAfter)
	return caKey, caCert, nil
}

func (cm *CertManager) ensureServingCert(
	ctx context.Context,
	log logr.Logger,
	caKey *ecdsa.PrivateKey,
	caCert *x509.Certificate,
) error {
	needsRenewal, err := cm.NeedsRenewal(ctx)
	if err != nil {
		return err
	}
	if !needsRenewal {
		return nil
	}

	log.Info("Generating serving certificate for webhook")

	// Generate serving key
	servingKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate serving key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// DNS names for the webhook service
	dnsNames := []string{
		cm.Service,
		fmt.Sprintf("%s.%s", cm.Service, cm.Namespace),
		fmt.Sprintf("%s.%s.svc", cm.Service, cm.Namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", cm.Service, cm.Namespace),
	}

	servingTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s.%s.svc", cm.Service, cm.Namespace),
			Organization: []string{"TSecret"},
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(ServingCertValidityDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	servingCertDER, err := x509.CreateCertificate(rand.Reader, servingTemplate, caCert, &servingKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create serving certificate: %w", err)
	}

	keyPEM, err := marshalECPrivateKey(servingKey)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: servingCertDER})

	// Create or update the serving cert Secret
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: ServingCertSecretName, Namespace: cm.Namespace}

	err = cm.Client.Get(ctx, secretKey, secret)
	if errors.IsNotFound(err) {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ServingCertSecretName,
				Namespace: cm.Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "tsecret-operator",
					"app.kubernetes.io/component":  "webhook-tls",
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
		}
		if err := cm.Client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create serving cert secret: %w", err)
		}
	} else if err == nil {
		secret.Data = map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		}
		if err := cm.Client.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to update serving cert secret: %w", err)
		}
	} else {
		return err
	}

	log.Info("Serving certificate created/renewed",
		"dnsNames", dnsNames,
		"notAfter", servingTemplate.NotAfter,
	)
	return nil
}

func (cm *CertManager) patchWebhookCABundle(ctx context.Context, log logr.Logger, caCert *x509.Certificate) error {
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
	key := types.NamespacedName{Name: WebhookConfigName}

	if err := cm.Client.Get(ctx, key, webhookConfig); err != nil {
		if errors.IsNotFound(err) {
			log.Info("MutatingWebhookConfiguration not found, skipping CA bundle patch")
			return nil
		}
		return err
	}

	// Patch all webhooks with the CA bundle
	updated := false
	for i := range webhookConfig.Webhooks {
		if string(webhookConfig.Webhooks[i].ClientConfig.CABundle) != string(caBundle) {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = caBundle
			updated = true
		}
	}

	if updated {
		if err := cm.Client.Update(ctx, webhookConfig); err != nil {
			return fmt.Errorf("failed to update webhook CA bundle: %w", err)
		}
		log.Info("Webhook CA bundle updated")
	}

	return nil
}

// --- Helpers ---

func parseCAFromSecret(secret *corev1.Secret) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyPEM := secret.Data["tls.key"]
	certPEM := secret.Data["tls.crt"]

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key: %w (also tried PKCS8: %v)", err, err2)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA key is not ECDSA")
		}
		key = ecKey
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return key, cert, nil
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
