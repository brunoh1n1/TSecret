// Package v1alpha1 contains the TSecret API types.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ─── TSecret ──────────────────────────────────────────────────────────────────

// TSecretSpec defines the desired state of TSecret.
type TSecretSpec struct {
	// EncryptionRef references the encryption configuration.
	EncryptionRef EncryptionRef `json:"encryptionRef"`

	// Data contains encrypted key-value pairs.
	// Each value is base64-encoded ciphertext with algorithm prefix.
	Data map[string]TSecretEntry `json:"data"`
}

// TSecretEntry represents a single encrypted value with metadata.
type TSecretEntry struct {
	// Value is the base64-encoded encrypted ciphertext.
	Value string `json:"value"`

	// Algorithm specifies the encryption algorithm used (xchacha20-poly1305 or chacha20-poly1305).
	Algorithm string `json:"algorithm"`

	// KeyRef identifies which key was used for encryption.
	KeyRef string `json:"keyRef"`
}

// EncryptionRef references the key provider configuration.
type EncryptionRef struct {
	// Provider is the key provider type (sealed-secret, aws-kms, azure-keyvault, gcp-kms, vault-transit).
	Provider string `json:"provider"`

	// Name is the name of the key or key reference in the provider.
	Name string `json:"name"`

	// Namespace is optional; if empty, uses the TSecret's namespace.
	Namespace string `json:"namespace,omitempty"`
}

// TSecretStatus defines the observed state of TSecret.
type TSecretStatus struct {
	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastEncryptedAt is the timestamp of the last encryption operation.
	LastEncryptedAt *metav1.Time `json:"lastEncryptedAt,omitempty"`

	// KeyVersion tracks the current key version used.
	KeyVersion string `json:"keyVersion,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Algorithm",type=string,JSONPath=`.spec.data[*].algorithm`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TSecret is the Schema for the tsecrets API.
type TSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TSecretSpec   `json:"spec,omitempty"`
	Status TSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TSecretList contains a list of TSecret.
type TSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TSecret `json:"items"`
}

// ─── TSecretStore ─────────────────────────────────────────────────────────────

// TSecretStoreSpec defines the desired state of TSecretStore.
type TSecretStoreSpec struct {
	// Provider configures the external secret provider.
	Provider SecretStoreProvider `json:"provider"`

	// RefreshInterval is how often to check provider health (default: 60s).
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// SecretStoreProvider configures a specific secret provider backend.
type SecretStoreProvider struct {
	// Vault configures HashiCorp Vault.
	Vault *VaultProvider `json:"vault,omitempty"`

	// AWS configures AWS Secrets Manager.
	AWS *AWSProvider `json:"aws,omitempty"`

	// Azure configures Azure Key Vault.
	Azure *AzureProvider `json:"azure,omitempty"`

	// GCP configures GCP Secret Manager.
	GCP *GCPProvider `json:"gcp,omitempty"`

	// Oracle configures Oracle Vault.
	Oracle *OracleProvider `json:"oracle,omitempty"`
}

// VaultProvider configures HashiCorp Vault connection.
type VaultProvider struct {
	// Server is the Vault server URL.
	Server string `json:"server"`

	// Path is the KV v2 mount path (e.g. "secret"), without the "/data" suffix.
	Path string `json:"path,omitempty"`

	// Auth configures Vault authentication.
	Auth VaultAuth `json:"auth"`
}

// VaultAuth configures Vault authentication methods.
type VaultAuth struct {
	// TokenSecretRef references a Secret containing the Vault token.
	TokenSecretRef *SecretKeyRef `json:"tokenSecretRef,omitempty"`

	// Kubernetes configures Kubernetes auth method.
	Kubernetes *VaultKubernetesAuth `json:"kubernetes,omitempty"`

	// AppRole configures AppRole auth method.
	AppRole *VaultAppRoleAuth `json:"appRole,omitempty"`
}

// VaultKubernetesAuth configures Vault Kubernetes auth.
type VaultKubernetesAuth struct {
	// MountPath is the Vault auth mount path (default: kubernetes).
	MountPath string `json:"mountPath,omitempty"`

	// Role is the Vault role to authenticate as.
	Role string `json:"role"`

	// ServiceAccountRef references the ServiceAccount to use.
	ServiceAccountRef string `json:"serviceAccountRef,omitempty"`
}

// VaultAppRoleAuth configures Vault AppRole auth.
type VaultAppRoleAuth struct {
	// RoleID is the AppRole role ID.
	RoleIDRef SecretKeyRef `json:"roleIdRef"`

	// SecretID references the AppRole secret ID.
	SecretIDRef SecretKeyRef `json:"secretIdRef"`
}

// AWSProvider configures AWS Secrets Manager.
type AWSProvider struct {
	// Region is the AWS region.
	Region string `json:"region"`

	// Auth configures AWS authentication.
	Auth AWSAuth `json:"auth,omitempty"`
}

// AWSAuth configures AWS authentication.
type AWSAuth struct {
	// SecretRef references a Secret with AWS credentials.
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`

	// Role is the IAM role ARN for IRSA.
	Role string `json:"role,omitempty"`
}

// AzureProvider configures Azure Key Vault.
type AzureProvider struct {
	// VaultURL is the Azure Key Vault URL.
	VaultURL string `json:"vaultUrl"`

	// TenantID is the Azure AD tenant ID.
	TenantID string `json:"tenantId,omitempty"`

	// Auth configures Azure authentication.
	Auth AzureAuth `json:"auth,omitempty"`
}

// AzureAuth configures Azure authentication.
type AzureAuth struct {
	// ClientID is the Azure AD application client ID.
	ClientID string `json:"clientId,omitempty"`

	// ClientSecretRef references a Secret with the client secret.
	ClientSecretRef *SecretKeyRef `json:"clientSecretRef,omitempty"`

	// UseManagedIdentity enables managed identity auth.
	UseManagedIdentity bool `json:"useManagedIdentity,omitempty"`
}

// GCPProvider configures GCP Secret Manager.
type GCPProvider struct {
	// ProjectID is the GCP project ID.
	ProjectID string `json:"projectId"`

	// Auth configures GCP authentication.
	Auth GCPAuth `json:"auth,omitempty"`
}

// GCPAuth configures GCP authentication.
type GCPAuth struct {
	// SecretRef references a Secret with GCP service account JSON.
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`

	// WorkloadIdentity enables GKE workload identity.
	WorkloadIdentity bool `json:"workloadIdentity,omitempty"`
}

// OracleProvider configures Oracle Vault.
type OracleProvider struct {
	// VaultID is the Oracle Vault OCID.
	VaultID string `json:"vaultId"`

	// Region is the Oracle Cloud region.
	Region string `json:"region"`

	// Auth configures Oracle authentication.
	Auth OracleAuth `json:"auth,omitempty"`
}

// OracleAuth configures Oracle authentication.
type OracleAuth struct {
	// SecretRef references a Secret with Oracle credentials.
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`

	// UseInstancePrincipal enables instance principal auth.
	UseInstancePrincipal bool `json:"useInstancePrincipal,omitempty"`
}

// SecretKeyRef references a key in a Kubernetes Secret.
type SecretKeyRef struct {
	// Name is the Secret name.
	Name string `json:"name"`

	// Key is the key within the Secret.
	Key string `json:"key"`

	// Namespace is optional; defaults to the resource's namespace.
	Namespace string `json:"namespace,omitempty"`
}

// TSecretStoreStatus defines the observed state of TSecretStore.
type TSecretStoreStatus struct {
	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status is the current store status (Available, Unavailable, Invalid).
	Status string `json:"status,omitempty"`

	// LastCheckedAt is the last health check timestamp.
	LastCheckedAt *metav1.Time `json:"lastCheckedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TSecretStore is the Schema for the tsecretstores API (namespace-scoped).
type TSecretStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TSecretStoreSpec   `json:"spec,omitempty"`
	Status TSecretStoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TSecretStoreList contains a list of TSecretStore.
type TSecretStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TSecretStore `json:"items"`
}

// ─── ClusterTSecretStore ──────────────────────────────────────────────────────

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterTSecretStore is the Schema for the clustertsecretstores API (cluster-scoped).
type ClusterTSecretStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TSecretStoreSpec   `json:"spec,omitempty"`
	Status TSecretStoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterTSecretStoreList contains a list of ClusterTSecretStore.
type ClusterTSecretStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterTSecretStore `json:"items"`
}

// ─── TSecretSync ──────────────────────────────────────────────────────────────

// TSecretSyncSpec defines the desired state of TSecretSync.
type TSecretSyncSpec struct {
	// SecretStoreRef references the TSecretStore or ClusterTSecretStore.
	SecretStoreRef SecretStoreRef `json:"secretStoreRef"`

	// Target defines the TSecret to create/update.
	Target TSecretSyncTarget `json:"target"`

	// Data defines which secrets to pull from the provider.
	Data []TSecretSyncData `json:"data"`

	// RefreshInterval defines how often to sync (e.g., "1h", "30m"). Min: 30s, Max: 24h.
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// SecretStoreRef references a TSecretStore or ClusterTSecretStore.
type SecretStoreRef struct {
	// Name is the store resource name.
	Name string `json:"name"`

	// Kind is either TSecretStore or ClusterTSecretStore.
	Kind string `json:"kind"`
}

// TSecretSyncTarget defines the target TSecret.
type TSecretSyncTarget struct {
	// Name is the TSecret name to create.
	Name string `json:"name"`
}

// TSecretSyncData defines a single secret to sync.
type TSecretSyncData struct {
	// SecretKey is the key in the external provider.
	SecretKey string `json:"secretKey"`

	// RemoteRef defines the remote secret reference.
	RemoteRef RemoteRef `json:"remoteRef"`
}

// RemoteRef defines a reference to a secret in the external provider.
type RemoteRef struct {
	// Key is the secret path/name in the provider.
	Key string `json:"key"`

	// Property is an optional property within the secret (for JSON secrets).
	Property string `json:"property,omitempty"`

	// Version is an optional version/stage identifier.
	Version string `json:"version,omitempty"`
}

// TSecretSyncStatus defines the observed state of TSecretSync.
type TSecretSyncStatus struct {
	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status is the current sync status (Synced, SyncFailed, Syncing).
	Status string `json:"status,omitempty"`

	// LastSyncedAt is the last successful sync timestamp.
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`

	// SyncedGeneration is the generation of the last successful sync.
	SyncedGeneration int64 `json:"syncedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncedAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TSecretSync is the Schema for the tsecretsyncs API.
type TSecretSync struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TSecretSyncSpec   `json:"spec,omitempty"`
	Status TSecretSyncStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TSecretSyncList contains a list of TSecretSync.
type TSecretSyncList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TSecretSync `json:"items"`
}
