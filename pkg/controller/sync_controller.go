package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/crypto"
	"github.com/brunoh1n1/tsecret/pkg/providers"
	"github.com/brunoh1n1/tsecret/pkg/webhook"
)

// TSecretSyncReconciler reconciles TSecretSync objects.
type TSecretSyncReconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	ProviderFactory providers.Factory
	KeyResolver     webhook.KeyResolver
}

// Reconcile handles TSecretSync create/update/delete events.
func (r *TSecretSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tsecretsync", req.NamespacedName)

	sync := &v1alpha1.TSecretSync{}
	if err := r.Get(ctx, req.NamespacedName, sync); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling TSecretSync", "target", sync.Spec.Target.Name)

	// Resolve the store
	storeSpec, err := r.resolveStore(ctx, sync)
	if err != nil {
		r.setSyncStatus(ctx, sync, "SyncFailed", "StoreResolutionFailed", err.Error())
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	// Create provider
	provider, err := r.ProviderFactory.NewProvider(storeSpec.Provider)
	if err != nil {
		r.setSyncStatus(ctx, sync, "SyncFailed", "ProviderError", err.Error())
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}
	defer provider.Close()

	if storeSpec.Provider.Vault != nil {
		if err := providers.ConfigureVaultAuth(ctx, r.Client, sync.Namespace, provider, storeSpec.Provider.Vault.Auth); err != nil {
			r.setSyncStatus(ctx, sync, "SyncFailed", "AuthFailed", err.Error())
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}
	}

	// Pull secrets from provider
	encRef := defaultEncryptionRef(sync)
	data := make(map[string]v1alpha1.TSecretEntry)
	for _, item := range sync.Spec.Data {
		value, err := provider.GetSecret(ctx, item.RemoteRef.Key, item.RemoteRef.Property)
		if err != nil {
			log.Error(err, "Failed to pull secret", "key", item.RemoteRef.Key)
			r.setSyncStatus(ctx, sync, "SyncFailed", "PullFailed",
				fmt.Sprintf("failed to pull %s: %v", item.RemoteRef.Key, err))
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}

		key, err := r.KeyResolver.ResolveKey(ctx, encRef, req.Namespace)
		if err != nil {
			r.setSyncStatus(ctx, sync, "SyncFailed", "KeyResolutionFailed", err.Error())
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}

		encrypted, err := crypto.Encrypt([]byte(value), key, crypto.AlgorithmXChaCha20Poly)
		if err != nil {
			r.setSyncStatus(ctx, sync, "SyncFailed", "EncryptionFailed", err.Error())
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}

		data[item.SecretKey] = v1alpha1.TSecretEntry{
			Value:     encrypted,
			Algorithm: crypto.AlgorithmXChaCha20Poly,
			KeyRef:    encRef.Name,
		}
	}

	// Create or update the target TSecret
	target := &v1alpha1.TSecret{}
	targetKey := types.NamespacedName{
		Name:      sync.Spec.Target.Name,
		Namespace: req.Namespace,
	}

	err = r.Get(ctx, targetKey, target)
	if err != nil {
		// Create new TSecret
		target = &v1alpha1.TSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sync.Spec.Target.Name,
				Namespace: req.Namespace,
				Labels: map[string]string{
					"tsecret.io/managed-by": "tsecretsync",
					"tsecret.io/sync-name":  sync.Name,
				},
			},
			Spec: v1alpha1.TSecretSpec{
				EncryptionRef: encRef,
				Data:          data,
			},
		}
		if err := r.Create(ctx, target); err != nil {
			r.setSyncStatus(ctx, sync, "SyncFailed", "CreateFailed", err.Error())
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}
	} else {
		// Update existing
		target.Spec.Data = data
		target.Spec.EncryptionRef = encRef
		if err := r.Update(ctx, target); err != nil {
			r.setSyncStatus(ctx, sync, "SyncFailed", "UpdateFailed", err.Error())
			return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
		}
	}

	// Update sync status
	now := metav1.Now()
	sync.Status.LastSyncedAt = &now
	sync.Status.SyncedGeneration = sync.Generation
	r.setSyncStatus(ctx, sync, "Synced", "SyncComplete",
		fmt.Sprintf("Successfully synced %d secrets", len(data)))

	// Calculate requeue interval
	interval := parseDuration(sync.Spec.RefreshInterval, 1*time.Hour)
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	if interval > 24*time.Hour {
		interval = 24 * time.Hour
	}

	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *TSecretSyncReconciler) resolveStore(
	ctx context.Context,
	sync *v1alpha1.TSecretSync,
) (*v1alpha1.TSecretStoreSpec, error) {
	ref := sync.Spec.SecretStoreRef

	switch ref.Kind {
	case "TSecretStore":
		store := &v1alpha1.TSecretStore{}
		key := types.NamespacedName{Name: ref.Name, Namespace: sync.Namespace}
		if err := r.Get(ctx, key, store); err != nil {
			return nil, fmt.Errorf("TSecretStore %s not found: %w", ref.Name, err)
		}
		if store.Status.Status == "Unavailable" {
			return nil, fmt.Errorf("TSecretStore %s is unavailable", ref.Name)
		}
		return &store.Spec, nil

	case "ClusterTSecretStore":
		store := &v1alpha1.ClusterTSecretStore{}
		key := types.NamespacedName{Name: ref.Name}
		if err := r.Get(ctx, key, store); err != nil {
			return nil, fmt.Errorf("ClusterTSecretStore %s not found: %w", ref.Name, err)
		}
		if store.Status.Status == "Unavailable" {
			return nil, fmt.Errorf("ClusterTSecretStore %s is unavailable", ref.Name)
		}
		return &store.Spec, nil

	default:
		return nil, fmt.Errorf("unsupported store kind: %s", ref.Kind)
	}
}

func (r *TSecretSyncReconciler) setSyncStatus(
	ctx context.Context,
	sync *v1alpha1.TSecretSync,
	status, reason, message string,
) {
	sync.Status.Status = status
	condition := metav1.Condition{
		Type:               "Synced",
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
	if status == "Synced" {
		condition.Status = metav1.ConditionTrue
	} else {
		condition.Status = metav1.ConditionFalse
	}
	setCondition(&sync.Status.Conditions, condition)

	if err := r.Status().Update(ctx, sync); err != nil {
		r.Log.Error(err, "Failed to update TSecretSync status")
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *TSecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TSecretSync{}).
		Complete(r)
}

func parseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}

func defaultEncryptionRef(sync *v1alpha1.TSecretSync) v1alpha1.EncryptionRef {
	if sync.Spec.EncryptionRef != nil {
		return *sync.Spec.EncryptionRef
	}
	return v1alpha1.EncryptionRef{
		Provider: "sealed-secret",
		Name:     "tsecret-master-key",
	}
}
