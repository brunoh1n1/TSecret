package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/providers"
)

// TSecretStoreReconciler reconciles TSecretStore and ClusterTSecretStore objects.
type TSecretStoreReconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	ProviderFactory providers.Factory
}

// Reconcile handles TSecretStore create/update/delete events.
func (r *TSecretStoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tsecretstore", req.NamespacedName)

	store := &v1alpha1.TSecretStore{}
	if err := r.Get(ctx, req.NamespacedName, store); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling TSecretStore")

	// Validate provider connection
	provider, err := r.ProviderFactory.NewProvider(store.Spec.Provider)
	if err != nil {
		r.setStoreStatus(ctx, store, "Invalid", "ProviderConfigError", err.Error())
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	// Health check with 30s timeout
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := provider.HealthCheck(checkCtx); err != nil {
		log.Error(err, "Provider health check failed")
		r.setStoreStatus(ctx, store, "Unavailable", "HealthCheckFailed", err.Error())
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	r.setStoreStatus(ctx, store, "Available", "HealthCheckPassed", "Provider is reachable")
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *TSecretStoreReconciler) setStoreStatus(
	ctx context.Context,
	store *v1alpha1.TSecretStore,
	status, reason, message string,
) {
	store.Status.Status = status
	now := metav1.Now()
	store.Status.LastCheckedAt = &now

	condition := metav1.Condition{
		Type:               "Ready",
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}
	if status == "Available" {
		condition.Status = metav1.ConditionTrue
	} else {
		condition.Status = metav1.ConditionFalse
	}

	setCondition(&store.Status.Conditions, condition)

	if err := r.Status().Update(ctx, store); err != nil {
		r.Log.Error(err, "Failed to update TSecretStore status",
			"store", fmt.Sprintf("%s/%s", store.Namespace, store.Name))
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *TSecretStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TSecretStore{}).
		Complete(r)
}
