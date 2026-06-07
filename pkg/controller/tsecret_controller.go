// Package controller implements reconciliation logic for TSecret CRDs.
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
	"github.com/brunoh1n1/tsecret/pkg/crypto"
)

// TSecretReconciler reconciles TSecret objects.
type TSecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile handles TSecret create/update/delete events.
func (r *TSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tsecret", req.NamespacedName)

	// Fetch the TSecret
	tsecret := &v1alpha1.TSecret{}
	if err := r.Get(ctx, req.NamespacedName, tsecret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling TSecret", "entries", len(tsecret.Spec.Data))

	// Validate all encrypted values
	allValid := true
	for key, entry := range tsecret.Spec.Data {
		if !crypto.IsValidEncryptedValue(entry.Value) {
			log.Error(nil, "Invalid encrypted value", "key", key)
			allValid = false
		}
		if entry.Algorithm != crypto.AlgorithmXChaCha20Poly && entry.Algorithm != crypto.AlgorithmChaCha20Poly {
			log.Error(nil, "Unsupported algorithm", "key", key, "algorithm", entry.Algorithm)
			allValid = false
		}
	}

	// Update status
	condition := metav1.Condition{
		Type:               "Ready",
		LastTransitionTime: metav1.Now(),
	}

	if allValid {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Valid"
		condition.Message = fmt.Sprintf("All %d entries are valid encrypted values", len(tsecret.Spec.Data))
	} else {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "ValidationFailed"
		condition.Message = "One or more entries have invalid encrypted format"
	}

	// Update conditions
	setCondition(&tsecret.Status.Conditions, condition)

	if err := r.Status().Update(ctx, tsecret); err != nil {
		log.Error(err, "Failed to update TSecret status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TSecret{}).
		Complete(r)
}

// setCondition updates or appends a condition.
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	for i, c := range *conditions {
		if c.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}
