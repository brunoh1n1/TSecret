// Package main is the entry point for the TSecret operator.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/certs"
	"github.com/brunoh1n1/tsecret/pkg/controller"
	"github.com/brunoh1n1/tsecret/pkg/providers"
	tswebhook "github.com/brunoh1n1/tsecret/pkg/webhook"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		healthProbeAddr      string
		webhookPort          int
		enableLeaderElection bool
		logLevel             string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "The port the webhook server binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error).")
	flag.Parse()

	// Configure structured JSON logging
	zapLevel := zapcore.InfoLevel
	switch logLevel {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	}

	zapConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	zapLogger, err := zapConfig.Build()
	if err != nil {
		os.Exit(1)
	}
	defer zapLogger.Sync()

	logger := zapr.NewLogger(zapLogger)
	ctrl.SetLogger(logger)

	setupLog := logger.WithName("setup")
	setupLog.Info("Starting TSecret Operator",
		"version", "0.1.0",
		"logLevel", logLevel,
	)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    webhookPort,
			CertDir: "/tmp/k8s-webhook-server/serving-certs",
		}),
		HealthProbeBindAddress: healthProbeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "tsecret-operator-leader",
	})
	if err != nil {
		setupLog.Error(err, "Unable to create manager")
		os.Exit(1)
	}

	// --- Certificate Management (Kyverno-style self-signed CA) ---
	operatorNamespace := os.Getenv("POD_NAMESPACE")
	if operatorNamespace == "" {
		operatorNamespace = "tsecret-system"
	}

	certMgr := &certs.CertManager{
		Client:    mgr.GetClient(),
		Log:       logger.WithName("certs"),
		Namespace: operatorNamespace,
		Service:   "tsecret-webhook",
	}

	// Ensure certs after cache is started (via a runnable)
	mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// Wait for cache sync
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return fmt.Errorf("cache sync failed")
		}
		return certMgr.EnsureCerts(ctx)
	}))

	// Provider factory
	providerFactory := &providers.DefaultFactory{}

	// Setup TSecret controller
	if err := (&controller.TSecretReconciler{
		Client: mgr.GetClient(),
		Log:    logger.WithName("controller").WithName("TSecret"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "TSecret")
		os.Exit(1)
	}

	// Setup TSecretStore controller
	if err := (&controller.TSecretStoreReconciler{
		Client:          mgr.GetClient(),
		Log:             logger.WithName("controller").WithName("TSecretStore"),
		Scheme:          mgr.GetScheme(),
		ProviderFactory: providerFactory,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "TSecretStore")
		os.Exit(1)
	}

	// Setup TSecretSync controller
	if err := (&controller.TSecretSyncReconciler{
		Client:          mgr.GetClient(),
		Log:             logger.WithName("controller").WithName("TSecretSync"),
		Scheme:          mgr.GetScheme(),
		ProviderFactory: providerFactory,
		KeyResolver: &tswebhook.DefaultKeyResolver{
			Client: mgr.GetClient(),
			Log:    logger.WithName("keyresolver"),
		},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "TSecretSync")
		os.Exit(1)
	}

	// --- Mutating Webhook ---
	injectorImage := os.Getenv("TSECRET_INJECTOR_IMAGE")
	if injectorImage == "" {
		injectorImage = "tsecret:latest"
	}
	injector := &tswebhook.TSecretInjector{
		Client:        mgr.GetClient(),
		Log:           logger.WithName("webhook"),
		Decoder:       admission.NewDecoder(mgr.GetScheme()),
		InjectorImage: injectorImage,
	}
	mgr.GetWebhookServer().Register("/mutate-pods", &webhook.Admission{Handler: injector})

	// Health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Problem running manager")
		os.Exit(1)
	}
}
