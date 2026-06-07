// tsecret-inject decrypts a TSecret at runtime and writes files to a tmpfs mount.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/inject"
	"github.com/brunoh1n1/tsecret/pkg/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		secretName string
		mountPath  string
		namespace  string
		prefix     string
		exportEnv  bool
	)

	flag.StringVar(&secretName, "secret", "", "TSecret name (required)")
	flag.StringVar(&mountPath, "mount", "", "Mount path for decrypted files (required)")
	flag.StringVar(&namespace, "namespace", "", "Namespace (defaults to POD_NAMESPACE)")
	flag.StringVar(&prefix, "prefix", "", "Optional prefix for file names (envFrom prefix)")
	flag.BoolVar(&exportEnv, "export-env", false, "Write load-env.sh for optional runtime env export")
	flag.Parse()

	if secretName == "" || mountPath == "" {
		fmt.Fprintln(os.Stderr, "--secret and --mount are required")
		os.Exit(2)
	}

	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	if namespace == "" {
		fmt.Fprintln(os.Stderr, "namespace is required via --namespace or POD_NAMESPACE")
		os.Exit(2)
	}

	zapLogger, _ := zap.NewProduction()
	logger := zapr.NewLogger(zapLogger)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "in-cluster config: %v\n", err)
		os.Exit(1)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}

	keyResolver := &webhook.DefaultKeyResolver{
		Client: k8sClient,
		Log:    logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := inject.Write(ctx, k8sClient, keyResolver, namespace, secretName, mountPath, prefix, exportEnv); err != nil {
		fmt.Fprintf(os.Stderr, "inject failed: %v\n", err)
		os.Exit(1)
	}
}
