// Package inject writes decrypted TSecret data to a mount path at runtime.
package inject

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
	"github.com/brunoh1n1/tsecret/pkg/crypto"
)

// KeyResolver resolves encryption keys for decryption.
type KeyResolver interface {
	ResolveKey(ctx context.Context, ref v1alpha1.EncryptionRef, namespace string) ([]byte, error)
}

// Write decrypts a TSecret and writes each key as a file under mountPath.
// File names use prefix + data key (for envFrom-style prefixes).
// When exportEnv is true, also writes load-env.sh for optional runtime env export.
func Write(
	ctx context.Context,
	c client.Client,
	keyResolver KeyResolver,
	namespace, secretName, mountPath, prefix string,
	exportEnv bool,
) error {
	tsecret := &v1alpha1.TSecret{}
	if err := c.Get(ctx, client.ObjectKey{Name: secretName, Namespace: namespace}, tsecret); err != nil {
		return fmt.Errorf("get TSecret %s/%s: %w", namespace, secretName, err)
	}

	key, err := keyResolver.ResolveKey(ctx, tsecret.Spec.EncryptionRef, namespace)
	if err != nil {
		return fmt.Errorf("resolve encryption key: %w", err)
	}

	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		return fmt.Errorf("create mount path: %w", err)
	}

	fileNames := make([]string, 0, len(tsecret.Spec.Data))
	for dataKey, entry := range tsecret.Spec.Data {
		plaintext, err := crypto.Decrypt(entry.Value, key)
		if err != nil {
			return fmt.Errorf("decrypt key %q: %w", dataKey, err)
		}

		fileName := prefix + dataKey
		fileNames = append(fileNames, fileName)
		target := filepath.Join(mountPath, fileName)
		if err := os.WriteFile(target, plaintext, 0o400); err != nil {
			return fmt.Errorf("write file %q: %w", target, err)
		}
	}

	if exportEnv {
		if err := WriteEnvLoader(mountPath, fileNames); err != nil {
			return err
		}
	}

	return nil
}

// WriteEnvLoader creates load-env.sh that exports each key from its file (no literals).
func WriteEnvLoader(mountPath string, envNames []string) error {
	sort.Strings(envNames)

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, name := range envNames {
		fmt.Fprintf(&b, "export %s=\"$(cat %s/%s)\"\n", name, mountPath, name)
	}

	target := filepath.Join(mountPath, "load-env.sh")
	if err := os.WriteFile(target, []byte(b.String()), 0o500); err != nil {
		return fmt.Errorf("write load-env.sh: %w", err)
	}
	return nil
}
