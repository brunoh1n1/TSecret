// encrypt generates TSecret ciphertext values using the cluster master key or a local key.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/brunoh1n1/tsecret/pkg/crypto"
)

func main() {
	var (
		keyFile string
		keyB64  string
		algo    string
	)
	flag.StringVar(&keyFile, "key-file", "", "Path to raw 32-byte key file")
	flag.StringVar(&keyB64, "key-b64", "", "Base64-encoded 32-byte key")
	flag.StringVar(&algo, "algorithm", crypto.AlgorithmXChaCha20Poly, "Encryption algorithm")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: encrypt [flags] key=value [key=value ...]")
		os.Exit(2)
	}

	key, err := loadKey(keyFile, keyB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, arg := range flag.Args() {
		name, value, ok := splitPair(arg)
		if !ok {
			fmt.Fprintf(os.Stderr, "invalid pair %q, expected key=value\n", arg)
			os.Exit(2)
		}
		enc, err := crypto.Encrypt([]byte(value), key, algo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encrypt %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("%s=%s\n", name, enc)
	}
}

func loadKey(keyFile, keyB64 string) ([]byte, error) {
	switch {
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		if len(data) != crypto.KeySize {
			return nil, fmt.Errorf("key-file must be %d bytes, got %d", crypto.KeySize, len(data))
		}
		return data, nil
	case keyB64 != "":
		data, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, err
		}
		if len(data) != crypto.KeySize {
			return nil, fmt.Errorf("key-b64 must decode to %d bytes, got %d", crypto.KeySize, len(data))
		}
		return data, nil
	default:
		return nil, fmt.Errorf("provide -key-file or -key-b64")
	}
}

func splitPair(arg string) (string, string, bool) {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[:i], arg[i+1:], true
		}
	}
	return "", "", false
}
