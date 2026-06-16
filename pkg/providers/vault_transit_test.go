package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultProviderTransitEncryptDecrypt(t *testing.T) {
	transitKey := "tsecret-kek"
	plaintext := []byte("01234567890123456789012345678901")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/encrypt/" + transitKey:
			var body struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode encrypt body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]string{
					"ciphertext": "vault:v1:" + body.Plaintext,
				},
			})
		case "/v1/transit/decrypt/" + transitKey:
			var body struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode decrypt body: %v", err)
			}
			plain := body.Ciphertext[len("vault:v1:"):]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]string{
					"plaintext": plain,
				},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := &VaultProvider{
		server: srv.URL,
		client: srv.Client(),
		token:  "test",
	}

	ciphertext, err := p.TransitEncrypt(context.Background(), transitKey, plaintext)
	if err != nil {
		t.Fatalf("TransitEncrypt: %v", err)
	}

	got, err := p.TransitDecrypt(context.Background(), transitKey, ciphertext)
	if err != nil {
		t.Fatalf("TransitDecrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}
