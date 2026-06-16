## TSecret v0.1.3 — Alpha

Release com **Vault Transit envelope encryption**: a chave de dados (DEK) **não fica mais em plaintext** no cluster. Validado end-to-end em laboratório (Vault KV v2 + Transit + `my-app`).

> API `v1alpha1` — pode mudar entre versões menores. Use em ambientes de teste/lab até estabilização.

---

## O que é

Operador Kubernetes para secrets **criptografados em repouso**, sync de cofre externo e **injeção em runtime** sem gravar valores decriptados no spec do Pod.

Licença: **Apache 2.0**

---

## Novidades nesta release

### Vault Transit — envelope encryption (principal)

**Problema resolvido:** no modo `sealed-secret`, a `tsecret-master-key` ficava no namespace da app — devs com `get secrets` podiam ler a chave mestra e decriptar todos os `TSecret` do namespace.

**Solução:** provider `vault-transit` com envelope encryption:

| Camada | Onde vive | No cluster |
|--------|-----------|------------|
| **KEK** | Vault Transit (`tsecret-kek`) | Nunca exportada |
| **DEK** | 32 bytes, usada para XChaCha20 | Apenas embrulhada: `vault:v1:...` |
| **Valores** | CRD `TSecret` | Ciphertext `tsecret:xchacha20-poly1305:...` |

**Fluxo:**

1. `bootstrap-vault-transit.sh` — habilita Transit, cria KEK, gera DEK, grava `tsecret-system/tsecret-wrapped-dek`
2. `TSecretSync` com `spec.encryptionRef.provider: vault-transit` — sync do Vault KV → cifra com DEK
3. Init `/tsecret-inject` — chama `transit/decrypt`, decripta `TSecret`, escreve tmpfs

**Arquivos novos:**

| Arquivo | Função |
|---------|--------|
| [`config/deploy/bootstrap-vault-transit.sh`](config/deploy/bootstrap-vault-transit.sh) | Bootstrap Transit + DEK embrulhada |
| [`config/samples/tsecretsync-vault-transit.yaml`](config/samples/tsecretsync-vault-transit.yaml) | Sync com `encryptionRef` Transit |
| [`config/samples/tsecret-workload-rbac-transit.yaml`](config/samples/tsecret-workload-rbac-transit.yaml) | RBAC cross-namespace (wrapped DEK) |
| [`pkg/providers/vault_transit.go`](pkg/providers/vault_transit.go) | API Transit encrypt/decrypt |
| [`pkg/webhook/keyresolver.go`](pkg/webhook/keyresolver.go) | Resolver `vault-transit` |

**API:**

```yaml
spec:
  encryptionRef:
    provider: vault-transit
    name: tsecret-kek
    vaultTransit:
      storeRef:
        name: vault-backend
        kind: TSecretStore
      wrappedKeySecret:
        name: tsecret-wrapped-dek
        key: ciphertext
        namespace: tsecret-system
```

`TSecretSync.spec.encryptionRef` — configurável; default continua `sealed-secret` para compatibilidade.

### CRDs atualizados

- `TSecret.spec.encryptionRef.vaultTransit` — `storeRef` + `wrappedKeySecret`
- `TSecretSync.spec.encryptionRef` — opcional, sobrescreve default do sync

---

## Comparação de modos

| | `sealed-secret` (lab) | `vault-transit` (produção) |
|--|-------------------------|----------------------------|
| Master key plaintext | Sim (`tsecret-master-key`) | **Não** |
| Secret no cluster | `encryption-key` (32 bytes) | `ciphertext` (`vault:v1:...`) |
| Dev com `get secrets` no app ns | Vê a chave | **Não vê** a DEK |
| Bootstrap | `kubectl create secret` | `bootstrap-vault-transit.sh` |
| Sample sync | `tsecretsync.yaml` | `tsecretsync-vault-transit.yaml` |
| RBAC workload | `tsecret-workload-rbac.yaml` | `tsecret-workload-rbac-transit.yaml` |

---

## O que funciona nesta release

- Tudo da v0.1.2 (webhook bootstrap, samples my-app, CLI encrypt, docs)
- **Vault Transit** encrypt/decrypt via API
- **KeyResolver** `vault-transit` no operador e no init container
- **TSecretSync** com `encryptionRef` configurável
- **E2E validado:** Vault dev → Transit → TSecretSync → my-app

---

## Instalação rápida (Vault Transit)

```bash
# Operador
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/crd/
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/deploy/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/deploy/webhook.yaml
curl -fsSL https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/deploy/bootstrap-webhook-certs.sh | bash
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/deploy/deployment.yaml

kubectl label namespace default tsecret.io/inject=enabled --overwrite

# Vault + Transit + app
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/samples/vault-token.yaml
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/samples/tsecretstore-vault.yaml
curl -fsSL https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/deploy/bootstrap-vault-transit.sh | bash
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/samples/tsecretsync-vault-transit.yaml
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/samples/tsecret-workload-rbac-transit.yaml
kubectl apply -f https://raw.githubusercontent.com/brunoh1n1/TSecret/v0.1.3/config/samples/my-app-deploy.yaml
```

Validar:

```bash
kubectl get tsecretsync db-pass-sync -n default          # Synced
kubectl get tsecret db-credentials -n default            # Ready=True
kubectl get secret tsecret-master-key -n default         # NotFound (esperado)
kubectl exec deploy/my-app -c app -- cat /var/run/tsecret/db-credentials/DB_PASSWORD
```

---

## Limitações

- Token Vault (`vault-token`) ainda necessário para Transit unwrap — restrinja com policy Vault
- AWS/Azure/GCP KMS como `encryptionRef` — não implementados nesta release
- Rotação automática de DEK/KEK — planejada
- Vault auth: apenas `tokenSecretRef`

---

## Links

- [README](https://github.com/brunoh1n1/TSecret/blob/main/README.md)
- [LICENSE (Apache 2.0)](https://github.com/brunoh1n1/TSecret/blob/main/LICENSE)

**Full Changelog:** https://github.com/brunoh1n1/TSecret/compare/v0.1.2...v0.1.3
