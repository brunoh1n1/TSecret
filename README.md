# TSecret (True Secret)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Operador Kubernetes para gerenciamento de secrets com **criptografia real em repouso**, sincronização opcional a cofres externos e **injeção em runtime** via webhook + init container — sem gravar valores decriptados no spec do Pod.

> **Status:** `v1alpha1` — projeto em estágio inicial. Cofre externo **validado em laboratório apenas com HashiCorp Vault**. Providers AWS, Azure, GCP e Oracle existem no código, mas **não foram testados end-to-end** neste repositório.

---

## O problema

| Situação | Limitação |
|----------|-----------|
| `Secret` nativo do Kubernetes | Valor é apenas base64 no etcd; quem tem RBAC de leitura vê o conteúdo |
| External Secrets Operator | Materializa `Secret` Kubernetes em plaintext no cluster |
| Criptografia no app | Cada aplicação precisa implementar decriptação, rotação e bootstrap de chaves |
| Injeção via env no spec | Valores decriptados ficam persistidos no objeto Pod (etcd, backups, audit logs) |

## O que o TSecret resolve

1. **Armazena secrets criptografados** no CRD `TSecret` (XChaCha20-Poly1305 / ChaCha20-Poly1305).
2. **Sincroniza de cofres externos** (`TSecretSync` → `TSecret`) sem criar `Secret` Kubernetes nativo.
3. **Injeta no Pod em runtime** via init container (`/tsecret-inject`): arquivos em **tmpfs (memória)**, não no `spec.containers[].env`.
4. **Export opcional de env** via annotations — carrega variáveis no processo sem persistir valores no spec.

---

## Fluxo end-to-end

```mermaid
flowchart TB
    subgraph External["Cofre externo (Vault — testado)"]
        V[(KV v2<br/>secret/db-pass)]
    end

    subgraph Operator["TSecret Operator — tsecret-system"]
        SC[TSecretSync Controller]
        ST[TSecretStore Controller]
        TC[TSecret Controller]
        WH[Mutating Webhook]
    end

    subgraph Cluster["Namespace da aplicação"]
        TS[(TSecret CRD<br/>valores criptografados)]
        MK[(Secret<br/>tsecret-master-key)]
        POD[Pod / Deployment]
        INIT[Init: /tsecret-inject]
        TMPFS[(tmpfs emptyDir<br/>/var/run/tsecret/...)]
        APP[Container da app]
    end

    V -->|pull + auth token| SC
    SC -->|encrypt + write| TS
    ST -->|health check| V
    MK -->|unwrap key| SC

    POD -->|CREATE| WH
    WH -->|emptyDir + init + mounts<br/>sem plaintext no spec| POD
    POD --> INIT
    INIT -->|GET TSecret + decrypt| TS
    INIT -->|GET master key| MK
    INIT -->|WriteFile 0400| TMPFS
    TMPFS --> APP
    APP -->|read files ou<br/>export-env opcional| APP
```

### Injeção no Pod (detalhe)

```mermaid
sequenceDiagram
    participant U as Usuário
    participant API as API Server
    participant WH as TSecret Webhook
    participant IC as Init tsecret-inject
    participant TS as TSecret CRD
    participant C as Container app

    U->>API: kubectl apply Pod/Deployment
    API->>WH: AdmissionReview
    WH->>WH: secret volume → emptyDir tmpfs<br/>adiciona init + volumeMount
    WH-->>API: Pod mutado (sem env plaintext)
    API->>IC: Init container start
    IC->>TS: GET + decrypt
    IC->>IC: escreve arquivos + load-env.sh opcional
    IC-->>C: Init complete
    C->>C: lê /var/run/tsecret/... ou source load-env.sh
```

---

## Árvore de recursos

```
Cluster
├── CRDs (cluster-scoped definitions)
│   ├── tsecrets.tsecret.io
│   ├── tsecretstores.tsecret.io
│   ├── clustertsecretstores.tsecret.io
│   └── tsecretsyncs.tsecret.io
│
├── Namespace: tsecret-system
│   ├── Deployment: tsecret-operator
│   ├── Service: tsecret-webhook
│   ├── ServiceAccount + ClusterRole(Binding)
│   ├── Secret: tsecret-webhook-certs
│   ├── Secret: tsecret-ca
│   └── MutatingWebhookConfiguration
│       └── namespaceSelector: tsecret.io/inject=enabled
│
└── Namespace: <app>  (ex.: default, tsecret-test)
    ├── Label no Namespace: tsecret.io/inject=enabled
    │
    ├── Secret: tsecret-master-key          ← chave simétrica (32 bytes)
    │
    ├── TSecretStore: vault-backend         ← conexão Vault (testado)
    │   └── auth.tokenSecretRef → vault-token
    │
    ├── TSecretSync: db-pass-sync           ← Vault → TSecret
    │   └── target → TSecret abaixo
    │
    ├── TSecret: db-credentials             ← dados criptografados no etcd
    │   └── spec.data.*.value (ciphertext)
    │
    ├── ServiceAccount: tsecret-workload    ← RBAC get tsecrets + secrets
    ├── Role + RoleBinding
    │
    └── Deployment/Pod
        ├── volume: secret → mutado p/ emptyDir (Memory)
        ├── initContainer: tsecret-init-*  → /tsecret-inject
        └── container: volumeMount /var/run/tsecret/<nome>/
            └── arquivos: DB_PASSWORD, DB_PASSWORD2, load-env.sh (opcional)
```

---

## CRDs

| CRD | Escopo | Função |
|-----|--------|--------|
| `TSecret` | Namespace | Armazena pares chave→valor **criptografados** |
| `TSecretStore` | Namespace | Configura provider de cofre externo + health check |
| `ClusterTSecretStore` | Cluster | Mesmo que `TSecretStore`, visível cluster-wide |
| `TSecretSync` | Namespace | Puxa secrets do cofre → criptografa → grava/atualiza `TSecret` |

### Formato do ciphertext (`TSecret`)

```
tsecret:<algorithm>:<nonce_b64>:<ciphertext_b64>
```

Algoritmos suportados: `xchacha20-poly1305` (recomendado), `chacha20-poly1305`. AES **não** é suportado (risco de side-channel sem AES-NI).

---

## Componentes do operador

| Componente | Responsabilidade |
|------------|------------------|
| `TSecretReconciler` | Valida formato criptografado; status `Ready` |
| `TSecretStoreReconciler` | Health check periódico do provider |
| `TSecretSyncReconciler` | Sync cofre → `TSecret` (all-or-nothing por reconcile) |
| **Mutating Webhook** | Estrutura o Pod: tmpfs + init; **não decripta** |
| **`/tsecret-inject`** | Init container: decripta em runtime e escreve arquivos |
| **CertManager** | TLS auto-assinado para webhook (estilo Kyverno) |

---

## Início rápido

Fluxo completo **my-app** (namespace `default`):

| Passo | O que faz | README | Manifest / comando |
|-------|-----------|--------|-------------------|
| 1 | CRDs + RBAC operador + webhook + label namespace | §1 | `config/crd/`, `config/deploy/rbac.yaml`, `config/deploy/webhook.yaml` |
| 2 | Certificados TLS + operador | §2 | `config/deploy/bootstrap-webhook-certs.sh`, `config/deploy/deployment.yaml` |
| 3 | Master key | §3 | `kubectl create secret generic tsecret-master-key ...` |
| 4 | Vault in-cluster + secrets KV | §4 | `helm install vault ...` + `vault kv put ...` |
| 5 | Token Vault + TSecretStore + TSecretSync | §5 | `vault-token.yaml`, `tsecretstore-vault.yaml`, `tsecretsync.yaml` |
| 6 | RBAC do workload | §6 | `config/samples/tsecret-workload-rbac.yaml` |
| 7 | Deployment my-app | §7 | `config/samples/my-app-deploy.yaml` |

Resumo em um bloco (após Vault e master key prontos):

```bash
kubectl label namespace default tsecret.io/inject=enabled --overwrite
kubectl apply -f config/crd/
kubectl apply -f config/deploy/rbac.yaml
kubectl apply -f config/deploy/webhook.yaml
bash config/deploy/bootstrap-webhook-certs.sh
kubectl apply -f config/deploy/deployment.yaml
KEY=$(openssl rand -base64 32 | head -c 32)
kubectl create secret generic tsecret-master-key \
  --from-literal=encryption-key="$KEY" -n default --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f config/samples/vault-token.yaml
kubectl apply -f config/samples/tsecretstore-vault.yaml
kubectl apply -f config/samples/tsecretsync.yaml
kubectl apply -f config/samples/tsecret-workload-rbac.yaml
kubectl apply -f config/samples/my-app-deploy.yaml
```

---

### 1. Instalar CRDs, RBAC e webhook

```bash
kubectl apply -f config/crd/
kubectl apply -f config/deploy/rbac.yaml
kubectl apply -f config/deploy/webhook.yaml
```

### 2. Certificados TLS do webhook (bootstrap obrigatório)

O Deployment monta o Secret `tsecret-webhook-certs` **antes** do container iniciar. O operador gerencia e renova esses certificados em runtime, mas na **primeira instalação** eles precisam existir com antecedência — caso contrário o Pod fica em `FailedMount`:

```
MountVolume.SetUp failed for volume "webhook-certs" : secret "tsecret-webhook-certs" not found
```

Gere a CA, o certificado de serving e aplique no cluster:

```bash
bash config/deploy/bootstrap-webhook-certs.sh
```

O script cria:

| Recurso | Conteúdo |
|---------|----------|
| Secret `tsecret-ca` | CA autoassinada (10 anos) |
| Secret `tsecret-webhook-certs` | Certificado TLS do webhook (1 ano) |
| `MutatingWebhookConfiguration` | Campo `caBundle` atualizado com a CA |

Equivalente manual (sem o script):

```bash
NAMESPACE=tsecret-system
SERVICE=tsecret-webhook
TMPDIR=$(mktemp -d)

# CA
openssl ecparam -name secp384r1 -genkey -noout -out "$TMPDIR/ca.key"
openssl req -x509 -new -key "$TMPDIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=TSecret CA/O=TSecret" -out "$TMPDIR/ca.crt"

kubectl create secret tls tsecret-ca \
  --cert="$TMPDIR/ca.crt" --key="$TMPDIR/ca.key" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Serving cert (SANs do Service tsecret-webhook)
openssl ecparam -name secp384r1 -genkey -noout -out "$TMPDIR/tls.key"
openssl req -new -key "$TMPDIR/tls.key" \
  -subj "/CN=${SERVICE}.${NAMESPACE}.svc/O=TSecret" -out "$TMPDIR/tls.csr"

cat > "$TMPDIR/san.cnf" <<EOF
subjectAltName = DNS:${SERVICE},DNS:${SERVICE}.${NAMESPACE},DNS:${SERVICE}.${NAMESPACE}.svc,DNS:${SERVICE}.${NAMESPACE}.svc.cluster.local
EOF

openssl x509 -req -in "$TMPDIR/tls.csr" -CA "$TMPDIR/ca.crt" -CAkey "$TMPDIR/ca.key" \
  -CAcreateserial -out "$TMPDIR/tls.crt" -days 365 -sha256 -extfile "$TMPDIR/san.cnf"

kubectl create secret tls tsecret-webhook-certs \
  --cert="$TMPDIR/tls.crt" --key="$TMPDIR/tls.key" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# CA bundle no webhook (API server precisa confiar no certificado de serving)
CA_BUNDLE=$(base64 -w0 "$TMPDIR/ca.crt" 2>/dev/null || base64 < "$TMPDIR/ca.crt" | tr -d '\n')
kubectl patch mutatingwebhookconfiguration tsecret-mutating-webhook \
  --type='json' \
  -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${CA_BUNDLE}\"}]"

rm -rf "$TMPDIR"
```

Depois dos certificados, suba o operador:

```bash
kubectl apply -f config/deploy/deployment.yaml
kubectl rollout status deployment/tsecret-operator -n tsecret-system
```

Habilitar injeção no namespace da app:

```bash
kubectl label namespace default tsecret.io/inject=enabled --overwrite
```

### 3. Master key (bootstrap)

```bash
KEY=$(openssl rand -base64 32 | head -c 32)
kubectl create secret generic tsecret-master-key \
  --from-literal=encryption-key="$KEY" \
  -n default
```

### 4. Vault in-cluster (laboratório)

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update hashicorp

kubectl create namespace vault
helm upgrade --install vault hashicorp/vault -n vault \
  --set "server.dev.enabled=true" \
  --set "server.dev.devRootToken=root" \
  --set "injector.enabled=false" \
  --wait --timeout 5m

# Habilitar KV v2 no mount secret (dev mode vem com KV v1 por padrão)
kubectl exec -n vault vault-0 -- vault login root
kubectl exec -n vault vault-0 -- vault secrets disable secret
kubectl exec -n vault vault-0 -- vault secrets enable -path=secret kv-v2

# Secrets de teste para o my-app
kubectl exec -n vault vault-0 -- vault kv put secret/db-pass value='minha-senha'
kubectl exec -n vault vault-0 -- vault kv put secret/db-pass2 value='outra-senha'
```

> O operador monta o path interno como `{path}/data/{key}` → `secret/data/db-pass`.

### 5. TSecretStore + TSecretSync

```bash
kubectl apply -f config/samples/vault-token.yaml
kubectl apply -f config/samples/tsecretstore-vault.yaml
kubectl apply -f config/samples/tsecretsync.yaml
```

Manifests: [`config/samples/vault-token.yaml`](config/samples/vault-token.yaml), [`config/samples/tsecretstore-vault.yaml`](config/samples/tsecretstore-vault.yaml), [`config/samples/tsecretsync.yaml`](config/samples/tsecretsync.yaml)

O operador **cria e atualiza o TSecret automaticamente** — você não precisa aplicar `config/samples/tsecret.yaml` nesse fluxo:

```bash
kubectl get tsecretsync db-pass-sync -n default
kubectl get tsecret db-credentials -n default
# STATUS: Synced / Ready=True
```

### 6. RBAC do workload

O init container lê o `TSecret` (criado pelo sync) e `tsecret-master-key` com o ServiceAccount do Pod:

```bash
kubectl apply -f config/samples/tsecret-workload-rbac.yaml
```

### 7. Usar no Deployment (recomendado: volume)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
  labels:
    app: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      serviceAccountName: tsecret-workload
      containers:
        - name: app
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -c
            - cat /var/run/tsecret/db-credentials/DB_PASSWORD && sleep 3600
          volumeMounts:
            - name: db-credentials
              mountPath: /var/run/tsecret/db-credentials
              readOnly: true
      volumes:
        - name: db-credentials
          secret:
            secretName: db-credentials   # TSecret criado pelo TSecretSync
```

Leitura no container:

```bash
kubectl exec deploy/my-app -c app -- cat /var/run/tsecret/db-credentials/DB_PASSWORD
```

```bash
kubectl apply -f config/samples/my-app-deploy.yaml
```

Manifest completo: [`config/samples/my-app-deploy.yaml`](config/samples/my-app-deploy.yaml)

---

## Export opcional de variáveis de ambiente

Por padrão, valores **não** aparecem em `spec.containers[].env`. Para exportar env **no runtime** (sem plaintext no spec):

```yaml
metadata:
  annotations:
    tsecret.io/export-env: "true"                    # ou tsecret.io/export-env.app
    tsecret.io/entrypoint.app: sh -c 'exec /app/run.sh'
```

O init grava `load-env.sh`; o webhook encapsula o entrypoint:

```sh
set -a; . /var/run/tsecret/db-credentials/load-env.sh; set +a; exec <entrypoint>
```

| Annotation | Escopo | Descrição |
|------------|--------|-----------|
| `tsecret.io/export-env` | Pod | Habilita export em containers com TSecret |
| `tsecret.io/export-env.<container>` | Container | Export só naquele container |
| `tsecret.io/entrypoint` | Pod | Comando após carregar env |
| `tsecret.io/entrypoint.<container>` | Container | Entrypoint específico |

**Atenção:** apps que fazem `exec` e substituem o processo principal podem **não** exibir env em `/proc/1/environ`. Nesses casos, prefira leitura por arquivo ou `source load-env.sh`.

Exemplo com export env: [`config/samples/my-app-deploy-export-env.yaml`](config/samples/my-app-deploy-export-env.yaml)

---

## Referências suportadas no Pod

| Referência no YAML | Comportamento |
|--------------------|---------------|
| `volumes[].secret.secretName` | **Recomendado** — tmpfs + arquivos |
| `envFrom.secretRef` | Convertido para volume + mount |
| `env.valueFrom.secretKeyRef` | Convertido para volume + mount |

Todas exigem que o nome aponte para um **TSecret** no mesmo namespace.

---

## Pontos de atenção

### Segurança

- **Master key** (`tsecret-master-key`): quem controla essa Secret controla todos os TSecrets do namespace. Proteja e rotacione com processo formal.
- **Valores decriptados** existem em **tmpfs** dentro do Pod em execução — visíveis a quem tem `exec` no container ou acesso ao nó (threat model padrão de secrets em memória).
- **Spec do Pod permanece limpo** — sem senhas em `env` nem scripts com literals no init; decriptação ocorre só no processo `/tsecret-inject`.
- **`failurePolicy: Fail`** — se o webhook ou init falhar, o Pod **não sobe** (fail-closed).
- **Webhook por namespace** — só namespaces com `tsecret.io/inject=enabled` são mutados.
- **Sync all-or-nothing** — se uma chave falhar no Vault, **nenhuma** chave é atualizada no `TSecret` alvo.
- **Health check do Vault** usa `/v1/sys/health` (sem auth) — store pode aparecer `Available` mesmo com token inválido; falhas aparecem no `TSecretSync`.

### Operacional

- **Vault KV v2:** use `path: "secret"` (mount), não `secret/data`.
- **Token Vault:** operador lê `tokenSecretRef` no sync; configure RBAC do SA do Pod para o init ler `TSecret` + master key.
- **Imagem do inject:** variável `TSECRET_INJECTOR_IMAGE` no operador (default `tsecret:latest`); mesma imagem contém `/manager` e `/tsecret-inject`.
- **Providers não testados:** AWS, Azure, GCP, Oracle — use com cautela até validação em ambiente real.

### Limitações conhecidas (`v1alpha1`)

- Auth Vault: apenas `tokenSecretRef` implementado (Kubernetes auth / AppRole planejados).
- Sem Helm chart oficial; manifests em `config/deploy/`.
- Sem CLI `tsecret encrypt` (roadmap).
- Rotação automática de chaves não implementada.

---

## Estrutura do projeto

```
TSecret/
├── cmd/
│   ├── manager/main.go       # Operador + webhook
│   └── inject/main.go        # Init container (/tsecret-inject)
├── pkg/
│   ├── apis/v1alpha1/        # CRD types
│   ├── controller/           # Reconcilers
│   ├── crypto/               # Encrypt / Decrypt
│   ├── inject/               # Escrita runtime em tmpfs
│   ├── providers/            # Vault, AWS, Azure, GCP, Oracle
│   ├── webhook/              # Mutação estrutural do Pod
│   └── certs/                # TLS do webhook
├── config/
│   ├── crd/
│   ├── deploy/               # RBAC, Deployment, Webhook
│   └── samples/              # Exemplos Vault, my-app, RBAC workload
├── Dockerfile                # manager + tsecret-inject
├── Makefile
└── go.mod
```

---

## Build e deploy local

```bash
make docker-build IMG=tsecret:latest

# kind (exemplo)
kind load docker-image tsecret:latest
kubectl apply -f config/crd/
kubectl apply -f config/deploy/rbac.yaml
kubectl apply -f config/deploy/webhook.yaml
bash config/deploy/bootstrap-webhook-certs.sh
kubectl apply -f config/deploy/deployment.yaml
kubectl set env deployment/tsecret-operator -n tsecret-system \
  TSECRET_INJECTOR_IMAGE=tsecret:latest
```

Variante em outro namespace (`tsecret-test`): [`examples/lab/`](examples/lab/) — mesmos recursos, namespace diferente.

Variáveis do operador:

| Variável | Descrição |
|----------|-----------|
| `TSECRET_INJECTOR_IMAGE` | Imagem usada nos init containers |
| `POD_NAMESPACE` | Namespace do operador (downward API) |

---

## Roadmap

- [ ] Helm chart
- [ ] Rotação automática de chaves
- [ ] Métricas Prometheus
- [ ] CLI `tsecret encrypt`
- [ ] Vault Kubernetes auth / AppRole
- [ ] Testes E2E para AWS, Azure, GCP, Oracle
- [ ] Publicação GHCR (`ghcr.io/...`)

---

## Licença

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
