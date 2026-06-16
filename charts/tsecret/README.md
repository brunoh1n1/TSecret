# TSecret Helm Chart

Helm chart for the [TSecret](https://github.com/brunoh1n1/TSecret) Kubernetes operator — encrypted secrets at rest, external store sync, and runtime injection via mutating webhook.

> **API `v1alpha1`** — intended for lab and early adopters. Pin chart versions in production.

## What this chart installs

| Component | Always | Notes |
|-----------|--------|-------|
| CRDs (`TSecret`, `TSecretStore`, `ClusterTSecretStore`, `TSecretSync`) | Yes | `crds/` folder |
| Operator Deployment + RBAC | Yes | 2 replicas, leader election |
| Mutating webhook + Service | Yes | TLS auto-managed by operator |
| HashiCorp Vault | **No** | Use your own Vault or lab install (below) |
| External Secrets Operator | **No** | Optional integration for Vault token sync |

## Quick install (operator only)

```bash
helm repo add tsecret https://brunoh1n1.github.io/TSecret
helm repo update

helm upgrade --install tsecret tsecret/tsecret \
  --namespace tsecret-system \
  --create-namespace \
  --set injection.enabled=true \
  --set 'injection.namespaces={default}'
```

Install from local checkout:

```bash
helm upgrade --install tsecret ./charts/tsecret -n tsecret-system --create-namespace
```

## Vault — use existing or install for PoC

**This chart does not bundle Vault.** If you already run Vault (in-cluster or external), configure `TSecretStore` with your server URL and credentials.

### Option A — Existing Vault (recommended)

```yaml
# values snippet when using poc.demo
poc:
  enabled: true
  vault:
    existing:
      address: "https://vault.prod.example.com:8200"
      kvMount: secret
    auth:
      method: existingSecret
      existingSecret:
        name: vault-token
        key: token
        namespace: my-app
```

Create the token Secret yourself (or via your secret management process) with a Vault policy scoped to KV read + Transit decrypt.

### Option B — Lab Vault (install separately)

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install vault hashicorp/vault -n vault --create-namespace \
  --set "server.dev.enabled=true" \
  --set "server.dev.devRootToken=root" \
  --set "injector.enabled=false" \
  --wait --timeout 5m
```

Then enable PoC resources in TSecret:

```bash
helm upgrade --install tsecret tsecret/tsecret -n tsecret-system --create-namespace \
  --set poc.enabled=true \
  --set poc.vault.existing.address="http://vault.vault.svc.cluster.local:8200" \
  --set poc.vault.existing.namespace=vault \
  --set poc.vault.existing.pod=vault-0 \
  --set poc.vault.auth.method=direct \
  --set poc.vault.auth.token=root \
  --set poc.encryption.mode=vault-transit
```

Bootstrap jobs (KV v2 + Transit wrapped DEK) run as Helm post-install hooks.

## External Secrets — optional PoC integration

**This chart does not install External Secrets Operator.** Use it when you already sync Vault credentials via ESO.

### Install ESO (lab only, separate release)

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm upgrade --install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace
```

### Let TSecret chart create ExternalSecret for `vault-token`

```bash
helm upgrade --install tsecret ./charts/tsecret -n tsecret-system --create-namespace \
  --set poc.enabled=true \
  --set poc.vault.auth.method=externalSecret \
  --set poc.externalSecrets.enabled=true \
  --set poc.externalSecrets.createClusterSecretStore=true
```

You must still provide a bootstrap `vault-token` Secret for the ClusterSecretStore auth ref (lab), or adjust `poc.externalSecrets.vault.tokenSecretRef` to match your ESO auth pattern.

## Encryption modes (PoC)

| Mode | `poc.encryption.mode` | Master key in app namespace |
|------|------------------------|------------------------------|
| Vault Transit (recommended) | `vault-transit` | No — only wrapped DEK in `tsecret-system` |
| Sealed secret (lab only) | `sealed-secret` | Yes — `tsecret-master-key` |

## Values reference

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/brunoh1n1/tsecret` | Operator image |
| `image.tag` | Chart `appVersion` | Image tag |
| `namespace` | `tsecret-system` | Operator namespace |
| `replicaCount` | `2` | Operator replicas |
| `webhook.enabled` | `true` | Mutating webhook |
| `injection.enabled` | `false` | Create labeled namespaces |
| `injection.namespaces` | `[]` | Namespaces with `tsecret.io/inject=enabled` |
| `poc.enabled` | `false` | Lab demo stack |
| `poc.encryption.mode` | `vault-transit` | `vault-transit` or `sealed-secret` |
| `poc.vault.existing.address` | in-cluster dev URL | Vault API URL |
| `poc.vault.auth.method` | `direct` | `direct`, `existingSecret`, `externalSecret` |
| `poc.externalSecrets.enabled` | `false` | Render ExternalSecret (requires ESO) |
| `poc.demo.enabled` | `true` | TSecretStore + TSecretSync |
| `poc.sampleApp.enabled` | `true` | busybox `my-app` deployment |

## Uninstall

```bash
helm uninstall tsecret -n tsecret-system
```

CRDs are not removed automatically (Helm behaviour). To remove:

```bash
kubectl delete crd tsecrets.tsecret.io tsecretstores.tsecret.io \
  clustertsecretstores.tsecret.io tsecretsyncs.tsecret.io
```

## Artifact Hub

Published from GitHub Pages: `https://brunoh1n1.github.io/TSecret`

## License

Apache 2.0 — see [LICENSE](https://github.com/brunoh1n1/TSecret/blob/main/LICENSE).
