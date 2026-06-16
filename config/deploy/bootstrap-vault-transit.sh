#!/usr/bin/env bash
# Bootstrap Vault Transit envelope encryption for TSecret (lab).
# Creates Transit KEK, wraps a random DEK, stores only ciphertext in tsecret-system.
set -euo pipefail

VAULT_NS="${VAULT_NS:-vault}"
VAULT_POD="${VAULT_POD:-vault-0}"
TSECRET_NS="${TSECRET_NS:-tsecret-system}"
TRANSIT_KEY="${TRANSIT_KEY:-tsecret-kek}"
WRAPPED_SECRET="${WRAPPED_SECRET:-tsecret-wrapped-dek}"

vault_exec() {
  kubectl exec -n "$VAULT_NS" "$VAULT_POD" -- vault "$@"
}

echo "Enabling Vault Transit engine..."
vault_exec login root >/dev/null
vault_exec secrets enable transit 2>/dev/null || true
vault_exec write -f "transit/keys/${TRANSIT_KEY}" >/dev/null

echo "Generating DEK and wrapping with Transit key ${TRANSIT_KEY}..."
DEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
CIPHERTEXT="$(vault_exec write -format=json "transit/encrypt/${TRANSIT_KEY}" "plaintext=${DEK_B64}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["ciphertext"])')"

kubectl create namespace "$TSECRET_NS" --dry-run=client -o yaml | kubectl apply -f -

echo "Creating Secret ${TSECRET_NS}/${WRAPPED_SECRET} (ciphertext only)..."
kubectl create secret generic "$WRAPPED_SECRET" \
  --from-literal=ciphertext="$CIPHERTEXT" \
  -n "$TSECRET_NS" --dry-run=client -o yaml | kubectl apply -f -

cat <<EOF

Done.
  Transit KEK : ${TRANSIT_KEY}
  Wrapped DEK : ${TSECRET_NS}/${WRAPPED_SECRET} (key: ciphertext)

Apply the Vault Transit sync sample:
  kubectl apply -f config/samples/tsecretsync-vault-transit.yaml
  kubectl apply -f config/samples/tsecret-workload-rbac-transit.yaml

EOF
