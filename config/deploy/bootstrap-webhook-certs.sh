#!/usr/bin/env bash
# Bootstrap TLS certificates for the TSecret mutating webhook.
# Run once before applying config/deploy/deployment.yaml.
set -euo pipefail

NAMESPACE="${NAMESPACE:-tsecret-system}"
SERVICE="${SERVICE:-tsecret-webhook}"
WEBHOOK_CONFIG="${WEBHOOK_CONFIG:-tsecret-mutating-webhook}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

echo "Generating CA..."
openssl ecparam -name secp384r1 -genkey -noout -out "$TMPDIR/ca.key"
openssl req -x509 -new -key "$TMPDIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=TSecret CA/O=TSecret" -out "$TMPDIR/ca.crt"

echo "Creating Secret ${NAMESPACE}/tsecret-ca..."
kubectl create secret tls tsecret-ca \
  --cert="$TMPDIR/ca.crt" --key="$TMPDIR/ca.key" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

echo "Generating serving certificate..."
openssl ecparam -name secp384r1 -genkey -noout -out "$TMPDIR/tls.key"
openssl req -new -key "$TMPDIR/tls.key" \
  -subj "/CN=${SERVICE}.${NAMESPACE}.svc/O=TSecret" \
  -out "$TMPDIR/tls.csr"

cat > "$TMPDIR/san.cnf" <<EOF
subjectAltName = DNS:${SERVICE},DNS:${SERVICE}.${NAMESPACE},DNS:${SERVICE}.${NAMESPACE}.svc,DNS:${SERVICE}.${NAMESPACE}.svc.cluster.local
EOF

openssl x509 -req -in "$TMPDIR/tls.csr" -CA "$TMPDIR/ca.crt" -CAkey "$TMPDIR/ca.key" \
  -CAcreateserial -out "$TMPDIR/tls.crt" -days 365 -sha256 \
  -extfile "$TMPDIR/san.cnf"

echo "Creating Secret ${NAMESPACE}/tsecret-webhook-certs..."
kubectl create secret tls tsecret-webhook-certs \
  --cert="$TMPDIR/tls.crt" --key="$TMPDIR/tls.key" \
  -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if kubectl get mutatingwebhookconfiguration "$WEBHOOK_CONFIG" >/dev/null 2>&1; then
  echo "Patching MutatingWebhookConfiguration ${WEBHOOK_CONFIG} with CA bundle..."
  if base64 --help 2>&1 | grep -q wrap; then
    CA_BUNDLE="$(base64 -w0 "$TMPDIR/ca.crt")"
  else
    CA_BUNDLE="$(base64 < "$TMPDIR/ca.crt" | tr -d '\n')"
  fi
  kubectl patch mutatingwebhookconfiguration "$WEBHOOK_CONFIG" \
    --type='json' \
    -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${CA_BUNDLE}\"}]"
else
  echo "MutatingWebhookConfiguration ${WEBHOOK_CONFIG} not found — apply config/deploy/webhook.yaml first, then re-run this script."
  exit 1
fi

echo "Done. Secrets tsecret-ca and tsecret-webhook-certs are ready in ${NAMESPACE}."
