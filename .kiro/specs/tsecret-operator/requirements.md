# Requirements Document

## Introduction

TSecret (True Secret) é um operator Kubernetes que fornece gerenciamento seguro de secrets com criptografia em repouso. O operator disponibiliza CRDs para armazenar valores criptografados (TSecret), conectar-se a cofres externos (TSecretStore/ClusterTSecretStore), e sincronizar secrets de provedores externos (TSecretSync). A injeção de secrets nos pods é feita via mutating admission webhook, que descriptografa os valores apenas no momento da injeção em variáveis de ambiente ou volumes.

## Glossary

- **Operator**: Controlador Kubernetes customizado que gerencia o ciclo de vida dos CRDs do TSecret
- **TSecret**: Custom Resource Definition que armazena pares chave-valor criptografados, equivalente funcional ao Secret nativo do Kubernetes
- **TSecretStore**: Custom Resource Definition com escopo de namespace que aponta para um cofre externo de secrets
- **ClusterTSecretStore**: Custom Resource Definition com escopo de cluster que aponta para um cofre externo de secrets, acessível por qualquer namespace
- **TSecretSync**: Custom Resource Definition que define a sincronização entre um cofre externo e um TSecret local
- **Mutating_Admission_Webhook**: Componente que intercepta requisições de criação/atualização de Pods para injetar secrets descriptografadas
- **Encryption_Key**: Chave simétrica (AES-256-GCM ou ChaCha20-Poly1305) usada para criptografar e descriptografar valores no TSecret
- **Key_Provider**: Fonte da chave de criptografia — pode ser Sealed Secret (bootstrap), Cloud KMS (AWS/Azure/GCP), Vault Transit, ou chave derivada do cluster
- **Secret_Provider**: Serviço externo de cofre de secrets (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Oracle Vault, entre outros)
- **Controller_Runtime**: Framework Go para construção de operators Kubernetes (kubebuilder/controller-runtime)
- **tmpfs_Volume**: Volume em memória montado no pod para armazenar secrets descriptografadas sem persistência em disco

## Requirements

### Requirement 1: TSecret CRD

**User Story:** As a platform engineer, I want to store encrypted secret values in a Kubernetes custom resource, so that secrets are never stored in plaintext in etcd.

#### Acceptance Criteria

1. WHEN the Operator is deployed, THE Operator SHALL register the TSecret Custom Resource Definition in the Kubernetes API server before processing any TSecret resources
2. WHEN a TSecret resource is created or updated, THE Operator SHALL validate that every value in the data field is a base64-encoded ciphertext prefixed with the algorithm identifier (AES-256-GCM or ChaCha20-Poly1305) and a key reference, containing at minimum a nonce and authentication tag as defined by the respective algorithm
3. IF a TSecret resource is created or updated with any value that does not conform to the expected encrypted format, THEN THE Operator SHALL reject the resource with a validation error indicating which field failed and the expected format structure
4. THE TSecret CRD SHALL require a metadata field for each entry in the data field specifying the encryption algorithm (AES-256-GCM or ChaCha20-Poly1305) and a key reference of at most 253 characters conforming to Kubernetes naming conventions
5. WHEN a TSecret resource is deleted, THE Operator SHALL remove all associated decrypted material from pods that have received injected secrets from that TSecret within 30 seconds of the deletion event
6. IF the metadata field is missing or contains an unsupported algorithm identifier, THEN THE Operator SHALL reject the TSecret resource with a validation error indicating the invalid or missing metadata field

### Requirement 2: TSecretStore CRD

**User Story:** As a platform engineer, I want to configure a namespaced connection to an external secret vault, so that workloads in a specific namespace can access secrets from that vault.

#### Acceptance Criteria

1. WHEN the Operator is deployed, THE Operator SHALL register the TSecretStore Custom Resource Definition with namespace scope in the Kubernetes API server
2. WHEN a TSecretStore resource is created, THE Operator SHALL validate the connection configuration for the specified Secret_Provider within 30 seconds and set the resource status to "Available" if the connection is successfully established
3. IF a TSecretStore references an unreachable Secret_Provider or connection validation fails, THEN THE Operator SHALL set the resource status to "Unavailable" and emit a Kubernetes event indicating the connection failure reason
4. THE TSecretStore SHALL support configuration for HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, and Oracle Vault as Secret_Provider backends
5. WHEN a TSecretStore authentication credential expires, THE Operator SHALL attempt credential renewal up to 3 times with exponential backoff, set the resource status to "Available" on successful renewal, or set the resource status to "Unavailable" if all renewal attempts fail
6. WHEN a TSecretStore resource is updated, THE Operator SHALL re-validate the connection configuration for the specified Secret_Provider and update the resource status to "Available" or "Unavailable" based on the validation result

### Requirement 3: ClusterTSecretStore CRD

**User Story:** As a cluster administrator, I want to configure a cluster-wide connection to an external secret vault, so that workloads in any namespace can reference secrets from that vault without duplicating configuration.

#### Acceptance Criteria

1. WHEN the Operator is deployed, THE Operator SHALL register the ClusterTSecretStore Custom Resource Definition with cluster scope in the Kubernetes API server
2. WHEN a ClusterTSecretStore resource is created and the connection to the specified Secret_Provider is reachable within 30 seconds, THE Operator SHALL set the resource status to "Ready"
3. IF a ClusterTSecretStore resource is created and the connection configuration for the specified Secret_Provider fails validation, THEN THE Operator SHALL set the resource status to "Invalid" and emit a Kubernetes event indicating the validation failure reason
4. THE ClusterTSecretStore SHALL support the same Secret_Provider backends as TSecretStore (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Oracle Vault)
5. WHEN a TSecretSync in any namespace references a ClusterTSecretStore, THE Operator SHALL resolve the secret from the referenced Secret_Provider without requiring a namespace-scoped TSecretStore
6. WHEN the Operator detects that a ClusterTSecretStore's Secret_Provider is unreachable after a connection timeout of 30 seconds during a periodic health check performed every 60 seconds, THE Operator SHALL set the resource status to "Unavailable" and emit a Kubernetes event indicating the connection error reason

### Requirement 4: TSecretSync CRD

**User Story:** As a platform engineer, I want to define synchronization rules between an external vault and a local TSecret, so that secrets are automatically pulled from the vault and stored encrypted locally.

#### Acceptance Criteria

1. WHEN the Operator is deployed, THE Operator SHALL register the TSecretSync Custom Resource Definition in the Kubernetes API server
2. WHEN a TSecretSync resource is created, THE Operator SHALL pull the specified secrets from the referenced TSecretStore or ClusterTSecretStore and create a corresponding TSecret resource, and set the TSecretSync status to "Synced"
3. IF the Operator fails to pull secrets from the referenced store during a sync triggered by TSecretSync creation or scheduled refresh, THEN THE Operator SHALL set the TSecretSync status to "SyncFailed", retain the last successfully synchronized TSecret if one exists, and record an event indicating the failure reason
4. WHEN a TSecretSync specifies a refresh interval, THE Operator SHALL re-synchronize secrets from the Secret_Provider at the configured interval, enforcing a minimum interval of 30 seconds and a maximum interval of 86400 seconds (24 hours)
5. IF a TSecretSync references a TSecretStore or ClusterTSecretStore with status "Unavailable", THEN THE Operator SHALL set the TSecretSync status to "SyncFailed" and retain the last successfully synchronized TSecret
6. WHEN secrets in the external Secret_Provider change and a sync occurs, THE Operator SHALL update the corresponding TSecret with newly encrypted values and increment the resource generation
7. WHEN a TSecretSync resource is deleted, THE Operator SHALL delete the corresponding TSecret resource that was created by that TSecretSync

### Requirement 5: Encryption and Key Management

**User Story:** As a security engineer, I want secrets to be encrypted with industry-standard algorithms and keys managed through trusted providers, so that secret data is protected at rest and in transit within the cluster.

#### Acceptance Criteria

1. THE Operator SHALL support AES-256-GCM and ChaCha20-Poly1305 as symmetric encryption algorithms for TSecret values, with the algorithm specified per TSecret resource in its spec
2. THE Operator SHALL support the following Key_Provider backends: Sealed Secret (bootstrap), AWS KMS, Azure Key Vault, GCP Cloud KMS, and HashiCorp Vault Transit
3. WHEN encrypting a value, THE Operator SHALL generate a cryptographically random nonce per encryption operation using the algorithm's required nonce size (96-bit for AES-256-GCM, 192-bit for XChaCha20-Poly1305) to prevent nonce reuse
4. IF a Key_Provider fails to respond within 5 seconds after 3 retry attempts, THEN THE Operator SHALL fail the encryption or decryption operation and set the resource status condition to indicate the Key_Provider connectivity failure
5. WHEN a key rotation event is received from the Key_Provider, THE Operator SHALL re-encrypt affected TSecret values with the new key version while maintaining decryptability using the previous key version until re-encryption of all affected secrets is complete
6. WHEN a key rotation event is received from the Key_Provider, THE Operator SHALL complete re-encryption of all affected TSecret values within 60 seconds per 1000 secrets

### Requirement 6: Mutating Admission Webhook for Pod Injection

**User Story:** As a developer, I want my pods to automatically receive decrypted secret values as environment variables or volume mounts when they reference a TSecret, so that I can use secrets without managing decryption logic in my application.

#### Acceptance Criteria

1. WHEN a Pod is created or updated with env[].valueFrom.secretRef referencing a TSecret in the same namespace, THE Mutating_Admission_Webhook SHALL decrypt the referenced values and inject them as environment variables in the pod spec
2. WHEN a Pod is created or updated with volumes[].secret referencing a TSecret in the same namespace, THE Mutating_Admission_Webhook SHALL decrypt the referenced values and mount them as files in a tmpfs_Volume
3. IF the Mutating_Admission_Webhook cannot decrypt one or more referenced TSecret values, THEN THE Mutating_Admission_Webhook SHALL reject the pod admission with an error message identifying each failing TSecret name and key
4. IF a Pod references a TSecret that does not exist or is not in a Ready condition, THEN THE Mutating_Admission_Webhook SHALL reject the pod admission with an error message indicating the missing or unready TSecret name
5. THE Mutating_Admission_Webhook SHALL process pod admission requests within 5 seconds to avoid Kubernetes API server timeout
6. THE Operator SHALL configure the webhook with failurePolicy "Fail" so that pods referencing a TSecret are not admitted when the webhook is unreachable or does not respond within 5 seconds
7. THE Mutating_Admission_Webhook SHALL only decrypt values at the moment of pod admission and SHALL NOT store decrypted values in any persistent storage including etcd, disk, or external databases

### Requirement 7: Operator Deployment and Lifecycle

**User Story:** As a cluster administrator, I want to deploy the TSecret operator using standard Kubernetes tooling, so that I can manage its lifecycle alongside other cluster components.

#### Acceptance Criteria

1. THE Operator SHALL be deployable via Helm chart with configurable values for replicas (1 to 5, default 2), CPU and memory resource limits, and Key_Provider connection configuration
2. THE Operator SHALL expose health check endpoints (/healthz and /readyz) that return HTTP 200 when healthy or HTTP 503 when unhealthy, with each endpoint responding within 5 seconds
3. WHEN the Operator starts, THE Operator SHALL verify connectivity to the configured Key_Provider within 30 seconds and report readiness probe as healthy (HTTP 200 on /readyz) on success, or as unhealthy (HTTP 503 on /readyz) on failure
4. THE Operator SHALL emit structured logs in JSON format with configurable log levels (debug, info, warn, error)
5. THE Operator SHALL expose Prometheus-compatible metrics for reconciliation counts, webhook latency, encryption operations, and error rates
6. IF the Operator loses connectivity to the Key_Provider after startup, THEN THE Operator SHALL set the readiness probe to unhealthy (HTTP 503 on /readyz) and retry connectivity every 30 seconds until the connection is restored
7. IF the Key_Provider connectivity check fails during startup and does not recover within 30 seconds, THEN THE Operator SHALL remain in a not-ready state and log an error message indicating the Key_Provider is unreachable

### Requirement 8: RBAC and Security

**User Story:** As a security engineer, I want the operator to follow the principle of least privilege, so that compromise of the operator does not grant excessive cluster access.

#### Acceptance Criteria

1. THE Operator SHALL request only the RBAC permissions limited to the verbs get, list, watch, create, update, patch, and delete on TSecret, TSecretStore, ClusterTSecretStore, and TSecretSync custom resources, and get, list, and watch on Secrets and ConfigMaps required for reconciliation
2. THE Operator SHALL use a ServiceAccount exclusively assigned to the operator, bound only to custom Roles or ClusterRoles scoped to the resources in criterion 1, with no cluster-admin ClusterRoleBinding
3. WHEN a namespace-scoped TSecretStore is referenced, THE Operator SHALL enforce that only workloads in the same namespace can access secrets from that store
4. IF a workload in a different namespace attempts to reference a namespace-scoped TSecretStore, THEN THE Operator SHALL deny the request and set the resource status condition to indicate a namespace access violation
5. THE Mutating_Admission_Webhook SHALL validate TLS certificates for all webhook communication with the Kubernetes API server, verifying the certificate chain of trust, expiration date, and hostname match
6. IF TLS certificate validation fails for webhook communication, THEN THE Mutating_Admission_Webhook SHALL reject the connection and emit a Kubernetes event on the webhook resource indicating the TLS validation failure reason
7. THE Operator SHALL NOT log or expose decrypted secret values in logs, events, or metrics under any circumstance
