# Security model

Krivy needs to see what runs in your cluster and to start pods that pull
arbitrary images. This page describes what it can do, what it cannot do, and
what leaves the cluster. To report a vulnerability in Krivy itself, see
[SECURITY.md](../SECURITY.md).

## Kubernetes permissions

The Helm chart creates two sets of permissions for the controller's
ServiceAccount, and none for the scanner.

**Discovery (read-only).** A ClusterRole, or a Role in
`kubernetes.watchNamespace` when that is set:

| API group | Resource | Verbs | Why |
|---|---|---|---|
| `""` | `pods` | get, list, watch | Find images of running Pods |
| `apps` | `replicasets` | get | Resolve Pod → ReplicaSet → Deployment |
| `batch` | `jobs` | get | Resolve Pod → Job → CronJob |

Krivy does not read Secrets, ConfigMaps or Pod specs beyond what `pods/list`
returns, and does not modify workloads.

**Scanner Jobs.** A Role in the job namespace only:

| API group | Resource | Verbs |
|---|---|---|
| `batch` | `jobs` | create, get, list, watch, delete |
| `""` | `pods` | get, list, watch |
| `""` | `pods/log` | get |

The Trivy report is read from the scanner pod's logs. Run scanner Jobs in a
dedicated namespace (the default is the release namespace) so this Role
covers nothing else.

**Scanner ServiceAccount** (`krivy-scanner`): no Role bindings and
`automountServiceAccountToken: false`. The scanner pod spec also sets
`automountServiceAccountToken: false`, so scanned images never run next to a
Kubernetes credential.

## Scanner pod hardening

Each image is scanned in its own Job (`internal/scanner/job.go`):

* `runAsNonRoot`, UID/GID 65534, `fsGroup` 65534;
* `allowPrivilegeEscalation: false`, `privileged: false`, all capabilities
  dropped, read-only root filesystem, seccomp `RuntimeDefault`;
* no PersistentVolume; `/tmp` and the Trivy cache are `emptyDir` volumes
  limited to the ephemeral-storage limit (default 2Gi);
* `enableServiceLinks: false`, no ServiceAccount token;
* `backoffLimit: 0`, `activeDeadlineSeconds` = `trivy.timeout`,
  `ttlSecondsAfterFinished` = `trivy.ttlAfterFinished`;
* CPU/memory/ephemeral-storage requests and limits from `trivy.resources`;
* the image reference is passed after `--`, so it can never be parsed as a
  Trivy flag.

Trivy does not execute the scanned image; it downloads and inspects its
layers. With `networkPolicy.enabled: true` the chart denies all ingress to
scanner pods and limits their egress to DNS and the configured ports/CIDRs.

The controller pod itself runs as non-root (UID 65532) with a read-only root
filesystem, no privilege escalation, all capabilities dropped and seccomp
`RuntimeDefault`.

## API tokens

REST and MCP share one authentication mechanism: static bearer tokens from
`auth.tokens`.

* **Scopes** are hierarchical: `read` < `scan` < `manage`. `read` sees
  everything (findings, scans, silences, summary); `scan` can also trigger and
  cancel scans; `manage` can also acknowledge findings and create or revoke
  silences. There are no per-namespace tokens: every token sees the whole
  cluster's findings.
* **Storage.** Tokens are supplied as `${ENV}` references (from a Kubernetes
  Secret) or as a SHA-256 hash (`sha256:`), so the ConfigMap never contains a
  raw token. In memory only the SHA-256 hash is kept.
* **Verification** hashes the presented token and compares it in constant
  time against **every** configured hash, so timing does not reveal which
  token matched.
* **Logging.** Tokens are never logged. Audit fields (`requestedBy`,
  `ackBy`, `createdBy`, `revokedBy`) record `token:<name>`.
* **Revocation.** Set `revoked: true` (or remove the entry) and restart Krivy;
  the chart rolls the pod on `helm upgrade`. There is no runtime revocation
  endpoint, and MCP sessions are bound to the token that opened them.
* **No OAuth/OIDC.** Krivy advertises no authorization server metadata.
  Unauthenticated requests get `401` with `WWW-Authenticate: Bearer`.
* With no tokens configured, every REST and MCP request is rejected.

Unauthenticated endpoints: `/healthz`, `/readyz`, `/version` (version and
commit) and `/api/v1/openapi.yaml`.

Tokens travel in every request. Expose Krivy outside the cluster only behind
TLS, and prefer `kubectl port-forward` or an internal Ingress with your usual
access controls.

## Webhooks and SSRF

Webhook destinations exist **only** in the config file. No API or MCP call
can create or change one, so a stolen token cannot redirect alerts.

* By default the HTTP client refuses to connect to loopback, private
  (RFC 1918, `fc00::/7`), link-local (including `169.254.169.254`), CGNAT,
  multicast, unspecified and reserved addresses. IPv4-mapped, NAT64 and 6to4
  forms are unwrapped and checked.
* The check runs at **dial time** on the resolved IP, so DNS rebinding cannot
  bypass it.
* Redirects are never followed, and `HTTP(S)_PROXY` is ignored.
* `notifications.allowPrivateNetworks: true` disables the guard for in-cluster
  receivers; only use it when everyone who can edit the config is trusted
  with the pod's network access.
* Header values, `secrets` values and URL parts are redacted from stored
  delivery errors. Templates cannot read the environment, files or network.

Details: [webhooks](webhooks.md#ssrf-protection).

## What leaves the cluster

| Traffic | From | To | Contents |
|---|---|---|---|
| Trivy DB download | scanner pods | `ghcr.io` / `mirror.gcr.io` (or your `--db-repository`) | Anonymous download, once per Job |
| Image pulls for scanning | scanner pods | Registry of each scanned image | Standard registry requests, with the matching `registryAuth` Secret's credentials if one matches |
| Trivy image pull | kubelet | `ghcr.io/aquasecurity/trivy` (or your mirror) | Standard image pull |
| Webhooks | controller | Configured destinations | Finding data (CVE, package, image, namespaces, workload names), scan status |

Krivy sends no telemetry. The REST and MCP APIs are inbound only. Trivy is run
with `--scanners vuln` and does not upload image contents anywhere.

Use a destination's `namespaces` filter to keep one team's workload names out
of another team's channel.

## Private registry credentials

* Krivy does **not** reuse the `imagePullSecrets` of your workloads, and it
  never reads Secrets in workload namespaces.
* `kubernetes.registryAuth.existingSecrets` (chart:
  `scanner.registryAuth.existingSecrets`) lists existing
  `kubernetes.io/dockerconfigjson` Secrets, or `kubernetes.io/basic-auth`
  Secrets with `server`, `username` and `password` keys, in the job
  namespace. You create
  and rotate them. Krivy never creates, copies or stores them, and they are
  not in Helm values or the database.
* The controller reads these Secrets (`get`, restricted by `resourceNames` in
  the chart) on every scan, to validate them and to choose the one whose
  entry matches the image. Only that Secret is mounted, read-only, at
  `/tmp/.docker/config.json` in that image's scanner pod. A basic-auth
  Secret's three keys are mounted read-only only into the pod's
  `registry-auth` init container (same image and hardening as the Trivy
  container: non-root, read-only root filesystem, no capabilities, no
  ServiceAccount token), which writes a `config.json` with the single
  entry for `server` to a memory-backed `emptyDir`. The Trivy container mounts
  only that file, read-only. The init container refuses to write it if
  `server` changed after the controller selected the Secret, so credentials
  only go to the registry they name. Images that no Secret covers get no
  credentials. Credentials never appear in Job specs,
  arguments, environment variables, logs, scan records, notifications or
  REST/MCP responses. Diagnostics from failed scans are scrubbed of the
  mounted credential values in addition to the generic redaction.
* `kubernetes.imagePullSecrets` only affects how the kubelet pulls the Trivy
  image; it does not give Trivy access to scanned images.

Limitations:

* A scanner pod can read every entry of the Secret mounted for its image. Keep
  unrelated registries in separate Secrets and use read-only, pull-only
  credentials.
* Anyone who can create Pods in the job namespace can mount these Secrets.
  Keep that namespace dedicated to Krivy.
* Cloud workload identity (IRSA, GKE Workload Identity) and credential
  helpers are not wired up, because scanner pods have no ServiceAccount token.
* Missing, invalid or rejected credentials fail the image with
  `registry_auth`, which is not retried. The rest of the run continues and
  finishes as `partial`. See [private registries](private-registries.md#errors).

## Data at rest

The database holds image references, workload names, findings, silences,
acknowledgement reasons and webhook delivery records. It holds no tokens and
no webhook URLs or credentials. Protect the SQLite PVC or PostgreSQL database
like any other operational data store.
