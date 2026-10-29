# krivy Helm chart

Krivy is a Kubernetes controller that discovers the images of running Pods and
scans each one for CVEs with an ephemeral [Trivy](https://trivy.dev) Job. It
exposes the results through a REST API (`/api/v1`) and an MCP endpoint (`/mcp`)
and can send webhook notifications.

```sh
helm install krivy oci://ghcr.io/l4r-s/charts/krivy \
  --namespace krivy-system --create-namespace \
  --set 'auth.tokens[0].name=admin' \
  --set 'auth.tokens[0].scopes={read,scan,manage}' \
  --set secret.create=true \
  --set-string secret.data.KRIVY_TOKEN_ADMIN="$(openssl rand -hex 24)"
```

See [docs/installation.md](../../docs/installation.md) for SQLite vs PostgreSQL,
tokens, webhooks, private registries and NetworkPolicies.

## What gets installed

| Object | Purpose |
|---|---|
| Deployment (1 replica) | The controller. Non-root, read-only root FS, all capabilities dropped, seccomp `RuntimeDefault`. |
| ConfigMap | `config.yaml` rendered from values. Secrets are only `${ENV}` references. |
| Service (ClusterIP :8080) | `/healthz`, `/readyz`, `/api/v1`, `/mcp`. |
| ServiceAccount (controller) | Used by the controller. |
| ServiceAccount `krivy-scanner` | Identity of the Trivy Job pods. It has no RBAC bindings and `automountServiceAccountToken: false`. |
| ClusterRole + binding (or Role when `kubernetes.watchNamespace` is set) | `pods` get/list/watch, `replicasets` and `jobs` get (owner resolution). Read-only. |
| Role + binding in the job namespace | `jobs` create/get/list/watch/delete, `pods` get/list/watch, `pods/log` get. With registry auth configured, also `secrets` get restricted by `resourceNames` to the configured Secrets. |
| PVC (sqlite only) | `/data/krivy.db`. Kept on uninstall (`helm.sh/resource-policy: keep`). |
| Secret (optional) | `secret.create=true`. You can use `existingSecret` instead. |
| NetworkPolicy / Ingress (optional) | Off by default. |

Scanner Jobs never use a PersistentVolume. Trivy's DB cache is ephemeral
storage, bounded by `trivy.resources.*.ephemeralStorage`.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/l4r-s/krivy` | Controller image. |
| `image.tag` | `""` (appVersion) | Image tag. |
| `image.digest` | `""` | Pin by digest. Takes precedence over the tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | Pull secrets for the controller image. |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / fullname / `{}` | Controller ServiceAccount. |
| `scanner.serviceAccount.create` | `true` | Create the scanner ServiceAccount in the job namespace. |
| `scanner.serviceAccount.name` | `krivy-scanner` | Scanner ServiceAccount name. |
| `scanner.serviceAccount.imagePullSecrets` | `[]` | Pull secrets used to pull the Trivy image itself (`[{name: ...}]`). |
| `scanner.imagePullSecrets` | `[]` | Secret names added to every scanner pod (`kubernetes.imagePullSecrets`). |
| `scanner.registryAuth.existingSecrets` | `[]` | Existing `kubernetes.io/dockerconfigjson` Secrets, or `kubernetes.io/basic-auth` Secrets with `server`, `username` and `password` keys, in the job namespace, in priority order. Trivy uses them to pull the private images it scans; per image at most one is mounted read-only. The chart grants `get` on exactly these names. See [private registries](../../docs/installation.md#private-registries). |
| `scanner.registrySecret` | `""` | Deprecated: use `scanner.registryAuth.existingSecrets`. If set, it is checked first. |
| `kubernetes.jobNamespace` | release namespace | Where scanner Jobs run. |
| `kubernetes.watchNamespace` | `""` | Only discover in this namespace. Uses a Role instead of a ClusterRole. |
| `kubernetes.excludeNamespaces` | `[]` | Namespaces skipped by discovery. |
| `database.driver` | `sqlite` | `sqlite` or `postgres`. |
| `database.dsn` | `""` | Default: `/data/krivy.db` (sqlite), or `${KRIVY_DATABASE_DSN}` from the Secret (postgres). |
| `persistence.enabled` | `true` | PVC for sqlite. If disabled, sqlite uses an `emptyDir` and data is lost on restart. Ignored for postgres. |
| `persistence.existingClaim` / `.storageClass` / `.accessModes` / `.size` | `""` / `""` / `[ReadWriteOnce]` / `1Gi` | PVC settings. |
| `scan.schedule` | `@every 12h` | Cron expression or `@every <duration>`. |
| `scan.maxConcurrentJobs` | `1` | Concurrent Trivy Jobs (1–50). |
| `scan.maxAttempts` | `2` | Attempts per image. |
| `scan.scanOnStartup` | `true` | Scan at startup if no scan ran within the schedule interval. |
| `trivy.image` | `ghcr.io/aquasecurity/trivy:0.67.2` | Pinned Trivy image. |
| `trivy.severities` | `[CRITICAL]` | Severities to report. |
| `trivy.timeout` / `trivy.ttlAfterFinished` | `15m` / `10m` | Job deadline and cleanup TTL. |
| `trivy.maxOutputBytes` | `16777216` | Maximum size of the Trivy report that is read. |
| `trivy.resources` | requests 100m/256Mi/512Mi eph., limits 1Gi/2Gi eph. | Scanner pod resources (`cpu`, `memory`, `ephemeralStorage`). |
| `trivy.extraArgs` | `[]` | Extra `trivy image` arguments. |
| `trivy.nodeSelector` / `trivy.tolerations` / `trivy.affinity` | empty | Placement of the scanner Job Pods. |
| `auth.tokens` | `[]` | API tokens: `{name, scopes[read,scan,manage], env?, sha256?, revoked?}`. Each token is rendered as `token: "${KRIVY_TOKEN_<NAME>}"`. |
| `notifications.baseURL` | `""` | Link base for webhook templates. |
| `notifications.allowPrivateNetworks` | `false` | Allow webhooks to private/loopback IPs. |
| `notifications.destinations` | `[]` | Webhook destinations, copied into the config unchanged. |
| `log.level` / `log.format` | `info` / `json` | |
| `server.shutdownTimeout` | `15s` | |
| `existingSecret` | `""` | Secret whose keys become env vars (`KRIVY_TOKEN_*`, `KRIVY_DATABASE_DSN`, webhook secrets). |
| `secret.create` / `secret.data` | `false` / `{}` | Chart-managed Secret (stringData). Ignored if `existingSecret` is set. |
| `extraEnv` / `extraEnvFrom` | `[]` | Additional env for the controller. |
| `updateStrategy` | `{}` | Default: `Recreate` (sqlite), or `RollingUpdate` with maxSurge 0 (postgres). |
| `resources` | 50m/64Mi req, 256Mi limit | Controller resources. |
| `podSecurityContext` / `securityContext` | hardened | See `values.yaml`. |
| `livenessProbe` / `readinessProbe` | `/healthz` / `/readyz` | |
| `nodeSelector` / `tolerations` / `affinity` / `priorityClassName` | empty | Placement of the controller Pod. |
| `podAnnotations` / `podLabels` | `{}` | |
| `service.type` / `.port` / `.annotations` | `ClusterIP` / `8080` / `{}` | |
| `ingress.*` | disabled | Standard Ingress (`className`, `annotations`, `hosts`, `tls`). |
| `networkPolicy.enabled` | `false` | Create NetworkPolicies for the controller and scanner pods. |
| `networkPolicy.ingressFrom` | `[]` (same namespace) | Peers allowed to reach the controller on port 8080. |
| `networkPolicy.controller.restrictEgress` | `false` | Limit controller egress to DNS + `egressPorts` (443, 6443, 5432) + `extraEgress`. |
| `networkPolicy.scanner.podSelector` | `app.kubernetes.io/name: krivy`, `app.kubernetes.io/component: scanner` | Labels of scanner pods. |
| `networkPolicy.scanner.egressPorts` / `.egressCIDRs` | `[443, 80]` / `0.0.0.0/0, ::/0` | Scanner pods need internet access for the Trivy DB (ghcr.io / mirror.gcr.io) and registries. |
| `networkPolicy.scanner.extraEgress` | `[]` | For example, an in-cluster registry. |

## Testing

```sh
helm lint charts/krivy
for f in charts/krivy/ci/*.yaml; do helm lint charts/krivy -f "$f"; done
sh hack/chart-test.sh
```
