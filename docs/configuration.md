# Configuration

Krivy reads one YAML file, given with `--config <path>` or the `KRIVY_CONFIG`
environment variable. Without a file, built-in defaults and the environment
overrides below are used. The Helm chart renders this file into a ConfigMap
from its values ([chart README](../charts/krivy/README.md)).

Parsing is **strict**: unknown keys are an error. Durations use Go syntax
(`90s`, `15m`, `12h`).

## Reference

Every key, with its default. Keys you omit get these values.

```yaml
server:
  address: ":8080"            # HTTP listen address for /healthz, /readyz, /version, /api/v1, /mcp
  shutdownTimeout: 15s        # graceful shutdown bound

database:
  driver: sqlite              # sqlite | postgres
  dsn: krivy.db               # sqlite: file path (default krivy.db; the chart uses /data/krivy.db)
                              # postgres: connection string, required, no default
                              # ${ENV} is expanded here

kubernetes:
  kubeconfig: ""              # empty: in-cluster config
  context: ""                 # required when kubeconfig is set; only this context is used
  jobNamespace: krivy-system  # where scanner Jobs are created (chart: release namespace)
  watchNamespace: ""          # limit discovery to one namespace; empty = all namespaces
  excludeNamespaces: []       # skipped during cluster-wide discovery
  scannerServiceAccount: krivy-scanner  # ServiceAccount of scanner pods (token never mounted)
  imagePullSecrets: []        # pod imagePullSecrets on scanner Jobs: only used by the kubelet
                              # to pull the Trivy image itself
  registryAuth:
    existingSecrets: []       # kubernetes.io/dockerconfigjson Secrets, or kubernetes.io/basic-auth
                              # Secrets with server/username/password keys, in jobNamespace, in
                              # priority order; per image at most one is used so Trivy can pull
                              # the private image it scans (docs/private-registries.md)
  registrySecret: ""          # deprecated: checked before registryAuth.existingSecrets

scan:
  schedule: "@every 12h"      # 5-field cron, descriptor (@daily, @hourly, ...) or "@every <duration>"
                              # "off" (or "disabled") turns scheduled scans off
  maxConcurrentJobs: 1        # Trivy Jobs running at once within a scan run, max 50
  maxAttempts: 2              # attempts per image for retryable failures
  scanOnStartup: false        # with no previous cluster scan, scan immediately at startup
                              # (chart default: true)

trivy:
  image: ghcr.io/aquasecurity/trivy:0.67.2   # pinned official image
  severities: [CRITICAL]      # passed to --severity and used to filter the report
  timeout: 15m                # Job activeDeadlineSeconds; Trivy's own --timeout is set slightly lower
  ttlAfterFinished: 10m       # Job ttlSecondsAfterFinished
  maxOutputBytes: 16777216    # 16 MiB cap on the JSON report; larger fails the image (not retried)
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
      ephemeralStorage: 512Mi
    limits:
      cpu: ""                 # unset by default
      memory: 1Gi
      ephemeralStorage: 2Gi   # also the sizeLimit of the scanner's emptyDir volumes
  extraArgs: []               # appended to `trivy image ...` before the image reference
  nodeSelector: {}            # scanner Pod placement, as in a Pod spec
  tolerations: []
  affinity: {}

auth:
  tokens: []                  # see "Tokens" below; no tokens = every REST/MCP request gets 401

notifications:
  baseURL: ""                 # exposed to templates as .BaseURL
  allowPrivateNetworks: false # allow webhook targets on loopback/private/link-local addresses
  destinations: []            # see docs/webhooks.md

log:
  level: info                 # debug | info | warn | error
  format: json                # json | text (logs go to stderr)
```

### Tokens

```yaml
auth:
  tokens:
    - name: ci                # required, unique; recorded as "token:ci" in audit fields
      token: ${KRIVY_TOKEN_CI}  # raw token, at least 16 characters
      scopes: [read, scan]    # read | scan | manage (manage implies scan, scan implies read)
    - name: dashboard
      sha256: 9f86d0...       # alternative to token: hex SHA-256 of the token (64 hex chars)
      scopes: [read]
    - name: old-admin
      token: ${KRIVY_TOKEN_OLD_ADMIN}
      scopes: [manage]
      revoked: true           # ignored at load time; requests with it get 401
```

Exactly one of `token` or `sha256` is required per entry. Compute a hash with
`printf %s "$TOKEN" | sha256sum`. See [security model](security-model.md#api-tokens).

### Webhook destinations

```yaml
notifications:
  destinations:
    - name: slack             # required, unique
      url: ${SLACK_WEBHOOK_URL}   # required, http:// or https://
      method: POST            # default POST
      contentType: application/json  # default; JSON bodies are validated before sending
      headers: {}             # ${ENV} expanded in values
      events: [new_critical, resolved, scan_failed]   # required
      namespaces: []          # optional finding filter
      timeout: 10s            # per attempt
      maxRetries: 3           # default 3 when 0 or omitted; -1 disables retries
      secrets: {}             # ${ENV} expanded; available in the template as .Secrets.<key>
      template: ""            # Go text/template for the body; empty sends the event as JSON
```

Full semantics, template functions and examples: [webhooks](webhooks.md).

## `${ENV}` substitution

Secrets are kept out of the YAML by referencing environment variables, which
the chart fills from a Kubernetes Secret.

* Syntax: `${NAME}` where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`. `$NAME`
  without braces is not substituted.
* Expanded **only** in these fields: `database.dsn`, `auth.tokens[].token`,
  `auth.tokens[].sha256`, `notifications.destinations[].url`,
  `.headers` values and `.secrets` values. Everywhere else `${...}` is kept
  literally.
* Substitution happens per string value after YAML parsing, so a secret
  containing YAML syntax cannot change the document structure.
* **An unset variable is an error.** Krivy refuses to start and lists every
  missing name. A variable set to the empty string is substituted as empty.
* `$${` produces a literal `${`.
* **Templates are never env-expanded.** To use a secret in a webhook body,
  put it in the destination's `secrets` map and reference it as
  `{{ json .Secrets.key }}`, so it is always escaped.

## Environment overrides

These variables override the matching key after the file is loaded and before
defaults are applied. They exist mainly for the Helm chart and local
development.

| Variable | Overrides |
|---|---|
| `KRIVY_CONFIG` | Default for `--config` |
| `KRIVY_DATABASE_DRIVER` | `database.driver` |
| `KRIVY_DATABASE_DSN` | `database.dsn` (taken verbatim, no `${}` expansion) |
| `KRIVY_KUBECONFIG` | `kubernetes.kubeconfig` |
| `KRIVY_KUBE_CONTEXT` | `kubernetes.context` |
| `KRIVY_JOB_NAMESPACE` | `kubernetes.jobNamespace` |
| `KRIVY_LISTEN_ADDRESS` | `server.address` |

## Validation and `--check-config`

```sh
krivy --config krivy.yaml --check-config   # prints "configuration OK" or the errors
krivy --version
```

`--check-config` loads the file exactly as at startup (including `${ENV}`
substitution, so the referenced variables must be set) and checks:

* `database.driver` is `sqlite` or `postgres`, and a DSN is set;
* `scan.maxConcurrentJobs` ≤ 50;
* token names are unique, each has exactly one of `token` (≥ 16 characters)
  or `sha256` (64 hex characters) and at least one valid scope;
* destination names are unique, URLs are http(s), `events` is non-empty and
  only contains known events;
* `scan.schedule` parses.

A few checks only run at full startup: Trivy resource quantities, the
Kubernetes connection, database migrations, and the webhook template dry-run
(each template is rendered against a sample event of every subscribed type).
Any failure stops the process with a non-zero exit code.

## Applying changes

Configuration is read once at startup. Change the file (or the Helm values)
and restart the pod; the chart's `checksum/config` annotation does this on
`helm upgrade`.
