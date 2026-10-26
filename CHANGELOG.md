# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Registry credentials as three fields: `registryAuth.existingSecrets` also
  accepts `kubernetes.io/basic-auth` Secrets with the keys `server`,
  `username` and `password` (the values of
  `kubectl create secret docker-registry`), for example as written by the
  1Password Operator. The Secret covers exactly `server` and is selected with
  the same rules as a Docker config with that single entry. Its keys are
  mounted read-only only into a `registry-auth` init container, which writes
  Trivy's `config.json` to a memory-backed `emptyDir`. Trivy mounts that
  file read-only. Credentials never appear in Job specs, arguments,
  environment variables or logs. If `server` changes between selection and
  pod start, the init container fails the scan instead of sending the
  credentials to the new registry. Invalid three-field Secrets fail with
  `registry_auth` before a Job is created. No new configuration keys or RBAC.

- Private registry credentials via existing Secrets:
  `kubernetes.registryAuth.existingSecrets` (chart:
  `scanner.registryAuth.existingSecrets`) lists
  `kubernetes.io/dockerconfigjson` Secrets in the job namespace, in priority
  order. For each image the controller selects the one matching Secret, using
  the same host and path rules as Trivy, and mounts only that Secret
  read-only into the scanner pod. Public images get no credentials. Secrets
  are re-read on every scan, so rotation needs no restart. The chart grants
  `get` on exactly the configured Secret names. See
  `docs/private-registries.md`.
- Scan failure kind `registry_auth` (not retried) for absent, unreadable,
  malformed or ambiguous registry Secrets (no Job is created) and for
  registry `unauthorized`/`denied`/403 responses. Messages name the Secret and
  registry, with hints for near misses, and never contain credentials.

### Changed

- `image_pull` now covers only images that do not exist (manifest or name
  unknown). Authentication failures are reported as `registry_auth`.
- The registry Secret is no longer mounted into every scanner pod, only into
  pods scanning an image that the Secret has an entry for. The controller now
  reads the configured Secrets (`get` in the job namespace only). The chart
  grants this; deployments that don't use the chart and set `registrySecret`
  must grant `get` on that Secret.

### Deprecated

- `kubernetes.registrySecret` / `scanner.registrySecret`: use
  `registryAuth.existingSecrets`. A value that is still set is treated as the
  first entry.

## [0.1.0]

Initial release.

### Added

- Kubernetes controller that discovers images of running and pending Pods
  (containers, init and ephemeral containers) with read-only RBAC and resolves
  owners to Deployment, CronJob, StatefulSet, DaemonSet, Job or Pod.
- Image deduplication by running digest, with tag fallback and Docker Hub
  name normalization.
- One ephemeral, hardened Trivy Job per image: no PersistentVolume, no
  ServiceAccount token, non-root, read-only root filesystem, bounded
  `emptyDir`, deadline and TTL. Default Trivy image
  `ghcr.io/aquasecurity/trivy:0.67.2`, `CRITICAL` severity by default.
- Persistent scan queue with request deduplication, bounded concurrency,
  per-image retries with failure classification, cancellation and restart
  recovery that re-attaches to running Jobs.
- Scheduler (default `@every 12h`, `off` to disable) anchored at the last
  cluster scan, with optional scan on first startup.
- Findings with stable IDs, automatic resolution (`fixed`, `not_deployed`)
  and reopening.
- Acknowledgements and silences by finding, image (digest or whole
  repository), namespace and vulnerability.
- REST API under `/api/v1` with an embedded OpenAPI 3.1 document.
- MCP server (Streamable HTTP) at `/mcp` with read, scan and triage tools.
- Static bearer tokens with `read`, `scan` and `manage` scopes, stored as
  SHA-256 hashes and compared in constant time.
- Webhook notifications (`new_critical`, `resolved`, `scan_failed`) with Go
  templates, examples for Telegram, Discord, Slack and generic JSON, SSRF
  protection, retries with backoff and delivery dedupe.
- SQLite and PostgreSQL storage with automatic migrations.
- YAML configuration with `${ENV}` substitution and `--check-config`.
- Helm chart published to `oci://ghcr.io/l4r-s/charts/krivy`, multi-arch
  container image `ghcr.io/l4r-s/krivy`.
- Local k3d development cluster and integration tests.

[Unreleased]: https://github.com/l4r-s/krivy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/l4r-s/krivy/releases/tag/v0.1.0
