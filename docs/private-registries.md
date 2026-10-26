# Private registries

Krivy discovers every image that runs in the cluster, including private ones,
but Trivy has to pull an image to scan it. Trivy runs in an ephemeral scanner
Job, and that Job has none of the credentials the nodes use. To scan private
images, point Krivy at **existing** Secrets in the job namespace. Two forms
are accepted, and you can mix them:

* `kubernetes.io/dockerconfigjson`, as created by
  `kubectl create secret docker-registry`. One Secret can cover several
  registries.
* `kubernetes.io/basic-auth` with the three keys `server`, `username` and
  `password`, the same three values you would pass to
  `kubectl create secret docker-registry`. One Secret covers one registry.
  This form suits secret managers that copy fields into a Secret but cannot
  build a Docker `config.json`, such as the 1Password Operator.

* You create and rotate the Secrets yourself. Krivy and the Helm chart never
  create them, and credentials never go into Helm values, the Krivy config or
  the Krivy database.
* For each image, at most **one** Secret is mounted, read-only, into that
  image's scanner pod. Images that no Secret covers (public images, for
  example) are scanned with no credentials at all.
* Without configuration nothing changes: public images are scanned
  anonymously, as before.

## Two different pulls

| Pull | Who pulls | Credentials |
|---|---|---|
| The Trivy image (`trivy.image`) | the kubelet | `scanner.serviceAccount.imagePullSecrets` or `scanner.imagePullSecrets` (Pod `imagePullSecrets`) |
| The image being scanned | Trivy, inside the scanner pod | `scanner.registryAuth.existingSecrets` (this page) |

Pod `imagePullSecrets` only help the kubelet start the scanner container. They
give Trivy nothing. Registry auth Secrets are never added as
`imagePullSecrets`.

## Create the Secrets

Create them in the **job namespace**: the release namespace, or
`kubernetes.jobNamespace` if you set it. Use read-only, pull-only credentials.

GitHub Container Registry (a classic personal access token with
`read:packages` only, or a fine-grained token with package read access):

```sh
kubectl -n krivy-system create secret docker-registry ghcr-auth \
  --docker-server=ghcr.io \
  --docker-username=<github-user> \
  --docker-password=<token>
```

Any other registry (Harbor, GitLab, Nexus, Artifactory, a self-hosted
`registry:2`, ...):

```sh
kubectl -n krivy-system create secret docker-registry internal-registry-auth \
  --docker-server=registry.example.com:5000 \
  --docker-username=<robot-account> \
  --docker-password=<token>
```

Docker Hub is special. Trivy reads Docker Hub credentials only under the key
`https://index.docker.io/v1/`, which is the `kubectl` default when you leave
out `--docker-server`:

```sh
kubectl -n krivy-system create secret docker-registry dockerhub-auth \
  --docker-username=<user> --docker-password=<access-token>
```

One Secret may hold several registries. You can also build one from an
existing Docker `config.json` that contains only `auths`:

```sh
kubectl -n krivy-system create secret generic multi-registry-auth \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson=./config.json
```

### Three fields: server, username, password

Instead of a Docker `config.json`, a Secret can hold the three values
separately. It must have the type `kubernetes.io/basic-auth`:

```sh
kubectl -n krivy-system create secret generic internal-registry-auth \
  --type=kubernetes.io/basic-auth \
  --from-literal=server=registry.example.com \
  --from-literal=username=<robot-account> \
  --from-literal=password=<token>
```

With the [1Password Operator](https://github.com/1Password/onepassword-operator),
give the item three fields labelled exactly `server`, `username` and
`password`, and set the Secret type on the `OnePasswordItem`:

```yaml
apiVersion: onepassword.com/v1
kind: OnePasswordItem
metadata:
  name: internal-registry-auth
  namespace: krivy-system
type: kubernetes.io/basic-auth
spec:
  itemPath: vaults/<vault>/items/<item>
```

The operator copies every field of the item into the Secret. Krivy reads only
`server`, `username` and `password` and passes only those three keys to the
scanner pod. Keep the item to these fields anyway, because anyone who can read
the Secret sees the others.

`server` takes the same values as `--docker-server`: a host
(`registry.example.com`, `registry.example.com:5000`), a host with a path
(`registry.example.com/team`, which covers only repositories under that
path), or an `https://` URL. For Docker Hub use `https://index.docker.io/v1/`.

How it reaches Trivy: the controller validates the Secret and selects it for
an image exactly like a Docker config with the single entry `auths[server]`.
The scanner pod then gets an init container, running the Trivy image's `sh`,
which reads the three keys from a read-only Secret volume and writes
`config.json` with that one entry into a memory-backed `emptyDir`. The Trivy
container mounts only that `emptyDir`, read-only, and never sees the Secret
volume. The values are never passed as arguments or environment variables,
and the init container prints nothing. If the Secret's `server` no longer
matches the registry the controller selected (a rotation racing the scan),
the init container writes nothing and the scan fails, so credentials are
never sent to another registry. The official Trivy images provide the `sh`,
`cat`, `base64` and `tr` this needs. A custom `trivy.image` must too.

### Requirements

Checked on every scan.

`kubernetes.io/dockerconfigjson` Secrets:

* type `kubernetes.io/dockerconfigjson` with a `.dockerconfigjson` key;
* every `auths` entry has `auth` (base64 of `user:password`),
  `username`/`password`, `identitytoken` or `registrytoken`;
* no `credsStore` or `credHelpers`, because scanner pods have no credential
  helpers.

`kubernetes.io/basic-auth` Secrets:

* non-empty `server`, `username` and `password` keys;
* `server` is a host, `host:port`, `host/path` or `http(s)://host` URL with
  no wildcards and no credentials;
* `username` contains no `:`, and neither value contains a line break or
  another control character. A trailing newline copied with a token is the
  usual cause.

An `Opaque` Secret with these three keys is rejected with a hint to set the
type: the type is what makes the three-field form explicit.

The legacy `kubernetes.io/dockercfg` type is **not supported**. Trivy cannot
read that format and Krivy does not rewrite credentials into new objects.
Recreate such Secrets with `kubectl create secret docker-registry`.

## Configure Krivy

Helm:

```yaml
scanner:
  registryAuth:
    existingSecrets:        # job namespace, in priority order
      - ghcr-auth
      - internal-registry-auth
```

Config file ([reference](configuration.md)):

```yaml
kubernetes:
  registryAuth:
    existingSecrets: [ghcr-auth, internal-registry-auth]
```

The chart grants the controller `get` on exactly these Secret names in the
job namespace (a Role with `resourceNames`). It gets no `list`, no `watch`,
no access to other Secrets, and no access to Secrets in workload namespaces.
If you run without the chart, grant the same yourself.

`kubernetes.registrySecret` / `scanner.registrySecret` from 0.1.0 still works
but is deprecated. It is treated as the first entry of `existingSecrets`.

## How a Secret is chosen

For every scan the controller reads all configured Secrets, validates them and
picks the entry for the image's registry. It uses the same keys that Trivy
(go-containerregistry with Docker's `config.json` rules) uses:

1. An exact repository key (`ghcr.io/acme/app`) wins over everything else.
2. A `host/path` key (`ghcr.io/acme`) matches repositories under that path,
   at a `/` boundary. The longest path wins.
3. A host key (`ghcr.io`, `registry.example.com:5000`) or a URL key
   (`https://registry.example.com/v2/`) matches every repository on that
   registry. Docker Hub uses only `https://index.docker.io/v1/`.
4. If two Secrets match equally well, the one listed first wins.

A `kubernetes.io/basic-auth` Secret takes part as the single entry
`server`. Only the chosen Secret is mounted, as `/tmp/.docker/config.json`
with `DOCKER_CONFIG=/tmp/.docker` (for a basic-auth Secret, the generated file
in the same place). If nothing matches, no Secret is mounted.

Inside one mounted file, Trivy ignores the path of `host/path` keys. A Secret
with `ghcr.io/team-a` and `ghcr.io/team-b` entries holding different
credentials is therefore ambiguous. Krivy refuses to guess and fails the scan
with a `registry_auth` error. Put such entries in separate Secrets and list
both.

Example:

| Secrets (in order) | Image | Mounted |
|---|---|---|
| `ghcr-auth` (`ghcr.io`), `internal-registry-auth` (`registry.example.com:5000`) | `registry.example.com:5000/team/api@sha256:…` | `internal-registry-auth` |
| same | `ghcr.io/acme/web:1.4` | `ghcr-auth` |
| same | `docker.io/library/nginx:1.27` | nothing (anonymous) |

## Rotation

Update the Secret in place, for example:

```sh
kubectl -n krivy-system create secret docker-registry ghcr-auth \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<new-token> \
  --dry-run=client -o yaml | kubectl apply -f -
```

For a basic-auth Secret, update its `password` (or the 1Password item: the
operator updates the Secret). No restart is needed. Krivy caches nothing:
every scan reads the Secrets again, and every scanner Job mounts the current
value. Jobs that are already
running finish with the credentials they started with.

## Namespace scope

* Registry auth Secrets live only in the job namespace. Krivy never reads
  Secrets in workload namespaces and does not reuse workload
  `imagePullSecrets`.
* Every configured Secret in the job namespace is visible to anyone who can
  create Pods there. Keep the job namespace dedicated to Krivy.
* With `networkPolicy.enabled`, scanner pods may only reach
  `networkPolicy.scanner.egressPorts` (default 443 and 80). Add the ports of
  registries such as `:5000`.

## Why k3s `registries.yaml` is not imported

On k3s, `/etc/rancher/k3s/registries.yaml` holds registry mirrors and
credentials for **containerd on each node**. Krivy does not read or import it:

* It is a host file, not a Kubernetes object. Reading it would require a
  `hostPath` mount or a privileged node agent in every scanner Job. That
  breaks the scanner's isolation (non-root, read-only root filesystem, no
  host mounts, no PersistentVolumes, no ServiceAccount token).
* It is per node. Nodes can differ, and a Job would see whichever node it was
  scheduled on.
* It holds the credentials of the whole node, for every registry. Scanner
  pods should get only the one credential they need.

Create the same credentials as a Secret instead, as shown above.

## Errors

Credential problems fail the image with the non-retryable kind
`registry_auth`. They never produce an empty, "clean" result. The rest of the
run continues and finishes as `partial`. Messages name the Secret, the
registry and what to do. They never contain credentials or Secret data.

| Situation | Message (abridged) | Job created? |
|---|---|---|
| Secret absent | `registry auth Secret "x" not found in namespace krivy-system` | no |
| RBAC forbids reading it | `krivy may not read registry auth Secret "x" …; grant get on it` | no |
| Wrong type, missing key, invalid JSON, bad `auth`, no `auths`, credential helpers | `registry auth Secret krivy-system/x …` with the specific problem | no |
| basic-auth Secret without `server`/`username`/`password`, invalid `server`, `:` in `username`, line break in a value | `registry auth Secret krivy-system/x (kubernetes.io/basic-auth) has no or an empty password key …` and similar | no |
| `Opaque` Secret with `server`/`username`/`password` | `… a Secret with server/username/password keys needs type kubernetes.io/basic-auth` | no |
| basic-auth Secret deleted, emptied or pointed at another `server` while the scan started | `registry auth Secret "x" changed its server after the scan started` / `… was deleted or lost its password key …` | yes (the init container fails, Trivy never starts) |
| The Trivy image cannot run the init container (no `sh`) | `could not build the Docker config from registry auth Secret "x": init container registry-auth exited with code …` | yes |
| Ambiguous path entries in one Secret | `… has several entries for ghcr.io …; put each path-specific entry in its own Secret` | no |
| Wrong, expired or revoked credentials, or no pull permission (401/403) | `registry rejected the credentials from Secret "x" (entry "ghcr.io") …` | yes |
| No Secret covers the registry (mismatch) | `registry denied anonymous access …; no Secret in registryAuth.existingSecrets has an entry for quay.io`, plus hints such as `entry "docker.io" is not used for Docker Hub` | yes |
| No registry auth configured | `… for a private registry add a kubernetes.io/dockerconfigjson or kubernetes.io/basic-auth Secret to registryAuth.existingSecrets` | yes |

All configured Secrets must be valid, including those that don't match the
image. One broken Secret fails every scan until it is fixed. This keeps the
choice of credentials deterministic.

`scan.maxAttempts` does not retry these failures. Fix the Secret, then scan
again with `POST /api/v1/scans` (or wait for the next scheduled scan). The
scanner Job (`kubectl -n krivy-system describe job <name>`) carries the
annotation `krivy.io/registry-auth-secret` with the name of the mounted
Secret.
