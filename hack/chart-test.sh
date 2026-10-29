#!/bin/sh
# Static assertions on the rendered Helm chart (no cluster required).
# Usage: sh hack/chart-test.sh
# Requires: helm. Optional: kubeconform (schema validation of rendered manifests).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CHART="$ROOT/charts/krivy"
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t krivy-chart)
trap 'rm -rf "$TMP"' EXIT INT TERM

FAILS=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; FAILS=$((FAILS + 1)); }

render() { # render <name> [helm args...]
  name=$1; shift
  helm template krivy "$CHART" --namespace krivy-system "$@" >"$TMP/$name.yaml"
}

# count_kind <file> <Kind> -> number of objects of that kind
count_kind() { grep -c "^kind: $2\$" "$1" || true; }

# doc_of_kind <file> <Kind> -> all documents of that kind, concatenated
doc_of_kind() {
  awk -v k="kind: $2" '
    /^---/ { if (keep) printf "%s", buf; buf=""; keep=0; next }
    { buf = buf $0 "\n"; if ($0 == k) keep=1 }
    END { if (keep) printf "%s", buf }' "$1"
}

assert_eq() { # assert_eq <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
assert_grep() { # assert_grep <desc> <pattern> <file>
  if grep -Eq -- "$2" "$3"; then pass "$1"; else fail "$1"; fi
}
assert_no_grep() {
  if grep -Eq -- "$2" "$3"; then fail "$1"; else pass "$1"; fi
}

echo "== helm lint"
if helm lint "$CHART" >/dev/null; then pass "helm lint (defaults)"; else fail "helm lint (defaults)"; fi
for f in "$CHART"/ci/*.yaml; do
  if helm lint "$CHART" -f "$f" >/dev/null; then pass "helm lint $(basename "$f")"; else fail "helm lint $(basename "$f")"; fi
done

render defaults
render default -f "$CHART/ci/default-values.yaml"
render postgres -f "$CHART/ci/postgres-values.yaml"
render netpol -f "$CHART/ci/networkpolicy-values.yaml"
render nswatch -f "$CHART/ci/namespaced-watch-values.yaml"
render regauth -f "$CHART/ci/registry-auth-values.yaml"

echo "== defaults (sqlite)"
F="$TMP/defaults.yaml"
assert_eq "exactly one Deployment" 1 "$(count_kind "$F" Deployment)"
assert_eq "exactly one PVC (controller sqlite data)" 1 "$(count_kind "$F" PersistentVolumeClaim)"
assert_grep "PVC is the controller data claim" '^  name: krivy-data$' "$F"
assert_grep "Recreate strategy with sqlite" '^    type: Recreate$' "$F"
assert_grep "sqlite DSN on /data" 'dsn: "/data/krivy.db"' "$F"
assert_grep "trivy image pinned" 'image: "ghcr.io/aquasecurity/trivy:0\.[0-9]+\.[0-9]+"' "$F"
assert_grep "default schedule" 'schedule: "@every 12h"' "$F"
assert_grep "maxConcurrentJobs 1" 'maxConcurrentJobs: 1$' "$F"
assert_grep "checksum/config annotation" 'checksum/config: [0-9a-f]{64}' "$F"
assert_grep "readOnlyRootFilesystem" 'readOnlyRootFilesystem: true' "$F"
assert_grep "runAsNonRoot" 'runAsNonRoot: true' "$F"
assert_grep "drop ALL capabilities" '^ +- ALL$' "$F"
assert_grep "seccomp RuntimeDefault" 'type: RuntimeDefault' "$F"
assert_grep "no privilege escalation" 'allowPrivilegeEscalation: false' "$F"
assert_grep "liveness /healthz" 'path: /healthz' "$F"
assert_grep "readiness /readyz" 'path: /readyz' "$F"
assert_grep "/tmp emptyDir mounted" 'mountPath: /tmp' "$F"
assert_eq "no NetworkPolicy by default" 0 "$(count_kind "$F" NetworkPolicy)"
assert_eq "no Ingress by default" 0 "$(count_kind "$F" Ingress)"
assert_eq "no Secret by default" 0 "$(count_kind "$F" Secret)"

SA=$(doc_of_kind "$F" ServiceAccount)
printf '%s\n' "$SA" >"$TMP/sa.yaml"
assert_grep "scanner ServiceAccount exists" '^  name: krivy-scanner$' "$TMP/sa.yaml"
assert_eq "scanner SA does not automount token" 1 "$(grep -c '^automountServiceAccountToken: false$' "$TMP/sa.yaml")"

echo "== RBAC is minimal"
for r in defaults postgres netpol nswatch regauth; do
  F="$TMP/$r.yaml"
  { doc_of_kind "$F" ClusterRole; doc_of_kind "$F" Role; } >"$TMP/rbac-$r.yaml"
  assert_no_grep "[$r] no wildcard verbs/resources" '"\*"' "$TMP/rbac-$r.yaml"
  assert_no_grep "[$r] no access to configmaps" '"configmaps"' "$TMP/rbac-$r.yaml"
  # Secrets only for registry auth: get, by name, in the job namespace Role.
  secret_rules=$(grep -c 'resources: \["secrets"\]' "$TMP/rbac-$r.yaml" || true)
  named_secret_rules=$(grep -A1 'resources: \["secrets"\]' "$TMP/rbac-$r.yaml" | grep -c 'resourceNames: \["' || true)
  assert_eq "[$r] secrets rules are restricted by resourceNames" "$secret_rules" "$named_secret_rules"
  doc_of_kind "$F" ClusterRole >"$TMP/rbac-$r-cluster.yaml"
  assert_no_grep "[$r] ClusterRole has no access to secrets" '"secrets"' "$TMP/rbac-$r-cluster.yaml"
  bad=$(grep -E '^ +resources:' "$TMP/rbac-$r.yaml" | grep -vE 'resources: \["(pods|pods/log|replicasets|jobs|secrets)"\]$' || true)
  assert_eq "[$r] resources limited to pods, pods/log, replicasets, jobs, secrets" "" "$bad"
  bad=$(grep -E '^ +verbs:' "$TMP/rbac-$r.yaml" | grep -vE 'verbs: \[("(get|list|watch|create|delete)"(, )?)+\]$' || true)
  assert_eq "[$r] verbs limited to get/list/watch/create/delete" "" "$bad"
  assert_eq "[$r] only one rule grants create (batch/jobs)" 1 "$(grep -c '"create"' "$TMP/rbac-$r.yaml")"
  assert_eq "[$r] only one rule grants delete (batch/jobs)" 1 "$(grep -c '"delete"' "$TMP/rbac-$r.yaml")"
  bad=$(grep -A2 'resources: \["secrets"\]' "$TMP/rbac-$r.yaml" | grep -E '^ +verbs:' | grep -vE 'verbs: \["get"\]$' || true)
  assert_eq "[$r] secrets are get-only" "" "$bad"
  # Scanner Jobs never get a PV/PVC: the only claim is the controller's own.
  claims=$(grep -c 'claimName:' "$F" || true)
  if [ "$claims" -le 1 ]; then pass "[$r] at most one claimName (controller only)"; else fail "[$r] unexpected claimName count $claims"; fi
done
assert_eq "cluster-wide discovery uses a ClusterRole" 1 "$(count_kind "$TMP/defaults.yaml" ClusterRole)"

echo "== postgres"
F="$TMP/postgres.yaml"
assert_eq "no PVC with postgres" 0 "$(count_kind "$F" PersistentVolumeClaim)"
assert_no_grep "no /data mount with postgres" 'mountPath: /data' "$F"
assert_grep "postgres DSN from env" 'dsn: "\$\{KRIVY_DATABASE_DSN\}"' "$F"
assert_grep "existingSecret as envFrom" 'name: krivy-secrets' "$F"
assert_grep "token rendered as env reference" 'token: "\$\{KRIVY_TOKEN_READER\}"' "$F"
assert_grep "custom token env name" 'token: "\$\{KRIVY_ADMIN_TOKEN\}"' "$F"
assert_grep "webhook template passed through verbatim" '\{\{ quote \.Secrets\.chatID \}\}' "$F"
assert_no_grep "no Recreate strategy with postgres" 'type: Recreate' "$F"

echo "== chart-managed secret"
F="$TMP/default.yaml"
assert_eq "secret.create renders a Secret" 1 "$(count_kind "$F" Secret)"
assert_grep "checksum/secret annotation" 'checksum/secret: [0-9a-f]{64}' "$F"

echo "== network policy"
F="$TMP/netpol.yaml"
assert_eq "two NetworkPolicies" 2 "$(count_kind "$F" NetworkPolicy)"
assert_grep "scanner policy selects scanner pods" 'app.kubernetes.io/component: scanner' "$F"
assert_grep "scanner egress allows 443" 'port: 443' "$F"
assert_grep "DNS egress" 'port: 53' "$F"
assert_eq "Ingress rendered" 1 "$(count_kind "$F" Ingress)"

echo "== namespaced watch"
F="$TMP/nswatch.yaml"
assert_eq "no ClusterRole when watchNamespace is set" 0 "$(count_kind "$F" ClusterRole)"
assert_eq "no ClusterRoleBinding when watchNamespace is set" 0 "$(count_kind "$F" ClusterRoleBinding)"
assert_grep "discovery Role in watched namespace" '^  namespace: production$' "$F"
assert_grep "job Role in job namespace" '^  namespace: krivy-scans$' "$F"
assert_eq "no PVC when persistence disabled" 0 "$(count_kind "$F" PersistentVolumeClaim)"
assert_grep "deprecated registrySecret rendered as registryAuth" '^ +- "registry-creds"$' "$F"
assert_no_grep "registrySecret key no longer rendered" 'registrySecret:' "$F"
assert_grep "get on the deprecated registrySecret only" 'resourceNames: \["registry-creds"\]' "$F"

echo "== registry auth"
for r in defaults postgres netpol; do
  assert_no_grep "[$r] no secrets access without registry auth" '"secrets"' "$TMP/$r.yaml"
  assert_no_grep "[$r] no registryAuth config without registry auth" 'registryAuth:' "$TMP/$r.yaml"
done
F="$TMP/regauth.yaml"
assert_grep "registryAuth.existingSecrets rendered in order" '^ +existingSecrets:$' "$F"
assert_eq "existingSecrets order" '- "ghcr-auth" - "internal-registry-auth"' "$(grep -E -A2 '^ +existingSecrets:$' "$F" | tail -n 2 | sed 's/^ *//' | tr '\n' ' ' | sed 's/ $//')"
doc_of_kind "$F" Role >"$TMP/regauth-role.yaml"
assert_grep "job namespace Role grants get on exactly the configured Secrets" 'resourceNames: \["ghcr-auth", "internal-registry-auth"\]' "$TMP/regauth-role.yaml"
assert_eq "chart creates no Secret for registry auth" 0 "$(count_kind "$F" Secret)"
assert_no_grep "no Secret data in rendered chart" 'dockerconfigjson' "$F"
if helm template krivy "$CHART" --set 'scanner.registryAuth.existingSecrets={Bad_Name}' >/dev/null 2>&1; then fail "invalid Secret name accepted"; else pass "invalid registry auth Secret name rejected"; fi
if helm template krivy "$CHART" --set 'scanner.registryAuth.existingSecrets={a,a}' >/dev/null 2>&1; then fail "duplicate Secret accepted"; else pass "duplicate registry auth Secret rejected"; fi
if helm template krivy "$CHART" --set 'scanner.registryAuth.username=x' >/dev/null 2>&1; then fail "inline credentials accepted"; else pass "inline registry credentials rejected"; fi

echo "== scanner placement"
for r in defaults postgres netpol; do
  assert_no_grep "[$r] no scanner placement by default" '^      (nodeSelector|tolerations|affinity):' "$TMP/$r.yaml"
done
render placement --set trivy.nodeSelector.dedicated=scanners \
  --set 'trivy.tolerations[0].key=dedicated' --set 'trivy.tolerations[0].value=scanners' --set 'trivy.tolerations[0].effect=NoSchedule'
F="$TMP/placement.yaml"
assert_grep "trivy.nodeSelector rendered into the config" '^        dedicated: scanners$' "$F"
assert_grep "trivy.tolerations rendered into the config" '^        - effect: NoSchedule$' "$F"
assert_no_grep "controller Pod not placed by trivy.*" '^      (nodeSelector|tolerations):' "$(doc_of_kind "$F" Deployment >"$TMP/placement-deploy.yaml"; echo "$TMP/placement-deploy.yaml")"

echo "== schema rejects invalid values"
if helm template krivy "$CHART" --set database.driver=mysql >/dev/null 2>&1; then fail "invalid driver accepted"; else pass "invalid driver rejected"; fi
if helm template krivy "$CHART" --set scan.maxConcurrentJobs=51 >/dev/null 2>&1; then fail "maxConcurrentJobs=51 accepted"; else pass "maxConcurrentJobs > 50 rejected"; fi
if helm template krivy "$CHART" --set trivy.nodeSelector.a=1 >/dev/null 2>&1; then fail "non-string nodeSelector accepted"; else pass "non-string trivy.nodeSelector rejected"; fi
if helm template krivy "$CHART" --set 'auth.tokens[0].name=x' --set 'auth.tokens[0].scopes[0]=admin' >/dev/null 2>&1; then fail "unknown scope accepted"; else pass "unknown token scope rejected"; fi

if command -v kubeconform >/dev/null 2>&1; then
  echo "== kubeconform"
  for r in defaults postgres netpol nswatch regauth; do
    if kubeconform -strict -summary "$TMP/$r.yaml" >/dev/null; then pass "kubeconform $r"; else fail "kubeconform $r"; fi
  done
fi

echo
if [ "$FAILS" -gt 0 ]; then
  echo "chart-test: $FAILS assertion(s) failed" >&2
  exit 1
fi
echo "chart-test: all assertions passed"
