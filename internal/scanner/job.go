package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and annotations set on scanner Jobs and their Pods.
const (
	LabelName       = "app.kubernetes.io/name"
	LabelComponent  = "app.kubernetes.io/component"
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	LabelScanJobID  = "krivy.io/scan-job-id"
	AnnotationImage = "krivy.io/image-ref"

	ContainerName = "trivy"
	cacheDir      = "/tmp/trivy-cache"
	dockerDir     = "/tmp/.docker"
	nonRootID     = int64(65534)

	// AuthInitContainerName builds Trivy's Docker config from a
	// kubernetes.io/basic-auth Secret (see RegistryAuth).
	AuthInitContainerName = "registry-auth"
	basicAuthDir          = "/registry-auth"
)

// RegistryAuth is the registry credential Secret selected for one scanner
// Job (see resolveAuth). The zero value means no credentials.
type RegistryAuth struct {
	// Secret is the name of the Secret in the job namespace.
	Secret string
	// Server is set when Secret is a kubernetes.io/basic-auth Secret: the
	// registry key the controller resolved from its server field. An init
	// container writes $DOCKER_CONFIG/config.json with that single entry.
	Server string
}

// basicAuthScript runs in the init container with the Trivy image's sh
// (busybox in the official images; cat, base64 and tr must be on its PATH).
// It reads the mounted server/username/password files and writes a Docker
// config with one "auth" entry for $KRIVY_REGISTRY_SERVER. Credentials pass
// only through files, shell builtins and pipes, never through arguments or
// the environment, and are never printed. It fails with a fixed message if
// the Secret lost a key or now names a different registry than the
// controller resolved, so a rotation never sends credentials elsewhere.
const basicAuthScript = `set -eu
fail() { echo "krivy-registry-auth: $1" >&2; exit 1; }
d=$KRIVY_REGISTRY_AUTH_DIR
for k in server username password; do [ -s "$d/$k" ] || fail "missing-$k"; done
[ "$(cat "$d/server")" = "$KRIVY_REGISTRY_SERVER" ] || fail server-changed
auth=$(printf '%s:%s' "$(cat "$d/username")" "$(cat "$d/password")" | base64 | tr -d '\n')
umask 077
printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$KRIVY_REGISTRY_SERVER" "$auth" >"$DOCKER_CONFIG/config.json"
`

// JobName returns the deterministic Job name for a target:
// "krivy-scan-<short id>-<attempt>" (DNS-1123, <= 63 chars).
func JobName(t Target) string {
	short := sanitize(t.ScanJobID, 8)
	if short == "" {
		sum := sha256.Sum256([]byte(t.ImageKey + "|" + t.ImageRef))
		short = hex.EncodeToString(sum[:])[:8]
	}
	attempt := t.Attempt
	if attempt < 1 {
		attempt = 1
	}
	return fmt.Sprintf("krivy-scan-%s-%d", short, attempt)
}

// sanitize keeps [a-z0-9] up to max characters.
func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			if b.Len() == max {
				break
			}
		}
	}
	return b.String()
}

// labelValue makes s a valid label value (<= 63, alnum ends, [-_.a-zA-Z0-9]).
func labelValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
		if b.Len() == 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-_.")
}

// trivyTimeout leaves a margin so Trivy fails cleanly before the Job deadline.
func trivyTimeout(d time.Duration) time.Duration {
	margin := d / 10
	if margin < 30*time.Second {
		margin = 30 * time.Second
	}
	if margin > 2*time.Minute {
		margin = 2 * time.Minute
	}
	if d-margin < 30*time.Second {
		return d
	}
	return d - margin
}

func quantities(r ResourceList) corev1.ResourceList {
	out := corev1.ResourceList{}
	set := func(name corev1.ResourceName, v string) {
		if v == "" {
			return
		}
		if q, err := resource.ParseQuantity(v); err == nil {
			out[name] = q
		}
	}
	set(corev1.ResourceCPU, r.CPU)
	set(corev1.ResourceMemory, r.Memory)
	set(corev1.ResourceEphemeralStorage, r.EphemeralStorage)
	if len(out) == 0 {
		return nil
	}
	return out
}

// TrivyArgs returns the arguments after the "trivy" command.
func TrivyArgs(cfg Config, imageRef string) []string {
	cfg = cfg.withDefaults()
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--output", "/dev/stdout",
		"--scanners", "vuln",
		"--severity", strings.ToUpper(strings.Join(cfg.Severities, ",")),
		"--no-progress",
		"--cache-dir", cacheDir,
		"--timeout", trivyTimeout(cfg.Timeout).String(),
	}
	args = append(args, cfg.ExtraArgs...)
	// "--" guards against a ref that looks like a flag.
	return append(args, "--", imageRef)
}

// BuildJob renders the hardened scanner Job for t. It never uses a PVC and
// never mounts a ServiceAccount token. auth, if set, is the Secret selected
// for t (see resolveAuth): a dockerconfigjson Secret is mounted read-only as
// Trivy's Docker config; a basic-auth Secret is mounted only into an init
// container that builds that config in a memory-backed emptyDir.
func BuildJob(cfg Config, t Target, auth RegistryAuth) *batchv1.Job {
	cfg = cfg.withDefaults()
	name := JobName(t)
	labels := map[string]string{
		LabelName:      "krivy",
		LabelComponent: "scanner",
		LabelManagedBy: "krivy",
	}
	if v := labelValue(t.ScanJobID); v != "" {
		labels[LabelScanJobID] = v
	}
	podLabels := make(map[string]string, len(labels))
	for k, v := range labels {
		podLabels[k] = v
	}
	annotations := map[string]string{AnnotationImage: t.ImageRef}
	if auth.Secret != "" {
		annotations[AnnotationRegistryAuth] = auth.Secret
	}

	scratch := cfg.ScratchSizeLimit
	if scratch == "" {
		scratch = cfg.Resources.Limits.EphemeralStorage
	}
	if scratch == "" {
		scratch = "2Gi"
	}
	var sizeLimit *resource.Quantity
	if q, err := resource.ParseQuantity(scratch); err == nil {
		sizeLimit = &q
	}

	deadline := int64(cfg.Timeout / time.Second)
	if deadline < 1 {
		deadline = 1
	}
	ttl := int32(min(int64(cfg.TTLAfterFinished/time.Second), math.MaxInt32)) //nolint:gosec // clamped to int32 range

	f, tr := false, true
	volumes := []corev1.Volume{
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: sizeLimit}}},
		{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: sizeLimit}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "cache", MountPath: cacheDir},
	}
	env := []corev1.EnvVar{
		{Name: "HOME", Value: "/tmp"},
		{Name: "TMPDIR", Value: "/tmp"},
		{Name: "TRIVY_CACHE_DIR", Value: cacheDir},
		{Name: "TRIVY_NO_PROGRESS", Value: "true"},
		{Name: "TRIVY_DISABLE_VEX_NOTICE", Value: "true"},
	}
	resources := corev1.ResourceRequirements{
		Requests: quantities(cfg.Resources.Requests),
		Limits:   quantities(cfg.Resources.Limits),
	}
	securityContext := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &f,
		ReadOnlyRootFilesystem:   &tr,
		RunAsNonRoot:             &tr,
		Privileged:               &f,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	var initContainers []corev1.Container
	mode := int32(0o440)
	switch {
	case auth.Secret != "" && auth.Server != "":
		// Only the three keys, read-only, and only in the init container.
		// Trivy gets the generated config.json read-only from a tmpfs
		// emptyDir. Optional, so a Secret deleted after resolution fails the
		// init container as an auth error instead of leaving the Pod stuck in
		// ContainerCreating.
		volumes = append(volumes,
			corev1.Volume{Name: "registry-auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: auth.Secret,
				Items: []corev1.KeyToPath{
					{Key: basicAuthServerKey, Path: basicAuthServerKey},
					{Key: corev1.BasicAuthUsernameKey, Path: corev1.BasicAuthUsernameKey},
					{Key: corev1.BasicAuthPasswordKey, Path: corev1.BasicAuthPasswordKey},
				},
				DefaultMode: &mode,
				Optional:    &tr,
			}}},
			corev1.Volume{Name: "docker-config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory, SizeLimit: resource.NewQuantity(1<<20, resource.BinarySI),
			}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "docker-config", MountPath: dockerDir, ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerDir})
		initContainers = append(initContainers, corev1.Container{
			Name:            AuthInitContainerName,
			Image:           cfg.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c", basicAuthScript},
			Env: []corev1.EnvVar{
				{Name: "KRIVY_REGISTRY_SERVER", Value: auth.Server},
				{Name: "KRIVY_REGISTRY_AUTH_DIR", Value: basicAuthDir},
				{Name: "DOCKER_CONFIG", Value: dockerDir},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "registry-auth", MountPath: basicAuthDir, ReadOnly: true},
				{Name: "docker-config", MountPath: dockerDir},
			},
			Resources:                resources,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			SecurityContext:          securityContext,
		})
	case auth.Secret != "":
		// Only the .dockerconfigjson key, read-only. Trivy reads it as
		// $DOCKER_CONFIG/config.json (= $HOME/.docker/config.json). Optional,
		// so a Secret deleted after resolution fails fast as an auth error
		// instead of leaving the Pod stuck in ContainerCreating.
		volumes = append(volumes, corev1.Volume{Name: "registry-auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  auth.Secret,
			Items:       []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: "config.json"}},
			DefaultMode: &mode,
			Optional:    &tr,
		}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "registry-auth", MountPath: dockerDir, ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerDir})
	}
	var pullSecrets []corev1.LocalObjectReference
	for _, s := range cfg.ImagePullSecrets {
		if s != "" {
			pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: s})
		}
	}

	uid := nonRootID
	backoff := int32(0)
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: cfg.Namespace, Labels: labels, Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   &deadline,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: annotations},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           cfg.ServiceAccount,
					AutomountServiceAccountToken: &f,
					EnableServiceLinks:           &f,
					ImagePullSecrets:             pullSecrets,
					NodeSelector:                 maps.Clone(cfg.NodeSelector),
					Tolerations:                  append([]corev1.Toleration(nil), cfg.Tolerations...),
					Affinity:                     cfg.Affinity.DeepCopy(),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &tr,
						RunAsUser:      &uid,
						RunAsGroup:     &uid,
						FSGroup:        &uid,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Volumes:        volumes,
					InitContainers: initContainers,
					Containers: []corev1.Container{{
						Name:                     ContainerName,
						Image:                    cfg.Image,
						ImagePullPolicy:          corev1.PullIfNotPresent,
						Command:                  command(cfg),
						Args:                     TrivyArgs(cfg, t.ImageRef),
						Env:                      env,
						VolumeMounts:             mounts,
						Resources:                resources,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						SecurityContext:          securityContext,
					}},
				},
			},
		},
	}
}

func command(cfg Config) []string {
	if len(cfg.Command) > 0 {
		return cfg.Command
	}
	return []string{"trivy"}
}
