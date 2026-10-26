//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/scanner"
)

// Private registries inside the dev cluster: two with htpasswd auth and one
// without. The scanner stub runs crane, which authenticates through the same
// go-containerregistry keychain ($DOCKER_CONFIG/config.json) as Trivy, so the
// tests exercise the real credential path without the vulnerability DB.
const (
	registryNamespace = "krivy-it-registry"
	registryImage     = "registry:2.8.3"
	craneImage        = "gcr.io/go-containerregistry/crane/debug:v0.20.3"

	// Test-only credentials for throwaway in-cluster registries.
	userA, passA = "krivy-a", "it-pass-a"
	userB, passB = "krivy-b", "it-pass-b"
	htpasswdA    = "krivy-a:$2a$10$cVAIZjI02uxenASwgZTeeOzgtrQKdORXJ9bUVR.EvwjniLGbCSthG"
	htpasswdB    = "krivy-b:$2a$10$GgQ5Ys1Kl6pj4hPfNJLLX.drLpFwTkSMx0jKg9QvNXPqau5NXdZsS"
)

func registryHost(name string) string {
	return name + "." + registryNamespace + ".svc.cluster.local:5000"
}

func dockerConfigJSON(entries map[string][2]string) []byte {
	auths := map[string]map[string]string{}
	for host, up := range entries {
		auths[host] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(up[0] + ":" + up[1]))}
	}
	b, _ := json.Marshal(map[string]any{"auths": auths})
	return b
}

func dockerSecret(ns, name string, data []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"krivy.dev/integration": "registry-auth"}},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: data},
	}
}

// basicAuthSecret is the three-field form (server, username, password), as
// produced by a OnePasswordItem with type kubernetes.io/basic-auth.
func basicAuthSecret(ns, name, server, user, pass string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"krivy.dev/integration": "registry-auth"}},
		Type:       corev1.SecretTypeBasicAuth,
		StringData: map[string]string{"server": server, corev1.BasicAuthUsernameKey: user, corev1.BasicAuthPasswordKey: pass},
	}
}

// apply creates or replaces a Secret.
func applySecret(t *testing.T, cs kubernetes.Interface, s *corev1.Secret) {
	t.Helper()
	ctx := context.Background()
	_, err := cs.CoreV1().Secrets(s.Namespace).Create(ctx, s, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = cs.CoreV1().Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
	}
	if err != nil {
		t.Fatalf("secret %s: %v", s.Name, err)
	}
}

func registryDeployment(name, htpasswd string) (*appsv1.Deployment, *corev1.Service, *corev1.Secret) {
	labels := map[string]string{"app": name}
	env := []corev1.EnvVar{{Name: "REGISTRY_STORAGE_DELETE_ENABLED", Value: "true"}}
	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount
	var sec *corev1.Secret
	if htpasswd != "" {
		sec = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-htpasswd", Namespace: registryNamespace},
			StringData: map[string]string{"htpasswd": htpasswd + "\n"}}
		env = append(env,
			corev1.EnvVar{Name: "REGISTRY_AUTH", Value: "htpasswd"},
			corev1.EnvVar{Name: "REGISTRY_AUTH_HTPASSWD_REALM", Value: "krivy-it"},
			corev1.EnvVar{Name: "REGISTRY_AUTH_HTPASSWD_PATH", Value: "/auth/htpasswd"})
		volumes = append(volumes, corev1.Volume{Name: "auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: sec.Name}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "auth", MountPath: "/auth", ReadOnly: true})
	}
	volumes = append(volumes, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	mounts = append(mounts, corev1.VolumeMount{Name: "data", MountPath: "/var/lib/registry"})
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: registryNamespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: ptr(false),
					Volumes:                      volumes,
					Containers: []corev1.Container{{
						Name: "registry", Image: registryImage, Env: env, VolumeMounts: mounts,
						Ports: []corev1.ContainerPort{{ContainerPort: 5000}},
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
							TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(5000)}}, PeriodSeconds: 1},
					}},
				},
			},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: registryNamespace},
		Spec:       corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Port: 5000, TargetPort: intstr.FromInt32(5000)}}},
	}
	return dep, svc, sec
}

// privateRegistries starts the registries, pushes one image to each and
// returns the digest references keyed by registry name.
func privateRegistries(t *testing.T, cs kubernetes.Interface) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// A previous run's namespace may still be terminating.
	for {
		ns, err := cs.CoreV1().Namespaces().Get(ctx, registryNamespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) || (err == nil && ns.DeletionTimestamp == nil) {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("namespace %s did not finish terminating", registryNamespace)
		}
		time.Sleep(2 * time.Second)
	}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: registryNamespace}}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.CoreV1().Namespaces().Delete(context.Background(), registryNamespace, metav1.DeleteOptions{})
	})
	for name, htpasswd := range map[string]string{"reg-a": htpasswdA, "reg-b": htpasswdB, "reg-public": ""} {
		dep, svc, sec := registryDeployment(name, htpasswd)
		if sec != nil {
			if _, err := cs.CoreV1().Secrets(registryNamespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatal(err)
			}
		}
		if _, err := cs.AppsV1().Deployments(registryNamespace).Create(ctx, dep, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		if _, err := cs.CoreV1().Services(registryNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"reg-a", "reg-b", "reg-public"} {
		for {
			d, err := cs.AppsV1().Deployments(registryNamespace).Get(ctx, name, metav1.GetOptions{})
			if err == nil && d.Status.ReadyReplicas >= 1 {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("registry %s not ready: %v", name, err)
			}
			time.Sleep(time.Second)
		}
	}

	// Push a tiny single-layer image to every registry.
	pushAuth := dockerSecret(registryNamespace, "push-auth", dockerConfigJSON(map[string][2]string{
		registryHost("reg-a"): {userA, passA}, registryHost("reg-b"): {userB, passB},
	}))
	applySecret(t, cs, pushAuth)
	script := `set -eu
mkdir -p /tmp/l && echo krivy-registry-auth > /tmp/l/hello.txt && tar -cf /tmp/layer.tar -C /tmp/l hello.txt
for r in reg-a reg-b reg-public; do
  ref="$r.` + registryNamespace + `.svc.cluster.local:5000/private/app:1"
  crane append --insecure -f /tmp/layer.tar -t "$ref" >/dev/null
  echo "DIGEST $r $(crane digest --insecure "$ref")"
done`
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "push-" + time.Now().Format("150405"), Namespace: registryNamespace},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr(int32(3)),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				RestartPolicy:                corev1.RestartPolicyNever,
				AutomountServiceAccountToken: ptr(false),
				Volumes: []corev1.Volume{{Name: "auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
					SecretName: pushAuth.Name, Items: []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: "config.json"}}}}}},
				Containers: []corev1.Container{{
					Name: "push", Image: craneImage, Command: []string{"sh", "-c", script},
					Env:          []corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/docker"}},
					VolumeMounts: []corev1.VolumeMount{{Name: "auth", MountPath: "/docker", ReadOnly: true}},
				}},
			}},
		},
	}
	if _, err := cs.BatchV1().Jobs(registryNamespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for {
		j, err := cs.BatchV1().Jobs(registryNamespace).Get(ctx, job.Name, metav1.GetOptions{})
		if err == nil && j.Status.Succeeded > 0 {
			break
		}
		if err == nil && j.Status.Failed > 3 || ctx.Err() != nil {
			t.Fatalf("push job failed: %v %+v", err, j.Status)
		}
		time.Sleep(time.Second)
	}
	pods, err := cs.CoreV1().Pods(registryNamespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + job.Name})
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]string{}
	for _, p := range pods.Items {
		if p.Status.Phase != corev1.PodSucceeded {
			continue
		}
		out, err := cs.CoreV1().Pods(registryNamespace).GetLogs(p.Name, &corev1.PodLogOptions{}).DoRaw(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) == 3 && f[0] == "DIGEST" && strings.HasPrefix(f[2], "sha256:") {
				refs[f[1]] = registryHost(f[1]) + "/private/app@" + f[2]
			}
		}
	}
	if len(refs) != 3 {
		t.Fatalf("pushed images: %v", refs)
	}
	return refs
}

// craneStubConfig is a scanner config whose "Trivy" fetches the target
// manifest with crane (failing exactly like Trivy on auth errors) and then
// prints a fixed report.
func craneStubConfig(t *testing.T, secrets ...string) scanner.Config {
	t.Helper()
	report, err := os.ReadFile(filepath.Join(repoRoot(), "internal", "scanner", "testdata", "vulnerable.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := scanner.ConfigFrom(config.Default())
	cfg.Namespace = jobNamespace
	cfg.Image = craneImage
	cfg.Timeout = 2 * time.Minute
	cfg.TTLAfterFinished = time.Minute
	cfg.PollInterval = time.Second
	cfg.SchedulingGracePeriod = 2 * time.Minute
	cfg.RegistrySecrets = secrets
	cfg.Command = []string{"sh", "-c", `ref=""; for a in "$@"; do ref="$a"; done
crane digest --insecure "$ref" >/dev/null || exit 1
echo ` + base64.StdEncoding.EncodeToString(report) + ` | base64 -d`, "stub"}
	return cfg
}

type authScan struct {
	res *scanner.Result
	err error
	job *batchv1.Job
}

func scanWith(t *testing.T, cs kubernetes.Interface, cfg scanner.Config, id, ref string) authScan {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	// JobName uses only 8 characters of the ID: make them unique per scan.
	tgt := scanner.Target{ScanJobID: fmt.Sprintf("%08x-%s", uint32(time.Now().UnixNano()), id), ImageKey: ref, ImageRef: ref, Attempt: 1}
	res, err := scanner.NewKubernetes(cs, cfg).Scan(ctx, tgt)
	out := authScan{res: res, err: err}
	if j, gerr := cs.BatchV1().Jobs(jobNamespace).Get(ctx, scanner.JobName(tgt), metav1.GetOptions{}); gerr == nil {
		out.job = j
	}
	return out
}

func mountedRegistrySecret(j *batchv1.Job) string {
	if j == nil {
		return ""
	}
	for _, v := range j.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			return v.Secret.SecretName
		}
	}
	return ""
}

func wantAuthError(t *testing.T, s authScan, contains string) {
	t.Helper()
	var se *scanner.Error
	if !errors.As(s.err, &se) || se.Kind != scanner.KindRegistryAuth || se.Retryable {
		t.Fatalf("want non-retryable registry_auth error, got res=%v err=%v", s.res, s.err)
	}
	if !strings.Contains(se.Error(), contains) {
		t.Errorf("error %q missing %q", se.Error(), contains)
	}
	for _, leak := range []string{passA, passB, base64.StdEncoding.EncodeToString([]byte(userA + ":" + passA)),
		base64.StdEncoding.EncodeToString([]byte(passA)), "not-base64!"} {
		if strings.Contains(se.Error()+se.Diagnostics, leak) {
			t.Errorf("credential material %q leaked: %s\n%s", leak, se.Error(), se.Diagnostics)
		}
	}
}

func TestRegistryAuth(t *testing.T) {
	cs := client(t)
	refs := privateRegistries(t, cs)
	t.Cleanup(func() {
		_ = cs.CoreV1().Secrets(jobNamespace).DeleteCollection(context.Background(), metav1.DeleteOptions{},
			metav1.ListOptions{LabelSelector: "krivy.dev/integration=registry-auth"})
		cleanupJobs(t, cs)
	})
	applySecret(t, cs, dockerSecret(jobNamespace, "krivy-it-auth-a", dockerConfigJSON(map[string][2]string{registryHost("reg-a"): {userA, passA}})))
	applySecret(t, cs, dockerSecret(jobNamespace, "krivy-it-auth-b", dockerConfigJSON(map[string][2]string{registryHost("reg-b"): {userB, passB}})))

	t.Run("private image by digest", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-a", "krivy-it-auth-b"), "it-auth-a", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("scan %s: %v", refs["reg-a"], s.err)
		}
		if len(s.res.Vulnerabilities) == 0 {
			t.Error("expected the stub report")
		}
		if got := mountedRegistrySecret(s.job); got != "krivy-it-auth-a" {
			t.Errorf("mounted %q", got)
		}
		spec := s.job.Spec.Template.Spec
		if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
			t.Error("service account token mounted")
		}
		for _, v := range spec.Volumes {
			if v.PersistentVolumeClaim != nil || v.HostPath != nil {
				t.Errorf("forbidden volume %s", v.Name)
			}
		}
		for _, m := range spec.Containers[0].VolumeMounts {
			if m.Name == "registry-auth" && !m.ReadOnly {
				t.Error("registry auth must be mounted read-only")
			}
		}
		if len(spec.ImagePullSecrets) != 0 {
			t.Error("registry auth must not be used as pod imagePullSecrets")
		}
		b, _ := json.Marshal(s.job)
		if strings.Contains(string(b), passA) || strings.Contains(string(b), base64.StdEncoding.EncodeToString([]byte(userA+":"+passA))) {
			t.Error("credentials in Job spec")
		}
	})

	t.Run("multiple secrets and registries", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-a", "krivy-it-auth-b"), "it-auth-b", refs["reg-b"])
		if s.err != nil {
			t.Fatalf("scan %s: %v", refs["reg-b"], s.err)
		}
		if got := mountedRegistrySecret(s.job); got != "krivy-it-auth-b" {
			t.Errorf("mounted %q", got)
		}
	})

	t.Run("public image gets no credentials", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-a", "krivy-it-auth-b"), "it-auth-pub", refs["reg-public"])
		if s.err != nil {
			t.Fatalf("scan %s: %v", refs["reg-public"], s.err)
		}
		if got := mountedRegistrySecret(s.job); got != "" {
			t.Errorf("public scan must not mount credentials, got %q", got)
		}
	})

	t.Run("no auth configured", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t), "it-auth-none", refs["reg-a"])
		wantAuthError(t, s, "registryAuth.existingSecrets")
		if s.res != nil {
			t.Error("auth failure must not produce a clean result")
		}
	})

	t.Run("mismatched secret", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-a"), "it-auth-mis", refs["reg-b"])
		wantAuthError(t, s, "has an entry for "+registryHost("reg-b"))
	})

	t.Run("absent secret", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-a", "krivy-it-missing"), "it-auth-abs", refs["reg-a"])
		wantAuthError(t, s, `"krivy-it-missing" not found`)
		if s.job != nil {
			t.Error("no Job may be created when a configured Secret is missing")
		}
	})

	t.Run("malformed secret", func(t *testing.T) {
		applySecret(t, cs, dockerSecret(jobNamespace, "krivy-it-malformed",
			[]byte(`{"auths":{"`+registryHost("reg-a")+`":{"auth":"not-base64!"}}}`)))
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-malformed"), "it-auth-bad", refs["reg-a"])
		wantAuthError(t, s, "is not base64")
		if s.job != nil {
			t.Error("no Job may be created for a malformed Secret")
		}
	})

	t.Run("rotated secret", func(t *testing.T) {
		// Wrong (e.g. expired) password first: the registry rejects it.
		applySecret(t, cs, dockerSecret(jobNamespace, "krivy-it-rotate", dockerConfigJSON(map[string][2]string{registryHost("reg-a"): {userA, "expired-password"}})))
		cfg := craneStubConfig(t, "krivy-it-rotate")
		s := scanWith(t, cs, cfg, "it-auth-rot1", refs["reg-a"])
		wantAuthError(t, s, `rejected the credentials from Secret "krivy-it-rotate"`)
		if strings.Contains(s.err.Error()+fmt.Sprint(s.res), "expired-password") {
			t.Error("rotated-out password leaked")
		}
		// Rotate in place; the next scan's Job uses the new value.
		applySecret(t, cs, dockerSecret(jobNamespace, "krivy-it-rotate", dockerConfigJSON(map[string][2]string{registryHost("reg-a"): {userA, passA}})))
		s = scanWith(t, cs, cfg, "it-auth-rot2", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("after rotation: %v", s.err)
		}
	})

	applySecret(t, cs, basicAuthSecret(jobNamespace, "krivy-it-basic-a", registryHost("reg-a"), userA, passA))

	t.Run("basic-auth secret, private image by digest", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-auth-b", "krivy-it-basic-a"), "it-basic-a", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("scan %s: %v", refs["reg-a"], s.err)
		}
		if len(s.res.Vulnerabilities) == 0 {
			t.Error("expected the stub report")
		}
		if got := mountedRegistrySecret(s.job); got != "krivy-it-basic-a" {
			t.Errorf("mounted %q", got)
		}
		spec := s.job.Spec.Template.Spec
		if len(spec.InitContainers) != 1 || spec.InitContainers[0].Name != scanner.AuthInitContainerName {
			t.Fatalf("init containers %+v", spec.InitContainers)
		}
		for _, m := range spec.Containers[0].VolumeMounts {
			if m.Name == "registry-auth" {
				t.Error("the scanner container must not mount the basic-auth Secret")
			}
		}
		b, _ := json.Marshal(s.job)
		for _, leak := range []string{passA, userA, base64.StdEncoding.EncodeToString([]byte(userA + ":" + passA))} {
			if strings.Contains(string(b), leak) {
				t.Errorf("Job spec contains %q", leak)
			}
		}
		// Neither container logs anything credential-related.
		pods, err := cs.CoreV1().Pods(jobNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: "batch.kubernetes.io/job-name=" + s.job.Name})
		if err != nil || len(pods.Items) == 0 {
			t.Fatalf("pods: %v", err)
		}
		for _, c := range []string{scanner.AuthInitContainerName, scanner.ContainerName} {
			out, err := cs.CoreV1().Pods(jobNamespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{Container: c}).DoRaw(context.Background())
			if err != nil {
				t.Fatalf("logs %s: %v", c, err)
			}
			if strings.Contains(string(out), passA) || strings.Contains(string(out), base64.StdEncoding.EncodeToString([]byte(userA+":"+passA))) {
				t.Errorf("container %s logged credentials", c)
			}
			if c == scanner.AuthInitContainerName && len(out) != 0 {
				t.Errorf("init container must print nothing, got %q", out)
			}
		}
	})

	t.Run("basic-auth secret is scoped to its server", func(t *testing.T) {
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-basic-a"), "it-basic-mis", refs["reg-b"])
		wantAuthError(t, s, "has an entry for "+registryHost("reg-b"))
		if got := mountedRegistrySecret(s.job); got != "" {
			t.Errorf("credentials for reg-a mounted for reg-b: %q", got)
		}
		s = scanWith(t, cs, craneStubConfig(t, "krivy-it-basic-a"), "it-basic-pub", refs["reg-public"])
		if s.err != nil || mountedRegistrySecret(s.job) != "" || len(s.job.Spec.Template.Spec.InitContainers) != 0 {
			t.Errorf("public image: err=%v mounted=%q", s.err, mountedRegistrySecret(s.job))
		}
	})

	t.Run("malformed basic-auth secret", func(t *testing.T) {
		applySecret(t, cs, basicAuthSecret(jobNamespace, "krivy-it-basic-bad", registryHost("reg-a"), userA+":x", passA))
		s := scanWith(t, cs, craneStubConfig(t, "krivy-it-basic-bad"), "it-basic-bad", refs["reg-a"])
		wantAuthError(t, s, `username contains ":"`)
		if s.job != nil {
			t.Error("no Job may be created for a malformed Secret")
		}
	})

	t.Run("rotated basic-auth secret", func(t *testing.T) {
		applySecret(t, cs, basicAuthSecret(jobNamespace, "krivy-it-basic-rot", registryHost("reg-a"), userA, "expired-password"))
		cfg := craneStubConfig(t, "krivy-it-basic-rot")
		s := scanWith(t, cs, cfg, "it-basic-rot1", refs["reg-a"])
		wantAuthError(t, s, `rejected the credentials from Secret "krivy-it-basic-rot"`)
		if strings.Contains(s.err.Error(), "expired-password") {
			t.Error("rotated-out password leaked")
		}
		applySecret(t, cs, basicAuthSecret(jobNamespace, "krivy-it-basic-rot", registryHost("reg-a"), userA, passA))
		s = scanWith(t, cs, cfg, "it-basic-rot2", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("after rotation: %v", s.err)
		}
	})

	t.Run("basic-auth server changed after resolution", func(t *testing.T) {
		// The controller resolved reg-b, but the Secret now names reg-a (a
		// rotation racing the Job): the init container must refuse to write
		// reg-a's credentials, and Trivy must never start.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cfg := craneStubConfig(t)
		tgt := scanner.Target{ScanJobID: fmt.Sprintf("%08x-race", uint32(time.Now().UnixNano())), ImageKey: refs["reg-b"], ImageRef: refs["reg-b"], Attempt: 1}
		job := scanner.BuildJob(cfg, tgt, scanner.RegistryAuth{Secret: "krivy-it-basic-a", Server: registryHost("reg-b")})
		if _, err := cs.BatchV1().Jobs(jobNamespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		for {
			pods, err := cs.CoreV1().Pods(jobNamespace).List(ctx, metav1.ListOptions{LabelSelector: "batch.kubernetes.io/job-name=" + job.Name})
			if err == nil && len(pods.Items) > 0 && pods.Items[0].Status.Phase == corev1.PodFailed {
				p := pods.Items[0]
				if len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].State.Terminated == nil {
					t.Fatalf("init status %+v", p.Status.InitContainerStatuses)
				}
				if msg := p.Status.InitContainerStatuses[0].State.Terminated.Message; strings.TrimSpace(msg) != "krivy-registry-auth: server-changed" {
					t.Errorf("init termination message %q", msg)
				}
				for _, c := range p.Status.ContainerStatuses {
					if c.State.Running != nil || c.State.Terminated != nil || c.LastTerminationState.Terminated != nil {
						t.Errorf("scanner container %s started: %+v", c.Name, c.State)
					}
				}
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("pod did not fail: %v", err)
			}
			time.Sleep(time.Second)
		}
	})

	t.Run("real trivy private image", func(t *testing.T) {
		if os.Getenv("KRIVY_INTEGRATION_REAL_TRIVY") != "1" {
			t.Skip("set KRIVY_INTEGRATION_REAL_TRIVY=1 to scan the private image with real Trivy")
		}
		cfg := scanner.ConfigFrom(config.Default())
		cfg.Namespace = jobNamespace
		cfg.RegistrySecrets = []string{"krivy-it-auth-a"}
		cfg.ExtraArgs = []string{"--insecure"}
		s := scanWith(t, cs, cfg, "it-auth-trivy", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("real trivy scan of %s: %v", refs["reg-a"], s.err)
		}
		t.Logf("real trivy scanned private %s (job %s)", refs["reg-a"], s.res.JobName)

		// The same image with the three-field Secret: the init container runs
		// the real Trivy image's busybox sh.
		cfg.RegistrySecrets = []string{"krivy-it-basic-a"}
		s = scanWith(t, cs, cfg, "it-basic-trivy", refs["reg-a"])
		if s.err != nil {
			t.Fatalf("real trivy scan with basic-auth Secret: %v", s.err)
		}
		t.Logf("real trivy scanned private %s with a basic-auth Secret (job %s)", refs["reg-a"], s.res.JobName)
	})
}
