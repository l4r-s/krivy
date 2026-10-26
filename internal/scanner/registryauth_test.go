package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Sentinel credentials: tests assert they never appear in errors, diagnostics
// or Job specs.
const (
	pwA = "s3cr3t-pass-A"
	pwB = "s3cr3t-pass-B"
)

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// dockerJSON builds a .dockerconfigjson with one auth entry per key.
func dockerJSON(entries map[string]string) []byte {
	auths := map[string]map[string]string{}
	for k, pass := range entries {
		auths[k] = map[string]string{"auth": basicAuth("user", pass)}
	}
	b, _ := json.Marshal(map[string]any{"auths": auths})
	return b
}

func regSecret(name string, data []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krivy-system"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: data},
	}
}

func authScanner(secrets []string, objs ...runtime.Object) *kubeScanner {
	cfg := testConfig()
	cfg.RegistrySecrets = secrets
	return NewKubernetes(fake.NewClientset(objs...), cfg).(*kubeScanner)
}

// assertNoLeak fails if s contains any credential material.
func assertNoLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, v := range []string{pwA, pwB, basicAuth("user", pwA), basicAuth("user", pwB), "not-base64!", "hunter2"} {
		if strings.Contains(s, v) {
			t.Errorf("%s leaks %q: %s", what, v, s)
		}
	}
}

func TestParseImageRepo(t *testing.T) {
	cases := map[string]imageRepo{
		"nginx":                                    {dockerHubRegistry, "library/nginx"},
		"docker.io/library/nginx:1.27":             {dockerHubRegistry, "library/nginx"},
		"docker.io/bitnami/redis@sha256:abc":       {dockerHubRegistry, "bitnami/redis"},
		"ghcr.io/org/app@sha256:abc":               {"ghcr.io", "org/app"},
		"ghcr.io/org/team/app:v1":                  {"ghcr.io", "org/team/app"},
		"localhost/app":                            {"localhost", "app"},
		"registry.example.com:5000/x/y:2@sha256:1": {"registry.example.com:5000", "x/y"},
	}
	for ref, want := range cases {
		got, ok := parseImageRepo(ref)
		if !ok || got != want {
			t.Errorf("%s: got %+v ok=%v, want %+v", ref, got, ok, want)
		}
	}
	if _, ok := parseImageRepo(""); ok {
		t.Error("empty ref accepted")
	}
}

func TestResolveAuthSelection(t *testing.T) {
	cases := []struct {
		name    string
		secrets map[string][]byte // name -> data
		order   []string
		image   string
		want    string // Secret name, "" = none
		wantKey string
		hint    string
	}{
		{"public image gets no credentials",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA})}, []string{"a"},
			"docker.io/library/nginx@sha256:1", "", "", ""},
		{"multiple registries, first secret",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA}), "b": dockerJSON(map[string]string{"registry.example.com:5000": pwB})},
			[]string{"a", "b"}, "ghcr.io/org/app@sha256:1", "a", "ghcr.io", ""},
		{"multiple registries, second secret",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA}), "b": dockerJSON(map[string]string{"registry.example.com:5000": pwB})},
			[]string{"a", "b"}, "registry.example.com:5000/x/y:1", "b", "registry.example.com:5000", ""},
		{"one secret, several registries",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA, "quay.io": pwB})},
			[]string{"a"}, "quay.io/org/app:1", "a", "quay.io", ""},
		{"tie goes to the first listed secret",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA}), "b": dockerJSON(map[string]string{"ghcr.io": pwB})},
			[]string{"b", "a"}, "ghcr.io/org/app:1", "b", "ghcr.io", ""},
		{"path entry beats host entry",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA}), "b": dockerJSON(map[string]string{"ghcr.io/org-b": pwB})},
			[]string{"a", "b"}, "ghcr.io/org-b/app:1", "b", "ghcr.io/org-b", ""},
		{"path entry does not cover other paths",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA}), "b": dockerJSON(map[string]string{"ghcr.io/org-b": pwB})},
			[]string{"a", "b"}, "ghcr.io/org-a/app:1", "a", "ghcr.io", ""},
		{"path entry is segment-aware",
			map[string][]byte{"b": dockerJSON(map[string]string{"ghcr.io/org": pwB})},
			[]string{"b"}, "ghcr.io/orgs/app:1", "", "", `entry "ghcr.io/org" does not cover repository orgs/app`},
		{"exact repository entry beats path",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io/org": pwA}), "b": dockerJSON(map[string]string{"ghcr.io/org/app": pwB})},
			[]string{"a", "b"}, "ghcr.io/org/app@sha256:1", "b", "ghcr.io/org/app", ""},
		{"URL key is host-wide",
			map[string][]byte{"a": dockerJSON(map[string]string{"https://registry.example.com/v2/": pwA})},
			[]string{"a"}, "registry.example.com/x/y:1", "a", "https://registry.example.com/v2/", ""},
		{"docker hub needs the legacy key",
			map[string][]byte{"a": dockerJSON(map[string]string{"https://index.docker.io/v1/": pwA})},
			[]string{"a"}, "docker.io/acme/private:1", "a", "https://index.docker.io/v1/", ""},
		{"docker hub alias is not read by trivy",
			map[string][]byte{"a": dockerJSON(map[string]string{"docker.io": pwA})},
			[]string{"a"}, "acme/private:1", "", "", `Trivy reads only "https://index.docker.io/v1/"`},
		{"same secret: exact host key is what trivy uses",
			map[string][]byte{"a": dockerJSON(map[string]string{"ghcr.io": pwA, "https://ghcr.io": pwB})},
			[]string{"a"}, "ghcr.io/org/app:1", "a", "ghcr.io", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			for n, d := range tc.secrets {
				objs = append(objs, regSecret(n, d))
			}
			res, err := authScanner(tc.order, objs...).resolveAuth(context.Background(), tc.image)
			if err != nil {
				t.Fatal(err)
			}
			if res.secret != tc.want || res.key != tc.wantKey {
				t.Errorf("got secret=%q key=%q, want %q/%q", res.secret, res.key, tc.want, tc.wantKey)
			}
			if tc.hint != "" && !strings.Contains(strings.Join(res.hints, "\n"), tc.hint) {
				t.Errorf("hints %q missing %q", res.hints, tc.hint)
			}
			if tc.want == "" && len(res.redact) != 0 {
				t.Error("no Secret selected but redaction values set")
			}
			assertNoLeak(t, "describe", res.describe())
			msg, hints := res.authFailure()
			assertNoLeak(t, "authFailure", msg+strings.Join(hints, ""))
		})
	}
}

func TestResolveAuthNoConfig(t *testing.T) {
	res, err := authScanner(nil).resolveAuth(context.Background(), "ghcr.io/org/app:1")
	if err != nil || res.secret != "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if msg, _ := res.authFailure(); !strings.Contains(msg, "registryAuth.existingSecrets") {
		t.Errorf("no-config auth failure should point at registryAuth: %s", msg)
	}
}

func TestResolveAuthAmbiguous(t *testing.T) {
	for name, data := range map[string][]byte{
		"two paths, one secret":   dockerJSON(map[string]string{"ghcr.io/org-a": pwA, "ghcr.io/org-b": pwB}),
		"host shadows path entry": dockerJSON(map[string]string{"ghcr.io": pwA, "ghcr.io/org-a": pwB}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := authScanner([]string{"a"}, regSecret("a", data)).resolveAuth(context.Background(), "ghcr.io/org-a/app:1")
			if kindOf(err) != KindRegistryAuth || IsRetryable(err) || !strings.Contains(err.Error(), "separate") && !strings.Contains(err.Error(), "own Secret") {
				t.Fatalf("want non-retryable registry_auth error, got %v", err)
			}
			assertNoLeak(t, "error", err.Error())
		})
	}
	// Identical credentials are not ambiguous.
	same := dockerJSON(map[string]string{"ghcr.io/org-a": pwA, "ghcr.io/org-b": pwA})
	res, err := authScanner([]string{"a"}, regSecret("a", same)).resolveAuth(context.Background(), "ghcr.io/org-a/app:1")
	if err != nil || res.secret != "a" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestResolveAuthInvalidSecrets(t *testing.T) {
	valid := regSecret("valid", dockerJSON(map[string]string{"ghcr.io": pwA}))
	withType := func(typ corev1.SecretType, key string, data []byte) *corev1.Secret {
		s := regSecret("bad", nil)
		s.Type, s.Data = typ, map[string][]byte{key: data}
		return s
	}
	cases := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{"absent", nil, `"bad" not found in namespace krivy-system`},
		{"opaque", withType(corev1.SecretTypeOpaque, corev1.DockerConfigJsonKey, dockerJSON(map[string]string{"ghcr.io": pwB})), `type "Opaque"`},
		{"dockercfg", withType(corev1.SecretTypeDockercfg, corev1.DockerConfigKey, []byte(`{"ghcr.io":{"auth":"`+basicAuth("u", pwB)+`"}}`)), "kubernetes.io/dockercfg"},
		{"missing key", withType(corev1.SecretTypeDockerConfigJson, "other", []byte("{}")), "no .dockerconfigjson key"},
		{"invalid json", regSecret("bad", []byte(`{"auths": {"ghcr.io": {"auth": "`+pwB+`"`)), "not a valid Docker config.json"},
		{"wrong json type", regSecret("bad", []byte(`{"auths": ["`+pwB+`"]}`)), "not a valid Docker config.json"},
		{"no auths", regSecret("bad", []byte(`{"auths": {}}`)), "no auths entries"},
		{"creds store", regSecret("bad", []byte(`{"auths": {"ghcr.io": {"auth": "`+basicAuth("u", pwB)+`"}}, "credsStore": "desktop"}`)), "credsStore/credHelpers"},
		{"bad key", regSecret("bad", []byte(`{"auths": {"`+pwB+` x": {"auth": "`+basicAuth("u", pwB)+`"}}}`)), "not a registry host"},
		{"not base64", regSecret("bad", []byte(`{"auths": {"ghcr.io": {"auth": "not-base64!"}}}`)), `auths["ghcr.io"].auth is not base64`},
		{"no colon", regSecret("bad", []byte(`{"auths": {"ghcr.io": {"auth": "`+base64.StdEncoding.EncodeToString([]byte(pwB))+`"}}}`)), `"user:password"`},
		{"no credentials", regSecret("bad", []byte(`{"auths": {"ghcr.io": {"email": "a@b.c"}}}`)), "has no credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []runtime.Object{valid}
			if tc.secret != nil {
				objs = append(objs, tc.secret)
			}
			// The broken Secret is listed after a valid, matching one: the scan
			// still fails (fail closed), for private and public images alike.
			for _, img := range []string{"ghcr.io/org/app:1", "docker.io/library/nginx:1"} {
				_, err := authScanner([]string{"valid", "bad"}, objs...).resolveAuth(context.Background(), img)
				var se *Error
				if !errors.As(err, &se) || se.Kind != KindRegistryAuth || se.Retryable {
					t.Fatalf("%s: want non-retryable registry_auth, got %v", img, err)
				}
				if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "bad") {
					t.Errorf("%s: error %q missing %q", img, err, tc.want)
				}
				assertNoLeak(t, "error", err.Error()+se.Diagnostics)
			}
		})
	}
}

func TestResolveAuthAPIErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		kind      ErrorKind
		retryable bool
	}{
		"forbidden": {apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "a", errors.New("rbac")), KindRegistryAuth, false},
		"transient": {apierrors.NewServiceUnavailable("etcd"), KindKubernetes, true},
	} {
		t.Run(name, func(t *testing.T) {
			s := authScanner([]string{"a"})
			s.client.(*fake.Clientset).PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			_, err := s.resolveAuth(context.Background(), "ghcr.io/org/app:1")
			if kindOf(err) != tc.kind || IsRetryable(err) != tc.retryable {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// ---------- Scan with registry auth ----------

func (h *harness) withSecrets(names []string, secrets ...*corev1.Secret) {
	h.cfg.RegistrySecrets = names
	for _, s := range secrets {
		if _, err := h.client.CoreV1().Secrets(s.Namespace).Create(context.Background(), s, metav1.CreateOptions{}); err != nil {
			panic(err)
		}
	}
}

func (h *harness) job(t *testing.T) *batchv1.Job {
	t.Helper()
	j, err := h.client.BatchV1().Jobs(h.cfg.Namespace).Get(context.Background(), h.jobName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func mountedSecret(j *batchv1.Job) string {
	for _, v := range j.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			return v.Secret.SecretName
		}
	}
	return ""
}

func TestScanPrivateImageMountsSelectedSecret(t *testing.T) {
	h := newHarness(t)
	h.tgt.ImageRef = "registry.example.com:5000/team/app@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	h.withSecrets([]string{"ghcr", "internal"},
		regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwA})),
		regSecret("internal", dockerJSON(map[string]string{"registry.example.com:5000": pwB})))
	h.logs = fixture(t, "vulnerable.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	res, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if err != nil || len(res.Vulnerabilities) != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	j := h.job(t)
	if got := mountedSecret(j); got != "internal" {
		t.Errorf("mounted %q, want internal", got)
	}
	if j.Annotations[AnnotationRegistryAuth] != "internal" {
		t.Errorf("annotations %v", j.Annotations)
	}
	spec, _ := json.Marshal(j)
	assertNoLeak(t, "job spec", string(spec))
	if strings.Contains(string(spec), base64.StdEncoding.EncodeToString(dockerJSON(map[string]string{"registry.example.com:5000": pwB}))) {
		t.Error("job spec contains Secret data")
	}
	assertNoLeak(t, "diagnostics", res.Diagnostics)
}

func TestScanPublicImageWithoutCredentials(t *testing.T) {
	h := newHarness(t)
	h.tgt.ImageRef = "docker.io/library/nginx@sha256:11"
	h.withSecrets([]string{"ghcr"}, regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwA})))
	h.logs = fixture(t, "clean.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	if _, err := h.scanner().Scan(withTimeout(t), h.tgt); err != nil {
		t.Fatal(err)
	}
	j := h.job(t)
	if got := mountedSecret(j); got != "" {
		t.Errorf("public image must not get credentials, mounted %q", got)
	}
	for _, e := range j.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "DOCKER_CONFIG" {
			t.Error("DOCKER_CONFIG set without credentials")
		}
	}
}

func TestScanMalformedSecretCreatesNoJob(t *testing.T) {
	h := newHarness(t)
	h.tgt.ImageRef = "ghcr.io/org/app:1"
	h.withSecrets([]string{"ghcr"}, regSecret("ghcr", []byte(`{"auths": {"ghcr.io": {"auth": "not-base64!"}}}`)))
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindRegistryAuth || IsRetryable(err) {
		t.Fatalf("got %v", err)
	}
	assertNoLeak(t, "error", err.Error())
	if h.jobExists() {
		t.Error("no Job may be created for an invalid registry auth Secret")
	}
}

func TestScanRotatedSecret(t *testing.T) {
	h := newHarness(t)
	h.tgt.ImageRef = "ghcr.io/org/app:1"
	h.withSecrets([]string{"ghcr"}, regSecret("ghcr", []byte(`{"auths": {"ghcr.io": {"auth": "not-base64!"}}}`)))
	if _, err := h.scanner().Scan(withTimeout(t), h.tgt); kindOf(err) != KindRegistryAuth {
		t.Fatalf("broken Secret: got %v", err)
	}
	// Rotate in place: the next scan reads the new value; nothing is cached.
	if _, err := h.client.CoreV1().Secrets("krivy-system").Update(context.Background(),
		regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwA})), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.logs = fixture(t, "clean.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	if _, err := h.scanner().Scan(withTimeout(t), h.tgt); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if got := mountedSecret(h.job(t)); got != "ghcr" {
		t.Errorf("mounted %q", got)
	}
}

func TestScanAuthFailureClassification(t *testing.T) {
	cases := []struct {
		name    string
		secrets []string
		image   string
		logs    string
		kind    ErrorKind
		msg     string
		hint    string
	}{
		{"rejected credentials (expired)", []string{"ghcr"}, "ghcr.io/org/app@sha256:1",
			"FATAL image scan error: GET https://ghcr.io/token: UNAUTHORIZED: authentication required (auth " + basicAuth("user", pwA) + " pw " + pwA + ")",
			KindRegistryAuth, `rejected the credentials from Secret "ghcr" (entry "ghcr.io")`, ""},
		{"forbidden by registry", []string{"ghcr"}, "ghcr.io/org/app@sha256:1",
			"unexpected status code 403 Forbidden",
			KindRegistryAuth, `rejected the credentials from Secret "ghcr"`, ""},
		{"mismatched registry", []string{"ghcr"}, "quay.io/org/app@sha256:1",
			"UNAUTHORIZED: access to the requested resource is not authorized",
			KindRegistryAuth, "no Secret in registryAuth.existingSecrets has an entry for quay.io", ""},
		{"mismatched path", []string{"ghcr-path"}, "ghcr.io/other/app@sha256:1",
			"UNAUTHORIZED: authentication required",
			KindRegistryAuth, "no Secret in registryAuth.existingSecrets has an entry for ghcr.io", `entry "ghcr.io/org" does not cover repository other/app`},
		{"no auth configured", nil, "ghcr.io/org/app@sha256:1",
			"UNAUTHORIZED: authentication required",
			KindRegistryAuth, "add a kubernetes.io/dockerconfigjson or kubernetes.io/basic-auth Secret to registryAuth.existingSecrets", ""},
		{"not found", []string{"ghcr"}, "ghcr.io/org/app@sha256:1",
			"MANIFEST_UNKNOWN: manifest unknown",
			KindImagePull, "could not find the image", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.tgt.ImageRef = tc.image
			h.withSecrets(tc.secrets,
				regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwA})),
				regSecret("ghcr-path", dockerJSON(map[string]string{"ghcr.io/org": pwB})))
			h.logs = []byte(tc.logs)
			h.finishJob(t, terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"})
			_, err := h.scanner().Scan(withTimeout(t), h.tgt)
			var se *Error
			if !errors.As(err, &se) || se.Kind != tc.kind || se.Retryable {
				t.Fatalf("want non-retryable %s, got %v", tc.kind, err)
			}
			if !strings.Contains(se.Msg, tc.msg) {
				t.Errorf("msg %q missing %q", se.Msg, tc.msg)
			}
			if tc.hint != "" && !strings.Contains(se.Diagnostics, tc.hint) {
				t.Errorf("diagnostics %q missing hint %q", se.Diagnostics, tc.hint)
			}
			if !strings.Contains(se.Diagnostics, "registry auth:") {
				t.Errorf("diagnostics lack registry auth summary: %q", se.Diagnostics)
			}
			assertNoLeak(t, "error", fmt.Sprint(err)+se.Diagnostics)
		})
	}
}
