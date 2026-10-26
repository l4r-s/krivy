package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// basicSecret is what `kubectl create secret generic --type=kubernetes.io/basic-auth`
// or a OnePasswordItem with that type and server/username/password fields
// produces.
func basicSecret(name, server, user, pass string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "krivy-system"},
		Type:       corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			basicAuthServerKey:          []byte(server),
			corev1.BasicAuthUsernameKey: []byte(user),
			corev1.BasicAuthPasswordKey: []byte(pass),
		},
	}
}

// assertNoBasicLeak fails if s contains pass in any form Krivy could derive.
func assertNoBasicLeak(t *testing.T, what, s, user, pass string) {
	t.Helper()
	assertNoLeak(t, what, s)
	for _, v := range []string{pass, basicAuth(user, pass), base64.StdEncoding.EncodeToString([]byte(pass))} {
		if strings.Contains(s, v) {
			t.Errorf("%s leaks %q: %s", what, v, s)
		}
	}
}

func TestResolveAuthBasicAuthSelection(t *testing.T) {
	cases := []struct {
		name    string
		secrets []runtime.Object
		order   []string
		image   string
		want    string
		server  string // RegistryAuth.Server, "" for dockerconfigjson or none
	}{
		{"basic-auth secret for its server",
			[]runtime.Object{basicSecret("hilars", "registry.hilars.dev", "robot", pwA)}, []string{"hilars"},
			"registry.hilars.dev/team/app@sha256:1", "hilars", "registry.hilars.dev"},
		{"public image gets no credentials",
			[]runtime.Object{basicSecret("hilars", "registry.hilars.dev", "robot", pwA)}, []string{"hilars"},
			"docker.io/library/nginx@sha256:1", "", ""},
		{"other registry gets no credentials",
			[]runtime.Object{basicSecret("hilars", "registry.hilars.dev", "robot", pwA)}, []string{"hilars"},
			"ghcr.io/org/app:1", "", ""},
		{"mixed with dockerconfigjson, basic-auth matches",
			[]runtime.Object{regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwB})), basicSecret("hilars", "registry.hilars.dev:5000", "robot", pwA)},
			[]string{"ghcr", "hilars"}, "registry.hilars.dev:5000/app:1", "hilars", "registry.hilars.dev:5000"},
		{"mixed with dockerconfigjson, dockerconfigjson matches",
			[]runtime.Object{regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwB})), basicSecret("hilars", "registry.hilars.dev", "robot", pwA)},
			[]string{"ghcr", "hilars"}, "ghcr.io/org/app:1", "ghcr", ""},
		{"tie goes to the first listed secret",
			[]runtime.Object{regSecret("cfg", dockerJSON(map[string]string{"registry.hilars.dev": pwB})), basicSecret("hilars", "registry.hilars.dev", "robot", pwA)},
			[]string{"hilars", "cfg"}, "registry.hilars.dev/app:1", "hilars", "registry.hilars.dev"},
		{"path server covers only its path",
			[]runtime.Object{basicSecret("team", "registry.hilars.dev/team", "robot", pwA)}, []string{"team"},
			"registry.hilars.dev/other/app:1", "", ""},
		{"path server beats a host entry",
			[]runtime.Object{regSecret("host", dockerJSON(map[string]string{"registry.hilars.dev": pwB})), basicSecret("team", "registry.hilars.dev/team", "robot", pwA)},
			[]string{"host", "team"}, "registry.hilars.dev/team/app:1", "team", "registry.hilars.dev/team"},
		{"URL server is host-wide",
			[]runtime.Object{basicSecret("hilars", "https://registry.hilars.dev", "robot", pwA)}, []string{"hilars"},
			"registry.hilars.dev/app:1", "hilars", "https://registry.hilars.dev"},
		{"docker hub with the kubectl default server",
			[]runtime.Object{basicSecret("hub", "https://index.docker.io/v1/", "robot", pwA)}, []string{"hub"},
			"acme/private:1", "hub", "https://index.docker.io/v1/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := authScanner(tc.order, tc.secrets...).resolveAuth(context.Background(), tc.image)
			if err != nil {
				t.Fatal(err)
			}
			m := res.mount()
			if m.Secret != tc.want || m.Server != tc.server {
				t.Errorf("mount %+v, want secret=%q server=%q", m, tc.want, tc.server)
			}
			if tc.want == "hilars" || tc.want == "team" || tc.want == "hub" {
				joined := strings.Join(res.redact, "\n")
				if !strings.Contains(joined, pwA) || !strings.Contains(joined, basicAuth("robot", pwA)) {
					t.Error("password and generated auth must be redacted")
				}
			}
			msg, hints := res.authFailure()
			assertNoBasicLeak(t, "authFailure", res.describe()+msg+strings.Join(hints, ""), "robot", pwA)
		})
	}
}

func TestResolveAuthInvalidBasicAuthSecrets(t *testing.T) {
	valid := regSecret("valid", dockerJSON(map[string]string{"ghcr.io": pwA}))
	without := func(key string) *corev1.Secret {
		s := basicSecret("bad", "registry.hilars.dev", "robot", pwB)
		delete(s.Data, key)
		return s
	}
	empty := basicSecret("bad", "registry.hilars.dev", "", pwB)
	opaque := basicSecret("bad", "registry.hilars.dev", "robot", pwB)
	opaque.Type = corev1.SecretTypeOpaque
	cases := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{"no server", without(basicAuthServerKey), "no or an empty server key"},
		{"no password", without(corev1.BasicAuthPasswordKey), "no or an empty password key"},
		{"empty username", empty, "no or an empty username key"},
		{"server with scheme only", basicSecret("bad", "https://", "robot", pwB), "server is not a registry"},
		{"server with quote", basicSecret("bad", `registry.hilars.dev"x`, "robot", pwB), "server is not a registry"},
		{"server with wildcard", basicSecret("bad", "*.hilars.dev", "robot", pwB), "server is not a registry"},
		{"server with newline", basicSecret("bad", "registry.hilars.dev\n", "robot", pwB), "server is not a registry"},
		{"server with credentials", basicSecret("bad", "https://robot:x@registry.hilars.dev", "robot", pwB), "server is not a registry"},
		{"server with other scheme", basicSecret("bad", "ftp://registry.hilars.dev", "robot", pwB), "server is not a registry"},
		{"server with bad port", basicSecret("bad", "registry.hilars.dev:port", "robot", pwB), "server is not a registry"},
		{"username with colon", basicSecret("bad", "registry.hilars.dev", "ro:bot", pwB), `username contains ":"`},
		{"password with trailing newline", basicSecret("bad", "registry.hilars.dev", "robot", pwB+"\n"), "trailing newline"},
		{"opaque with three fields", opaque, "needs type kubernetes.io/basic-auth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, img := range []string{"registry.hilars.dev/app:1", "docker.io/library/nginx:1"} {
				_, err := authScanner([]string{"valid", "bad"}, valid, tc.secret).resolveAuth(context.Background(), img)
				var se *Error
				if !errors.As(err, &se) || se.Kind != KindRegistryAuth || se.Retryable {
					t.Fatalf("%s: want non-retryable registry_auth, got %v", img, err)
				}
				if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "krivy-system/bad") {
					t.Errorf("%s: error %q missing %q", img, err, tc.want)
				}
				assertNoBasicLeak(t, "error", err.Error()+se.Diagnostics, "robot", pwB)
			}
		})
	}
	// The generic wrong-type message lists both accepted types.
	other := regSecret("bad", nil)
	other.Type = "example.com/custom"
	_, err := authScanner([]string{"bad"}, other).resolveAuth(context.Background(), "ghcr.io/a/b:1")
	if err == nil || !strings.Contains(err.Error(), "kubernetes.io/basic-auth with server/username/password keys") {
		t.Errorf("got %v", err)
	}
}

func TestBuildJobBasicAuth(t *testing.T) {
	cfg := testConfig()
	tgt := Target{ScanJobID: "abc", ImageRef: "registry.hilars.dev/app@sha256:1", Attempt: 1}
	j := BuildJob(cfg, tgt, RegistryAuth{Secret: "hilars", Server: "registry.hilars.dev"})
	spec := j.Spec.Template.Spec
	if j.Annotations[AnnotationRegistryAuth] != "hilars" {
		t.Errorf("annotations %v", j.Annotations)
	}
	vols := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		vols[v.Name] = v
		if v.PersistentVolumeClaim != nil || v.HostPath != nil {
			t.Errorf("forbidden volume %s", v.Name)
		}
	}
	sv := vols["registry-auth"].Secret
	if sv == nil || sv.SecretName != "hilars" || sv.Optional == nil || !*sv.Optional || *sv.DefaultMode != 0o440 {
		t.Fatalf("registry-auth volume %+v", vols["registry-auth"])
	}
	var keys []string
	for _, it := range sv.Items {
		keys = append(keys, it.Key)
	}
	if strings.Join(keys, ",") != "server,username,password" {
		t.Errorf("secret volume items %v: only the three keys may be projected", keys)
	}
	ed := vols["docker-config"].EmptyDir
	if ed == nil || ed.Medium != corev1.StorageMediumMemory || ed.SizeLimit == nil {
		t.Errorf("docker-config must be a size-limited tmpfs emptyDir: %+v", vols["docker-config"])
	}

	if len(spec.InitContainers) != 1 {
		t.Fatalf("init containers %d", len(spec.InitContainers))
	}
	ic, c := spec.InitContainers[0], spec.Containers[0]
	if ic.Name != AuthInitContainerName || ic.Image != cfg.Image || ic.Command[0] != "sh" || len(ic.Args) != 0 {
		t.Errorf("init container %s %s %v %v", ic.Name, ic.Image, ic.Command, ic.Args)
	}
	sc := ic.SecurityContext
	if sc == nil || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem || !*sc.RunAsNonRoot || *sc.Privileged ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("init container security context %+v", sc)
	}
	initMounts := map[string]corev1.VolumeMount{}
	for _, m := range ic.VolumeMounts {
		initMounts[m.Name] = m
	}
	if m := initMounts["registry-auth"]; !m.ReadOnly || m.MountPath != basicAuthDir {
		t.Errorf("init registry-auth mount %+v", m)
	}
	if m := initMounts["docker-config"]; m.ReadOnly || m.MountPath != dockerDir {
		t.Errorf("init docker-config mount %+v", m)
	}
	initEnv := map[string]string{}
	for _, e := range ic.Env {
		if e.ValueFrom != nil {
			t.Errorf("init env %s must not reference Secret values", e.Name)
		}
		initEnv[e.Name] = e.Value
	}
	if initEnv["KRIVY_REGISTRY_SERVER"] != "registry.hilars.dev" || initEnv["DOCKER_CONFIG"] != dockerDir || initEnv["KRIVY_REGISTRY_AUTH_DIR"] != basicAuthDir {
		t.Errorf("init env %v", initEnv)
	}

	// Trivy sees only the generated config, read-only, never the raw keys.
	for _, m := range c.VolumeMounts {
		if m.Name == "registry-auth" {
			t.Error("trivy must not mount the basic-auth Secret")
		}
		if m.Name == "docker-config" && (!m.ReadOnly || m.MountPath != dockerDir) {
			t.Errorf("trivy docker-config mount %+v", m)
		}
	}
	for _, e := range c.Env {
		if e.ValueFrom != nil {
			t.Errorf("trivy env %s must not reference Secret values", e.Name)
		}
	}
	// Trivy's arguments are the same as without credentials.
	plain := BuildJob(cfg, tgt, RegistryAuth{})
	if strings.Join(c.Args, " ") != strings.Join(plain.Spec.Template.Spec.Containers[0].Args, " ") {
		t.Errorf("args changed: %v", c.Args)
	}
	if len(plain.Spec.Template.Spec.InitContainers) != 0 {
		t.Error("no init container without credentials")
	}
	// A dockerconfigjson Secret needs no init container.
	if cj := BuildJob(cfg, tgt, RegistryAuth{Secret: "cfg"}); len(cj.Spec.Template.Spec.InitContainers) != 0 {
		t.Error("dockerconfigjson Secret must not add an init container")
	}
}

func TestScanPrivateImageBasicAuth(t *testing.T) {
	h := newHarness(t)
	h.tgt.ImageRef = "registry.hilars.dev/team/app@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	h.withSecrets([]string{"ghcr", "hilars"},
		regSecret("ghcr", dockerJSON(map[string]string{"ghcr.io": pwB})),
		basicSecret("hilars", "registry.hilars.dev", "robot", pwA))
	h.logs = fixture(t, "vulnerable.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	res, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if err != nil || len(res.Vulnerabilities) != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	j := h.job(t)
	if got := mountedSecret(j); got != "hilars" {
		t.Errorf("mounted %q", got)
	}
	if ics := j.Spec.Template.Spec.InitContainers; len(ics) != 1 || ics[0].Env[0].Value != "registry.hilars.dev" {
		t.Errorf("init containers %+v", ics)
	}
	spec, _ := json.Marshal(j)
	assertNoBasicLeak(t, "job spec", string(spec), "robot", pwA)
	if strings.Contains(string(spec), "robot") {
		t.Error("job spec contains the username")
	}
	assertNoBasicLeak(t, "diagnostics", res.Diagnostics, "robot", pwA)
}

func TestScanBasicAuthInitFailure(t *testing.T) {
	initFailed := func(code int32, reason, msg string) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodFailed
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: AuthInitContainerName, State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Reason: reason, Message: msg},
			}}}
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: ContainerName, State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"},
			}}}
		}
	}
	cases := []struct {
		name string
		pod  func(*corev1.Pod)
		msg  string
	}{
		{"server changed after resolution", initFailed(1, "Error", "krivy-registry-auth: server-changed\n"),
			`Secret "hilars" changed its server after the scan started`},
		{"secret deleted after resolution", initFailed(1, "Error", "krivy-registry-auth: missing-server\n"),
			`Secret "hilars" was deleted or lost its server key`},
		{"lost password key", initFailed(1, "Error", "krivy-registry-auth: missing-password\n"),
			"lost its password key"},
		{"trivy image without a shell", initFailed(128, "StartError", `exec: "sh": executable file not found in $PATH`),
			"exited with code 128 (StartError); the Trivy image must provide sh"},
		{"unknown code is not echoed", initFailed(1, "Error", "krivy-registry-auth: missing-"+pwA+"\n"),
			"exited with code 1 (Error)"},
		{"unexpected output is redacted", initFailed(2, "Error", "base64: write error: "+pwA+" "+basicAuth("robot", pwA)),
			"exited with code 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.tgt.ImageRef = "registry.hilars.dev/app@sha256:1"
			h.withSecrets([]string{"hilars"}, basicSecret("hilars", "registry.hilars.dev", "robot", pwA))
			h.finishJob(t, tc.pod, batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"})
			_, err := h.scanner().Scan(withTimeout(t), h.tgt)
			var se *Error
			if !errors.As(err, &se) || se.Kind != KindRegistryAuth || se.Retryable {
				t.Fatalf("want non-retryable registry_auth, got %v", err)
			}
			if !strings.Contains(se.Msg, tc.msg) {
				t.Errorf("msg %q missing %q", se.Msg, tc.msg)
			}
			if !strings.Contains(se.Diagnostics, "container="+AuthInitContainerName) {
				t.Errorf("diagnostics lack the init container: %q", se.Diagnostics)
			}
			assertNoBasicLeak(t, "error", se.Error()+se.Diagnostics, "robot", pwA)
		})
	}
}

func TestCheckPendingInitContainerPullFailure(t *testing.T) {
	h := newHarness(t)
	h.cfg.SchedulingGracePeriod = time.Millisecond
	h.tgt.ImageRef = "registry.hilars.dev/app@sha256:1"
	h.withSecrets([]string{"hilars"}, basicSecret("hilars", "registry.hilars.dev", "robot", pwA))
	go func() {
		for !h.jobExists() {
			time.Sleep(time.Millisecond)
		}
		h.createPod(t, func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodPending
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: AuthInitContainerName, State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "back-off pulling trivy"},
			}}}
		})
	}()
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindScheduling || !strings.Contains(err.Error(), "ImagePullBackOff") {
		t.Fatalf("got %v", err)
	}
}

// TestBasicAuthScript runs the init container script with the local sh.
// Official Trivy images run it with busybox sh; CI runners use dash/bash.
func TestBasicAuthScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, tool := range []string{"cat", "base64", "tr"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	type result struct {
		code           int
		stdout, stderr string
		config         []byte
	}
	run := func(t *testing.T, server string, files map[string]string) result {
		t.Helper()
		dir := t.TempDir()
		authDir, dockerCfg := filepath.Join(dir, "auth"), filepath.Join(dir, "docker")
		for _, d := range []string{authDir, dockerCfg} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for k, v := range files {
			if err := os.WriteFile(filepath.Join(authDir, k), []byte(v), 0o400); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(sh, "-c", basicAuthScript)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "KRIVY_REGISTRY_SERVER=" + server, "KRIVY_REGISTRY_AUTH_DIR=" + authDir, "DOCKER_CONFIG=" + dockerCfg}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var r result
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
			r.code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		r.stdout, r.stderr = stdout.String(), stderr.String()
		if b, err := os.ReadFile(filepath.Join(dockerCfg, "config.json")); err == nil {
			r.config = b
			if st, _ := os.Stat(filepath.Join(dockerCfg, "config.json")); st.Mode().Perm() != 0o600 {
				t.Errorf("config.json mode %v, want 0600", st.Mode().Perm())
			}
		}
		return r
	}

	passwords := map[string]string{
		"simple":                        pwA,
		"json and shell metacharacters": `p"a\ss'$HOME` + "`id`" + `%s%n;|&<>{}*?!#~ =`,
		"leading dash and unicode":      "-n -e päss🔑",
		"longer than one base64 line":   strings.Repeat("0123456789abcdef", 16),
	}
	for name, pass := range passwords {
		t.Run(name, func(t *testing.T) {
			server := "registry.hilars.dev:5000"
			r := run(t, server, map[string]string{"server": server, "username": "robot", "password": pass})
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			if r.stdout != "" || r.stderr != "" {
				t.Errorf("script must print nothing: %q %q", r.stdout, r.stderr)
			}
			var cfg dockerConfig
			if err := json.Unmarshal(r.config, &cfg); err != nil {
				t.Fatalf("config.json is not valid JSON: %v", err)
			}
			if len(cfg.Auths) != 1 {
				t.Fatalf("auths %v", cfg.Auths)
			}
			user, got, err := decodeDockerAuth(cfg.Auths[server].Auth)
			if err != nil || user != "robot" || got != pass {
				t.Errorf("auth decodes to %q/%q (%v)", user, got, err)
			}
			img, _ := parseImageRepo(server + "/team/app@sha256:1")
			if key, amb := trivyLookup(cfg, img); key != server || amb != nil {
				t.Errorf("trivy lookup %q %v", key, amb)
			}
		})
	}

	failures := []struct {
		name   string
		files  map[string]string
		stderr string
	}{
		{"server changed", map[string]string{"server": "evil.example.com", "username": "robot", "password": pwA}, "krivy-registry-auth: server-changed"},
		{"deleted secret", nil, "krivy-registry-auth: missing-server"},
		{"missing password", map[string]string{"server": "registry.hilars.dev", "username": "robot"}, "krivy-registry-auth: missing-password"},
		{"empty username", map[string]string{"server": "registry.hilars.dev", "username": "", "password": pwA}, "krivy-registry-auth: missing-username"},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "registry.hilars.dev", tc.files)
			if r.code != 1 || strings.TrimSpace(r.stderr) != tc.stderr {
				t.Errorf("exit %d stderr %q, want 1 %q", r.code, r.stderr, tc.stderr)
			}
			if r.config != nil {
				t.Error("no config.json may be written on failure")
			}
			assertNoBasicLeak(t, "output", r.stdout+r.stderr, "robot", pwA)
		})
	}
}
