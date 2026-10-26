package scanner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/l4r-s/krivy/internal/config"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func kindOf(err error) ErrorKind {
	var se *Error
	if errors.As(err, &se) {
		return se.Kind
	}
	return ""
}

// ---------- ParseReport ----------

func TestParseReportVulnerable(t *testing.T) {
	res, err := ParseReport(bytes.NewReader(fixture(t, "vulnerable.json")), []string{"CRITICAL"})
	if err != nil {
		t.Fatal(err)
	}
	if res.OS != "debian 12.5" {
		t.Errorf("OS = %q", res.OS)
	}
	if res.ImageDigest != "sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Errorf("digest = %q", res.ImageDigest)
	}
	// 5 entries: 1 duplicate dropped, 1 HIGH filtered, lowercase "critical" kept.
	if len(res.Vulnerabilities) != 3 {
		t.Fatalf("got %d vulns: %+v", len(res.Vulnerabilities), res.Vulnerabilities)
	}
	ids := []string{}
	for _, v := range res.Vulnerabilities {
		ids = append(ids, v.VulnerabilityID)
		if v.Severity != "CRITICAL" {
			t.Errorf("severity not normalized: %+v", v)
		}
	}
	if strings.Join(ids, ",") != "CVE-2024-6387,CVE-2023-45853,CVE-2024-24790" {
		t.Errorf("ids = %v", ids)
	}
	if v := res.Vulnerabilities[2]; v.PkgPath != "usr/local/bin/app" || v.Target != "usr/local/bin/app" || v.FixedVersion == "" {
		t.Errorf("go vuln = %+v", v)
	}
	// No severity filter keeps HIGH too.
	all, _ := ParseReport(bytes.NewReader(fixture(t, "vulnerable.json")), nil)
	if len(all.Vulnerabilities) != 4 {
		t.Errorf("unfiltered = %d", len(all.Vulnerabilities))
	}
}

func TestParseReportClean(t *testing.T) {
	for _, f := range []string{"clean.json", "results-null.json", "noisy.log"} {
		t.Run(f, func(t *testing.T) {
			res, err := ParseReport(bytes.NewReader(fixture(t, f)), []string{"CRITICAL"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Vulnerabilities == nil || len(res.Vulnerabilities) != 0 {
				t.Errorf("want empty non-nil slice, got %#v", res.Vulnerabilities)
			}
			if res.ImageRef == "" || res.ImageDigest == "" {
				t.Errorf("missing ref/digest: %+v", res)
			}
		})
	}
}

func TestParseReportInvalid(t *testing.T) {
	cases := map[string][]byte{
		"truncated":    fixture(t, "truncated.json"),
		"not a report": fixture(t, "not-a-report.log"),
		"empty":        nil,
		"plain text":   []byte("FATAL something broke\n"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseReport(bytes.NewReader(in), []string{"CRITICAL"})
			if kindOf(err) != KindOutput || !IsRetryable(err) {
				t.Fatalf("want retryable KindOutput, got %v", err)
			}
		})
	}
}

// ---------- BuildJob ----------

func testConfig() Config {
	c := ConfigFrom(config.Default())
	c.ImagePullSecrets = []string{"pull-trivy"}
	c.ExtraArgs = []string{"--ignore-unfixed"}
	c.PollInterval = 5 * time.Millisecond
	return c
}

func TestBuildJobSecurity(t *testing.T) {
	cfg := testConfig()
	tgt := Target{ScanJobID: "0B1C2D3E-aaaa-bbbb-cccc-ddddeeeeffff", ImageRef: "docker.io/library/nginx@sha256:11", Attempt: 2}
	j := BuildJob(cfg, tgt, RegistryAuth{Secret: "regcred"})

	if j.Name != "krivy-scan-0b1c2d3e-2" || len(validation.IsDNS1123Label(j.Name)) != 0 {
		t.Errorf("name %q", j.Name)
	}
	if j.Namespace != "krivy-system" {
		t.Errorf("ns %q", j.Namespace)
	}
	for k, v := range map[string]string{LabelName: "krivy", LabelComponent: "scanner", LabelManagedBy: "krivy", LabelScanJobID: "0B1C2D3E-aaaa-bbbb-cccc-ddddeeeeffff"} {
		if j.Labels[k] != v || j.Spec.Template.Labels[k] != v {
			t.Errorf("label %s: job=%q pod=%q", k, j.Labels[k], j.Spec.Template.Labels[k])
		}
	}
	if j.Annotations[AnnotationImage] != tgt.ImageRef {
		t.Error("image annotation")
	}
	s := j.Spec
	if *s.BackoffLimit != 0 || *s.ActiveDeadlineSeconds != 900 || *s.TTLSecondsAfterFinished != 600 {
		t.Errorf("backoff/deadline/ttl = %d/%d/%d", *s.BackoffLimit, *s.ActiveDeadlineSeconds, *s.TTLSecondsAfterFinished)
	}
	p := s.Template.Spec
	if p.RestartPolicy != corev1.RestartPolicyNever || p.ServiceAccountName != "krivy-scanner" {
		t.Error("restart policy / SA")
	}
	if p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken {
		t.Error("SA token must not be mounted")
	}
	if len(p.ImagePullSecrets) != 1 || p.ImagePullSecrets[0].Name != "pull-trivy" {
		t.Error("image pull secrets")
	}
	psc := p.SecurityContext
	if !*psc.RunAsNonRoot || *psc.RunAsUser != 65534 || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("pod security context")
	}
	for _, v := range p.Volumes {
		if v.PersistentVolumeClaim != nil || v.HostPath != nil {
			t.Errorf("forbidden volume %s", v.Name)
		}
		if v.EmptyDir != nil && v.EmptyDir.SizeLimit == nil {
			t.Errorf("emptyDir %s without sizeLimit", v.Name)
		}
		if v.Secret != nil && (v.Secret.SecretName != "regcred" || len(v.Secret.Items) != 1 || v.Secret.Items[0].Key != ".dockerconfigjson" || v.Secret.Items[0].Path != "config.json" || *v.Secret.DefaultMode != 0o440) {
			t.Errorf("registry secret volume %+v", v.Secret)
		}
	}
	if j.Annotations[AnnotationRegistryAuth] != "regcred" {
		t.Errorf("registry auth annotation %v", j.Annotations)
	}
	c := p.Containers[0]
	csc := c.SecurityContext
	if *csc.AllowPrivilegeEscalation || !*csc.ReadOnlyRootFilesystem || len(csc.Capabilities.Drop) != 1 || csc.Capabilities.Drop[0] != "ALL" {
		t.Error("container security context")
	}
	if c.Resources.Limits.Memory().String() != "1Gi" || c.Resources.Limits.StorageEphemeral().String() != "2Gi" {
		t.Errorf("limits %v", c.Resources.Limits)
	}
	if _, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		t.Error("empty cpu limit must be omitted")
	}
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	if env["HOME"] != "/tmp" || env["TRIVY_CACHE_DIR"] != "/tmp/trivy-cache" || env["DOCKER_CONFIG"] != "/tmp/.docker" {
		t.Errorf("env %v", env)
	}
	for _, e := range c.Env {
		if e.ValueFrom != nil {
			t.Errorf("env %s must not come from a Secret", e.Name)
		}
	}
	authMount := false
	for _, m := range c.VolumeMounts {
		if m.Name == "registry-auth" {
			authMount = m.ReadOnly && m.MountPath == "/tmp/.docker"
		}
	}
	if !authMount {
		t.Errorf("registry-auth must be mounted read-only at /tmp/.docker: %+v", c.VolumeMounts)
	}
	args := strings.Join(append(c.Command, c.Args...), " ")
	for _, want := range []string{"trivy image", "--format json", "--scanners vuln", "--severity CRITICAL", "--quiet", "--no-progress", "--timeout 13m30s", "--output /dev/stdout", "--ignore-unfixed -- docker.io/library/nginx@sha256:11"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}

	// Without a selected Secret: no secret volume, DOCKER_CONFIG or annotation.
	j = BuildJob(cfg, tgt, RegistryAuth{})
	for _, v := range j.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			t.Error("unexpected secret volume")
		}
	}
	for _, e := range j.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "DOCKER_CONFIG" {
			t.Error("unexpected DOCKER_CONFIG")
		}
	}
	if _, ok := j.Annotations[AnnotationRegistryAuth]; ok {
		t.Error("unexpected registry auth annotation")
	}
}

func TestJobNameFallback(t *testing.T) {
	n := JobName(Target{ImageRef: "x", Attempt: 0})
	if !strings.HasPrefix(n, "krivy-scan-") || !strings.HasSuffix(n, "-1") || len(validation.IsDNS1123Label(n)) != 0 {
		t.Errorf("name %q", n)
	}
}

// ---------- Scan ----------

type harness struct {
	client *fake.Clientset
	cfg    Config
	logs   []byte
	logErr error
	tgt    Target
}

func newHarness(t *testing.T) *harness {
	h := &harness{client: fake.NewClientset(), cfg: testConfig(), tgt: Target{ScanJobID: "abc123", ImageRef: "nginx@sha256:11", Attempt: 1}}
	h.cfg.Logs = func(ctx context.Context, ns, pod string, opts *corev1.PodLogOptions) ([]byte, error) {
		if opts.Container != ContainerName {
			t.Errorf("container %q", opts.Container)
		}
		b := h.logs
		if opts.LimitBytes != nil && int64(len(b)) > *opts.LimitBytes {
			b = b[:*opts.LimitBytes]
		}
		return b, h.logErr
	}
	return h
}

func (h *harness) jobName() string { return JobName(h.tgt) }

func (h *harness) scanner() Scanner { return NewKubernetes(h.client, h.cfg) }

// finishJob waits for the Job, creates its pod and sets the final status.
func (h *harness) finishJob(t *testing.T, pod func(*corev1.Pod), cond batchv1.JobCondition) {
	go func() {
		ctx := context.Background()
		for i := 0; i < 2000; i++ {
			j, err := h.client.BatchV1().Jobs(h.cfg.Namespace).Get(ctx, h.jobName(), metav1.GetOptions{})
			if err == nil {
				h.createPod(t, pod)
				cond.Status = corev1.ConditionTrue
				j.Status.Conditions = append(j.Status.Conditions, cond)
				if _, err := h.client.BatchV1().Jobs(h.cfg.Namespace).UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
					t.Errorf("update status: %v", err)
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("job never created")
	}()
}

func (h *harness) createPod(t *testing.T, mutate func(*corev1.Pod)) {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: h.jobName() + "-xyz", Namespace: h.cfg.Namespace,
		Labels: map[string]string{"batch.kubernetes.io/job-name": h.jobName()},
	}}
	if mutate != nil {
		mutate(p)
	}
	if _, err := h.client.CoreV1().Pods(h.cfg.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Errorf("create pod: %v", err)
	}
}

func succeeded(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }

func terminated(code int32, reason string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Status.Phase = corev1.PodFailed
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: ContainerName, State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Reason: reason},
		}}}
	}
}

func (h *harness) jobExists() bool {
	_, err := h.client.BatchV1().Jobs(h.cfg.Namespace).Get(context.Background(), h.jobName(), metav1.GetOptions{})
	return err == nil
}

func withTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestScanSuccess(t *testing.T) {
	h := newHarness(t)
	h.logs = fixture(t, "noisy.log")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	res, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if err != nil {
		t.Fatal(err)
	}
	if res.JobName != h.jobName() || res.OS != "alpine 3.20.3" || len(res.Vulnerabilities) != 0 {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(res.Diagnostics, "output=") {
		t.Errorf("diagnostics %q", res.Diagnostics)
	}
}

func TestScanVulnerable(t *testing.T) {
	h := newHarness(t)
	h.logs = fixture(t, "vulnerable.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	res, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if err != nil || len(res.Vulnerabilities) != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestScanOutputTooLarge(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxOutputBytes = 100
	h.logs = fixture(t, "vulnerable.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindOutput || IsRetryable(err) || !strings.Contains(err.Error(), "output too large") {
		t.Fatalf("got %v", err)
	}
}

func TestScanMalformedOutput(t *testing.T) {
	h := newHarness(t)
	h.logs = fixture(t, "truncated.json")
	h.finishJob(t, succeeded, batchv1.JobCondition{Type: batchv1.JobComplete})
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindOutput || !IsRetryable(err) {
		t.Fatalf("got %v", err)
	}
}

func TestScanFailureClassification(t *testing.T) {
	cases := []struct {
		name      string
		logs      string
		pod       func(*corev1.Pod)
		cond      batchv1.JobCondition
		kind      ErrorKind
		retryable bool
	}{
		{"deadline", "", terminated(137, "Error"),
			batchv1.JobCondition{Type: batchv1.JobFailed, Reason: batchv1.JobReasonDeadlineExceeded}, KindTimeout, true},
		{"unauthorized", "FATAL\timage scan error: GET https://registry/v2/x/manifests/y: UNAUTHORIZED: authentication required; password=hunter2",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindRegistryAuth, false},
		{"denied", "remote error: DENIED: requested access to the resource is denied",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindRegistryAuth, false},
		{"local permission denied is not registry auth", "FATAL mkdir /tmp/trivy-cache/db: permission denied",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindScanner, true},
		{"manifest unknown", "remote error: MANIFEST_UNKNOWN: manifest unknown",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindImagePull, false},
		{"image not found", "unable to inspect the image: image not found in remote",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindImagePull, false},
		{"db rate limited", "FATAL\tinit error: DB error: failed to download vulnerability DB: TOOMANYREQUESTS: retry later",
			terminated(1, "Error"), batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindScanner, true},
		{"oom", "", terminated(137, "OOMKilled"),
			batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindScanner, true},
		{"generic", "panic: something", terminated(2, "Error"),
			batchv1.JobCondition{Type: batchv1.JobFailed, Reason: "BackoffLimitExceeded"}, KindScanner, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.logs = []byte(tc.logs)
			h.finishJob(t, tc.pod, tc.cond)
			_, err := h.scanner().Scan(withTimeout(t), h.tgt)
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("want *Error, got %v", err)
			}
			if se.Kind != tc.kind || se.Retryable != tc.retryable {
				t.Errorf("kind=%s retryable=%v, want %s/%v (%v)", se.Kind, se.Retryable, tc.kind, tc.retryable, err)
			}
			if !strings.Contains(se.Diagnostics, "job=") || !strings.Contains(se.Diagnostics, "pod ") {
				t.Errorf("diagnostics %q", se.Diagnostics)
			}
			if strings.Contains(se.Diagnostics, "hunter2") {
				t.Error("secret leaked into diagnostics")
			}
		})
	}
}

func TestScanSchedulingFailure(t *testing.T) {
	h := newHarness(t)
	h.cfg.SchedulingGracePeriod = time.Millisecond
	go func() {
		for i := 0; i < 2000 && !h.jobExists(); i++ {
			time.Sleep(time.Millisecond)
		}
		h.createPod(t, func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodPending
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: ContainerName, State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "Back-off pulling image"},
			}}}
		})
	}()
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindScheduling || !IsRetryable(err) {
		t.Fatalf("got %v", err)
	}
	if h.jobExists() {
		t.Error("stuck job should be deleted")
	}
}

func TestScanUnschedulable(t *testing.T) {
	h := newHarness(t)
	h.cfg.SchedulingGracePeriod = time.Millisecond
	go func() {
		for i := 0; i < 2000 && !h.jobExists(); i++ {
			time.Sleep(time.Millisecond)
		}
		h.createPod(t, func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodPending
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
				Reason: corev1.PodReasonUnschedulable, Message: "0/3 nodes are available: insufficient memory"}}
		})
	}()
	_, err := h.scanner().Scan(withTimeout(t), h.tgt)
	if kindOf(err) != KindScheduling {
		t.Fatalf("got %v", err)
	}
}

func TestScanReattachesToCompletedJob(t *testing.T) {
	h := newHarness(t)
	h.logs = fixture(t, "vulnerable.json")
	ctx := withTimeout(t)
	// A previous controller instance created the Job and it already finished.
	j := BuildJob(h.cfg, h.tgt, RegistryAuth{})
	j.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if _, err := h.client.BatchV1().Jobs(h.cfg.Namespace).Create(ctx, j, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.createPod(t, succeeded)
	res, err := h.scanner().Scan(ctx, h.tgt)
	if err != nil || len(res.Vulnerabilities) != 3 || !strings.Contains(res.Diagnostics, "reused=true") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestScanCancellation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cause      error
		wantExists bool
	}{
		{"user cancel deletes job", ErrScanCancelled, false},
		{"shutdown keeps job", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx, cancel := context.WithCancelCause(context.Background())
			go func() {
				for i := 0; i < 2000 && !h.jobExists(); i++ {
					time.Sleep(time.Millisecond)
				}
				cancel(tc.cause)
			}()
			_, err := h.scanner().Scan(ctx, h.tgt)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("want context.Canceled, got %v", err)
			}
			if got := h.jobExists(); got != tc.wantExists {
				t.Errorf("job exists = %v, want %v", got, tc.wantExists)
			}
		})
	}
}

// ---------- Fake ----------

func TestFake(t *testing.T) {
	f := NewFake()
	f.Results["a"] = &Result{Vulnerabilities: []Vulnerability{{VulnerabilityID: "CVE-1"}}}
	f.Errors["b"] = &Error{Kind: KindImagePull, Msg: "nope"}
	ctx := context.Background()
	if r, err := f.Scan(ctx, Target{ImageRef: "a"}); err != nil || len(r.Vulnerabilities) != 1 || r.ImageRef != "a" {
		t.Errorf("a: %+v %v", r, err)
	}
	if _, err := f.Scan(ctx, Target{ImageRef: "b"}); kindOf(err) != KindImagePull {
		t.Errorf("b: %v", err)
	}
	if r, err := f.Scan(ctx, Target{ImageRef: "c"}); err != nil || r == nil || len(r.Vulnerabilities) != 0 {
		t.Errorf("c: %+v %v", r, err)
	}
	if len(f.Calls()) != 3 {
		t.Errorf("calls %d", len(f.Calls()))
	}
	f.Delay = time.Hour
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.Scan(cctx, Target{ImageRef: "a"}); !errors.Is(err, context.Canceled) {
		t.Errorf("delay cancel: %v", err)
	}
}
