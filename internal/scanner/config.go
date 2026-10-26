package scanner

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/l4r-s/krivy/internal/config"
)

// ResourceList holds Kubernetes quantity strings; empty values are omitted.
type ResourceList struct {
	CPU              string
	Memory           string
	EphemeralStorage string
}

// Resources for the Trivy container.
type Resources struct {
	Requests ResourceList
	Limits   ResourceList
}

// LogFetcher reads a container's logs. Tests replace it because the fake
// clientset's GetLogs always returns "fake logs".
type LogFetcher func(ctx context.Context, namespace, pod string, opts *corev1.PodLogOptions) ([]byte, error)

// Config configures the Kubernetes Job scanner.
type Config struct {
	// Namespace where scanner Jobs run.
	Namespace string
	// Image is the Trivy image.
	Image string
	// Severities passed to --severity and used to filter results.
	Severities []string
	// Timeout becomes activeDeadlineSeconds; Trivy gets a slightly smaller --timeout.
	Timeout time.Duration
	// TTLAfterFinished becomes ttlSecondsAfterFinished.
	TTLAfterFinished time.Duration
	// MaxOutputBytes caps the collected log size; larger output fails non-retryably.
	MaxOutputBytes int64
	Resources      Resources
	// ServiceAccount for the scanner Pod (token is never mounted).
	ServiceAccount string
	// ImagePullSecrets are used only to pull the Trivy image itself.
	ImagePullSecrets []string
	// RegistrySecrets are kubernetes.io/dockerconfigjson Secrets, or
	// kubernetes.io/basic-auth Secrets with server/username/password keys, in
	// Namespace, in priority order. Per image at most one of them is mounted read-only
	// for Trivy (see registryauth.go); the controller needs get on each.
	RegistrySecrets []string
	// ExtraArgs are inserted before the image reference.
	ExtraArgs []string
	// PollInterval between Job status checks; default 2s.
	PollInterval time.Duration
	// SchedulingGracePeriod is how long the scanner Pod may stay unschedulable
	// or fail to pull the Trivy image before the scan fails with
	// KindScheduling; default 3m.
	SchedulingGracePeriod time.Duration
	// ScratchSizeLimit bounds the emptyDir volumes; default is the
	// ephemeral-storage limit, else 2Gi.
	ScratchSizeLimit string
	// Logs overrides log fetching (tests); default uses Pods().GetLogs.
	Logs LogFetcher
	// Command overrides the container entrypoint (default ["trivy"]). Only
	// integration tests set it, to run a deterministic stub scanner image;
	// it is not exposed in the YAML configuration.
	Command []string
}

// ConfigFrom maps the application config onto a scanner Config.
func ConfigFrom(c *config.Config) Config {
	rl := func(r config.ResourceList) ResourceList {
		return ResourceList{CPU: r.CPU, Memory: r.Memory, EphemeralStorage: r.EphemeralStorage}
	}
	return Config{
		Namespace:        c.Kubernetes.JobNamespace,
		Image:            c.Trivy.Image,
		Severities:       append([]string(nil), c.Trivy.Severities...),
		Timeout:          c.Trivy.Timeout.Duration,
		TTLAfterFinished: c.Trivy.TTLAfterFinished.Duration,
		MaxOutputBytes:   c.Trivy.MaxOutputBytes,
		Resources: Resources{
			Requests: rl(c.Trivy.Resources.Requests),
			Limits:   rl(c.Trivy.Resources.Limits),
		},
		ServiceAccount:   c.Kubernetes.ScannerServiceAccount,
		ImagePullSecrets: append([]string(nil), c.Kubernetes.ImagePullSecrets...),
		RegistrySecrets:  c.Kubernetes.RegistryAuthSecrets(),
		ExtraArgs:        append([]string(nil), c.Trivy.ExtraArgs...),
	}
}

// withDefaults fills unset values.
func (c Config) withDefaults() Config {
	if c.Namespace == "" {
		c.Namespace = "krivy-system"
	}
	if c.Image == "" {
		c.Image = config.DefaultTrivyImage
	}
	if len(c.Severities) == 0 {
		c.Severities = []string{"CRITICAL"}
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Minute
	}
	if c.TTLAfterFinished <= 0 {
		c.TTLAfterFinished = 10 * time.Minute
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = 16 << 20
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.SchedulingGracePeriod <= 0 {
		c.SchedulingGracePeriod = 3 * time.Minute
	}
	return c
}

// Validate reports invalid resource quantities (BuildJob silently omits them).
func (c Config) Validate() error {
	var errs []error
	check := func(field, v string) {
		if v == "" {
			return
		}
		if _, err := resource.ParseQuantity(v); err != nil {
			errs = append(errs, fmt.Errorf("scanner: invalid %s %q: %w", field, v, err))
		}
	}
	check("requests.cpu", c.Resources.Requests.CPU)
	check("requests.memory", c.Resources.Requests.Memory)
	check("requests.ephemeralStorage", c.Resources.Requests.EphemeralStorage)
	check("limits.cpu", c.Resources.Limits.CPU)
	check("limits.memory", c.Resources.Limits.Memory)
	check("limits.ephemeralStorage", c.Resources.Limits.EphemeralStorage)
	check("scratchSizeLimit", c.ScratchSizeLimit)
	return errors.Join(errs...)
}
