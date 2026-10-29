// Package config loads and validates Krivy's declarative YAML configuration.
//
// Sensitive values are referenced as ${ENV_VAR} and substituted from the
// process environment at load time, so the YAML can live in a ConfigMap while
// secrets come from a Kubernetes Secret mounted as environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// Config is the root configuration document.
type Config struct {
	Server        ServerConfig        `json:"server"`
	Database      DatabaseConfig      `json:"database"`
	Kubernetes    KubernetesConfig    `json:"kubernetes"`
	Scan          ScanConfig          `json:"scan"`
	Trivy         TrivyConfig         `json:"trivy"`
	Auth          AuthConfig          `json:"auth"`
	Notifications NotificationsConfig `json:"notifications"`
	Log           LogConfig           `json:"log"`
}

type ServerConfig struct {
	// Address the HTTP server (health, REST, MCP) listens on.
	Address string `json:"address"`
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout Duration `json:"shutdownTimeout"`
}

type DatabaseConfig struct {
	// Driver is "sqlite" or "postgres".
	Driver string `json:"driver"`
	// DSN is a file path for sqlite or a connection string for postgres.
	DSN string `json:"dsn"`
}

type KubernetesConfig struct {
	// Kubeconfig path; empty uses in-cluster config.
	Kubeconfig string `json:"kubeconfig"`
	// Context restricts out-of-cluster runs to one kubeconfig context.
	Context string `json:"context"`
	// JobNamespace is where scanner Jobs are created.
	JobNamespace string `json:"jobNamespace"`
	// WatchNamespace limits discovery to one namespace; empty means all.
	WatchNamespace string `json:"watchNamespace"`
	// ExcludeNamespaces are skipped during cluster-wide discovery.
	ExcludeNamespaces []string `json:"excludeNamespaces"`
	// ScannerServiceAccount is the low-privilege SA used by scanner Jobs.
	ScannerServiceAccount string `json:"scannerServiceAccount"`
	// ImagePullSecrets are attached to scanner Job Pods; the kubelet uses them
	// only to pull the Trivy image itself.
	ImagePullSecrets []string `json:"imagePullSecrets"`
	// RegistryAuth configures the credentials Trivy uses for the images it scans.
	RegistryAuth RegistryAuthConfig `json:"registryAuth"`
	// RegistrySecret is deprecated: use RegistryAuth.ExistingSecrets. When set
	// it is checked before the ExistingSecrets.
	RegistrySecret string `json:"registrySecret"`
}

// RegistryAuthConfig references existing registry credential Secrets.
type RegistryAuthConfig struct {
	// ExistingSecrets are kubernetes.io/dockerconfigjson Secrets, or
	// kubernetes.io/basic-auth Secrets with server/username/password keys, in
	// JobNamespace, in priority order. Krivy never creates or stores them.
	ExistingSecrets []string `json:"existingSecrets"`
}

// RegistryAuthSecrets returns the deprecated RegistrySecret followed by
// RegistryAuth.ExistingSecrets, without duplicates.
func (k KubernetesConfig) RegistryAuthSecrets() []string {
	var out []string
	if k.RegistrySecret != "" {
		out = append(out, k.RegistrySecret)
	}
	for _, s := range k.RegistryAuth.ExistingSecrets {
		if s != k.RegistrySecret {
			out = append(out, s)
		}
	}
	return out
}

type ScanConfig struct {
	// Schedule is a cron expression or "@every <duration>"; empty defaults to
	// "@every 12h" and "off" disables scheduled scans.
	Schedule string `json:"schedule"`
	// MaxConcurrentJobs caps simultaneously running scanner Jobs.
	MaxConcurrentJobs int `json:"maxConcurrentJobs"`
	// MaxAttempts per image before the image is marked failed.
	MaxAttempts int `json:"maxAttempts"`
	// ScanOnStartup triggers a cluster scan when no scan ran within the schedule interval.
	ScanOnStartup bool `json:"scanOnStartup"`
}

type TrivyConfig struct {
	// Image is the pinned official Trivy image.
	Image string `json:"image"`
	// Severities scanned; default CRITICAL.
	Severities []string `json:"severities"`
	// Timeout is the Job activeDeadlineSeconds equivalent.
	Timeout Duration `json:"timeout"`
	// TTLAfterFinished for Job cleanup.
	TTLAfterFinished Duration `json:"ttlAfterFinished"`
	// MaxOutputBytes caps the collected log size.
	MaxOutputBytes int64     `json:"maxOutputBytes"`
	Resources      Resources `json:"resources"`
	// ExtraArgs are appended to the trivy image command.
	ExtraArgs []string `json:"extraArgs"`
	// NodeSelector, Tolerations and Affinity place the scanner Pods, e.g. on
	// a node whose disk can take Trivy's image and DB unpacking.
	NodeSelector map[string]string   `json:"nodeSelector"`
	Tolerations  []corev1.Toleration `json:"tolerations"`
	Affinity     *corev1.Affinity    `json:"affinity"`
}

type Resources struct {
	Requests ResourceList `json:"requests"`
	Limits   ResourceList `json:"limits"`
}

type ResourceList struct {
	CPU              string `json:"cpu"`
	Memory           string `json:"memory"`
	EphemeralStorage string `json:"ephemeralStorage"`
}

type AuthConfig struct {
	Tokens []TokenConfig `json:"tokens"`
}

// Scope is an API permission.
type Scope string

const (
	ScopeRead   Scope = "read"
	ScopeScan   Scope = "scan"
	ScopeManage Scope = "manage"
)

type TokenConfig struct {
	Name string `json:"name"`
	// Token is the raw bearer token (usually ${ENV_VAR}).
	Token string `json:"token"`
	// SHA256 is an alternative to Token: the hex sha256 of the token.
	SHA256  string  `json:"sha256"`
	Scopes  []Scope `json:"scopes"`
	Revoked bool    `json:"revoked"`
}

type NotificationsConfig struct {
	// BaseURL is included in templates as .BaseURL for links.
	BaseURL      string               `json:"baseURL"`
	Destinations []WebhookDestination `json:"destinations"`
	// AllowPrivateNetworks permits webhook targets on loopback/private IPs.
	AllowPrivateNetworks bool `json:"allowPrivateNetworks"`
}

// Event types a webhook can subscribe to.
const (
	EventNewCritical = "new_critical"
	EventResolved    = "resolved"
	EventScanFailed  = "scan_failed"
)

type WebhookDestination struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Events  []string          `json:"events"`
	// Template renders the request body; {{ }} Go template syntax.
	Template string `json:"template"`
	// ContentType defaults to application/json.
	ContentType string   `json:"contentType"`
	Timeout     Duration `json:"timeout"`
	MaxRetries  int      `json:"maxRetries"`
	// Namespaces optionally restricts which namespaces' findings are sent.
	Namespaces []string `json:"namespaces"`
	// Secrets are ${ENV}-substituted values exposed to the template as
	// .Secrets.<key> (e.g. a Telegram chat ID) without hard-coding them.
	Secrets map[string]string `json:"secrets"`
}

type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// Duration is a time.Duration that unmarshals from strings like "12h".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

// Default returns a configuration with all defaults applied.
func Default() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	setDefault(&c.Server.Address, ":8080")
	if c.Server.ShutdownTimeout.Duration == 0 {
		c.Server.ShutdownTimeout.Duration = 15 * time.Second
	}
	setDefault(&c.Database.Driver, "sqlite")
	if c.Database.DSN == "" && c.Database.Driver == "sqlite" {
		c.Database.DSN = "krivy.db"
	}
	setDefault(&c.Kubernetes.JobNamespace, "krivy-system")
	setDefault(&c.Kubernetes.ScannerServiceAccount, "krivy-scanner")
	setDefault(&c.Scan.Schedule, "@every 12h")
	if strings.EqualFold(c.Scan.Schedule, "off") || strings.EqualFold(c.Scan.Schedule, "disabled") {
		c.Scan.Schedule = ""
	}
	if c.Scan.MaxConcurrentJobs <= 0 {
		c.Scan.MaxConcurrentJobs = 1
	}
	if c.Scan.MaxAttempts <= 0 {
		c.Scan.MaxAttempts = 2
	}
	setDefault(&c.Trivy.Image, DefaultTrivyImage)
	if len(c.Trivy.Severities) == 0 {
		c.Trivy.Severities = []string{"CRITICAL"}
	}
	if c.Trivy.Timeout.Duration == 0 {
		c.Trivy.Timeout.Duration = 15 * time.Minute
	}
	if c.Trivy.TTLAfterFinished.Duration == 0 {
		c.Trivy.TTLAfterFinished.Duration = 10 * time.Minute
	}
	if c.Trivy.MaxOutputBytes <= 0 {
		c.Trivy.MaxOutputBytes = 16 << 20
	}
	setDefault(&c.Trivy.Resources.Requests.CPU, "100m")
	setDefault(&c.Trivy.Resources.Requests.Memory, "256Mi")
	setDefault(&c.Trivy.Resources.Limits.Memory, "1Gi")
	setDefault(&c.Trivy.Resources.Limits.EphemeralStorage, "2Gi")
	setDefault(&c.Trivy.Resources.Requests.EphemeralStorage, "512Mi")
	for i := range c.Notifications.Destinations {
		d := &c.Notifications.Destinations[i]
		setDefault(&d.Method, "POST")
		setDefault(&d.ContentType, "application/json")
		if d.Timeout.Duration == 0 {
			d.Timeout.Duration = 10 * time.Second
		}
		if d.MaxRetries == 0 {
			d.MaxRetries = 3
		}
	}
	setDefault(&c.Log.Level, "info")
	setDefault(&c.Log.Format, "json")
}

// DefaultTrivyImage is the pinned official Trivy image.
const DefaultTrivyImage = "ghcr.io/aquasecurity/trivy:0.67.2"

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

// Load reads a YAML file (if path is non-empty), substitutes ${ENV} references,
// applies defaults and validates the result.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := Parse(raw, c, os.LookupEnv); err != nil {
			return nil, err
		}
	}
	applyEnvOverrides(c)
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// LookupFunc resolves an environment variable.
type LookupFunc func(string) (string, bool)

// Parse substitutes ${VAR} references using lookup and unmarshals YAML.
// Substitution happens per string value after YAML parsing so substituted
// secrets can never inject YAML structure.
func Parse(raw []byte, c *Config, lookup LookupFunc) error {
	if err := yaml.UnmarshalStrict(raw, c); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	var missing []string
	expand := func(s string) string {
		out, miss := Expand(s, lookup)
		missing = append(missing, miss...)
		return out
	}
	c.Database.DSN = expand(c.Database.DSN)
	for i := range c.Auth.Tokens {
		c.Auth.Tokens[i].Token = expand(c.Auth.Tokens[i].Token)
		c.Auth.Tokens[i].SHA256 = expand(c.Auth.Tokens[i].SHA256)
	}
	for i := range c.Notifications.Destinations {
		d := &c.Notifications.Destinations[i]
		d.URL = expand(d.URL)
		for k, v := range d.Headers {
			d.Headers[k] = expand(v)
		}
		for k, v := range d.Secrets {
			d.Secrets[k] = expand(v)
		}
		// Templates themselves are never env-expanded: secrets reach them only
		// through .Secrets so the renderer can escape them safely.
	}
	if len(missing) > 0 {
		return fmt.Errorf("config references unset environment variables: %s", strings.Join(dedupe(missing), ", "))
	}
	return nil
}

// secretName is a DNS-1123 subdomain, the format of Kubernetes Secret names.
var secretName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Expand replaces ${VAR} with its value; "$${" escapes a literal "${".
// It returns the names of unset variables.
func Expand(s string, lookup LookupFunc) (string, []string) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	const esc = "\x00KRIVY_ESC\x00"
	s = strings.ReplaceAll(s, "$${", esc)
	var missing []string
	s = envRef.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		v, ok := lookup(name)
		if !ok {
			missing = append(missing, name)
			return ""
		}
		return v
	})
	return strings.ReplaceAll(s, esc, "${"), missing
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// applyEnvOverrides lets a few deployment-specific values come from env
// without editing YAML (used by the Helm chart).
func applyEnvOverrides(c *Config) {
	if v := os.Getenv("KRIVY_DATABASE_DRIVER"); v != "" {
		c.Database.Driver = v
	}
	if v := os.Getenv("KRIVY_DATABASE_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("KRIVY_KUBECONFIG"); v != "" {
		c.Kubernetes.Kubeconfig = v
	}
	if v := os.Getenv("KRIVY_KUBE_CONTEXT"); v != "" {
		c.Kubernetes.Context = v
	}
	if v := os.Getenv("KRIVY_JOB_NAMESPACE"); v != "" {
		c.Kubernetes.JobNamespace = v
	}
	if v := os.Getenv("KRIVY_LISTEN_ADDRESS"); v != "" {
		c.Server.Address = v
	}
}

// Validate checks semantic constraints.
func (c *Config) Validate() error {
	var errs []error
	switch c.Database.Driver {
	case "sqlite", "postgres":
	default:
		errs = append(errs, fmt.Errorf("database.driver must be sqlite or postgres, got %q", c.Database.Driver))
	}
	if c.Database.DSN == "" {
		errs = append(errs, errors.New("database.dsn is required"))
	}
	if c.Scan.MaxConcurrentJobs > 50 {
		errs = append(errs, errors.New("scan.maxConcurrentJobs must be <= 50"))
	}
	seenSecrets := map[string]bool{}
	for i, name := range c.Kubernetes.RegistryAuth.ExistingSecrets {
		if !secretName.MatchString(name) || len(name) > 253 {
			errs = append(errs, fmt.Errorf("kubernetes.registryAuth.existingSecrets[%d]: %q is not a valid Secret name", i, name))
		}
		if seenSecrets[name] {
			errs = append(errs, fmt.Errorf("kubernetes.registryAuth.existingSecrets: duplicate Secret %q", name))
		}
		seenSecrets[name] = true
	}
	if n := c.Kubernetes.RegistrySecret; n != "" && (!secretName.MatchString(n) || len(n) > 253) {
		errs = append(errs, fmt.Errorf("kubernetes.registrySecret: %q is not a valid Secret name", n))
	}
	names := map[string]bool{}
	for i, t := range c.Auth.Tokens {
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("auth.tokens[%d].name is required", i))
		}
		if names[t.Name] {
			errs = append(errs, fmt.Errorf("auth.tokens: duplicate name %q", t.Name))
		}
		names[t.Name] = true
		if (t.Token == "") == (t.SHA256 == "") {
			errs = append(errs, fmt.Errorf("auth.tokens[%s]: exactly one of token or sha256 is required", t.Name))
		}
		if t.Token != "" && len(t.Token) < 16 {
			errs = append(errs, fmt.Errorf("auth.tokens[%s]: token must be at least 16 characters", t.Name))
		}
		if t.SHA256 != "" && !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(t.SHA256) {
			errs = append(errs, fmt.Errorf("auth.tokens[%s]: sha256 must be 64 hex characters", t.Name))
		}
		if len(t.Scopes) == 0 {
			errs = append(errs, fmt.Errorf("auth.tokens[%s]: at least one scope is required", t.Name))
		}
		for _, s := range t.Scopes {
			if s != ScopeRead && s != ScopeScan && s != ScopeManage {
				errs = append(errs, fmt.Errorf("auth.tokens[%s]: unknown scope %q", t.Name, s))
			}
		}
	}
	dnames := map[string]bool{}
	for i, d := range c.Notifications.Destinations {
		if d.Name == "" {
			errs = append(errs, fmt.Errorf("notifications.destinations[%d].name is required", i))
		}
		if dnames[d.Name] {
			errs = append(errs, fmt.Errorf("notifications.destinations: duplicate name %q", d.Name))
		}
		dnames[d.Name] = true
		if !strings.HasPrefix(d.URL, "https://") && !strings.HasPrefix(d.URL, "http://") {
			errs = append(errs, fmt.Errorf("notifications.destinations[%s].url must be http(s)", d.Name))
		}
		if len(d.Events) == 0 {
			errs = append(errs, fmt.Errorf("notifications.destinations[%s].events is required", d.Name))
		}
		for _, e := range d.Events {
			if e != EventNewCritical && e != EventResolved && e != EventScanFailed {
				errs = append(errs, fmt.Errorf("notifications.destinations[%s]: unknown event %q", d.Name, e))
			}
		}
	}
	return errors.Join(errs...)
}
