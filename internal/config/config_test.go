package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) LookupFunc {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// clearOverrides makes sure ambient KRIVY_* variables do not leak into tests.
func clearOverrides(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"KRIVY_DATABASE_DRIVER", "KRIVY_DATABASE_DSN", "KRIVY_KUBECONFIG",
		"KRIVY_KUBE_CONTEXT", "KRIVY_JOB_NAMESPACE", "KRIVY_LISTEN_ADDRESS",
	} {
		t.Setenv(k, "")
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "krivy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	clearOverrides(t)
	for _, tc := range []struct {
		name string
		load func() (*Config, error)
	}{
		{"Default", func() (*Config, error) { return Default(), nil }},
		{"Load empty path", func() (*Config, error) { return Load("") }},
		{"Load empty file", func() (*Config, error) { return Load(writeFile(t, "")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.load()
			if err != nil {
				t.Fatal(err)
			}
			checks := []struct {
				name      string
				got, want any
			}{
				{"schedule", c.Scan.Schedule, "@every 12h"},
				{"maxConcurrentJobs", c.Scan.MaxConcurrentJobs, 1},
				{"maxAttempts", c.Scan.MaxAttempts, 2},
				{"driver", c.Database.Driver, "sqlite"},
				{"dsn", c.Database.DSN, "krivy.db"},
				{"address", c.Server.Address, ":8080"},
				{"shutdown", c.Server.ShutdownTimeout.Duration, 15 * time.Second},
				{"jobNamespace", c.Kubernetes.JobNamespace, "krivy-system"},
				{"scannerSA", c.Kubernetes.ScannerServiceAccount, "krivy-scanner"},
				{"trivyImage", c.Trivy.Image, DefaultTrivyImage},
				{"severities", strings.Join(c.Trivy.Severities, ","), "CRITICAL"},
				{"trivyTimeout", c.Trivy.Timeout.Duration, 15 * time.Minute},
				{"ttl", c.Trivy.TTLAfterFinished.Duration, 10 * time.Minute},
				{"maxOutput", c.Trivy.MaxOutputBytes, int64(16 << 20)},
				{"logLevel", c.Log.Level, "info"},
				{"logFormat", c.Log.Format, "json"},
			}
			for _, ch := range checks {
				if ch.got != ch.want {
					t.Errorf("%s = %v, want %v", ch.name, ch.got, ch.want)
				}
			}
		})
	}
}

func TestDestinationDefaultsAndPostgresNoDSNDefault(t *testing.T) {
	clearOverrides(t)
	c, err := Load(writeFile(t, `
database:
  driver: postgres
  dsn: postgres://x
notifications:
  destinations:
    - name: hook
      url: https://example.com/hook
      events: [new_critical]
`))
	if err != nil {
		t.Fatal(err)
	}
	d := c.Notifications.Destinations[0]
	if d.Method != "POST" || d.ContentType != "application/json" || d.Timeout.Duration != 10*time.Second || d.MaxRetries != 3 {
		t.Fatalf("destination defaults not applied: %+v", d)
	}
	// Postgres without DSN must not silently get the sqlite default.
	c2 := &Config{Database: DatabaseConfig{Driver: "postgres"}}
	c2.applyDefaults()
	if c2.Database.DSN != "" {
		t.Fatalf("postgres DSN defaulted to %q", c2.Database.DSN)
	}
	if err := c2.Validate(); err == nil || !strings.Contains(err.Error(), "dsn is required") {
		t.Fatalf("want dsn required error, got %v", err)
	}
}

func TestExpand(t *testing.T) {
	env := map[string]string{"A": "alpha", "EMPTY": "", "B_2": "beta"}
	for _, tc := range []struct {
		in, want string
		missing  []string
	}{
		{"plain", "plain", nil},
		{"${A}", "alpha", nil},
		{"x-${A}-${B_2}-y", "x-alpha-beta-y", nil},
		{"${EMPTY}", "", nil},
		{"${MISSING}", "", []string{"MISSING"}},
		{"${MISSING}${MISSING2}", "", []string{"MISSING", "MISSING2"}},
		{"$${A}", "${A}", nil},
		{"$${MISSING} and ${A}", "${MISSING} and alpha", nil},
		{"$A", "$A", nil},
		{"${1BAD}", "${1BAD}", nil},
		{"${unterminated", "${unterminated", nil},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, missing := Expand(tc.in, lookupFrom(env))
			if got != tc.want {
				t.Errorf("Expand(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Join(missing, ",") != strings.Join(tc.missing, ",") {
				t.Errorf("missing = %v, want %v", missing, tc.missing)
			}
		})
	}
}

func TestParseSubstitution(t *testing.T) {
	raw := []byte(`
database:
  driver: postgres
  dsn: postgres://krivy:${DB_PASS}@db/krivy
auth:
  tokens:
    - name: admin
      token: ${ADMIN_TOKEN}
      scopes: [manage]
notifications:
  destinations:
    - name: tg
      url: https://api.telegram.org/bot${TG_TOKEN}/sendMessage
      events: [new_critical]
      headers:
        X-Key: ${HDR}
      secrets:
        chat: ${CHAT}
      template: '{"x":"${NOT_EXPANDED}"}'
`)
	env := map[string]string{
		"DB_PASS": "p@ss", "ADMIN_TOKEN": "0123456789abcdef0123", "TG_TOKEN": "t0k",
		"HDR": "hv", "CHAT": "42",
	}
	var c Config
	if err := Parse(raw, &c, lookupFrom(env)); err != nil {
		t.Fatal(err)
	}
	d := c.Notifications.Destinations[0]
	for _, ch := range []struct{ got, want string }{
		{c.Database.DSN, "postgres://krivy:p@ss@db/krivy"},
		{c.Auth.Tokens[0].Token, "0123456789abcdef0123"},
		{d.URL, "https://api.telegram.org/bott0k/sendMessage"},
		{d.Headers["X-Key"], "hv"},
		{d.Secrets["chat"], "42"},
		{d.Template, `{"x":"${NOT_EXPANDED}"}`},
	} {
		if ch.got != ch.want {
			t.Errorf("got %q, want %q", ch.got, ch.want)
		}
	}
}

func TestParseSubstitutionCannotInjectYAML(t *testing.T) {
	var c Config
	env := map[string]string{"DSN": "x\nauth:\n  tokens: []"}
	if err := Parse([]byte("database:\n  dsn: ${DSN}\n"), &c, lookupFrom(env)); err != nil {
		t.Fatal(err)
	}
	if c.Database.DSN != env["DSN"] {
		t.Fatalf("DSN = %q", c.Database.DSN)
	}
}

func TestParseScannerPlacement(t *testing.T) {
	raw := `trivy:
  nodeSelector:
    dedicated: scanners
  tolerations:
  - key: dedicated
    operator: Equal
    value: scanners
    effect: NoSchedule
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/arch
            operator: In
            values: [amd64]
`
	var c Config
	if err := Parse([]byte(raw), &c, lookupFrom(nil)); err != nil {
		t.Fatal(err)
	}
	if got := c.Trivy.NodeSelector["dedicated"]; got != "scanners" {
		t.Errorf("nodeSelector = %v", c.Trivy.NodeSelector)
	}
	if len(c.Trivy.Tolerations) != 1 || c.Trivy.Tolerations[0].Effect != "NoSchedule" || c.Trivy.Tolerations[0].Value != "scanners" {
		t.Errorf("tolerations = %+v", c.Trivy.Tolerations)
	}
	na := c.Trivy.Affinity
	if na == nil || na.NodeAffinity == nil || na.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		t.Fatalf("affinity = %+v", na)
	}
	if v := na.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Values; len(v) != 1 || v[0] != "amd64" {
		t.Errorf("affinity values = %v", v)
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, wantErr string
	}{
		{"missing env", "database:\n  dsn: ${NOPE}\nauth:\n  tokens:\n  - name: a\n    token: ${NOPE}\n    scopes: [read]\n  - name: b\n    token: ${NOPE2}\n    scopes: [read]\n", "NOPE, NOPE2"},
		{"unknown top-level key", "bogus: 1\n", "bogus"},
		{"unknown nested key", "scan:\n  scheduel: '@daily'\n", "scheduel"},
		{"bad duration", "server:\n  shutdownTimeout: 10 parsecs\n", "invalid duration"},
		{"wrong type", "scan:\n  maxConcurrentJobs: lots\n", "parse config"},
		{"unknown toleration key", "trivy:\n  tolerations:\n  - key: a\n    efect: NoSchedule\n", "efect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			err := Parse([]byte(tc.yaml), &c, lookupFrom(nil))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadMissingEnvAndFile(t *testing.T) {
	clearOverrides(t)
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
	t.Setenv("KRIVY_TEST_UNSET_FOR_SURE", "")
	os.Unsetenv("KRIVY_TEST_UNSET_FOR_SURE")
	_, err := Load(writeFile(t, "database:\n  dsn: ${KRIVY_TEST_UNSET_FOR_SURE}\n"))
	if err == nil || !strings.Contains(err.Error(), "KRIVY_TEST_UNSET_FOR_SURE") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("KRIVY_TEST_DSN", "/data/x.db")
	c, err := Load(writeFile(t, "database:\n  dsn: ${KRIVY_TEST_DSN}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Database.DSN != "/data/x.db" {
		t.Fatalf("dsn = %q", c.Database.DSN)
	}
}

func TestDuration(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{`"12h"`, 12 * time.Hour, false},
		{`"1m30s"`, 90 * time.Second, false},
		{`""`, 0, false},
		{`null`, 0, false},
		{`"abc"`, 0, true},
		{`5`, 0, true}, // unit required
	} {
		t.Run(tc.in, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tc.in), &d)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if d.Duration != tc.want {
				t.Fatalf("got %v want %v", d.Duration, tc.want)
			}
		})
	}
	b, err := json.Marshal(Duration{90 * time.Second})
	if err != nil || string(b) != `"1m30s"` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
}

func TestEnvOverrides(t *testing.T) {
	clearOverrides(t)
	t.Setenv("KRIVY_DATABASE_DRIVER", "postgres")
	t.Setenv("KRIVY_DATABASE_DSN", "postgres://override")
	t.Setenv("KRIVY_KUBECONFIG", "/kc")
	t.Setenv("KRIVY_KUBE_CONTEXT", "ctx")
	t.Setenv("KRIVY_JOB_NAMESPACE", "jobs")
	t.Setenv("KRIVY_LISTEN_ADDRESS", ":9999")
	c, err := Load(writeFile(t, "database:\n  driver: sqlite\n  dsn: file.db\nkubernetes:\n  jobNamespace: yaml-ns\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range []struct{ name, got, want string }{
		{"driver", c.Database.Driver, "postgres"},
		{"dsn", c.Database.DSN, "postgres://override"},
		{"kubeconfig", c.Kubernetes.Kubeconfig, "/kc"},
		{"context", c.Kubernetes.Context, "ctx"},
		{"jobNamespace", c.Kubernetes.JobNamespace, "jobs"},
		{"address", c.Server.Address, ":9999"},
	} {
		if ch.got != ch.want {
			t.Errorf("%s = %q, want %q", ch.name, ch.got, ch.want)
		}
	}
	// Overrides also apply with no config file.
	c, err = Load("")
	if err != nil || c.Database.DSN != "postgres://override" {
		t.Fatalf("Load(\"\") = %+v, %v", c, err)
	}
}

func TestValidate(t *testing.T) {
	const tok = "0123456789abcdef"
	sha := strings.Repeat("a", 64)
	valid := func() *Config {
		c := Default()
		c.Auth.Tokens = []TokenConfig{{Name: "a", Token: tok, Scopes: []Scope{ScopeRead}}}
		c.Notifications.Destinations = []WebhookDestination{{Name: "w", URL: "https://x", Events: []string{EventNewCritical, EventResolved, EventScanFailed}}}
		return c
	}
	for _, tc := range []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"valid sha256", func(c *Config) {
			c.Auth.Tokens[0] = TokenConfig{Name: "a", SHA256: strings.ToUpper(sha), Scopes: []Scope{ScopeManage}}
		}, ""},
		{"bad driver", func(c *Config) { c.Database.Driver = "mysql" }, "database.driver"},
		{"empty dsn", func(c *Config) { c.Database.DSN = "" }, "dsn is required"},
		{"too many jobs", func(c *Config) { c.Scan.MaxConcurrentJobs = 51 }, "maxConcurrentJobs"},
		{"missing token name", func(c *Config) { c.Auth.Tokens[0].Name = "" }, "name is required"},
		{"duplicate token names", func(c *Config) {
			c.Auth.Tokens = append(c.Auth.Tokens, TokenConfig{Name: "a", Token: tok + "x", Scopes: []Scope{ScopeRead}})
		}, `duplicate name "a"`},
		{"short token", func(c *Config) { c.Auth.Tokens[0].Token = "short" }, "at least 16"},
		{"token and sha", func(c *Config) { c.Auth.Tokens[0].SHA256 = sha }, "exactly one"},
		{"neither token nor sha", func(c *Config) { c.Auth.Tokens[0].Token = "" }, "exactly one"},
		{"bad sha256 length", func(c *Config) { c.Auth.Tokens[0] = TokenConfig{Name: "a", SHA256: "abcd", Scopes: []Scope{ScopeRead}} }, "64 hex"},
		{"bad sha256 chars", func(c *Config) {
			c.Auth.Tokens[0] = TokenConfig{Name: "a", SHA256: strings.Repeat("z", 64), Scopes: []Scope{ScopeRead}}
		}, "64 hex"},
		{"no scopes", func(c *Config) { c.Auth.Tokens[0].Scopes = nil }, "at least one scope"},
		{"unknown scope", func(c *Config) { c.Auth.Tokens[0].Scopes = []Scope{"admin"} }, `unknown scope "admin"`},
		{"missing dest name", func(c *Config) { c.Notifications.Destinations[0].Name = "" }, "name is required"},
		{"duplicate dest", func(c *Config) {
			c.Notifications.Destinations = append(c.Notifications.Destinations, c.Notifications.Destinations[0])
		}, "duplicate name"},
		{"bad webhook scheme", func(c *Config) { c.Notifications.Destinations[0].URL = "ftp://x" }, "must be http(s)"},
		{"webhook no scheme", func(c *Config) { c.Notifications.Destinations[0].URL = "example.com" }, "must be http(s)"},
		{"no events", func(c *Config) { c.Notifications.Destinations[0].Events = nil }, "events is required"},
		{"unknown event", func(c *Config) { c.Notifications.Destinations[0].Events = []string{"new_high"} }, `unknown event "new_high"`},
		{"registry auth secrets", func(c *Config) {
			c.Kubernetes.RegistryAuth.ExistingSecrets = []string{"ghcr-auth", "registry.example.com"}
		}, ""},
		{"invalid registry auth secret name", func(c *Config) {
			c.Kubernetes.RegistryAuth.ExistingSecrets = []string{"Bad_Name"}
		}, `existingSecrets[0]: "Bad_Name" is not a valid Secret name`},
		{"empty registry auth secret name", func(c *Config) {
			c.Kubernetes.RegistryAuth.ExistingSecrets = []string{""}
		}, "is not a valid Secret name"},
		{"duplicate registry auth secret", func(c *Config) {
			c.Kubernetes.RegistryAuth.ExistingSecrets = []string{"a", "a"}
		}, `duplicate Secret "a"`},
		{"invalid deprecated registrySecret", func(c *Config) { c.Kubernetes.RegistrySecret = "x/y" }, "kubernetes.registrySecret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateJoinsMultipleErrors(t *testing.T) {
	c := Default()
	c.Database.Driver = "oracle"
	c.Auth.Tokens = []TokenConfig{{Name: "x", Token: "short", Scopes: []Scope{"bad"}}}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"database.driver", "at least 16", "unknown scope"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestRegistryAuth(t *testing.T) {
	var c Config
	yml := "kubernetes:\n  registryAuth:\n    existingSecrets: [ghcr-auth, internal-auth]\n"
	if err := Parse([]byte(yml), &c, lookupFrom(nil)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Kubernetes.RegistryAuthSecrets(), ","); got != "ghcr-auth,internal-auth" {
		t.Errorf("secrets = %q", got)
	}
	// Strict parsing: credentials cannot be put into the config.
	for _, bad := range []string{
		"kubernetes:\n  registryAuth:\n    username: u\n",
		"kubernetes:\n  registryAuth:\n    existingSecrets: [{name: a}]\n",
	} {
		if err := Parse([]byte(bad), &Config{}, lookupFrom(nil)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// ${ENV} is not expanded in Secret names.
	var e Config
	if err := Parse([]byte("kubernetes:\n  registryAuth:\n    existingSecrets: ['${X}']\n"), &e, lookupFrom(map[string]string{"X": "a"})); err != nil {
		t.Fatal(err)
	}
	if e.Validate() == nil {
		t.Error("unexpanded ${X} must fail validation")
	}
	// The deprecated registrySecret comes first and is not repeated.
	k := KubernetesConfig{RegistrySecret: "old", RegistryAuth: RegistryAuthConfig{ExistingSecrets: []string{"a", "old", "b"}}}
	if got := strings.Join(k.RegistryAuthSecrets(), ","); got != "old,a,b" {
		t.Errorf("merged = %q", got)
	}
	if got := (KubernetesConfig{}).RegistryAuthSecrets(); len(got) != 0 {
		t.Errorf("default = %v", got)
	}
}
