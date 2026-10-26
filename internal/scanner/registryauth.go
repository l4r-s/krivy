package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Registry credentials for the images Trivy scans.
//
// The controller reads the configured Secrets from the job namespace for
// every scan, validates all of them and selects at most one Secret per image.
// Only that Secret is mounted into the scanner Pod; images without a matching
// entry get no credentials at all. Credentials are never copied into other
// objects, arguments, environment variables or diagnostics.
//
// Two Secret types are accepted:
//
//   - kubernetes.io/dockerconfigjson: mounted read-only as
//     $DOCKER_CONFIG/config.json.
//   - kubernetes.io/basic-auth with the keys server, username and password
//     (the fields of kubectl create secret docker-registry): treated as a
//     config with the single entry auths[server]. Its keys are mounted
//     read-only into an init container only, which writes that config.json
//     into a memory-backed emptyDir that Trivy mounts read-only (see
//     BuildJob).
//
// Trivy reads config.json through go-containerregistry's default keychain,
// which looks up "<registry>/<repository>" and then "<registry>" (Docker Hub:
// "https://index.docker.io/v1/") and, failing an exact key, any key whose
// hostname equals the lookup key, in map order. Selection here follows the
// same rules, restricted so that it is deterministic:
//
//   - an exact "<registry>/<repository>" key beats any other entry;
//   - a bare "<registry>/<path>" key matches only repositories under <path>
//     (the longest path wins);
//   - a "<registry>" or URL key ("https://<registry>/...") matches every
//     repository of that registry;
//   - ties go to the Secret listed first.
//
// The chosen Secret is then checked against Trivy's own lookup; if Trivy
// would pick different credentials from it (e.g. two path entries for the
// same host in one Secret) the scan fails instead of guessing.

const (
	// dockerHubAuthKey is the only host key Trivy reads for Docker Hub.
	dockerHubAuthKey  = "https://index.docker.io/v1/"
	dockerHubRegistry = "index.docker.io"

	// AnnotationRegistryAuth names the Secret mounted for registry auth.
	AnnotationRegistryAuth = "krivy.io/registry-auth-secret"

	// basicAuthServerKey holds the registry of a kubernetes.io/basic-auth
	// Secret, next to the standard username and password keys.
	basicAuthServerKey = "server"
)

// registryKeyPattern accepts "[scheme://]host[:port][/path]" keys. Keys are
// shown in diagnostics only after passing it.
var registryKeyPattern = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*://)?[a-zA-Z0-9*\[\]][a-zA-Z0-9.*:\[\]-]*(/[a-zA-Z0-9._/-]*)?$`)

// dockerAuth mirrors an entry of docker/cli's config.json "auths".
type dockerAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth,omitempty"`
	Email         string `json:"email,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// credentials returns the decoded credentials used for equality checks.
func (a dockerAuth) credentials() [4]string {
	user, pass := a.Username, a.Password
	if a.Auth != "" {
		user, pass, _ = decodeDockerAuth(a.Auth)
	}
	return [4]string{user, pass, a.IdentityToken, a.RegistryToken}
}

// secretValues returns the sensitive strings of an entry for redaction.
func (a dockerAuth) secretValues() []string {
	_, pass, _ := decodeDockerAuth(a.Auth)
	out := []string{a.Auth, a.Password, pass, a.IdentityToken, a.RegistryToken}
	if a.Username != "" && a.Password != "" {
		// The auth value a basic-auth init container generates.
		out = append(out, base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Password)))
	}
	return out
}

type dockerConfig struct {
	Auths       map[string]dockerAuth `json:"auths"`
	CredsStore  string                `json:"credsStore,omitempty"`
	CredHelpers map[string]string     `json:"credHelpers,omitempty"`
}

// registrySecret is one parsed, validated Secret.
type registrySecret struct {
	name string
	cfg  dockerConfig
	// basic is set for a kubernetes.io/basic-auth Secret; cfg then holds its
	// single server entry.
	basic bool
	// raw is the base64 form of the Secret data, redacted from diagnostics.
	raw string
}

// imageRepo is an image reference split the way go-containerregistry does.
type imageRepo struct {
	registry   string // e.g. ghcr.io, index.docker.io, localhost:5000
	repository string // e.g. org/app, library/nginx
}

func (r imageRepo) String() string { return r.registry + "/" + r.repository }

// hostKey is the registry key Trivy looks up.
func (r imageRepo) hostKey() string {
	if r.registry == dockerHubRegistry {
		return dockerHubAuthKey
	}
	return r.registry
}

// parseImageRepo splits ref like go-containerregistry's name.ParseReference.
func parseImageRepo(ref string) (imageRepo, bool) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	if ref == "" {
		return imageRepo{}, false
	}
	r := imageRepo{registry: dockerHubRegistry, repository: ref}
	if first, rest, ok := strings.Cut(ref, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.registry, r.repository = first, rest
		if first == "docker.io" {
			r.registry = dockerHubRegistry
		}
	}
	if r.repository == "" {
		return imageRepo{}, false
	}
	if r.registry == dockerHubRegistry && !strings.Contains(r.repository, "/") {
		r.repository = "library/" + r.repository
	}
	return r, true
}

// convertToHostname mirrors docker/cli credentials.ConvertToHostname.
func convertToHostname(maybeURL string) string {
	if strings.Contains(maybeURL, "://") {
		if u, err := url.Parse(maybeURL); err == nil && u.Hostname() != "" {
			if u.Port() == "" {
				return u.Hostname()
			}
			return net.JoinHostPort(u.Hostname(), u.Port())
		}
	}
	host, _, _ := strings.Cut(maybeURL, "/")
	return host
}

// decodeDockerAuth mirrors docker/cli's decodeAuth.
func decodeDockerAuth(s string) (user, pass string, err error) {
	if s == "" {
		return "", "", nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", errors.New("not base64")
	}
	user, pass, ok := strings.Cut(string(b), ":")
	if !ok || user == "" {
		return "", "", errors.New("not user:password")
	}
	return user, strings.Trim(pass, "\x00"), nil
}

// matchSpecificity reports whether key covers img and how specifically
// (higher wins): exact repository > longest path prefix > host.
func matchSpecificity(key string, img imageRepo) (int, bool) {
	if key == img.String() {
		return 1 << 20, true
	}
	if key == img.hostKey() {
		return 0, true
	}
	if convertToHostname(key) != img.hostKey() {
		return 0, false
	}
	if strings.Contains(key, "://") {
		return 0, true // URL keys are host-wide, as in Docker
	}
	_, path, _ := strings.Cut(key, "/")
	path = strings.Trim(path, "/")
	if path == "" {
		return 0, true
	}
	if img.repository == path || strings.HasPrefix(img.repository, path+"/") {
		return strings.Count(path, "/") + 1, true
	}
	return 0, false
}

// trivyLookup returns the key go-containerregistry's default keychain picks
// from cfg for img; ambiguous lists the candidates when it would choose by map
// order between entries with different credentials.
func trivyLookup(cfg dockerConfig, img imageRepo) (key string, ambiguous []string) {
	for _, lookup := range []string{img.String(), img.hostKey()} {
		if _, ok := cfg.Auths[lookup]; ok {
			return lookup, nil
		}
		var cands []string
		for k := range cfg.Auths {
			if convertToHostname(k) == lookup {
				cands = append(cands, k)
			}
		}
		if len(cands) == 0 {
			continue
		}
		sort.Strings(cands)
		for _, c := range cands[1:] {
			if cfg.Auths[c].credentials() != cfg.Auths[cands[0]].credentials() {
				return "", cands
			}
		}
		return cands[0], nil
	}
	return "", nil
}

// authResolution is the outcome of resolving registry credentials for one
// image.
type authResolution struct {
	image imageRepo
	// secret is the Secret to mount; empty when no Secret matches.
	secret string
	// key is the matching auths key in secret (a basic-auth Secret's server).
	key string
	// basic is set when secret is a kubernetes.io/basic-auth Secret.
	basic bool
	// configured lists the Secret names that were checked.
	configured []string
	// hints are safe, user-facing notes explaining near misses.
	hints []string
	// redact holds sensitive values to scrub from diagnostics.
	redact []string
}

// authErr is a non-retryable registry auth error; msg must not contain
// Secret data.
func authErr(msg string) *Error {
	return &Error{Kind: KindRegistryAuth, Retryable: false, Msg: msg}
}

// loadRegistrySecret fetches and validates one Secret.
func (s *kubeScanner) loadRegistrySecret(ctx context.Context, name string) (*registrySecret, error) {
	ns := s.cfg.Namespace
	sec, err := s.client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
	case apierrors.IsNotFound(err):
		return nil, authErr(fmt.Sprintf("registry auth Secret %q not found in namespace %s; create it there or remove it from registryAuth.existingSecrets", name, ns))
	case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
		return nil, authErr(fmt.Sprintf("krivy may not read registry auth Secret %q in namespace %s; grant get on it (the Helm chart does this for registryAuth.existingSecrets)", name, ns))
	default:
		return nil, kerr(fmt.Sprintf("get registry auth Secret %q", name), err)
	}
	prefix := fmt.Sprintf("registry auth Secret %s/%s", ns, name)
	switch sec.Type {
	case corev1.SecretTypeDockerConfigJson:
	case corev1.SecretTypeBasicAuth:
		return loadBasicAuthSecret(prefix, name, sec)
	case corev1.SecretTypeDockercfg:
		return nil, authErr(prefix + " has the legacy type kubernetes.io/dockercfg, which Trivy cannot read; recreate it as kubernetes.io/dockerconfigjson (kubectl create secret docker-registry)")
	default:
		if _, ok := sec.Data[basicAuthServerKey]; ok {
			return nil, authErr(fmt.Sprintf("%s has type %q; a Secret with server/username/password keys needs type kubernetes.io/basic-auth", prefix, sec.Type))
		}
		return nil, authErr(fmt.Sprintf("%s has type %q; want kubernetes.io/dockerconfigjson, or kubernetes.io/basic-auth with server/username/password keys", prefix, sec.Type))
	}
	data := sec.Data[corev1.DockerConfigJsonKey]
	if len(data) == 0 {
		return nil, authErr(prefix + " has no .dockerconfigjson key")
	}
	rs := &registrySecret{name: name, raw: base64.StdEncoding.EncodeToString(data)}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&rs.cfg); err != nil {
		// json errors may quote input bytes; never include them.
		return nil, authErr(prefix + ": .dockerconfigjson is not a valid Docker config.json")
	}
	if rs.cfg.CredsStore != "" || len(rs.cfg.CredHelpers) > 0 {
		return nil, authErr(prefix + ": credsStore/credHelpers are not supported (scanner pods have no credential helpers); store credentials under auths")
	}
	if len(rs.cfg.Auths) == 0 {
		return nil, authErr(prefix + ": .dockerconfigjson has no auths entries")
	}
	keys := make([]string, 0, len(rs.cfg.Auths))
	for k := range rs.cfg.Auths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !registryKeyPattern.MatchString(k) {
			return nil, authErr(prefix + ": an auths key is not a registry host (want host[:port][/path] or https://host)")
		}
		a := rs.cfg.Auths[k]
		if _, _, err := decodeDockerAuth(a.Auth); err != nil {
			return nil, authErr(fmt.Sprintf("%s: auths[%q].auth is not base64 of \"user:password\"", prefix, k))
		}
		if a.Auth == "" && a.Password == "" && a.IdentityToken == "" && a.RegistryToken == "" {
			return nil, authErr(fmt.Sprintf("%s: auths[%q] has no credentials (auth, username/password, identitytoken or registrytoken)", prefix, k))
		}
	}
	return rs, nil
}

// loadBasicAuthSecret validates a kubernetes.io/basic-auth Secret holding
// server, username and password, and returns it as a config with the single
// entry auths[server]. Messages name keys, never values.
func loadBasicAuthSecret(prefix, name string, sec *corev1.Secret) (*registrySecret, error) {
	var missing []string
	for _, k := range []string{basicAuthServerKey, corev1.BasicAuthUsernameKey, corev1.BasicAuthPasswordKey} {
		if len(sec.Data[k]) == 0 {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, authErr(fmt.Sprintf("%s (kubernetes.io/basic-auth) has no or an empty %s key; it needs server, username and password", prefix, strings.Join(missing, ", ")))
	}
	server := string(sec.Data[basicAuthServerKey])
	user := string(sec.Data[corev1.BasicAuthUsernameKey])
	pass := string(sec.Data[corev1.BasicAuthPasswordKey])
	if !validServer(server) {
		return nil, authErr(prefix + ": server is not a registry (want host[:port][/path] or https://host, e.g. registry.example.com)")
	}
	if strings.Contains(user, ":") {
		return nil, authErr(prefix + `: username contains ":", which a Docker config cannot represent`)
	}
	if hasControl(user) || hasControl(pass) {
		return nil, authErr(prefix + ": username or password contains a line break or another control character (check for a trailing newline)")
	}
	raw := make([]string, 0, 3)
	for _, k := range []string{basicAuthServerKey, corev1.BasicAuthUsernameKey, corev1.BasicAuthPasswordKey} {
		raw = append(raw, base64.StdEncoding.EncodeToString(sec.Data[k]))
	}
	return &registrySecret{
		name:  name,
		basic: true,
		cfg:   dockerConfig{Auths: map[string]dockerAuth{server: {Username: user, Password: pass}}},
		// Only the password's encoding is sensitive; server and username are
		// shown in messages anyway.
		raw: raw[2],
	}, nil
}

// serverHostPattern is a DNS name or IPv4 address with an optional port.
var serverHostPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$`)

// validServer accepts the values of kubectl's --docker-server for one
// registry: host[:port][/path] or http(s)://host[:port][/path]. The value is
// also the JSON key the init container writes, so the character set is
// restricted to what registryKeyPattern allows, minus wildcards.
func validServer(s string) bool {
	if !registryKeyPattern.MatchString(s) || strings.ContainsAny(s, "*[]") {
		return false
	}
	rest := s
	if scheme, after, ok := strings.Cut(s, "://"); ok {
		if scheme != "https" && scheme != "http" {
			return false
		}
		rest = after
	}
	host, _, _ := strings.Cut(rest, "/")
	return serverHostPattern.MatchString(host)
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// resolveAuth loads every configured Secret and selects the one to mount for
// imageRef. Any unreadable or invalid Secret fails the scan, even when it
// would not match, so the outcome never depends on which Secrets happen to be
// broken.
func (s *kubeScanner) resolveAuth(ctx context.Context, imageRef string) (*authResolution, error) {
	res := &authResolution{configured: s.cfg.RegistrySecrets}
	if len(s.cfg.RegistrySecrets) == 0 {
		return res, nil
	}
	img, ok := parseImageRepo(imageRef)
	if !ok {
		return res, nil
	}
	res.image = img
	secrets := make([]*registrySecret, 0, len(s.cfg.RegistrySecrets))
	for _, name := range s.cfg.RegistrySecrets {
		rs, err := s.loadRegistrySecret(ctx, name)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, rs)
	}

	type match struct {
		sec  *registrySecret
		key  string
		spec int
	}
	var best *match
	for _, rs := range secrets {
		keys := make([]string, 0, len(rs.cfg.Auths))
		for k := range rs.cfg.Auths {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		trivyKey, _ := trivyLookup(rs.cfg, img)
		var own *match
		for _, k := range keys {
			spec, ok := matchSpecificity(k, img)
			if !ok {
				if h := nearMissHint(rs.name, k, img); h != "" {
					res.hints = append(res.hints, h)
				}
				continue
			}
			// Among equally specific keys of one Secret, prefer Trivy's pick.
			if own == nil || spec > own.spec || (spec == own.spec && k == trivyKey) {
				own = &match{sec: rs, key: k, spec: spec}
			}
		}
		// Strictly greater: on a tie the Secret listed first wins.
		if own != nil && (best == nil || own.spec > best.spec) {
			best = own
		}
	}
	if best == nil {
		return res, nil
	}

	picked, ambiguous := trivyLookup(best.sec.cfg, img)
	switch {
	case len(ambiguous) > 0:
		return nil, authErr(fmt.Sprintf("registry auth Secret %q has several entries for %s (%s) and Trivy matches them by host only; put each path-specific entry in its own Secret",
			best.sec.name, img.registry, strings.Join(ambiguous, ", ")))
	case picked == "" || best.sec.cfg.Auths[picked].credentials() != best.sec.cfg.Auths[best.key].credentials():
		return nil, authErr(fmt.Sprintf("registry auth Secret %q: entry %q matches %s but Trivy would use entry %q from the same Secret; put them in separate Secrets",
			best.sec.name, best.key, img, picked))
	}
	res.secret, res.key, res.basic = best.sec.name, best.key, best.sec.basic
	res.redact = append(best.sec.cfg.Auths[best.key].secretValues(), best.sec.raw)
	return res, nil
}

// nearMissHint explains why a key that looks related to img does not match.
func nearMissHint(secret, key string, img imageRepo) string {
	host := convertToHostname(key)
	if img.registry == dockerHubRegistry {
		switch host {
		case "docker.io", "index.docker.io", "registry-1.docker.io":
			return fmt.Sprintf("Secret %q entry %q is not used for Docker Hub; Trivy reads only %q", secret, key, dockerHubAuthKey)
		}
		return ""
	}
	if host == img.registry {
		return fmt.Sprintf("Secret %q entry %q does not cover repository %s", secret, key, img.repository)
	}
	return ""
}

// mount returns what BuildJob mounts for the resolution.
func (r *authResolution) mount() RegistryAuth {
	if r == nil || r.secret == "" {
		return RegistryAuth{}
	}
	ra := RegistryAuth{Secret: r.secret}
	if r.basic {
		ra.Server = r.key
	}
	return ra
}

// describe summarizes the resolution for diagnostics (no secret data).
func (r *authResolution) describe() string {
	switch {
	case r == nil || len(r.configured) == 0:
		return "registry auth: none configured"
	case r.secret == "":
		return fmt.Sprintf("registry auth: no entry in %s matches %s", strings.Join(r.configured, ","), r.image.registry)
	default:
		return fmt.Sprintf("registry auth: Secret %q entry %q", r.secret, r.key)
	}
}

// authFailure builds the error for a registry that rejected the request.
func (r *authResolution) authFailure() (string, []string) {
	var hints []string
	if r != nil {
		hints = r.hints
	}
	switch {
	case r == nil || len(r.configured) == 0:
		return "registry denied access to the image (authentication required, or the image does not exist); for a private registry add a kubernetes.io/dockerconfigjson or kubernetes.io/basic-auth Secret to registryAuth.existingSecrets", hints
	case r.secret == "":
		return fmt.Sprintf("registry denied anonymous access to the image; no Secret in registryAuth.existingSecrets has an entry for %s", r.image.registry), hints
	default:
		return fmt.Sprintf("registry rejected the credentials from Secret %q (entry %q): they may be wrong, expired or lack pull access to %s; update the Secret (the next scan uses the new value)",
			r.secret, r.key, r.image), hints
	}
}

// redactValues replaces known sensitive values in s.
func redactValues(s string, values []string) string {
	for _, v := range values {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}
