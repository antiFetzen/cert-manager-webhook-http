package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cmacme "github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// Ensure interface compliance at compile time.
var _ cmacme.Solver = &httpSolver{}

// httpSolverConfig is decoded from the ACME Issuer's webhook config JSON.
//
// Example Issuer config:
//
//	dns01:
//	  webhook:
//	    groupName: acme.example.com
//	    solverName: http-solver
//	    config:
//	      presentUrl:  "https://api.best.hosting/api/dns?action=add&token={token}&user={username}&record={record}&zone={zone}&fqdn={fqdn}&key={key}"
//	      cleanupUrl:  "https://api.best.hosting/api/dns?action=del&token={token}&user={username}&record={record}&zone={zone}"
//	      method:      "GET"          # GET (default) | POST
//	      tokenSecretRef:
//	        name: "hosting-secret"
//	        key:  "token"
//	      usernameSecretRef:
//	        name: "hosting-secret"
//	        key:  "username"
//	      # Static values (used when no secretRef is given):
//	      # token:    "my-static-token"
//	      # username: "my-static-user"
//	      successCodes: [200, 201, 204]  # optional, defaults to [200]
//	      timeoutSeconds: 10             # optional, default 10
type httpSolverConfig struct {
	// URL template for the "present" (add TXT record) call.
	// Supported placeholders: {token} {username} {record} {zone} {fqdn} {key}
	PresentURL string `json:"presentUrl"`

	// URL template for the "cleanup" (remove TXT record) call.
	// Same placeholders as PresentURL. Leave empty to skip cleanup.
	CleanupURL string `json:"cleanupUrl,omitempty"`

	// HTTP method to use: "GET" or "POST". Default: "GET".
	Method string `json:"method,omitempty"`

	// Optional: load the token value from a Kubernetes Secret.
	TokenSecretRef *corev1.SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// Optional: load the username value from a Kubernetes Secret.
	UsernameSecretRef *corev1.SecretKeySelector `json:"usernameSecretRef,omitempty"`

	// Static token (used when TokenSecretRef is not set).
	Token string `json:"token,omitempty"`

	// Static username (used when UsernameSecretRef is not set).
	Username string `json:"username,omitempty"`

	// HTTP status codes that are considered success. Default: [200].
	SuccessCodes []int `json:"successCodes,omitempty"`

	// Timeout in seconds for each HTTP call. Default: 10.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// httpSolver implements the cert-manager DNS01 webhook solver interface.
type httpSolver struct {
	client *kubernetes.Clientset
}

// Name returns the solver identifier used in the Issuer config.
func (s *httpSolver) Name() string {
	return "http-solver"
}

// Present creates the DNS TXT record by calling the configured URL.
func (s *httpSolver) Present(ch *acme.ChallengeRequest) error {
	klog.Infof("Present called: fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	cfg, err := s.loadConfig(ch)
	if err != nil {
		return fmt.Errorf("http-solver: loading config: %w", err)
	}

	if cfg.PresentURL == "" {
		return fmt.Errorf("http-solver: presentUrl is required")
	}

	token, username, err := s.resolveCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("http-solver: resolving credentials: %w", err)
	}

	url := expandPlaceholders(cfg.PresentURL, token, username, ch)
	klog.Infof("Present → %s %s", method(cfg), url)

	return s.doRequest(cfg, url)
}

// CleanUp removes the DNS TXT record by calling the configured cleanup URL.
func (s *httpSolver) CleanUp(ch *acme.ChallengeRequest) error {
	klog.Infof("CleanUp called: fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	cfg, err := s.loadConfig(ch)
	if err != nil {
		return fmt.Errorf("http-solver: loading config: %w", err)
	}

	if cfg.CleanupURL == "" {
		klog.Info("http-solver: cleanupUrl not set, skipping cleanup")
		return nil
	}

	token, username, err := s.resolveCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("http-solver: resolving credentials: %w", err)
	}

	url := expandPlaceholders(cfg.CleanupURL, token, username, ch)
	klog.Infof("CleanUp → %s %s", method(cfg), url)

	return s.doRequest(cfg, url)
}

// Initialize wires up the Kubernetes client for Secret lookups.
func (s *httpSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("http-solver: creating k8s client: %w", err)
	}
	s.client = cl
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (s *httpSolver) loadConfig(ch *acme.ChallengeRequest) (*httpSolverConfig, error) {
	cfg := &httpSolverConfig{}
	if ch.Config == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(ch.Config.Raw, cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return cfg, nil
}

func (s *httpSolver) resolveCredentials(cfg *httpSolverConfig, namespace string) (token, username string, err error) {
	token = cfg.Token
	username = cfg.Username

	if cfg.TokenSecretRef != nil {
		token, err = s.secretValue(cfg.TokenSecretRef, namespace)
		if err != nil {
			return "", "", fmt.Errorf("reading token secret: %w", err)
		}
	}

	if cfg.UsernameSecretRef != nil {
		username, err = s.secretValue(cfg.UsernameSecretRef, namespace)
		if err != nil {
			return "", "", fmt.Errorf("reading username secret: %w", err)
		}
	}

	return token, username, nil
}

func (s *httpSolver) secretValue(ref *corev1.SecretKeySelector, namespace string) (string, error) {
	secret, err := s.client.CoreV1().Secrets(namespace).Get(
		context.Background(),
		ref.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		return "", err
	}
	val, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", ref.Key, ref.Name)
	}
	return string(val), nil
}

func (s *httpSolver) doRequest(cfg *httpSolverConfig, url string) error {
	timeout := 10
	if cfg.TimeoutSeconds > 0 {
		timeout = cfg.TimeoutSeconds
	}

	successCodes := cfg.SuccessCodes
	if len(successCodes) == 0 {
		successCodes = []int{200}
	}

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	req, err := http.NewRequest(method(cfg), url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "cert-manager-webhook-http/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	for _, code := range successCodes {
		if resp.StatusCode == code {
			klog.Infof("http-solver: request succeeded (%d)", resp.StatusCode)
			return nil
		}
	}

	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// expandPlaceholders replaces all supported {placeholder} tokens in the URL.
//
// Supported placeholders:
//
//	{token}    – API token / password
//	{username} – username
//	{record}   – the TXT record name (FQDN without trailing dot)
//	{zone}     – the DNS zone (without trailing dot)
//	{fqdn}     – the full FQDN with trailing dot (as cert-manager provides it)
//	{key}      – the ACME challenge key (the TXT record value)
func expandPlaceholders(tmpl, token, username string, ch *acme.ChallengeRequest) string {
	record := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	zone := strings.TrimSuffix(ch.ResolvedZone, ".")

	r := strings.NewReplacer(
		"{token}", token,
		"{username}", username,
		"{record}", record,
		"{zone}", zone,
		"{fqdn}", ch.ResolvedFQDN,
		"{key}", ch.Key,
	)
	return r.Replace(tmpl)
}

func method(cfg *httpSolverConfig) string {
	if cfg.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(cfg.Method)
}
