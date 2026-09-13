// Package k8s implements Kubernetes API interaction for Kraken's Eye:
// credential discovery, SelfSubjectAccessReview-driven privilege checks
// and read-only resource enumeration. No mutating requests are issued.
package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// ServiceAccountPaths are the standard in-cluster projected token files.
	SATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	SACAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	SANsFile    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	userAgent        = "krakenseye/0.1"
	requestTimeout   = 6 * time.Second
	maxResponseBytes = 1 << 20
)

// Client talks to one Kubernetes API server using a single bearer token.
type Client struct {
	Server     string
	Token      string
	CACertFile string
	Insecure   bool
	Namespace  string
	HTTP       *http.Client
	Version    string
	Dead       bool // set when the API server is unreachable; scanning stops
}

// Claims are the interesting subset of a Kubernetes service account token.
type Claims struct {
	Iss         string   `json:"iss"`
	Sub         string   `json:"sub"`
	Namespace   string   `json:"kubernetes.io/namespace"`
	ServiceAcct string   `json:"kubernetes.io/serviceaccount/name"`
	UID         string   `json:"kubernetes.io/serviceaccount/uid"`
	Aud         []string `json:"aud"`
	Exp         int64    `json:"exp"`
	PodName     string   `json:"kubernetes.io/pod/name"`
	PodUID      string   `json:"kubernetes.io/pod/uid"`
}

func tokenClaims(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("token is not a JWT")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal(data, &c)
	return c, nil
}

// InCluster detects the in-cluster API configuration exposed to pods.
func InCluster() (server, token, ns, caFile string, ok bool) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" {
		return "", "", "", "", false
	}
	if port == "" {
		port = "443"
	}
	t, err := os.ReadFile(SATokenPath)
	if err != nil {
		return "", "", "", "", false
	}
	nsData, _ := os.ReadFile(SANsFile)
	url := "https://" + net.JoinHostPort(host, port)
	return url, strings.TrimSpace(string(t)), strings.TrimSpace(string(nsData)), SACAFile, true
}

// New builds a Client. The CA is loaded from caFile when provided,
// otherwise the system pool is used; insecure skips verification entirely.
func New(server, token, caFile, namespace string, insecure bool) *Client {
	c := &Client{
		Server:     server,
		Token:      token,
		CACertFile: caFile,
		Insecure:   insecure,
		Namespace:  namespace,
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case insecure:
		tlsCfg.InsecureSkipVerify = true
	case caFile != "":
		if pem, err := os.ReadFile(caFile); err == nil {
			tlsCfg.RootCAs = newCertPool(pem)
		}
	default:
		tlsCfg.RootCAs, _ = x509.SystemCertPool()
	}
	c.HTTP = &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 4 * time.Second,
		},
	}
	return c
}

func newCertPool(pem []byte) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(pem)
	return pool
}

func (c *Client) req(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Server+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.HTTP.Do(req)
}

func drainStatus(resp *http.Response, err error) (int, []byte) {
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	return resp.StatusCode, b
}

// GetJSON performs a GET and decodes the response into out.
func (c *Client) GetJSON(path string, out any) error {
	return c.doJSON(http.MethodGet, path, nil, out)
}

// PostJSON performs a POST with a JSON body and decodes the response into out.
func (c *Client) PostJSON(path string, body []byte, out any) error {
	return c.doJSON(http.MethodPost, path, body, out)
}

func (c *Client) doJSON(method, path string, body []byte, out any) error {
	resp, err := c.req(method, path, body)
	code, b := drainStatus(resp, err)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("http %d: %s", code, truncate(string(b), 300))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ServerVersion fetches /version and caches the result on the Client.
func (c *Client) ServerVersion() (string, error) {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.GetJSON("/version", &v); err != nil {
		return "", err
	}
	c.Version = v.GitVersion
	return v.GitVersion, nil
}

// AnonymousProbe reports whether core APIs answer without credentials.
func (c *Client) AnonymousProbe() (string, error) {
	resp, err := c.req(http.MethodGet, "/api/v1/namespaces", nil)
	code, b := drainStatus(resp, err)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("status=%d body=%s", code, truncate(string(b), 150)), nil
}
