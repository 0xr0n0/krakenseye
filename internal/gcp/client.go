// Package gcp implements GCP interaction for Kraken's Eye: metadata
// server probing, token introspection, testIamPermissions and read-only
// resource listing. No mutating API calls are made.
package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MetadataHost is the GKE metadata server address. 169.254.169.254 is
// tried as a fallback for classic GCE metadata.
const MetadataHost = "metadata.google.internal"

const (
	userAgent         = "krakenseye/0.1"
	apiRequestTimeout = 8 * time.Second
	maxApiResponse    = 2 << 20
	maxMetaResponse   = 1 << 20
)

// Client carries the OAuth token and resolved project identity.
type Client struct {
	HTTP      *http.Client
	Token     string // OAuth access token, resolved from metadata or a flag
	TokenFrom string
	Project   string // project-id used in resource-scoped URLs
	ProjectID string
	SAEmail   string
	Scopes    []string
	Dead      bool // set when the GCP API is unreachable; scanning stops
}

type metaResult struct {
	Code int
	Body string
	OK   bool
}

// New builds an API client with sane timeouts. The token itself is
// resolved later from the metadata server or supplied via --gcp-token.
func New() *Client {
	return &Client{HTTP: &http.Client{
		Timeout: apiRequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    8,
			IdleConnTimeout: 20 * time.Second,
		},
	}}
}

func (c *Client) hasToken() bool { return c.Token != "" }

func (c *Client) metaGet(host, path string) metaResult {
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}
	req, err := http.NewRequest(http.MethodGet, host+path, nil)
	if err != nil {
		return metaResult{}
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return metaResult{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxMetaResponse))
	return metaResult{Code: resp.StatusCode, Body: string(b), OK: resp.StatusCode == 200}
}

func (c *Client) apiGet(url string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if c.hasToken() {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxApiResponse))
	return resp.StatusCode, b, nil
}

func (c *Client) apiPostJSON(url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	if c.hasToken() {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxApiResponse))
	return resp.StatusCode, b, nil
}

// TokenInfo resolves the subject of the current OAuth token.
func (c *Client) TokenInfo() (email string, expires int64, err error) {
	code, body, err := c.apiGet("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + c.Token)
	if err != nil {
		return "", 0, err
	}
	if code != 200 {
		return "", 0, errFromBody(code, body)
	}
	var info struct {
		Email     string `json:"email"`
		ExpiresIn int64  `json:"expires_in"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", 0, err
	}
	if info.Error != "" {
		return "", 0, errFromBody(code, body)
	}
	return info.Email, info.ExpiresIn, nil
}

func errFromBody(code int, body []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return &APIError{Code: code, Status: e.Error.Status, Message: e.Error.Message}
	}
	return &APIError{Code: code, Message: strings.TrimSpace(string(body))}
}

// APIError represents a non-2xx Google API response.
type APIError struct {
	Code    int
	Status  string
	Message string
}

func (e *APIError) Error() string {
	return e.Status + ": " + e.Message + " (http " + strconv.Itoa(e.Code) + ")"
}

// TestIAMPermissions asks cloudresourcemanager which of perms the current
// identity holds on resource. Returns the subset that is allowed.
func (c *Client) TestIAMPermissions(resource string, perms []string) ([]string, error) {
	payload, err := json.Marshal(map[string]any{"permissions": perms})
	if err != nil {
		return nil, err
	}
	code, body, err := c.apiPostJSON("https://cloudresourcemanager.googleapis.com/v1/"+resource+":testIamPermissions", payload)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errFromBody(code, body)
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	sort.Strings(out.Permissions)
	return out.Permissions, nil
}
