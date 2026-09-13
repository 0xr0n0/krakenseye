package k8s

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Obj carries the metadata subset shared by every Kubernetes object.
type Obj struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		UID       string            `json:"uid"`
		Labels    map[string]string `json:"labels"`
		Annot     map[string]string `json:"annotations"`
	} `json:"metadata"`
}

// List returns the raw items of any collection endpoint.
func (c *Client) List(path string) ([]json.RawMessage, error) {
	code, body, err := c.rawGet(path)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %v (http %d)", path, err, code)
	}
	var ol struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &ol); err != nil {
		return nil, fmt.Errorf("GET %s: decode: %v", path, err)
	}
	return ol.Items, nil
}

// listInto lists a collection and decodes every item into T.
func listInto[T any](c *Client, path string) ([]T, error) {
	items, err := c.List(path)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(items))
	for _, it := range items {
		var v T
		if json.Unmarshal(it, &v) == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

func (c *Client) rawGet(path string) (int, []byte, error) {
	resp, err := c.req("GET", path, nil)
	code, body := drainStatus(resp, err)
	if err != nil {
		return code, body, err
	}
	if code >= 300 {
		return code, body, fmt.Errorf("request failed")
	}
	return code, body, nil
}

func (c *Client) ListObjs(path string) ([]Obj, error) { return listInto[Obj](c, path) }

// Pod is the security-relevant subset of a pod spec.
type Pod struct {
	Obj
	Spec struct {
		NodeName            string            `json:"nodeName"`
		HostNetwork         bool              `json:"hostNetwork"`
		HostPID             bool              `json:"hostPID"`
		HostIPC             bool              `json:"hostIPC"`
		ServiceAccountName  string            `json:"serviceAccountName"`
		AutomountSAToken    *bool             `json:"automountServiceAccountToken"`
		Containers          []Container       `json:"containers"`
		InitContainers      []Container       `json:"initContainers"`
		EphemeralContainers []Container       `json:"ephemeralContainers"`
		Volumes             []Volume          `json:"volumes"`
		ImagePullSecrets    []json.RawMessage `json:"imagePullSecrets"`
		NodeSelector        map[string]string `json:"nodeSelector"`
	} `json:"spec"`
	Status struct {
		Phase  string `json:"phase"`
		HostIP string `json:"hostIP"`
		PodIP  string `json:"podIP"`
	} `json:"status"`
}

// Container holds fields that decide pod escape feasibility.
type Container struct {
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Command     []string `json:"command"`
	Args        []string `json:"args"`
	SecurityCtx struct {
		Privileged               *bool  `json:"privileged"`
		RunAsUser                *int64 `json:"runAsUser"`
		AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
		Capabilities             struct {
			Add  []string `json:"add"`
			Drop []string `json:"drop"`
		} `json:"capabilities"`
	} `json:"securityContext"`
	VolumeMounts []struct {
		Name      string `json:"name"`
		MountPath string `json:"mountPath"`
		ReadOnly  bool   `json:"readOnly"`
	} `json:"volumeMounts"`
}

// Volume flags hostPath, projected SA tokens and secret mounts.
type Volume struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"hostPath"`
	Projected *struct {
		Sources []struct {
			ServiceAccountToken *struct {
				Path     string `json:"path"`
				Audience string `json:"audience"`
			} `json:"serviceAccountToken"`
		} `json:"sources"`
	} `json:"projected"`
	Secret *struct {
		SecretName string `json:"secretName"`
	} `json:"secret"`
	GCEPD    *json.RawMessage `json:"gcePersistentDisk"`
	CSI      *json.RawMessage `json:"csi"`
	EmptyDir *json.RawMessage `json:"emptyDir"`
}

// Secret exposes names and types; data stays on the wire.
type Secret struct {
	Obj
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

// ServiceAccount carries the workload identity annotation needed for
// GCP pivots.
type ServiceAccount struct {
	Obj
	Secrets []struct {
		Name string `json:"name"`
	} `json:"secrets"`
	ImagePullSecrets []json.RawMessage `json:"imagePullSecrets"`
	AutomountSAToken *bool             `json:"automountServiceAccountToken"`
}

// Node exposes addresses for kubelet probing and node identity.
type Node struct {
	Obj
	Status struct {
		Addresses []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		NodeInfo struct {
			KubeletVersion string `json:"kubeletVersion"`
			OSImage        string `json:"osImage"`
			Architecture   string `json:"architecture"`
		} `json:"nodeInfo"`
	} `json:"status"`
	Spec struct {
		ProviderID string `json:"providerID"`
		PodCIDR    string `json:"podCIDR"`
	} `json:"spec"`
}

func (c *Client) Namespaces() ([]Obj, error) { return c.ListObjs("/api/v1/namespaces") }
func (c *Client) PodsNS(ns string) ([]Pod, error) {
	return listInto[Pod](c, "/api/v1/namespaces/"+ns+"/pods")
}
func (c *Client) PodsAll() ([]Pod, error) { return listInto[Pod](c, "/api/v1/pods") }
func (c *Client) SAsNS(ns string) ([]ServiceAccount, error) {
	path := "/api/v1/serviceaccounts"
	if ns != "" {
		path = "/api/v1/namespaces/" + ns + "/serviceaccounts"
	}
	return listInto[ServiceAccount](c, path)
}
func (c *Client) NodesFull() ([]Node, error) { return listInto[Node](c, "/api/v1/nodes") }

// SecretsNS reports whether secrets are readable in ns and returns them.
// Data is never printed by the scanner beyond presence checks.
func (c *Client) SecretsNS(ns string) ([]Secret, bool) {
	var ol struct {
		Items []Secret `json:"items"`
	}
	code, body, err := c.rawGet("/api/v1/namespaces/" + ns + "/secrets")
	if err != nil || code >= 300 {
		return nil, false
	}
	if err := json.Unmarshal(body, &ol); err != nil {
		return nil, false
	}
	return ol.Items, true
}

// SecretsAll tries cluster-wide secret listing (/api/v1/secrets).
func (c *Client) SecretsAll() ([]Secret, bool) {
	var ol struct {
		Items []Secret `json:"items"`
	}
	code, body, err := c.rawGet("/api/v1/secrets")
	if err != nil || code >= 300 {
		return nil, false
	}
	if err := json.Unmarshal(body, &ol); err != nil {
		return nil, false
	}
	return ol.Items, true
}

// SecretTypesSummary counts secret kinds and normalizes legacy token secrets.
func SecretTypesSummary(secrets []Secret) map[string]int {
	m := map[string]int{}
	for _, s := range secrets {
		t := s.Type
		if t == "" || strings.HasPrefix(s.Metadata.Name, s.Metadata.Namespace+"-token") {
			t = "kubernetes.io/service-account-token"
		}
		m[t]++
	}
	return m
}

// SecretFinding holds the per-secret severity classification.
type SecretFinding struct {
	Name      string
	Namespace string
	Type      string
	Severity  string // "crit", "warn", "info"
	Reason    string
}

// credentialSecretPatterns are name substrings that suggest a secret
// carries credentials beyond its Kubernetes type.
var credentialSecretPatterns = []string{
	"github", "app-key", "app-private", "private-key", "webhook",
	"credential", "password", "passwd", "token", "api-key", "apikey",
	"oauth", "client-secret", "runner", "registry", "docker", "gcr",
	"aws", "azure", "gcp", "service-account", "sa-key",
}

// ClassifySecrets returns per-secret findings based on type and name
// heuristics. This is where ARC GitHub App secrets and similar
// high-value targets get flagged individually.
func ClassifySecrets(secrets []Secret) []SecretFinding {
	var out []SecretFinding
	for _, s := range secrets {
		sf := SecretFinding{
			Name:      s.Metadata.Name,
			Namespace: s.Metadata.Namespace,
			Type:      s.Type,
			Severity:  "info",
			Reason:    s.Type,
		}
		switch s.Type {
		case "kubernetes.io/service-account-token":
			sf.Severity = "crit"
			sf.Reason = "SA bearer token, steal and auth as this SA"
		case "kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg":
			sf.Severity = "crit"
			sf.Reason = "registry credentials, pull private images and grep for secrets"
		case "kubernetes.io/basic-auth":
			sf.Severity = "crit"
			sf.Reason = "basic-auth credentials"
		case "kubernetes.io/ssh-auth":
			sf.Severity = "crit"
			sf.Reason = "SSH private key"
		case "kubernetes.io/tls":
			sf.Severity = "warn"
			sf.Reason = "TLS cert/key pair, check if it's a CA or signing key"
		default:
			name := strings.ToLower(s.Metadata.Name)
			for _, pat := range credentialSecretPatterns {
				if strings.Contains(name, pat) {
					sf.Severity = "warn"
					sf.Reason = fmt.Sprintf("name matches credential pattern %q, likely app credentials", pat)
					break
				}
			}
		}
		out = append(out, sf)
	}
	return out
}
