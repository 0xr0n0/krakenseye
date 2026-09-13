package k8s

import (
	"encoding/json"
)

// ResourceAttrs mirrors the RBAC authorization.v1 ResourceAttributes used
// in SelfSubjectAccessReview requests.
type ResourceAttrs struct {
	Namespace string `json:"namespace,omitempty"`
	Verb      string `json:"verb"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`
	SubRes    string `json:"subresource,omitempty"`
	Name      string `json:"name,omitempty"`
}

type sarrReq struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Spec       sarrSpec `json:"spec"`
}

type sarrSpec struct {
	ResourceAttributes *ResourceAttrs `json:"resourceAttributes,omitempty"`
	Namespace          string         `json:"namespace,omitempty"`
}

type sarrResp struct {
	Status struct {
		Allowed bool   `json:"allowed"`
		Denied  bool   `json:"denied"`
		Reason  string `json:"reason"`
	} `json:"status"`
}

type rulesResp struct {
	Status struct {
		ResourceRules []struct {
			Verbs         []string `json:"verbs"`
			APIGroups     []string `json:"apiGroups"`
			Resources     []string `json:"resources"`
			ResourceNames []string `json:"resourceNames"`
		} `json:"resourceRules"`
		NonResourceRules []struct {
			Verbs           []string `json:"verbs"`
			NonResourceURLs []string `json:"nonResourceURLs"`
		} `json:"nonResourceRules"`
		Incomplete bool `json:"incomplete"`
	} `json:"status"`
}

// SelfSubjectRulesReview lists the rules that apply to the current token.
func (c *Client) SelfSubjectRulesReview(ns string) (rulesResp, error) {
	var out rulesResp
	req := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Namespace string `json:"namespace,omitempty"`
		} `json:"spec"`
	}{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}
	if ns != "" {
		req.Spec.Namespace = ns
	}
	b, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	err = c.PostJSON("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", b, &out)
	return out, err
}

// CanI asks the API server whether the current token may perform ra.
// It returns the allowed flag and the authorizer's reason when denied.
func (c *Client) CanI(ra ResourceAttrs) (bool, string) {
	if ra.Namespace == "" {
		ra.Namespace = c.Namespace
	}
	req := sarrReq{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SelfSubjectAccessReview",
		Spec:       sarrSpec{ResourceAttributes: &ra},
	}
	b, err := json.Marshal(req)
	if err != nil {
		return false, err.Error()
	}
	var out sarrResp
	if err := c.PostJSON("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", b, &out); err != nil {
		return false, err.Error()
	}
	if out.Status.Denied {
		return false, out.Status.Reason
	}
	return out.Status.Allowed, out.Status.Reason
}
