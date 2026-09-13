package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"krakenseye/internal/report"
)

func TestScannerAgainstFakeAPI(t *testing.T) {
	allowed := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
	})
	mux.HandleFunc("/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"forbidden"}`))
			return
		}
		w.Write([]byte(`{"items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}}]}`))
	})
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec struct {
				ResourceAttributes struct {
					Group     string `json:"group"`
					Resource  string `json:"resource"`
					SubRes    string `json:"subresource"`
					Verb      string `json:"verb"`
					Namespace string `json:"namespace"`
				} `json:"resourceAttributes"`
			} `json:"spec"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		ra := in.Spec.ResourceAttributes
		key := ra.Group + "/" + ra.Resource + "/" + ra.SubRes + "/" + ra.Verb
		allowed := allowed[key]
		resp := map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
			"status": map[string]any{"allowed": allowed, "denied": !allowed}}
		if strings.Contains(key, "invalid") {
			resp["status"] = map[string]any{"allowed": false, "denied": true, "reason": "webhook says no"}
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"kind":"SelfSubjectRulesReview","status":{"resourceRules":[],"nonResourceRules":[],"incomplete":true}}`))
	})
	for _, p := range []string{"/api/v1/pods", "/api/v1/serviceaccounts", "/api/v1/secrets", "/api/v1/nodes", "/api/v1/services"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(403)
				w.Write([]byte(`{}`))
				return
			}
			w.Write([]byte(`{"items":[]}`))
		})
	}
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	allowed["/pods//create"] = true
	allowed["/secrets//list"] = true
	allowed["rbac.authorization.k8s.io/roles/bind/"] = false

	client := New(srv.URL, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cnVubmVycyJ9.sig", "", "runners", true)
	rep := report.New(true)
	sc := &Scanner{Client: client, Rep: rep}
	if err := sc.Run(); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range rep.Findings {
		found[f.Section+"|"+f.Severity.String()+"|"+f.Title] = true
	}
	if client.Version == "" {
		t.Fatalf("version not populated")
	}
	var crit int
	for _, f := range rep.Findings {
		if f.Severity == report.Crit {
			crit++
		}
	}
	if crit < 2 {
		t.Fatalf("expected >=2 CRIT findings (pods create + secrets list), got %d", crit)
	}
}
