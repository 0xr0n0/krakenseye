package gcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"krakenseye/internal/report"
)

// Scanner runs read-only GCP checks (metadata, IAM probing, resource
// listing) and feeds findings to the shared report.
type Scanner struct {
	Client *Client
	Rep    *report.Report
}

func (s *Scanner) Run() {
	c := s.Client
	s.metadata()
	if !c.hasToken() {
		return
	}
	s.whoami()
	if c.Dead {
		return
	}
	if c.ProjectID == "" {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: "no project resolved from identity; skipping project-scoped checks"})
		return
	}
	c.Project = c.ProjectID
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "project-id: " + c.ProjectID})
	s.permissions()
	s.resources()
}

func (s *Scanner) metadata() {
	c := s.Client
	hosts := []string{MetadataHost, "169.254.169.254"}
	reachable := false
	for _, h := range hosts {
		r := c.metaGet(h, "/computeMetadata/v1/instance/project/project-id")
		if r.OK {
			c.ProjectID = strings.TrimSpace(r.Body)
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: fmt.Sprintf("metadata reachable via %s, project-id: %s", h, c.ProjectID)})
			reachable = true
			zone := c.metaGet(h, "/computeMetadata/v1/instance/zone")
			if zone.OK {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: "zone: " + strings.TrimSpace(zone.Body)})
			}
			name := c.metaGet(h, "/computeMetadata/v1/instance/name")
			if name.OK {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: "instance name: " + strings.TrimSpace(name.Body)})
			}
			if strings.Contains(c.ProjectID, "gke") {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: fmt.Sprintf("looks like an autopilot/GKE sandbox %s host", h)})
			}
			s.attributes(h)
			s.serviceAccounts(h)
			return
		}
	}
	if !reachable {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: "metadata server not reachable (GCE metadata disabled or network blocked)"})
	}
}

func (s *Scanner) attributes(host string) {
	c := s.Client
	attrs := []struct {
		key    string
		sev    report.Severity
		attack string
	}{
		{"kube-env", report.Crit, "parse KUBERNETES_MASTER plus kubelet client cert/key or basic-auth creds to own the whole cluster"},
		{"cluster-name", report.Info, ""},
		{"cluster-location", report.Info, ""},
		{"kubelet-config", report.Warn, "kubelet flags can reveal credential files and insecure node settings"},
		{"configure-sh", report.Warn, "setup script may contain bootstrap secrets"},
		{"startup-script", report.Warn, "startup scripts often embed creds"},
		{"shutdown-script", report.Warn, ""},
	}
	for _, a := range attrs {
		r := c.metaGet(host, "/computeMetadata/v1/instance/attributes/"+a.key)
		if !r.OK {
			continue
		}
		var det []string
		if a.sev != report.Info && len(r.Body) > 0 {
			if len(r.Body) > 40000 {
				r.Body = r.Body[:40000] + "..."
			}
			det = []string{r.Body}
		}
		s.Rep.Add(report.Finding{Severity: a.sev, Section: "GKE metadata", Title: "attribute " + a.key + " readable", Details: det, AttackPath: a.attack})
	}
}

func (s *Scanner) serviceAccounts(host string) {
	c := s.Client
	email := c.metaGet(host, "/computeMetadata/v1/instance/service-accounts/default/email")
	if !email.OK {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: "no service account email on metadata"})
		return
	}
	c.SAEmail = strings.TrimSpace(email.Body)
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: "node SA email: " + c.SAEmail})
	scopes := c.metaGet(host, "/computeMetadata/v1/instance/service-accounts/default/scopes")
	if scopes.OK {
		for _, sc := range strings.Fields(scopes.Body) {
			c.Scopes = append(c.Scopes, sc)
		}
		sort.Strings(c.Scopes)
		joined := strings.Join(c.Scopes, ", ")
		sev := report.Warn
		t := "restricted scopes (limited): " + joined
		for _, sc := range c.Scopes {
			if sc == "https://www.googleapis.com/auth/cloud-platform" {
				sev = report.Crit
				t = "FULL cloud-platform scope"
				break
			}
		}
		if len(c.Scopes) > 5 {
			t = "scopes: " + joined
		}
		s.Rep.Add(report.Finding{Severity: sev, Section: "GKE metadata", Title: t, AttackPath: "scope restrictions apply to this token; find static SA keys (keys.list) or other VMs to bypass"})
	}
	tok := c.metaGet(host, "/computeMetadata/v1/instance/service-accounts/default/token")
	if tok.OK {
		var tv struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal([]byte(tok.Body), &tv); err == nil && tv.AccessToken != "" {
			c.Token = tv.AccessToken
			c.TokenFrom = "metadata " + host
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "GKE metadata", Title: fmt.Sprintf("obtained OAuth token from metadata (%s, expires in %ds)", tv.TokenType, tv.ExpiresIn)})
		}
	} else {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GKE metadata", Title: "metadata endpoint visible but /token returned nothing"})
	}
}

func (s *Scanner) whoami() {
	c := s.Client
	email, exp, err := c.TokenInfo()
	src := c.TokenFrom
	if src == "" {
		src = "user-supplied"
	}
	if err != nil {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: fmt.Sprintf("tokeninfo failed (%v) from %s", err, src)})
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: "GCP API is NOT reachable from this pod (no egress or token invalid)"})
		c.Dead = true
		return
	}
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: fmt.Sprintf("whoami: %s (token from %s, lifetime %ds)", email, src, exp)})
}

func (s *Scanner) permissions() {
	c := s.Client
	res := "projects/" + c.Project
	allowed, err := c.TestIAMPermissions(res, topPerms)
	if err != nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "testing IAM permissions on " + res + " failed (no testIamPermissions right): " + err.Error()})
		return
	}
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: fmt.Sprintf("testIamPermissions returned %d allowed permissions on %s", len(allowed), res)})
	for _, p := range allowed {
		if hint := permHints[p]; hint != "" {
			s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: "has " + p, AttackPath: hint})
		}
	}
}

func (s *Scanner) resources() {
	s.storage()
	s.gkeClusters()
	s.compute()
	s.iamSAs()
	s.secretManager()
}

func (s *Scanner) storage() {
	c := s.Client
	code, body, err := c.apiGet("https://storage.googleapis.com/storage/v1/b?project=" + c.Project)
	if err == nil && code == 200 {
		var out struct {
			Items []struct {
				Name     string `json:"name"`
				Location string `json:"location"`
			} `json:"items"`
		}
		if json.Unmarshal(body, &out) == nil {
			n := len(out.Items)
			sev := report.Warn
			title := fmt.Sprintf("CAN list storage buckets: %d", n)
			if n == 0 {
				title = "bucket list works, zero buckets"
				sev = report.Info
			}
			f := report.Finding{Severity: sev, Section: "GCP", Title: title, AttackPath: "enumerate buckets for secrets: gsutil ls / cat interesting files"}
			if n > 0 {
				var names []string
				for i, b := range out.Items {
					if i >= 30 {
						names = append(names, fmt.Sprintf("... +%d more", n-30))
						break
					}
					names = append(names, b.Name)
				}
				f.Details = names
			}
			s.Rep.Add(f)
		}
	} else if err != nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "cannot list buckets (scope or IAM)"})
	} else {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: fmt.Sprintf("bucket list denied: http %d", code)})
	}
}

func (s *Scanner) gkeClusters() {
	c := s.Client
	code, body, err := c.apiGet(fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/-/clusters", c.Project))
	if err == nil && code == 200 {
		var out struct {
			Clusters []struct {
				Name     string `json:"name"`
				Location string `json:"location"`
				Status   string `json:"status"`
			} `json:"clusters"`
		}
		if json.Unmarshal(body, &out) == nil {
			s.Rep.Add(report.Finding{
				Severity:   report.Crit,
				Section:    "GCP",
				Title:      fmt.Sprintf("CAN enumerate GKE clusters: %d", len(out.Clusters)),
				AttackPath: "this pod's identity can pull cluster info; gcloud container clusters get-credentials <name> --region <r> for kubeconfig",
			})
			for _, cl := range out.Clusters {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "cluster: " + cl.Name + " @ " + cl.Location + " (" + cl.Status + ")"})
			}
		}
	} else if err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: fmt.Sprintf("GKE clusters list denied: http %d", code)})
	}
}

func (s *Scanner) compute() {
	c := s.Client
	code, body, err := c.apiGet(fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/zones", c.Project))
	if err != nil || code != 200 {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "compute instances not enumerable (scope or IAM)"})
		return
	}
	var zones struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &zones) == nil {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: fmt.Sprintf("CAN enumerate zones: %d", len(zones.Items)), AttackPath: "iterate zones, list instances, look for VMs with static SA keys or juicy metadata"})
		var names []string
		for _, z := range zones.Items {
			names = append(names, z.Name)
			if len(names) >= 50 {
				break
			}
		}
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "zones: " + strings.Join(names, ", ")})
	}
	count := 0
	for _, z := range zones.Items {
		if count > 200 {
			break
		}
		_, body, err := c.apiGet(fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances", c.Project, z.Name))
		if err != nil {
			continue
		}
		var inst struct {
			Items []struct {
				Name         string `json:"name"`
				MachineType  string `json:"machineType"`
				Status       string `json:"status"`
				CanIpForward bool   `json:"canIpForward"`
			} `json:"items"`
		}
		if json.Unmarshal(body, &inst) == nil && count == 0 && len(inst.Items) > 0 {
			s.Rep.Add(report.Finding{Severity: report.Crit, Section: "GCP", Title: fmt.Sprintf("CAN enumerate compute instances (first zone %s has %d)", z.Name, len(inst.Items)), AttackPath: "instances may carry per-VM SAs; pivot via SSH keys, startup scripts, serial console"})
			for i, in := range inst.Items {
				if i >= 10 {
					break
				}
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "instance: " + in.Name + " (" + in.Status + ")"})
			}
		}
		count += len(inst.Items)
	}
}

func (s *Scanner) iamSAs() {
	c := s.Client
	code, body, err := c.apiGet(fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts", c.Project))
	if err != nil || code != 200 {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "cannot list service accounts (iam.serviceAccounts.list)"})
		return
	}
	var out struct {
		Accounts []struct {
			Email          string `json:"email"`
			UniqueID       string `json:"uniqueId"`
			Disabled       bool   `json:"disabled"`
			Oauth2ClientID string `json:"oauth2ClientId"`
		} `json:"accounts"`
	}
	if json.Unmarshal(body, &out) == nil {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "GCP", Title: fmt.Sprintf("CAN list service accounts: %d", len(out.Accounts)), AttackPath: "enumerate SAs for keys.list, workload identity bindings and impersonation targets"})
		keysFound := false
		for _, a := range out.Accounts {
			kc, kb, err := c.apiGet(fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys", c.Project, a.Email))
			if err == nil && kc == 200 {
				var keys struct {
					Keys []struct {
						Name        string `json:"name"`
						KeyType     string `json:"keyType"`
						ValidAfter  string `json:"validAfterTime"`
						ValidBefore string `json:"validBeforeTime"`
					} `json:"keys"`
				}
				if json.Unmarshal(kb, &keys) == nil {
					for _, k := range keys.Keys {
						if k.KeyType == "USER_MANAGED" {
							keysFound = true
							s.Rep.Add(report.Finding{Severity: report.Crit, Section: "GCP", Title: "SA " + a.Email + " has USER_MANAGED key " + k.Name, AttackPath: "static key bypasses metadata scopes; export private key to act as this SA with full IAM rights"})
						}
					}
				}
			}
			if len(out.Accounts) <= 40 {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "SA: " + a.Email})
			}
		}
		if !keysFound {
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "no USER_MANAGED keys found (or keys.list denied)"})
		}
	}
}

func (s *Scanner) secretManager() {
	c := s.Client
	code, body, err := c.apiGet(fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets", c.Project))
	if err != nil || code != 200 {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "cannot list Secret Manager secrets"})
		return
	}
	var out struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if json.Unmarshal(body, &out) == nil {
		s.Rep.Add(report.Finding{Severity: report.Crit, Section: "GCP", Title: fmt.Sprintf("CAN list Secret Manager secrets: %d", len(out.Secrets)), AttackPath: "gcloud secrets versions access latest <name> for each"})
		for i, ss := range out.Secrets {
			if i >= 30 {
				break
			}
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "GCP", Title: "secret: " + ss.Name})
		}
	}
}
