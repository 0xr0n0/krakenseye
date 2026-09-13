package k8s

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"krakenseye/internal/report"
)

// Scanner runs every read-only check against one Kubernetes API server
// and feeds findings to the shared report.
type Scanner struct {
	Client *Client
	Rep    *report.Report
}

func (s *Scanner) Run() error {
	s.identity()
	s.serverInfo()
	if s.Client.Dead {
		return nil
	}
	s.privileges()
	s.resources()
	return nil
}

func (s *Scanner) identity() {
	c := s.Client
	claims, err := tokenClaims(c.Token)
	if err != nil {
		return
	}
	sub := claims.Sub
	if claims.Namespace != "" {
		sub = fmt.Sprintf("system:serviceaccount:%s:%s", claims.Namespace, claims.ServiceAcct)
	}
	s.Rep.AddHeader(fmt.Sprintf("  [-i] API: %s", c.Server))
	if sub != "" {
		s.Rep.AddHeader(fmt.Sprintf("  [-i] Subject: %s", sub))
	}
	s.Rep.AddHeader(fmt.Sprintf("  [-i] Namespace: %s", c.Namespace))
	if claims.Exp == 0 {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "Identity", Title: "SA token has no expiry claim", AttackPath: "legacy long-lived token, survives pod eviction; keep as fallback credential"})
	} else {
		exp := time.Unix(claims.Exp, 0)
		left := time.Until(exp)
		sev := report.Info
		label := "INFO"
		if left < 24*time.Hour {
			sev, label = report.Warn, "WARN"
		}
		s.Rep.Add(report.Finding{Severity: sev, Section: "Identity", Title: fmt.Sprintf("SA token expires %s (%s), valid for %s", exp.Format(time.RFC3339), label, left.Round(time.Second))})
	}
	if claims.PodName != "" {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Identity", Title: "bound to pod " + claims.PodName})
	}
	if len(claims.Aud) > 0 {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Identity", Title: "token audiences: " + strings.Join(claims.Aud, ", ")})
	}
}

func (s *Scanner) serverInfo() {
	c := s.Client
	ver, err := c.ServerVersion()
	if err != nil {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "API server", Title: fmt.Sprintf("cannot reach API server at %s: %v", c.Server, err)})
		c.Dead = true
		return
	}
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "API server", Title: "reachable, version: " + ver})
	if anon, err := c.AnonymousProbe(); err == nil {
		if strings.Contains(anon, "status=200") {
			s.Rep.Add(report.Finding{Severity: report.Crit, Section: "API server", Title: "anonymous access allowed: " + anon, AttackPath: "enumerate namespaces/secrets without any credentials"})
		} else {
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "API server", Title: "anonymous probe: " + anon})
		}
	}
}

func (s *Scanner) privileges() {
	c := s.Client
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "RBAC - current privileges", Title: "SelfSubjectAccessReview matrix against " + c.Namespace})
	for _, pc := range DangerousChecks() {
		ra := ResourceAttrs{Verb: pc.Verb, Group: pc.Group, Resource: pc.Resource, SubRes: pc.SubRes, Namespace: c.Namespace}
		allowed, reason := c.CanI(ra)
		if allowed {
			s.Rep.Add(report.Finding{Severity: pc.Severity, Section: pc.Section, Title: "CAN " + pc.Title, AttackPath: pc.AttackPath})
			continue
		}
		if reason != "" {
			reason = " (" + reason + ")"
		}
		s.Rep.Add(report.Finding{Severity: report.Info, Section: pc.Section, Title: "cannot " + pc.Title + reason})
	}
	if rr, err := c.SelfSubjectRulesReview(""); err == nil {
		for _, r := range rr.Status.ResourceRules {
			for _, g := range r.APIGroups {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "RBAC - current privileges", Title: fmt.Sprintf("group %s resources %v verbs %v names %v", g, r.Resources, r.Verbs, r.ResourceNames)})
			}
		}
		if rr.Status.Incomplete {
			s.Rep.Add(report.Finding{Severity: report.Warn, Section: "RBAC - current privileges", Title: "rule review incomplete: webhook authorizers present"})
		}
	}
}

func (s *Scanner) resources() {
	c := s.Client
	if nss, err := c.Namespaces(); err == nil {
		names := make([]string, 0, len(nss))
		for _, n := range nss {
			names = append(names, n.Metadata.Name)
		}
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("namespaces (%d): %s", len(names), strings.Join(names, ", "))})
	}
	if pods, err := c.PodsAll(); err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("pods cluster-wide readable: %d", len(pods))})
		s.hotPods(pods)
	} else if pods, err := c.PodsNS(c.Namespace); err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("pods readable in %s: %d", c.Namespace, len(pods))})
	} else {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "Cluster inventory", Title: "no pod read permission anywhere"})
	}
	s.serviceAccounts()
	s.secrets()
	if nodes, err := c.NodesFull(); err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("nodes (%d):", len(nodes))})
		for _, n := range nodes {
			var ips []string
			for _, a := range n.Status.Addresses {
				ips = append(ips, a.Address)
			}
			s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("  %s [%s] %s", n.Metadata.Name, strings.Join(ips, ", "), n.Status.NodeInfo.OSImage), AttackPath: "test kubelet ports 10250/10255 on node IPs"})
		}
		s.kubeletProbes(nodes)
	}
	if svcs, err := c.ListObjs("/api/v1/services"); err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Cluster inventory", Title: fmt.Sprintf("services readable: %d", len(svcs))})
	}
}

const kubeletProbeTimeout = 4 * time.Second

func kubeletGet(url string) (int, []byte) {
	client := &http.Client{
		Timeout: kubeletProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 2 * time.Second,
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

// kubeletProbes issues strictly read-only requests against node kubelets.
// Only /pods is fetched; no /exec, /run or other state-changing endpoints
// are ever touched.
func (s *Scanner) kubeletProbes(nodes []Node) {
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			ip := a.Address
			code, body := kubeletGet(fmt.Sprintf("http://%s:10255/pods", ip))
			if code != 0 {
				s.reportKubelet(ip, "10255", false, code, body)
			}
			code, body = kubeletGet(fmt.Sprintf("https://%s:10250/pods", ip))
			if code != 0 {
				s.reportKubelet(ip, "10250", true, code, body)
			}
			break
		}
	}
}

func (s *Scanner) reportKubelet(ip, port string, secure bool, code int, body []byte) {
	title := fmt.Sprintf("kubelet %s:%s /pods -> HTTP %d", ip, port, code)
	sev, attack := report.Warn, ""
	switch {
	case code == 200:
		sev = report.Crit
		var pods struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		n := 0
		if json.Unmarshal(body, &pods) == nil {
			n = len(pods.Items)
		}
		title += fmt.Sprintf(", %d pods visible", n)
		if !secure {
			attack = "read-only kubelet unauthenticated: leaks every pod on this node incl. names, IPs and images; /spec also yields full pod specs"
		} else {
			title += " (unauth/anonymous kubelet!)"
			attack = "10250 without auth = kubelet RCE via /exec /run on ALL pods of this node"
		}
	case code == 401 || code == 403:
		sev = report.Info
		title += " (auth required)"
	}
	s.Rep.Add(report.Finding{Severity: sev, Section: "Kubelet surface", Title: title, AttackPath: attack})
}

// hotPods locates pods whose runtime flags make them breakout or token
// theft targets.
func (s *Scanner) hotPods(pods []Pod) {
	for _, p := range pods {
		var issues []string
		for _, cont := range p.Spec.Containers {
			if cont.SecurityCtx.Privileged != nil && *cont.SecurityCtx.Privileged {
				issues = append(issues, "privileged "+cont.Name+" ("+cont.Image+")")
			}
			for _, c := range cont.SecurityCtx.Capabilities.Add {
				if c == "SYS_ADMIN" || c == "ALL" {
					issues = append(issues, "cap "+c+" on "+cont.Name)
				}
			}
		}
		if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
			issues = append(issues, fmt.Sprintf("host namespaces net=%v pid=%v ipc=%v", p.Spec.HostNetwork, p.Spec.HostPID, p.Spec.HostIPC))
		}
		for _, v := range p.Spec.Volumes {
			if v.HostPath != nil {
				issues = append(issues, "hostPath "+v.HostPath.Path)
			}
		}
		if len(issues) == 0 {
			continue
		}
		s.Rep.Add(report.Finding{
			Severity:   report.Crit,
			Section:    "Hot pods",
			Title:      fmt.Sprintf("%s/%s on node %s: %s", p.Metadata.Namespace, p.Metadata.Name, p.Spec.NodeName, strings.Join(issues, "; ")),
			Details:    []string{"serviceAccount: " + p.Spec.ServiceAccountName},
			AttackPath: "exec into this pod or schedule onto its node, steal its SA token + mounted host paths",
		})
	}
}

func (s *Scanner) serviceAccounts() {
	c := s.Client
	sas, err := c.SAsNS("")
	if err != nil {
		return
	}
	for _, sa := range sas {
		gsa := sa.Metadata.Annot["iam.gke.io/gcp-service-account"]
		if gsa == "" {
			continue
		}
		s.Rep.Add(report.Finding{
			Severity:   report.Crit,
			Section:    "GCP pivot",
			Title:      fmt.Sprintf("SA %s/%s maps to GCP SA %s (workload identity)", sa.Metadata.Namespace, sa.Metadata.Name, gsa),
			AttackPath: "create pod with this KSA, curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token, act as the GSA",
		})
	}
}

func (s *Scanner) secrets() {
	c := s.Client

	// Try cluster-wide first: strongest signal.
	if allSecs, ok := c.SecretsAll(); ok {
		s.Rep.Add(report.Finding{
			Severity:   report.Crit,
			Section:    "Secrets",
			Title:      fmt.Sprintf("CAN read secrets CLUSTER-WIDE: %d across all namespaces", len(allSecs)),
			AttackPath: "dump every SA token from every namespace including kube-system; auth as each, repeat can-i",
		})
		s.reportSecretDetails(allSecs, "cluster-wide")
		return
	}

	// Namespace-scoped fallback.
	nsSecs, ok := c.SecretsNS(c.Namespace)
	if !ok {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Secrets", Title: "cannot list secrets in " + c.Namespace})
		return
	}
	s.Rep.Add(report.Finding{
		Severity:   report.Crit,
		Section:    "Secrets",
		Title:      fmt.Sprintf("CAN read secrets in namespace %s: %d (namespace-scoped only)", c.Namespace, len(nsSecs)),
		AttackPath: "dump namespace SA tokens and app secrets; check for ARC/CI credentials, GitHub App keys, registry auth",
	})
	s.reportSecretDetails(nsSecs, c.Namespace)
}

// reportSecretDetails classifies each secret individually and reports
// type histogram + high-value secrets flagged by name/type heuristics.
func (s *Scanner) reportSecretDetails(secrets []Secret, scope string) {
	types := SecretTypesSummary(secrets)
	var ds []string
	for t, n := range types {
		ds = append(ds, fmt.Sprintf("%s x%d", t, n))
	}
	s.Rep.Add(report.Finding{
		Severity: report.Info,
		Section:  "Secrets",
		Title:    fmt.Sprintf("types in %s: %s", scope, strings.Join(ds, ", ")),
	})

	classified := ClassifySecrets(secrets)
	sevMap := map[string]report.Severity{"crit": report.Crit, "warn": report.Warn, "info": report.Info}
	for _, sf := range classified {
		if sf.Severity == "info" {
			continue // skip boring secrets to avoid flooding
		}
		s.Rep.Add(report.Finding{
			Severity:   sevMap[sf.Severity],
			Section:    "Secrets",
			Title:      fmt.Sprintf("secret %s/%s (%s)", sf.Namespace, sf.Name, sf.Type),
			AttackPath: sf.Reason,
		})
	}
}
