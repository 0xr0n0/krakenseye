// Package probe inspects the local pod: capabilities, mounts, credential
// files and network facts. Purely local reads, no network scanning.
package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"krakenseye/internal/report"
)

// Scanner feeds pod-local findings into the shared report.
type Scanner struct {
	Rep *report.Report
}

func (s *Scanner) Run() {
	s.capabilities()
	s.mounts()
	s.credentialFiles()
	s.envCreds()
	s.network()
}

// perilousCaps drive escape-related findings; the rest are informational.
var perilousCaps = map[string]bool{
	"SYS_ADMIN":       true,
	"SYS_PTRACE":      true,
	"DAC_OVERRIDE":    true,
	"DAC_READ_SEARCH": true,
	"NET_ADMIN":       true,
}

var capNames = map[uint]string{
	0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER",
	4: "FSETID", 5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP",
	9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_BROADCAST",
	12: "NET_ADMIN", 13: "NET_RAW", 14: "IPC_LOCK", 21: "SYS_ADMIN",
	27: "MKNOD", 33: "SYS_PTRACE", 34: "SYS_CHROOT", 38: "AUDIT_CONTROL",
}

func (s *Scanner) capabilities() {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}
	var capEff uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			if v, err := strconv.ParseUint(strings.Fields(line)[1], 16, 64); err == nil {
				capEff = v
			}
			break
		}
	}
	var caps, risky []string
	for bit, name := range capNames {
		if capEff&(1<<bit) != 0 {
			caps = append(caps, name)
			if perilousCaps[name] {
				risky = append(risky, name)
			}
		}
	}
	if len(risky) > 0 {
		s.Rep.Add(report.Finding{
			Severity:   report.Warn,
			Section:    "Pod surface",
			Title:      "dangerous capabilities: " + strings.Join(risky, ", "),
			AttackPath: "SYS_ADMIN+NET_ADMIN = mount/remount and breakout attempts; SYS_PTRACE = inject into other processes",
		})
	}
	s.Rep.Add(report.Finding{Severity: report.Info, Section: "Pod surface", Title: "effective capabilities: " + strings.Join(caps, ", ")})
	if _, err := os.Stat("/.dockerenv"); err == nil {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Pod surface", Title: "inside container (/.dockerenv present)"})
	}
	if os.Getuid() != 0 {
		s.Rep.Add(report.Finding{Severity: report.Warn, Section: "Pod surface", Title: "not root (uid " + strconv.Itoa(os.Getuid()) + ")"})
	}
}

func (s *Scanner) mounts() {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	var sockets []string
	var interesting []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, sock := range []string{"docker.sock", "containerd.sock", "crio.sock", "podman.sock", "kubelet.sock"} {
			if strings.Contains(line, sock) {
				sockets = append(sockets, sock)
			}
		}
		if strings.Contains(line, "kubernetes.io~host-path") || strings.Contains(line, "/var/lib/kubelet") {
			fields := strings.Fields(line)
			if len(fields) >= 10 {
				interesting = append(interesting, fields[4]+" -> "+fields[9])
			}
		}
	}
	if len(sockets) > 0 {
		s.Rep.Add(report.Finding{
			Severity:   report.Crit,
			Section:    "Pod surface",
			Title:      "container runtime sockets mounted: " + strings.Join(sockets, ", "),
			AttackPath: "socket mounted = host container runtime; run your own privileged container on the node and escape",
		})
	}
	for _, m := range interesting {
		s.Rep.Add(report.Finding{
			Severity:   report.Warn,
			Section:    "Pod surface",
			Title:      "host-ish mount: " + m,
			AttackPath: "writable hostPath mount: plant SUID binary, cron, SSH key on the host",
		})
	}
}

var credPaths = []string{
	"/root/.kube/config", "/home/*/.kube/config",
	"/root/.config/gcloud/application_default_credentials.json",
	"/home/*/.config/gcloud/application_default_credentials.json",
	"/root/.config/gcloud/credentials.db",
	"/root/.docker/config.json", "/home/*/.docker/config.json",
	"/root/.config/gcloud/access_tokens.db",
	"/actions-runner/.credentials", "/actions-runner/.credentials_rsaparams",
	"/actions-runner/.runner",
	"/github/_work/_temp/*",
}

func (s *Scanner) credentialFiles() {
	for _, p := range credPaths {
		matches, _ := filepath.Glob(p)
		if len(matches) == 0 {
			if _, err := os.Stat(p); err == nil {
				matches = []string{p}
			}
		}
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil || fi.IsDir() {
				continue
			}
			name := m
			sev := report.Info
			attack := ""
			switch {
			case strings.Contains(m, "application_default_credentials"):
				sev = report.Crit
				attack = "ADC JSON = user credentials; use with gcloud auth application-default login --impersonate-service-account or export GOOGLE_APPLICATION_CREDENTIALS + gcloud auth activate-service-account"
				name = "found ADC credentials: " + m
			case strings.Contains(m, ".kube/config"):
				sev = report.Crit
				attack = "kubeconfig found; use it to auth as its user"
				name = "found kubeconfig: " + m
			case strings.Contains(m, ".docker/config.json"):
				sev = report.Warn
				attack = "registry creds; pull private images (GitLab/GCR/ECR-style registries) and grep layers for secrets"
				name = "found docker config: " + m
			case strings.Contains(m, ".credentials_rsaparams") || strings.Contains(m, ".credentials"):
				sev = report.Warn
				attack = "runner registration credentials; register own runner as that repo/org for command injection"
				name = "found GitHub runner creds: " + m
			case strings.Contains(m, ".runner"):
				sev = report.Info
				name = "found runner state: " + m
			}
			s.Rep.Add(report.Finding{Severity: sev, Section: "Credential hunting", Title: name, AttackPath: attack})
		}
	}
}

func (s *Scanner) envCreds() {
	hits := []string{}
	for _, e := range os.Environ() {
		name, val, _ := strings.Cut(e, "=")
		up := strings.ToUpper(name)
		val = strings.ToLower(val)
		if strings.Contains(up, "TOKEN") || strings.Contains(up, "SECRET") ||
			strings.Contains(up, "PASSWORD") || strings.Contains(up, "PASSWD") ||
			strings.Contains(up, "CREDENTIAL") || strings.Contains(up, "API_KEY") ||
			strings.Contains(up, "_KEY") || strings.Contains(up, "AUTH") {
			if name == "ACTIONS_ID_TOKEN_REQUEST_TOKEN" && strings.Contains(val, "github") {
				continue
			}
			hits = append(hits, name)
		}
		if strings.Contains(name, "GOOGLE_APPLICATION_CREDENTIALS") {
			hits = append(hits, name+"="+val)
		}
	}
	if len(hits) > 40 {
		s.Rep.Add(report.Finding{Severity: report.Info, Section: "Credential hunting", Title: fmt.Sprintf("%d credential-like env vars (names only)", len(hits))})
		return
	}
	already := map[string]bool{}
	var uniq []string
	for _, h := range hits {
		if !already[h] {
			uniq = append(uniq, h)
			already[h] = true
		}
	}
	s.Rep.Add(report.Finding{
		Severity:   report.Warn,
		Section:    "Credential hunting",
		Title:      fmt.Sprintf("credential-like env vars: %s", strings.Join(uniq, ", ")),
		AttackPath: "inspect values of the interesting names; runners export secrets to steps",
	})
}

func (s *Scanner) network() {
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nameserver") {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "Pod surface", Title: "dns: " + strings.TrimSpace(line), AttackPath: "the .1 address of the same range usually is the kube-api server"})
				break
			}
		}
	}
	if route, err := os.ReadFile("/proc/net/route"); err == nil {
		lines := strings.Split(string(route), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 1 {
				s.Rep.Add(report.Finding{Severity: report.Info, Section: "Pod surface", Title: "default route: " + fields[0]})
			}
		}
	}
}
