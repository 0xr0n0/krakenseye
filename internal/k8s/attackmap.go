package k8s

import "krakenseye/internal/report"

// PermCheck describes one RBAC grant worth testing, the severity of its
// impact and the attack path it unlocks when allowed.
type PermCheck struct {
	Section    string
	Title      string
	Group      string
	Resource   string
	Verb       string
	SubRes     string
	Severity   report.Severity
	AttackPath string
}

// DangerousChecks lists the grants from the Kubernetes privesc playbook
// (hacktricks abusing-roles + KubiScan risky role set), verified through
// SelfSubjectAccessReview.
func DangerousChecks() []PermCheck {
	p := func(title, group, res, verb, sub string, sev report.Severity, path string) PermCheck {
		return PermCheck{Section: "RBAC - current privileges", Title: title, Group: group, Resource: res, Verb: verb, SubRes: sub, Severity: sev, AttackPath: path}
	}
	return []PermCheck{
		p("Read secrets (get/list)", "", "secrets", "list", "", report.Crit,
			"list secrets in every reachable namespace, steal SA tokens from kubernetes.io/service-account-token secrets"),
		p("Read any resource (wildcard)", "*", "*", "list", "", report.Crit,
			"wildcard read reaches secrets and future resources; hunt tokens, kubeconfigs, cloud keys in configmaps"),
		p("Mint SA tokens", "", "serviceaccounts", "create", "token", report.Crit,
			"request tokens for privileged SAs (kube-system controllers, workload identity SA) via TokenRequest"),
		p("Reach kubelet via nodes/proxy", "", "nodes", "get", "proxy", report.Crit,
			"/api/v1/nodes/<node>/proxy/<path> hits the kubelet; combine with its exec API to run in all pods on that node"),
		p("Impersonate subjects", "rbac.authorization.k8s.io", "users", "impersonate", "", report.Crit,
			"impersonate cluster-admin or privileged SAs with Impersonate-User headers"),
		p("bind on Roles/ClusterRoles", "rbac.authorization.k8s.io", "roles", "bind", "", report.Crit,
			"bind yourself to cluster-admin: kubectl create rolebinding <name> --clusterrole=cluster-admin"),
		p("escalate on Roles/ClusterRoles", "rbac.authorization.k8s.io", "roles", "escalate", "", report.Crit,
			"edit a Role you can touch to add verbs beyond your own permissions"),
		p("Write clusterrolebindings/rolebindings", "rbac.authorization.k8s.io", "rolebindings", "create", "", report.Crit,
			"bind any role to any subject, including cluster-admin"),
		p("Create pods", "", "pods", "create", "", report.Crit,
			"mount hostPath / with privileged + hostPID/hostNetwork and nodeName to break out; steal all node-level tokens"),
		p("Update/patch workloads (deployments etc.)", "apps", "deployments", "patch", "", report.Crit,
			"patch a deployment to mount a privileged SA token or hostPath; the controller recreates pods for you"),
		p("Exec into pods", "", "pods", "create", "exec", report.Crit,
			"run commands in any pod's container and steal its SA token"),
		p("Attach/portforward/proxy pods", "", "pods", "create", "portforward", report.Warn,
			"reach services only available from inside the pod network"),
		p("Create secret (SA token secret)", "", "secrets", "create", "", report.Warn,
			"create a kubernetes.io/service-account-token secret annotated to a target SA to mint a long-lived token"),
		p("Read configmaps", "", "configmaps", "list", "", report.Warn,
			"configmaps carry app config, creds, GitOps state and runner registrations"),
		p("Create/modify networkpolicies", "networking.k8s.io", "networkpolicies", "create", "", report.Warn,
			"re-open network paths or allow egress to your listener"),
		p("Delete pods + mark nodes unschedulable", "", "pods", "delete", "", report.Warn,
			"force sensitive pods to reschedule onto your compromised node to steal their token files"),
		p("CSR create + approve", "certificates.k8s.io", "certificatesigningrequests", "create", "", report.Warn,
			"mint a client certificate for an existing privileged username"),
		p("PV create (hostPath storage)", "", "persistentvolumes", "create", "", report.Warn,
			"create PV with hostPath source, bind PVC + pod to mount arbitrary node directories"),
		p("Create serviceaccounts", "", "serviceaccounts", "create", "", report.Warn,
			"create an SA, request a bound token and abuse wherever automount is enabled"),
		p("Ephemeral containers", "", "pods", "patch", "ephemeralcontainers", report.Warn,
			"inject a privileged ephemeral container into any running pod"),
		p("List pods (all namespaces)", "", "pods", "list", "", report.Info,
			"map the cluster: find hot pods with privileged SAs"),
		p("List/read nodes", "", "nodes", "list", "", report.Info,
			"get node internal IPs to test kubelet 10250/10255 and cloud metadata"),
		p("List serviceaccounts", "", "serviceaccounts", "list", "", report.Info,
			"find SAs with iam.gke.io/gcp-service-account annotations (workload identity pivot)"),
		p("List roles/clusterroles", "rbac.authorization.k8s.io", "roles", "list", "", report.Info,
			"map which roles exist to plan escalation chains"),
	}
}
