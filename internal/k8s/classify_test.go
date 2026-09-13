package k8s

import (
	"testing"
)

func TestClassifySecrets(t *testing.T) {
	secrets := []Secret{
		{Obj: Obj{}, Type: "kubernetes.io/service-account-token"},
		{Obj: Obj{}, Type: "kubernetes.io/dockerconfigjson"},
		{Obj: Obj{}, Type: "kubernetes.io/tls"},
		{Obj: Obj{}, Type: "Opaque"},
		{Obj: Obj{}, Type: "Opaque"},
	}
	secrets[0].Metadata.Name = "default-token-abc12"
	secrets[0].Metadata.Namespace = "runners"
	secrets[1].Metadata.Name = "gcr-pull-secret"
	secrets[1].Metadata.Namespace = "runners"
	secrets[2].Metadata.Name = "ingress-tls"
	secrets[2].Metadata.Namespace = "runners"
	secrets[3].Metadata.Name = "arc-github-app-key"
	secrets[3].Metadata.Namespace = "runners"
	secrets[4].Metadata.Name = "some-config"
	secrets[4].Metadata.Namespace = "runners"

	findings := ClassifySecrets(secrets)
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	expected := map[string]string{
		"default-token-abc12": "crit",
		"gcr-pull-secret":     "crit",
		"ingress-tls":         "warn",
		"arc-github-app-key":  "warn",
		"some-config":         "info",
	}
	for _, f := range findings {
		want, ok := expected[f.Name]
		if !ok {
			t.Errorf("unexpected secret %s", f.Name)
			continue
		}
		if f.Severity != want {
			t.Errorf("secret %q: got severity %q, want %q (reason: %s)", f.Name, f.Severity, want, f.Reason)
		}
	}
}

func TestClassifySecretsGitHubApp(t *testing.T) {
	secrets := []Secret{
		{Obj: Obj{}, Type: "Opaque"},
		{Obj: Obj{}, Type: "Opaque"},
		{Obj: Obj{}, Type: "Opaque"},
	}
	secrets[0].Metadata.Name = "arc-gha-runner-scale-set-github-secret"
	secrets[1].Metadata.Name = "runner-token-abc"
	secrets[2].Metadata.Name = "my-app-config"

	findings := ClassifySecrets(secrets)
	sevMap := map[string]string{}
	for _, f := range findings {
		sevMap[f.Name] = f.Severity
	}
	if sevMap["arc-gha-runner-scale-set-github-secret"] != "warn" {
		t.Errorf("ARC github secret should be warn, got %s", sevMap["arc-gha-runner-scale-set-github-secret"])
	}
	if sevMap["runner-token-abc"] != "warn" {
		t.Errorf("runner-token secret should be warn, got %s", sevMap["runner-token-abc"])
	}
	if sevMap["my-app-config"] != "info" {
		t.Errorf("generic config should be info, got %s", sevMap["my-app-config"])
	}
}
