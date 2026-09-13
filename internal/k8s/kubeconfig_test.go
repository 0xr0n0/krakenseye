package k8s

import (
	"testing"
)

func TestMiniYAML(t *testing.T) {
	doc := "apiVersion: v1\n" +
		"clusters:\n" +
		"  - cluster:\n" +
		"    certificate-authority-data: LS0t\n" +
		"    server: https://10.0.0.1:8443\n" +
		"  name: gke_runner\n" +
		"contexts:\n" +
		"  - context:\n" +
		"    cluster: gke_runner\n" +
		"    user: runner-user\n" +
		"    namespace: runners\n" +
		"  name: gke_runner\n" +
		"current-context: gke_runner\n" +
		"users:\n" +
		"  - name: runner-user\n" +
		"  user:\n" +
		"    token: eyJ\n"
	root, err := miniYAML(doc)
	if err != nil {
		t.Fatal(err)
	}
	if c := mstr(root["current-context"]); c != "gke_runner" {
		t.Fatalf("current-context = %q", c)
	}
	cls := listOf(mapIn(root, "clusters"), "clusters")
	if len(cls) != 1 || mstr(mapIn(cls[0], "cluster")["server"]) != "https://10.0.0.1:8443" {
		t.Fatalf("clusters wrong: %+v", cls)
	}
	if mstr(cls[0]["name"]) != "gke_runner" {
		t.Fatalf("cluster name wrong: %+v", cls[0])
	}
	us := listOf(mapIn(root, "users"), "users")
	if len(us) != 1 || mstr(mapIn(us[0], "user")["token"]) != "eyJ" {
		t.Fatalf("users wrong: %+v", us)
	}
	ctxs := listOf(mapIn(root, "contexts"), "contexts")
	if len(ctxs) != 1 || mstr(mapIn(ctxs[0], "context")["namespace"]) != "runners" {
		t.Fatalf("contexts wrong: %+v", ctxs)
	}
}
