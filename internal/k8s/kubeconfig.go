package k8s

import (
	"fmt"
	"os"
	"strings"
)

type kubeContext struct {
	Cluster   string
	User      string
	Namespace string
}

type kubeUser struct {
	Token          string
	ClientCertData string
}

// FromKubeconfig loads the current context of a kubeconfig file supporting
// bearer-token users. Embedded certs are detected but not supported yet;
// use --token in that case.
func FromKubeconfig(path string) (server, token, namespace string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}
	root, err := miniYAML(string(data))
	if err != nil {
		return "", "", "", err
	}

	clusters := map[string]string{}
	for _, item := range listOf(mapIn(root, "clusters"), "clusters") {
		clusters[mstr(item["name"])] = mstr(mapIn(item, "cluster")["server"])
	}
	users := map[string]kubeUser{}
	for _, item := range listOf(mapIn(root, "users"), "users") {
		u := mapIn(item, "user")
		users[mstr(item["name"])] = kubeUser{
			Token:          mstr(u["token"]),
			ClientCertData: mstr(u["client-certificate-data"]),
		}
	}
	ctxs := map[string]kubeContext{}
	for _, item := range listOf(mapIn(root, "contexts"), "contexts") {
		cc := mapIn(item, "context")
		ctxs[mstr(item["name"])] = kubeContext{
			Cluster:   mstr(cc["cluster"]),
			User:      mstr(cc["user"]),
			Namespace: mstr(cc["namespace"]),
		}
	}
	current := mstr(root["current-context"])
	if current == "" {
		for name := range ctxs {
			current = name
			break
		}
	}
	ctx, ok := ctxs[current]
	if !ok {
		return "", "", "", fmt.Errorf("no context named %q", current)
	}
	server, ok = clusters[ctx.Cluster]
	if !ok {
		return "", "", "", fmt.Errorf("cluster %q not found", ctx.Cluster)
	}
	u, ok := users[ctx.User]
	if ok {
		token = u.Token
	}
	if token == "" && u.ClientCertData != "" {
		return "", "", "", fmt.Errorf("user %q uses client certs; pass --token with the SA token instead", ctx.User)
	}
	return server, token, ctx.Namespace, nil
}

func mstr(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func mapIn(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

func listOf(m map[string]any, key string) []map[string]any {
	v, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(v))
	for _, it := range v {
		if mm, ok := it.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

type ymFrame struct {
	m       map[string]any
	lastKey string
	depth   int
}

// miniYAML parses the flat subset of YAML kubeconfigs use: 2-space nested
// maps and lists of maps with "- key:" items. No anchors, flow collections
// or multi-line scalars.
func miniYAML(text string) (map[string]any, error) {
	root := map[string]any{}
	stack := []ymFrame{{m: root, lastKey: "", depth: -1}}
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		d := indent / 2
		line := strings.TrimSpace(raw)
		isItem := strings.HasPrefix(line, "- ")
		content := strings.TrimPrefix(line, "- ")
		key, val, found := strings.Cut(content, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		for len(stack) > 1 && stack[len(stack)-1].depth >= d {
			stack = stack[:len(stack)-1]
		}
		top := &stack[len(stack)-1]

		if isItem {
			obj := map[string]any{}
			list, _ := top.m[top.lastKey].([]any)
			top.m[top.lastKey] = append(list, obj)
			stack = append(stack, ymFrame{m: obj, depth: d - 1})
			top = &stack[len(stack)-1]
		}

		if val == "" {
			child := map[string]any{}
			top.m[key] = child
			stack = append(stack, ymFrame{m: child, lastKey: key, depth: d})
			continue
		}
		top.m[key] = val
	}
	return root, nil
}
