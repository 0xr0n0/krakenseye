package main

import (
	"flag"
	"fmt"
	"os"

	"krakenseye/internal/gcp"
	"krakenseye/internal/k8s"
	"krakenseye/internal/probe"
	"krakenseye/internal/report"
)

var version = "dev"

func main() {
	var (
		server      = flag.String("server", "", "kubernetes API server URL (https://host:port)")
		token       = flag.String("token", "", "bearer token (SA token); empty = auto-detect in-cluster")
		gcpToken    = flag.String("gcp-token", "", "explicit GCP OAuth access token (skip metadata acquisition)")
		kubeconf    = flag.String("kubeconfig", "", "kubeconfig path (bearer-token users only)")
		ns          = flag.String("namespace", "", "explicit namespace for scoped checks")
		insecure    = flag.Bool("insecure", false, "skip TLS verification")
		noColor     = flag.Bool("no-color", false, "disable ANSI colors")
		quiet       = flag.Bool("quiet", false, "hide INFO findings")
		skipK8s     = flag.Bool("skip-k8s", false, "skip kubernetes checks")
		skipCloud   = flag.Bool("skip-cloud", false, "skip GCP metadata/API checks")
		jsonOut     = flag.String("json", "", "write findings to JSON file (- for stdout)")
		showVersion = flag.Bool("version", false, "print version and exit")
		showUsage   = flag.Bool("h", false, "help")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("krakenseye " + version)
		os.Exit(0)
	}
	if *showUsage {
		flag.Usage()
		os.Exit(0)
	}

	rep := report.New(*noColor)
	rep.Quiet = *quiet

	srv, tok, autoNS, caFile, ok := k8s.InCluster()
	tokenSrc := "in-cluster service account"
	if *server != "" {
		srv = *server
	}
	if *token != "" {
		tok = *token
		tokenSrc = "flag --token"
	}
	if *kubeconf != "" {
		s2, t2, n2, err := k8s.FromKubeconfig(*kubeconf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] kubeconfig: %v\n", err)
			os.Exit(1)
		}
		srv, tok, autoNS = s2, t2, n2
		tokenSrc = "kubeconfig " + *kubeconf
		ok = true
	}
	if *ns != "" {
		autoNS = *ns
	}

	if !*skipK8s {
		if !ok && *token == "" {
			rep.Add(report.Finding{Severity: report.Crit, Section: "Bootstrap", Title: "no credentials found: not in-cluster, no --token/--kubeconfig"})
		} else {
			client := k8s.New(srv, tok, caFile, autoNS, *insecure)
			rep.AddHeader(fmt.Sprintf("  [-i] auth source: %s", tokenSrc))
			s := &k8s.Scanner{Client: client, Rep: rep}
			s.Run()
		}
	}

	if !*skipCloud {
		gc := gcp.New()
		if *gcpToken != "" {
			gc.Token = *gcpToken
			gc.TokenFrom = "flag --gcp-token"
		}
		g := &gcp.Scanner{Client: gc, Rep: rep}
		g.Run()
	}

	probe := &probe.Scanner{Rep: rep}
	probe.Run()

	if *jsonOut != "" {
		if err := rep.ToJSON(*jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "[-] json: %v\n", err)
		}
	}
	rep.Print()
}
