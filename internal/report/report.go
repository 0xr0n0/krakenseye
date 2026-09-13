// Package report collects findings from every scanner and renders them
// as a linpeas-style terminal report and optional JSON.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Severity orders findings; higher values are worse.
type Severity int

const (
	Info Severity = iota
	Warn
	Crit
)

func (s Severity) String() string {
	switch s {
	case Crit:
		return "CRIT"
	case Warn:
		return "WARN"
	default:
		return "INFO"
	}
}

// Finding is one observed fact, ability or credential.
type Finding struct {
	Severity   Severity `json:"severity"`
	Section    string   `json:"section"`
	Title      string   `json:"title"`
	Details    []string `json:"details,omitempty"`
	AttackPath string   `json:"attack_path,omitempty"`
}

// Report stores findings grouped by section. It is safe for concurrent
// Add calls.
type Report struct {
	mu       sync.Mutex
	Findings []Finding `json:"findings"`
	Header   []string  `json:"header,omitempty"`
	NoColor  bool      `json:"-"`
	Quiet    bool      `json:"-"`
	Shown    [3]int    `json:"-"`
	Sections []string  `json:"-"`
}

// New returns a report; noColor disables ANSI escapes for pipes.
func New(noColor bool) *Report {
	return &Report{NoColor: noColor}
}

func (r *Report) Add(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
	seen := false
	for _, s := range r.Sections {
		if s == f.Section {
			seen = true
			break
		}
	}
	if !seen {
		r.Sections = append(r.Sections, f.Section)
	}
	r.Shown[f.Severity]++
}

func (r *Report) AddHeader(line string) {
	r.Header = append(r.Header, line)
}

const (
	cReset  = "\033[0m"
	cRed    = "\033[1;31m"
	cYellow = "\033[1;33m"
	cGreen  = "\033[0;32m"
	cBold   = "\033[1m"
)

func (r *Report) color(s Severity) string {
	if r.NoColor {
		return ""
	}
	switch s {
	case Crit:
		return cRed
	case Warn:
		return cYellow
	default:
		return cGreen
	}
}

func (r *Report) banner(text string) string {
	if r.NoColor {
		return "\n" + strings.Repeat("=", len(text)+8) + "\n  " + text + "\n" + strings.Repeat("=", len(text)+8)
	}
	return "\n" + cBold + strings.Repeat("=", len(text)+8) + cReset + "\n  " + cBold + text + cReset + "\n" + cBold + strings.Repeat("=", len(text)+8) + cReset
}

// Print renders findings grouped by section, CRIT first per section.
func (r *Report) Print() {
	fmt.Println(r.banner("Kraken's Eye - GKE/GCP & Kubernetes recon"))
	for _, h := range r.Header {
		fmt.Println(h)
	}
	for _, sec := range r.Sections {
		fmt.Println(r.banner(sec))
		var fs []Finding
		for _, f := range r.Findings {
			if f.Section == sec {
				fs = append(fs, f)
			}
		}
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
		for _, f := range fs {
			if r.Quiet && f.Severity == Info {
				continue
			}
			tag := fmt.Sprintf("[%s] ", f.Severity)
			if !r.NoColor {
				tag = r.color(f.Severity) + tag + cReset
			}
			fmt.Printf("%s%s\n", tag, f.Title)
			for _, d := range f.Details {
				fmt.Printf("    %s\n", d)
			}
			if f.AttackPath != "" {
				ap := "-> attack: " + f.AttackPath
				if !r.NoColor {
					ap = cBold + ap + cReset
				}
				fmt.Printf("    %s\n", ap)
			}
		}
	}
	fmt.Println(r.banner("Summary"))
	fmt.Printf("  CRIT: %d  WARN: %d  INFO: %d\n", r.Shown[2], r.Shown[1], r.Shown[0])
}

// ToJSON writes findings as JSON to path; "-" means stdout.
func (r *Report) ToJSON(path string) error {
	b, err := json.MarshalIndent(r.Findings, "", "  ")
	if err != nil {
		return err
	}
	if path == "-" {
		os.Stdout.Write(append(b, '\n'))
		return nil
	}
	return os.WriteFile(path, b, 0o644)
}
