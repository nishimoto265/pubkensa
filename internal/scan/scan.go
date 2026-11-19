package scan

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/nishimoto265/pubkensa/internal/config"
	"github.com/nishimoto265/pubkensa/internal/gitleaks"
)

type Kind string

const (
	KindGitleaks Kind = "gitleaks"
	KindDeny     Kind = "deny"
	KindAuthor   Kind = "author"
)

type Finding struct {
	Kind   Kind   `json:"kind"`
	Rule   string `json:"rule"`
	Path   string `json:"path,omitempty"`
	Commit string `json:"commit,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Result struct {
	OK        bool           `json:"ok"`
	Findings  []Finding      `json:"findings"`
	Scanned   Scanned        `json:"scanned"`
	Gitleaks  bool           `json:"gitleaks_ok"`
	ConfigPath string        `json:"config_path,omitempty"`
}

type Scanned struct {
	Commits int `json:"commits"`
	Files   int `json:"files"`
}

type Options struct {
	RepoDir       string
	ConfigPath    string
	Since         string
	SkipGitleaks  bool
}

func GitRoot(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository: %s", dir)
	}
	return strings.TrimSpace(string(out)), nil
}

func Run(opts Options) (*Result, error) {
	root, err := GitRoot(opts.RepoDir)
	if err != nil {
		return nil, err
	}
	cfgPath, err := config.Find(root, opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	res := &Result{ConfigPath: cfgPath, Gitleaks: true, Findings: []Finding{}}

	authors, nCommits, err := CheckAuthors(root, opts.Since, cfg.AuthorEmailAllow)
	if err != nil {
		return nil, err
	}
	res.Scanned.Commits = nCommits
	res.Findings = append(res.Findings, authors...)

	deny, nFiles, err := CheckDeny(root, opts.Since, cfg)
	if err != nil {
		return nil, err
	}
	res.Scanned.Files = nFiles
	res.Findings = append(res.Findings, deny...)

	if !opts.SkipGitleaks {
		rep, err := gitleaks.Run(root, cfg.Gitleaks.Command, cfg.Gitleaks.ExtraArgs)
		if err != nil {
			return nil, err
		}
		res.Gitleaks = rep.Available
		for _, f := range rep.Findings {
			res.Findings = append(res.Findings, Finding{
				Kind:   KindGitleaks,
				Rule:   f.Rule,
				Path:   f.File,
				Commit: f.Commit,
				Line:   f.StartLine,
				Detail: f.Message,
			})
		}
	}

	res.OK = len(res.Findings) == 0
	return res, nil
}

func FormatHuman(r *Result) string {
	if r.OK {
		return fmt.Sprintf("pubkensa: no findings (%d commits, %d files)\n", r.Scanned.Commits, r.Scanned.Files)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pubkensa: %d finding(s)\n", len(r.Findings))
	for _, f := range r.Findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		if f.Commit != "" {
			c := f.Commit
			if len(c) > 7 {
				c = c[:7]
			}
			if loc != "" {
				loc = c + " " + loc
			} else {
				loc = c
			}
		}
		fmt.Fprintf(&b, "[%s] %s %s %s\n", f.Kind, f.Rule, loc, f.Detail)
	}
	return b.String()
}
