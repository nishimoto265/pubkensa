package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/nishimoto265/pubkensa/internal/config"
)

type matcher struct {
	name    string
	literal string
	re      *regexp.Regexp
}

func CheckDeny(repoDir, since string, cfg *config.Config) ([]Finding, int, error) {
	ms, err := buildMatchers(cfg)
	if err != nil {
		return nil, 0, err
	}
	if len(ms) == 0 {
		// Still count files so the report is honest.
		files, err := listFiles(repoDir)
		if err != nil {
			return nil, 0, err
		}
		n := 0
		for _, f := range files {
			if excluded(f, cfg.ExcludePaths) {
				continue
			}
			n++
		}
		return nil, n, nil
	}

	files, err := listFiles(repoDir)
	if err != nil {
		return nil, 0, err
	}
	var findings []Finding
	nFiles := 0
	for _, rel := range files {
		if excluded(rel, cfg.ExcludePaths) {
			continue
		}
		nFiles++
		path := filepath.Join(repoDir, rel)
		hits, err := scanFile(path, rel, ms)
		if err != nil {
			return nil, nFiles, err
		}
		findings = append(findings, hits...)
	}

	msgHits, err := scanCommitMessages(repoDir, since, ms)
	if err != nil {
		return nil, nFiles, err
	}
	findings = append(findings, msgHits...)

	histHits, err := scanHistoryPatches(repoDir, since, cfg.ExcludePaths, ms)
	if err != nil {
		return nil, nFiles, err
	}
	findings = append(findings, histHits...)

	return dedupe(findings), nFiles, nil
}

func buildMatchers(cfg *config.Config) ([]matcher, error) {
	var ms []matcher
	for i, lit := range cfg.DenyLiterals {
		if lit == "" {
			continue
		}
		ms = append(ms, matcher{name: fmt.Sprintf("literal-%d", i+1), literal: lit})
	}
	for _, p := range cfg.ResolvedPatterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("deny pattern %s: %w", p.Name, err)
		}
		ms = append(ms, matcher{name: p.Name, re: re})
	}
	return ms, nil
}

func listFiles(repoDir string) ([]string, error) {
	out, err := exec.Command("git", "-C", repoDir, "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) == 0 {
			continue
		}
		files = append(files, string(p))
	}
	return files, nil
}

func scanFile(abs, rel string, ms []matcher) ([]Finding, error) {
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if isBinary(b) {
		return nil, nil
	}
	var findings []Finding
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		for _, m := range ms {
			if !matchLine(line, m) {
				continue
			}
			findings = append(findings, Finding{
				Kind:   KindDeny,
				Rule:   m.name,
				Path:   rel,
				Line:   i + 1,
				Detail: "working tree",
			})
		}
	}
	return findings, nil
}

func scanCommitMessages(repoDir, since string, ms []matcher) ([]Finding, error) {
	args := []string{"-C", repoDir, "log", "--all", "--format=%H%x00%s%x00%b%x1e"}
	if since != "" {
		args = []string{"-C", repoDir, "log", since + "..HEAD", "--format=%H%x00%s%x00%b%x1e"}
	}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git log (messages): %w", err)
	}
	var findings []Finding
	for _, rec := range bytes.Split(out, []byte{0x1e}) {
		rec = bytes.TrimSpace(rec)
		if len(rec) == 0 {
			continue
		}
		parts := strings.SplitN(string(rec), "\x00", 3)
		if len(parts) < 2 {
			continue
		}
		hash := parts[0]
		text := parts[1]
		if len(parts) == 3 {
			text = parts[1] + "\n" + parts[2]
		}
		for i, line := range strings.Split(text, "\n") {
			for _, m := range ms {
				if !matchLine(line, m) {
					continue
				}
				findings = append(findings, Finding{
					Kind:   KindDeny,
					Rule:   m.name,
					Commit: hash,
					Line:   i + 1,
					Detail: "commit message",
				})
			}
		}
	}
	return findings, nil
}

func scanHistoryPatches(repoDir, since string, exclude []string, ms []matcher) ([]Finding, error) {
	args := []string{"-C", repoDir, "log", "--all", "-p", "-U0", "--format=-----COMMIT %H"}
	if since != "" {
		args = []string{"-C", repoDir, "log", since + "..HEAD", "-p", "-U0", "--format=-----COMMIT %H"}
	}
	cmd := exec.Command("git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git log -p: %w", err)
	}
	var findings []Finding
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var commit, path string
	var lineNo int
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "-----COMMIT "):
			commit = strings.TrimSpace(strings.TrimPrefix(line, "-----COMMIT "))
			path = ""
			lineNo = 0
		case strings.HasPrefix(line, "+++ b/"):
			path = strings.TrimPrefix(line, "+++ b/")
			if path == "/dev/null" {
				path = ""
			}
			lineNo = 0
		case strings.HasPrefix(line, "@@"):
			// @@ -a,b +c,d @@
			lineNo = parseNewLine(line)
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if path == "" || excluded(path, exclude) {
				continue
			}
			body := line[1:]
			for _, m := range ms {
				if !matchLine(body, m) {
					continue
				}
				findings = append(findings, Finding{
					Kind:   KindDeny,
					Rule:   m.name,
					Path:   path,
					Commit: commit,
					Line:   lineNo,
					Detail: "history",
				})
			}
			if lineNo > 0 {
				lineNo++
			}
		}
	}
	if err := sc.Err(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log -p: %w", err)
	}
	return findings, nil
}

func parseNewLine(hunk string) int {
	// @@ -l,s +l,s @@
	plus := strings.Index(hunk, "+")
	if plus < 0 {
		return 0
	}
	rest := hunk[plus+1:]
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func matchLine(line string, m matcher) bool {
	if m.literal != "" {
		return strings.Contains(line, m.literal)
	}
	if m.re != nil {
		return m.re.MatchString(line)
	}
	return false
}

func isBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	if bytes.IndexByte(b[:n], 0) >= 0 {
		return true
	}
	return !utf8.Valid(b[:n]) && bytes.IndexFunc(b[:n], func(r rune) bool { return r == utf8.RuneError }) >= 0
}

func excluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range patterns {
		if matchPath(rel, p) {
			return true
		}
	}
	return false
}

func matchPath(rel, pattern string) bool {
	pattern = filepath.ToSlash(pattern)
	if strings.HasSuffix(pattern, "/") {
		pattern += "**"
	}
	if ok, _ := filepath.Match(pattern, rel); ok {
		return true
	}
	// prefix directory
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	if strings.HasPrefix(pattern, "**/") {
		suf := strings.TrimPrefix(pattern, "**/")
		if ok, _ := filepath.Match(suf, filepath.Base(rel)); ok {
			return true
		}
		if ok, _ := filepath.Match(suf, rel); ok {
			return true
		}
	}
	return false
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		k := fmt.Sprintf("%s|%s|%s|%s|%d", f.Kind, f.Rule, f.Path, f.Commit, f.Line)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
