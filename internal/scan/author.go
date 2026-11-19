package scan

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func CheckAuthors(repoDir, since string, allow []string) ([]Finding, int, error) {
	res, err := compileAllow(allow)
	if err != nil {
		return nil, 0, err
	}
	args := []string{"-C", repoDir, "log", "--all", "--format=%H%x00%ae%x00%ce%x00%s"}
	if since != "" {
		args = []string{"-C", repoDir, "log", since + "..HEAD", "--format=%H%x00%ae%x00%ce%x00%s"}
	}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, 0, fmt.Errorf("git log (authors): %w", err)
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if len(out) == 0 {
		return nil, 0, nil
	}
	var findings []Finding
	n := 0
	seen := map[string]bool{}
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		n++
		parts := strings.Split(string(line), "\x00")
		if len(parts) < 4 {
			continue
		}
		hash, author, committer, subject := parts[0], parts[1], parts[2], parts[3]
		for _, pair := range [][2]string{{"author", author}, {"committer", committer}} {
			role, email := pair[0], pair[1]
			if allowedEmail(email, res) {
				continue
			}
			key := hash + role + strings.ToLower(email)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{
				Kind:   KindAuthor,
				Rule:   "email-allow",
				Commit: hash,
				Detail: role + " email is not on the allow list" + subjectSuffix(subject),
			})
		}
	}
	return findings, n, nil
}

func compileAllow(allow []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for i, p := range allow {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("author_email_allow[%d]: %w", i, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func allowedEmail(email string, allow []*regexp.Regexp) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	for _, re := range allow {
		if re.MatchString(email) {
			return true
		}
	}
	return false
}

func subjectSuffix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 72 {
		s = s[:72] + "…"
	}
	return " (" + s + ")"
}
