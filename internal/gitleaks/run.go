package gitleaks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Finding is a subset of a gitleaks JSON finding. The secret value is omitted
// even if a report somehow includes it.
type Finding struct {
	Rule     string `json:"RuleID"`
	File     string `json:"File"`
	StartLine int   `json:"StartLine"`
	Commit   string `json:"Commit"`
	Message  string `json:"Message"`
}

type Report struct {
	Available bool
	Findings  []Finding
}

func Run(repoDir, command string, extra []string) (Report, error) {
	if command == "" {
		command = "gitleaks"
	}
	if _, err := exec.LookPath(command); err != nil {
		return Report{}, fmt.Errorf("gitleaks not found in PATH (%s): %w", command, err)
	}
	tmp, err := os.MkdirTemp("", "aratame-gitleaks-")
	if err != nil {
		return Report{}, err
	}
	defer os.RemoveAll(tmp)
	reportPath := filepath.Join(tmp, "report.json")
	args := []string{"detect", "--source", ".", "--no-banner", "--redact", "--report-format", "json", "--report-path", reportPath}
	args = append(args, extra...)
	cmd := exec.Command(command, args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	// gitleaks exits 1 when it finds leaks; 0 when clean.
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			err = nil
		} else {
			return Report{}, fmt.Errorf("gitleaks: %w\n%s", err, out)
		}
	}
	rep := Report{Available: true}
	b, rerr := os.ReadFile(reportPath)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return rep, nil
		}
		return Report{}, rerr
	}
	if len(b) == 0 {
		return rep, nil
	}
	var findings []Finding
	if err := json.Unmarshal(b, &findings); err != nil {
		return Report{}, fmt.Errorf("parse gitleaks report: %w", err)
	}
	rep.Findings = findings
	return rep, nil
}
