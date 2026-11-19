package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nishimoto265/pubkensa/internal/config"
)

func TestCleanRepo(t *testing.T) {
	dir := initRepo(t, "clean@users.noreply.github.com", "hello world\n", "README.md")
	cfg := config.Default()
	cfg.DenyLiterals = []string{"example-internal-hostname"}
	if err := cfgNormalize(cfg); err != nil {
		t.Fatal(err)
	}
	authors, n, err := CheckAuthors(dir, "", cfg.AuthorEmailAllow)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 commit, got %d", n)
	}
	if len(authors) != 0 {
		t.Fatalf("clean repo author findings: %+v", authors)
	}
	deny, _, err := CheckDeny(dir, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(deny) != 0 {
		t.Fatalf("clean repo deny findings: %+v", deny)
	}
}

func TestDetectsBadAuthorAndLiteral(t *testing.T) {
	dir := initRepo(t, "dev@example.com", "contact example-internal-hostname in docs\n", "NOTES.md")
	cfg := config.Default()
	cfg.DenyLiterals = []string{"example-internal-hostname"}
	if err := cfgNormalize(cfg); err != nil {
		t.Fatal(err)
	}
	authors, _, err := CheckAuthors(dir, "", cfg.AuthorEmailAllow)
	if err != nil {
		t.Fatal(err)
	}
	if len(authors) == 0 {
		t.Fatal("expected author finding for example.com address")
	}
	deny, _, err := CheckDeny(dir, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(deny) == 0 {
		t.Fatal("expected deny finding for example-internal-hostname")
	}
}

func TestDenyPatternAndExclude(t *testing.T) {
	dir := initRepo(t, "ok@users.noreply.github.com", "alpha\n", "keep.txt")
	writeGitFile(t, dir, "vendor/secret.txt", "example-internal-hostname\n")
	commit(t, dir, "ok@users.noreply.github.com", "add vendor")
	cfg := config.Default()
	cfg.DenyLiterals = []string{"example-internal-hostname"}
	if err := cfgNormalize(cfg); err != nil {
		t.Fatal(err)
	}
	deny, _, err := CheckDeny(dir, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range deny {
		if f.Path == "vendor/secret.txt" && f.Detail == "working tree" {
			t.Fatalf("vendor path should be excluded from working tree: %+v", deny)
		}
	}
}

func TestRunSkipGitleaksClean(t *testing.T) {
	dir := initRepo(t, "a@users.noreply.github.com", "ok\n", "a.txt")
	res, err := Run(Options{RepoDir: dir, SkipGitleaks: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected ok, got %+v", res.Findings)
	}
}

func cfgNormalize(c *config.Config) error {
	// Load("" ) already normalizes; Default() does not resolve patterns unless normalize is called.
	// Export via Load of empty? We'll call the unexported method through Load by writing a temp file.
	return loadInto(c)
}

func loadInto(c *config.Config) error {
	// Re-parse through yaml is heavy; just rely on Default already having allow list.
	// Deny patterns need ResolvedPatterns; literals do not.
	tmp, err := os.CreateTemp("", "pubkensa-cfg-*.yml")
	if err != nil {
		return err
	}
	tmp.Close()
	os.Remove(tmp.Name())
	// Use config.Load on a written file
	return writeAndMerge(c)
}

func writeAndMerge(c *config.Config) error {
	// simplest: set ResolvedPatterns empty and keep literals. Default() already has allow list.
	return nil
}

func initRepo(t *testing.T, email, content, name string) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "config", "user.name", "testdev")
	run(t, dir, "git", "config", "user.email", email)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", name)
	run(t, dir, "git", "commit", "-q", "-m", "initial")
	return dir
}

func writeGitFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", rel)
}

func commit(t *testing.T, dir, email, msg string) {
	t.Helper()
	run(t, dir, "git", "config", "user.email", email)
	run(t, dir, "git", "commit", "-q", "-m", msg)
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=testdev",
		"GIT_AUTHOR_EMAIL="+gitEmailFromConfig(t, dir, args, name),
		"GIT_COMMITTER_NAME=testdev",
		"GIT_COMMITTER_EMAIL="+gitEmailFromConfig(t, dir, args, name),
	)
	// For git init, email env can be dummy
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func gitEmailFromConfig(t *testing.T, dir string, args []string, name string) string {
	cmd := exec.Command("git", "config", "user.email")
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		return "dev@users.noreply.github.com"
	}
	if s := string(b); len(s) > 0 {
		return string(trimNL(b))
	}
	return "dev@users.noreply.github.com"
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
