package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Gitleaks struct {
	Command   string   `yaml:"command"`
	ExtraArgs []string `yaml:"extra_args"`
}

type Pattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

type Config struct {
	DenyLiterals      []string `yaml:"deny_literals"`
	DenyPatterns      []any    `yaml:"deny_patterns"` // string or {name, regex}
	AuthorEmailAllow  []string `yaml:"author_email_allow"`
	ExcludePaths      []string `yaml:"exclude_paths"`
	Gitleaks          Gitleaks `yaml:"gitleaks"`
	ResolvedPatterns  []Pattern
}

func Default() *Config {
	return &Config{
		AuthorEmailAllow: []string{`@users\.noreply\.github\.com$`},
		ExcludePaths:     []string{"vendor/**", "**/*.min.js"},
		Gitleaks:         Gitleaks{Command: "gitleaks"},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		if err := cfg.normalize(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Find(repoDir, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	for _, name := range []string{"aratame.yml", "aratame.yaml"} {
		p := filepath.Join(repoDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", nil
}

func (c *Config) normalize() error {
	if c.Gitleaks.Command == "" {
		c.Gitleaks.Command = "gitleaks"
	}
	if len(c.AuthorEmailAllow) == 0 {
		c.AuthorEmailAllow = []string{`@users\.noreply\.github\.com$`}
	}
	c.ResolvedPatterns = nil
	for i, raw := range c.DenyPatterns {
		switch v := raw.(type) {
		case string:
			c.ResolvedPatterns = append(c.ResolvedPatterns, Pattern{Name: fmt.Sprintf("pattern-%d", i+1), Regex: v})
		case map[string]any:
			p := Pattern{Name: fmt.Sprintf("pattern-%d", i+1)}
			if n, ok := v["name"].(string); ok && n != "" {
				p.Name = n
			}
			if r, ok := v["regex"].(string); ok {
				p.Regex = r
			}
			if p.Regex == "" {
				return fmt.Errorf("deny_patterns[%d] missing regex", i)
			}
			c.ResolvedPatterns = append(c.ResolvedPatterns, p)
		default:
			return fmt.Errorf("deny_patterns[%d]: want string or {name, regex}", i)
		}
	}
	return nil
}
