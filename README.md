# aratame（改め）

A small pre-publish gate for Git repositories. One command runs three checks:

1. **Secrets** — delegates to [gitleaks](https://github.com/gitleaks/gitleaks) (default rules, history included).
2. **Deny list** — literals and regular expressions you provide (current tree, commit messages, and patch history). For names that are not secrets but should not be published.
3. **Author / committer policy** — emails must match an allow list (default: GitHub `users.noreply.github.com` addresses).

It does not rewrite history, fix files, or change repository settings.

The name is provisional. A trademark check should be done before a public release.

## Requirements

- Git
- [gitleaks](https://github.com/gitleaks/gitleaks) on `PATH` (the scanner does not bundle a secret-detection engine)
- Go 1.23 or later to build

```bash
go build -o bin/aratame ./cmd/aratame
```

## Usage

```bash
aratame scan [path]
  --config path     default: <repo>/aratame.yml if that file exists
  --json            JSON on stdout, human text on stderr
  --since <rev>     limit author and history checks to commits after this revision
```

Exit codes: `0` no findings, `1` findings, `2` tool error (bad config, not a git repo, gitleaks missing).

Copy `aratame.yml.example` to `aratame.yml` and add your own deny list. Do not commit real internal hostnames or personal addresses in the example file.

A copy-paste GitHub Actions workflow is in `examples/github-workflow.yml`. This repository is not published yet; until it is, run the binary locally.

## License

MIT. Secret detection is performed by gitleaks, which has its own license (MIT as of the version we tested against).
