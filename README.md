# pubkensa（パブケンサ）

A small pre-publish gate for Git repositories. One command runs three checks:

1. **Secrets** — delegates to [gitleaks](https://github.com/gitleaks/gitleaks) (default rules, history included). This tool does not bundle a secret-detection engine.
2. **Deny list** — literals and regular expressions you provide, scanned in the current tree, commit messages, and patch history. For names that are not secrets but should not be published.
3. **Author / committer policy** — emails must match an allow list (default: GitHub `users.noreply.github.com` addresses).

It does not rewrite history, fix files, or change repository settings.

This repository is not public yet. The install commands below will work only after a GitHub repository exists.

## Requirements

- Git
- [gitleaks](https://github.com/gitleaks/gitleaks) on `PATH`
- Go 1.23 or later to build

```bash
go build -o bin/pubkensa ./cmd/pubkensa
```

After a public release, a binary from the Releases page, or:

```bash
go install github.com/nishimoto265/pubkensa/cmd/pubkensa@latest
```

## Usage

```bash
pubkensa scan [path]
  --config path     default: <repo>/pubkensa.yml if that file exists
  --json            JSON on stdout, human text on stderr
  --since <rev>     limit author and history checks to commits after this revision
```

Exit codes: `0` no findings, `1` findings, `2` tool error (bad config, not a git repo, gitleaks missing).

Copy `pubkensa.yml.example` to `pubkensa.yml` and add your own deny list. Do not commit real internal hostnames or personal addresses in the example file. The example deny word appears in the example file itself; using that file as `--config` against this repository will report it.

A copy-paste GitHub Actions workflow is in `examples/github-workflow.yml`. Until a release exists, build from source (or drop a prebuilt binary on `PATH`) instead of `go install @latest`.

A typographic social-preview draft is in `docs/social-preview.png` (1280×640). It is not uploaded to any GitHub setting.

## License

MIT. Secret detection is performed by gitleaks, which has its own license (MIT as of the version we tested against).

---

## 日本語

Git リポジトリ向けの、小さな公開前ゲートです。次の3つを1コマンドで見ます。

1. **秘密情報** — [gitleaks](https://github.com/gitleaks/gitleaks) に委譲します（既定ルール、履歴込み）。検出エンジン自体は同梱しません。
2. **拒否リスト** — 指定した文字列と正規表現を、作業ツリー・コミットメッセージ・パッチ履歴から探します。秘密ではないが公開したくない名前向けです。
3. **author / committer の方針** — メールが許可リストに合うこと（既定は GitHub の `users.noreply.github.com`）。

履歴の書き換え、ファイルの修正、リポジトリ設定の変更はしません。

このリポジトリはまだ公開していません。下記のインストールは、公開後に使えるようになります。

### 必要条件

- Git
- PATH 上の [gitleaks](https://github.com/gitleaks/gitleaks)
- ビルドする場合は Go 1.23 以降

```bash
go build -o bin/pubkensa ./cmd/pubkensa
```

公開後は Releases のバイナリか、次でも入れられます。

```bash
go install github.com/nishimoto265/pubkensa/cmd/pubkensa@latest
```

### 使い方

```bash
pubkensa scan [path]
  --config path     既定は、リポジトリに pubkensa.yml があればそれ
  --json            JSON を標準出力、人間向けの文は標準エラー
  --since <rev>     このリビジョンより後のコミットだけを author と履歴の対象にする
```

終了コードは `0` が指摘なし、`1` が指摘あり、`2` が設定誤り・Git リポジトリではない・gitleaks がない、などです。

`pubkensa.yml.example` を `pubkensa.yml` にコピーし、自分の拒否リストを書いてください。実在のホスト名や個人のメールを example に書かないでください。example の拒否語は example ファイル自身に出てくるので、このリポジトリをその設定でスキャンするとヒットします。

GitHub Actions の控えは `examples/github-workflow.yml` にあります。リリースが出るまでは、ソースからビルドするか、バイナリを PATH に置いてください。

ソーシャルプレビューの案は `docs/social-preview.png`（1280×640）です。GitHub の設定へは上げていません。

### ライセンス

MIT。秘密検出は gitleaks が行い、gitleaks 自身にもライセンスがあります（検証に使った版は MIT）。
