package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nishimoto265/pubkensa/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("pubkensa", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("config", "", "path to pubkensa.yml (default: <repo>/pubkensa.yml if present)")
	jsonOut := fs.Bool("json", false, "write JSON to stdout")
	since := fs.String("since", "", "limit author and history checks to commits after this revision")
	skipGL := fs.Bool("skip-gitleaks", false, "skip the gitleaks invocation (for tests)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pubkensa scan [path] [flags]\n")
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	if args[0] != "scan" {
		fmt.Fprintf(os.Stderr, "unknown command %q (want: scan)\n", args[0])
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dir := "."
	if rest := fs.Args(); len(rest) > 0 {
		dir = rest[0]
	}

	res, err := scan.Run(scan.Options{
		RepoDir:      dir,
		ConfigPath:   *config,
		Since:        *since,
		SkipGitleaks: *skipGL,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkensa: %v\n", err)
		return 2
	}
	human := scan.FormatHuman(res)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "pubkensa: %v\n", err)
			return 2
		}
		fmt.Fprint(os.Stderr, human)
	} else {
		fmt.Fprint(os.Stdout, human)
	}
	if !res.OK {
		return 1
	}
	return 0
}
