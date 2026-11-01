// Package github generates the GitHub side of the policy-in-force protection
// (DES §3.4 step 3): CODEOWNERS, the default-branch ruleset and CI workflows.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	hosting "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	tpl "github.com/vanssata/agentic-risk-rails/templates/github"
)

func init() { rrsync.Register(gen{}) }

const (
	codeownersPath = ".github/CODEOWNERS"
	rulesetPath    = ".github/rulesets/default-branch.json"

	// rrVersion is the rr release the workflows install. The module path has no
	// /vN suffix, so the version must stay v0.x/v1.x (Go rejects v2+ without it).
	rrVersion = "v0.4.3"
	// goVersion is the toolchain the workflows build rr with (the go.mod version at release).
	goVersion = "1.27.3"
	// Action pins [V]: gh api repos/actions/<name>/commits/<tag> (docs:
	// https://docs.github.com/en/rest/commits/commits#get-a-commit).
	checkoutSHA = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09" // actions/checkout v5
	setupGoSHA  = "924ae3a1cded613372ab5595356fb5720e22ba16" // actions/setup-go v6
)

var validBranch = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

type gen struct{}

func (gen) Name() string { return "github" }

// team returns the code owner: the first owner (team or user, e.g. a personal
// repository's login) on the existing riskrails.yaml line of CODEOWNERS
// (hand-edited, kept), else @<owner of ceiling remote>/code-owners.
// core has no field for the team (CORE_CHANGE_REQUEST); OWNER marks an unset org.
func team(in core.SyncInput) (string, error) {
	if b, err := os.ReadFile(filepath.Join(in.Root, codeownersPath)); err == nil {
		owners, err := hosting.Owners(b, "riskrails.yaml")
		if err != nil {
			return "", err
		}
		if len(owners) > 0 {
			return owners[0], nil
		}
	}
	org, _, _ := strings.Cut(in.Policy.Policy.Remote, "/")
	if org == "" {
		org = "OWNER"
	}
	return "@" + org + "/code-owners", nil
}

func render(name string, data any) ([]byte, error) {
	t, err := template.ParseFS(tpl.FS, name)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b.Bytes(), nil
}

func (gen) Render(_ context.Context, in core.SyncInput) ([]core.File, error) {
	p := in.Policy.Policy
	branch := p.Project.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	if !validBranch.MatchString(branch) || strings.HasPrefix(branch, "-") || strings.Contains(branch, "..") {
		return nil, fmt.Errorf("github: invalid project.default_branch %q", branch)
	}

	seen := map[string]bool{}
	var paths []string
	// "/.github/" is always owned: a PR must not be able to replace the
	// policy-check workflow, CODEOWNERS or the ruleset without code-owner review.
	owned := append([]string{"riskrails.yaml", "/.github/"}, core.AlwaysProtected...)
	for _, s := range append(owned, p.Enforcement.ProtectedPaths...) {
		if !seen[s] && !strings.HasPrefix(s, "~") && !strings.Contains(s, "$") {
			seen[s] = true
			paths = append(paths, s)
		}
	}
	tm, err := team(in)
	if err != nil {
		return nil, err
	}
	owners, err := render("CODEOWNERS.tmpl", struct {
		Team  string
		Paths []string
	}{tm, paths})
	if err != nil {
		return nil, err
	}
	data := struct {
		Check, Branch, RR, Checkout, SetupGo, GoVersion string
		Nightly                                         bool
	}{hosting.PolicyCheck, branch, rrVersion, checkoutSHA, setupGoSHA, goVersion, p.Verify.NightlyFull != nil && *p.Verify.NightlyFull}
	verify, err := render("rr-verify.yml.tmpl", data)
	if err != nil {
		return nil, err
	}
	policy, err := render("rr-policy-check.yml.tmpl", data)
	if err != nil {
		return nil, err
	}
	rs, err := ruleset()
	if err != nil {
		return nil, err
	}
	return []core.File{
		{Path: codeownersPath, Content: owners},
		{Path: rulesetPath, Content: rs},
		{Path: ".github/workflows/rr-verify.yml", Content: verify},
		{Path: ".github/workflows/rr-policy-check.yml", Content: policy},
	}, nil
}

// ruleset is importable through the repository rulesets API / UI. bypass_actors
// is empty on purpose: nobody, including admins, bypasses the policy gate.
func ruleset() ([]byte, error) {
	type rule struct {
		Type       string         `json:"type"`
		Parameters map[string]any `json:"parameters,omitempty"`
	}
	doc := map[string]any{
		"name":          "riskrails default branch",
		"target":        "branch",
		"enforcement":   "active",
		"bypass_actors": []any{},
		"conditions":    map[string]any{"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}}},
		"rules": []rule{
			{Type: "deletion"},
			{Type: "non_fast_forward"},
			{Type: "pull_request", Parameters: map[string]any{
				"required_approving_review_count":   1,
				"dismiss_stale_reviews_on_push":     true,
				"require_code_owner_review":         true,
				"require_last_push_approval":        true,
				"required_review_thread_resolution": false,
			}},
			{Type: "required_status_checks", Parameters: map[string]any{
				"strict_required_status_checks_policy": true,
				"required_status_checks":               []map[string]any{{"context": hosting.PolicyCheck, "integration_id": hosting.ActionsAppID}},
			}},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n'), err
}
