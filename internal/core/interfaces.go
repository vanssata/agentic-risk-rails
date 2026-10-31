package core

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// ---- events / journal (DES §8.4, §16.1) ----

// Event is one journal line. PrevSHA256 chains it to the previous line of the
// same task file; the journal package fills PrevSHA256 and Time on Append.
type Event struct {
	Schema         int             `json:"schema"`
	Type           string          `json:"type"`
	Task           string          `json:"task"`
	Actor          Actor           `json:"actor"`
	Via            string          `json:"via,omitempty"` // cli | hook:<runtime> | mcp | runner
	PolicySHA      string          `json:"policy_sha,omitempty"`
	TiersEffective map[Tier]string `json:"tiers_effective,omitempty"`
	Time           time.Time       `json:"time"`
	PrevSHA256     string          `json:"prev_sha256"`
	Data           json.RawMessage `json:"data,omitempty"`
}

// Journal is the append-only, hash-chained, audit-first event log of a task.
// Append must durably write the event before returning; callers change state
// only after Append succeeded.
type Journal interface {
	Append(ctx context.Context, e Event) (Event, error)
	Events(ctx context.Context, task string) ([]Event, error)
}

// ---- policy (DES §3) ----

// PolicyLayers are the inputs to resolution, strictest-wins (DES §3.3).
type PolicyLayers struct {
	Enterprise    *Policy // /etc/riskrails/ceiling.yaml; nil if absent
	User          *Policy // ~/.config/riskrails/ceiling.yaml; nil if absent
	DefaultBranch *Policy // riskrails.yaml on the default branch (policy in force)
	WorkingTree   *Policy // riskrails.yaml in checkout; may only tighten
}

// EffectivePolicy is the resolved policy plus provenance for the journal.
type EffectivePolicy struct {
	Policy     Policy
	PolicySHA  string   // sha256 of canonical form of Policy
	CeilingSHA string   // sha256 of the raw ceiling file(s), checked every wave
	Clamped    []string // fields cut to the ceiling (journal: policy_clamped)
	Ignored    []string // working-tree loosenings ignored (policy_loosening_ignored)
}

type PolicyResolver interface {
	Resolve(ctx context.Context, layers PolicyLayers) (EffectivePolicy, error)
}

// FieldChange is one differing field between two policies.
type FieldChange struct {
	Path      string    `json:"path"` // e.g. "enforcement.commands.allow"
	Direction Direction `json:"direction"`
	Detail    string    `json:"detail,omitempty"`
}

// PolicyDiffer compares candidate to base deterministically, without a model.
// files is `git ls-files` of the current tree, used for glob-set comparison.
type PolicyDiffer interface {
	Diff(base, candidate Policy, files []string) (Direction, []FieldChange, error)
}

// ---- guard and hooks (DES §2.2, ADR-9) ----

// ToolCall is the runtime-neutral form of a hook event.
type ToolCall struct {
	Runtime string          `json:"runtime"`
	Event   string          `json:"event"` // PreToolUse, BeforeTool, …
	Tool    string          `json:"tool"`  // Bash, Edit, Write, Read, Agent, mcp__x__y …
	Command string          `json:"command,omitempty"`
	Paths   []string        `json:"paths,omitempty"`
	Content string          `json:"content,omitempty"` // proposed file content for Edit/Write
	Model   string          `json:"model,omitempty"`   // explicit subagent model, if the runtime exposes it
	Cwd     string          `json:"cwd,omitempty"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

type Verdict struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Rule     string   `json:"rule,omitempty"` // which policy entry matched
}

// GuardContext is what the guard needs besides the call itself.
type GuardContext struct {
	Policy    EffectivePolicy
	Level     Level
	StepFiles []string // armed scope guard; nil = not armed
	RepoFiles []string // git ls-files, for policy diff of riskrails.yaml edits
}

// Guard must be fail-closed: any internal error yields Deny.
type Guard interface {
	Check(ctx context.Context, call ToolCall, gc GuardContext) Verdict
}

// ---- runtimes and generators (DES §2.2, §10) ----

// RuntimeAdapter translates one runtime's hook protocol and owns its generators.
type RuntimeAdapter interface {
	Name() string
	ParseHookInput(event string, r io.Reader) (ToolCall, error)
	// RenderHookOutput writes the runtime's response and returns the process exit code.
	RenderHookOutput(v Verdict, w io.Writer) (exitCode int, err error)
	Generators() []Generator
	Enforcement() Enforcement
}

// EffectiveTiers is the model availability result for one runtime (DES §4.2).
type EffectiveTiers struct {
	Runtime      string          `json:"runtime"`
	Models       map[Tier]string `json:"models"` // only PASS models
	Ladder       map[Tier]Tier   `json:"ladder"`
	CatalogueSHA string          `json:"catalogue_sha"`
	ProbedAt     time.Time       `json:"probed_at"`
}

// SyncInput is everything a generator may render from.
type SyncInput struct {
	Root   string
	Policy EffectivePolicy
	Tiers  map[string]EffectiveTiers // by runtime
	Level  Level                     // ≥ L2 ⇒ every ask is compiled to deny
}

// File is one generated file, path relative to the repo root.
type File struct {
	Path    string
	Content []byte
	Mode    uint32 // 0 ⇒ 0o644
}

// Generator renders manifests; it must be pure (same input ⇒ same bytes).
type Generator interface {
	Name() string
	Render(ctx context.Context, in SyncInput) ([]File, error)
}

// ---- models (DES §4) ----

type ProbeResult struct {
	Model    string     `json:"model"`
	State    ModelState `json:"state"`
	Error    string     `json:"error,omitempty"` // provider error.type
	ProbedAt time.Time  `json:"probed_at"`
}

type ModelProber interface {
	Runtime() string
	Probe(ctx context.Context, candidates []string) ([]ProbeResult, error)
}

// ---- verify (DES §9.2) ----

type TestResult struct {
	Passed   bool     `json:"passed"`
	Ran      []string `json:"ran,omitempty"`
	Failed   []string `json:"failed,omitempty"`
	Output   string   `json:"-"`
	Duration time.Duration
}

type VerifyAdapter interface {
	Name() string
	Detect(root string) bool
	Map(ctx context.Context, root string, changed []string) (tests []string, err error)
	Run(ctx context.Context, root string, tests []string) (TestResult, error) // nil tests ⇒ full run
}

// ---- release (DES §9.1) ----

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type ReleaseAdapter interface {
	Name() string
	Detect(root string) bool
	Preflight(ctx context.Context, root string) []Check
	DryRun(ctx context.Context, root string) (Check, error)
	PrepareTag(ctx context.Context, root, version string) ([]File, error)
	CIWorkflow() File
}

// ---- ledger (DES §7) ----

type Usage struct {
	Runtime    string    `json:"runtime"`
	Session    string    `json:"session"`
	Model      string    `json:"model"`
	Input      int64     `json:"input"`
	Output     int64     `json:"output"`
	CacheRead  int64     `json:"cache_read"`
	CacheWrite int64     `json:"cache_write"`
	Time       time.Time `json:"time"`
}

type TranscriptParser interface {
	Runtime() string
	Parse(r io.Reader) ([]Usage, error)
}

// ---- workers: scouts, implementers, reviewers (DES §5, §6) ----

type WorkerSpec struct {
	Role     string     `json:"role"` // code-scout, implementer, reviewer-spec, …
	Tier     Tier       `json:"tier"`
	Brief    string     `json:"brief"`
	Worktree string     `json:"worktree,omitempty"`
	MaxTurns int        `json:"max_turns"`
	Budget   TokenCount `json:"budget"`
}

type WorkerReport struct {
	Status WorkerStatus `json:"status"`
	Body   string       `json:"body"`
	Tokens int64        `json:"tokens"`
	Calls  int          `json:"calls"`
}

type WorkerRunner interface {
	Run(ctx context.Context, spec WorkerSpec) (WorkerReport, error)
}

// ---- hosting (DES §3.4 step 3–4, §8.2) ----

type Review struct {
	Login string `json:"login"`
	State string `json:"state"` // APPROVED, CHANGES_REQUESTED, COMMENTED
	IsBot bool   `json:"is_bot"`
}

type PullRequest struct {
	Number int    `json:"number"`
	Author string `json:"author"`
	URL    string `json:"url"`
}

// Hosting is read through the API from outside the agent sandbox.
type Hosting interface {
	ReadFile(ctx context.Context, ref, path string) ([]byte, error)
	OpenDraftPR(ctx context.Context, head, base, title, body string) (PullRequest, error)
	Reviews(ctx context.Context, pr int) ([]Review, error)
	IsTeamMember(ctx context.Context, team, login string) (bool, error)
	Rulesets(ctx context.Context, branch string) (json.RawMessage, error)
}
