package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Stability: journal, policy, guard, runtime/generator and sync contracts are
// FROZEN for wave 1. Models, verify, release, ledger, worker and hosting
// interfaces are PROVISIONAL: revised between waves after their module's research.

// ---- events / journal (DES §8.4, §16.1) ----

// Event is one journal line. PrevSHA256 chains it to the previous line of the
// same task file; the journal package fills PrevSHA256 and Time on Append.
// TiersEffective is set on task_started only (tiers_resolved carries changes).
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
//
// Lifecycle (DES §16.1): Append to a task with no open file and type
// task_started opens .rr/run/<task>.jsonl; a second open task in the same
// checkout ⇒ *Refusal{Code: "TASK_IN_FLIGHT"}. Close moves it to .rr/tasks/.
type Journal interface {
	Append(ctx context.Context, e Event) (Event, error)
	Events(ctx context.Context, task string) ([]Event, error)
	Open(ctx context.Context) ([]string, error) // tasks in flight in this checkout
	Close(ctx context.Context, task string) error
}

// ---- policy (DES §3) ----

// Layer is one parsed policy source with its raw bytes (for hashing).
type Layer struct {
	Policy Policy
	Raw    []byte
	Source string // path or "git:<ref>:riskrails.yaml" or "api:<owner/repo>@<ref>"
}

// PolicyLayers are the inputs to resolution, strictest-wins (DES §3.3).
// Ceiling layers: absent field = unconstrained. Project layers: absent = StrictDefaults().
type PolicyLayers struct {
	Enterprise    *Layer // /etc/riskrails/ceiling.yaml; nil if absent
	User          *Layer // ~/.config/riskrails/ceiling.yaml; nil if absent
	DefaultBranch *Layer // riskrails.yaml on the default branch (policy in force)
	WorkingTree   *Layer // riskrails.yaml in checkout; may only tighten
}

// EffectivePolicy is the resolved policy plus provenance for the journal.
// Invariant: Policy is fully defaulted — every pointer is non-nil — so no
// consumer picks its own default. Use fakes.StrictPolicy() in tests.
type EffectivePolicy struct {
	Policy     Policy
	InForce    Policy   // defaulted policy of the default branch: base for LOOSEN checks
	PolicySHA  string   // sha256 of canonical form of Policy
	CeilingSHA string   // sha256 over Raw of the ceiling layers, checked every wave
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
// Callers must use Direction.Loosens(); an error is treated as LOOSEN.
type PolicyDiffer interface {
	Diff(base, candidate Policy, files []string) (Direction, []FieldChange, error)
}

// PolicyLoader strictly parses a project riskrails.yaml and applies StrictDefaults().
// A parse error is a deny for the caller.
type PolicyLoader interface {
	Parse(b []byte) (Policy, error)
}

// ---- guard and hooks (DES §2.2, ADR-9) ----

// ToolCall is the runtime-neutral form of a hook event, filled by a RuntimeAdapter.
//
//   - Paths are absolute and filepath.Clean'ed; the guard resolves symlinks and
//     makes them relative to GuardContext.Root.
//   - Content is the FULL post-edit file for Edit/MultiEdit/Write: the adapter
//     reads the current file and applies the edit(s). If it cannot, ParseHookInput
//     returns an error and the caller denies.
//   - URL is the target of WebFetch/WebSearch-like tools, for egress rules.
//   - Edits: a call that changes several files at once (e.g. a multi-file
//     apply_patch) lists every file with its FULL post-edit content (empty =
//     deletion; a move is a deletion of From plus the new Path). When Edits is
//     set, Paths lists every path in Edits and Content is unused. The guard
//     checks every edit; one denied edit denies the call.
type ToolCall struct {
	Runtime string          `json:"runtime"`
	Event   string          `json:"event"` // PreToolUse, BeforeTool, …
	Tool    string          `json:"tool"`  // Bash, Edit, Write, Read, Agent, mcp__x__y …
	Command string          `json:"command,omitempty"`
	Paths   []string        `json:"paths,omitempty"`
	Content string          `json:"content,omitempty"`
	Edits   []FileEdit      `json:"edits,omitempty"`
	URL     string          `json:"url,omitempty"`
	Model   string          `json:"model,omitempty"` // explicit subagent model, if the runtime exposes it
	Cwd     string          `json:"cwd,omitempty"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

// FileEdit is one file of a multi-file edit; Path is absolute and Clean'ed.
type FileEdit struct {
	Path    string `json:"path"`
	From    string `json:"from,omitempty"` // previous path for a move
	Content string `json:"content"`
	Delete  bool   `json:"delete,omitempty"`
}

type Verdict struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Rule     string   `json:"rule,omitempty"` // which policy entry matched
}

// GuardContext is what the guard needs besides the call itself.
// A nil Loader or Differ means every riskrails.yaml edit is denied.
type GuardContext struct {
	Policy    EffectivePolicy
	Level     Level
	Root      string         // absolute repo root
	Home      string         // for expanding ~ in path rules
	Tiers     EffectiveTiers // explicit Agent model outside Tiers.Models ⇒ deny (DES §4.5c)
	StepFiles []string       // armed scope guard; nil = not armed
	RepoFiles []string       // git ls-files, for policy diff of riskrails.yaml edits
	Loader    PolicyLoader
	Differ    PolicyDiffer
}

// Guard must be fail-closed: any internal error yields Deny.
type Guard interface {
	Check(ctx context.Context, call ToolCall, gc GuardContext) Verdict
}

// ---- runtimes and generators (DES §2.2, §10) ----

// RuntimeAdapter translates one runtime's hook protocol and owns its generators.
// Adapters register with internal/runtimes.Register in init(); the hook command
// is `rr guard --runtime <name> --event <event>`.
type RuntimeAdapter interface {
	Name() string
	// ParseHookInput error ⇒ the caller renders Verdict{Decision: Deny}.
	ParseHookInput(event string, r io.Reader) (ToolCall, error)
	// RenderHookOutput writes the runtime's response for event and returns the
	// exit code. Any Decision other than Allow/Ask renders as deny with a
	// blocking exit code. call is the parsed call (zero value if parsing
	// failed), so messages can name the command or paths.
	RenderHookOutput(event string, call ToolCall, v Verdict, stdout, stderr io.Writer) (exitCode int, err error)
	Generators() []Generator
	// Enforcement reports what actually enforces on this host (e.g. no bwrap ⇒ hook_only).
	Enforcement(ctx context.Context, root string) (Enforcement, error)
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
// Committed manifests (and CI `rr sync --check`) render at Level = policy
// autonomy ceiling capped at L1; the runner renders L≥2 into the container only.
type SyncInput struct {
	Root   string
	Home   string // for ~ expansion in sandbox paths; goldens use a fixed value
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
	Passed   bool          `json:"passed"`
	Ran      []string      `json:"ran,omitempty"`
	Failed   []string      `json:"failed,omitempty"`
	Output   string        `json:"-"`
	Duration time.Duration `json:"duration"`
}

// VerifyAdapter: an empty non-full selection must yield Passed=false (no fake green).
// uncovered lists changed files no test maps to (⇒ full run, DES §9.2).
type VerifyAdapter interface {
	Name() string
	Detect(root string) bool
	Map(ctx context.Context, root string, changed []string) (tests, uncovered []string, err error)
	Run(ctx context.Context, root string, spec VerifyAdapterSpec, tests []string, full bool) (TestResult, error)
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
	// Env is extra KEY=VALUE environment for the worker process on top of the
	// runner's own (e.g. RR_SCOPE_FILE arming the step's scope guard).
	Env []string `json:"env,omitempty"`
	// Step is the plan step a factory worker runs for ("" = research, planner);
	// worker_usage carries it so `rr cost` attributes per step (wave 6).
	Step string `json:"step,omitempty"`
}

type WorkerReport struct {
	Status WorkerStatus `json:"status"`
	Body   string       `json:"body"`
	Tokens int64        `json:"tokens"`
	Calls  int          `json:"calls"`
	// Usage is the priced breakdown when the runtime reports it; a zero Usage
	// (empty Model) means unknown and is never priced as free.
	Usage Usage `json:"usage"`
}

type WorkerRunner interface {
	Run(ctx context.Context, spec WorkerSpec) (WorkerReport, error)
}

// ---- hosting (DES §3.4 step 3–4, §8.2) ----

type Review struct {
	Login    string `json:"login"`
	State    string `json:"state"` // APPROVED, CHANGES_REQUESTED, COMMENTED
	IsBot    bool   `json:"is_bot"`
	CommitID string `json:"commit_id"`
}

type PullRequest struct {
	Number  int    `json:"number"`
	Author  string `json:"author"`
	URL     string `json:"url"`
	HeadSHA string `json:"head_sha"`
	Base    string `json:"base"` // base branch name
}

// ErrNotFound is the only "absent" error from Hosting.ReadFile. Any other error
// on a safety read (kill switch, policy in force) ⇒ halt.
var ErrNotFound = errors.New("not found")

// Hosting is read through the API from outside the agent sandbox.
//
//   - OpenDraftPR applies labels to the new PR; an error applying them is an error.
//   - Push pushes refs/heads/<branch> of the local repository at root to the
//     hosted repository with the hosting credentials (never available to the
//     agent). It refuses any branch outside rr/* and never force-pushes.
//   - BranchSHA returns the tip commit of branch on the hosted repository;
//     ErrNotFound if the branch does not exist.
type Hosting interface {
	ReadFile(ctx context.Context, ref, path string) ([]byte, error)
	OpenDraftPR(ctx context.Context, head, base, title, body string, labels []string) (PullRequest, error)
	Push(ctx context.Context, root, branch string) error
	BranchSHA(ctx context.Context, branch string) (string, error)
	PullRequest(ctx context.Context, n int) (PullRequest, error)
	Reviews(ctx context.Context, pr int) ([]Review, error)
	IsTeamMember(ctx context.Context, team, login string) (bool, error)
	Rulesets(ctx context.Context, branch string) (json.RawMessage, error)
}
