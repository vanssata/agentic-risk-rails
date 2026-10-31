package core

import (
	"fmt"
	"strconv"
	"strings"
)

// Policy mirrors riskrails.yaml schema 1 (DES §3.2). It holds shape only:
// defaults, tightening and LOOSEN detection live in internal/policy.
// Pointer scalars distinguish "absent" (→ strictest default) from zero.
type Policy struct {
	Schema      int             `yaml:"schema" json:"schema"`
	Project     ProjectSpec     `yaml:"project" json:"project"`
	Risk        RiskSpec        `yaml:"risk" json:"risk"`
	Models      ModelsSpec      `yaml:"models" json:"models"`
	Autonomy    AutonomySpec    `yaml:"autonomy" json:"autonomy"`
	Enforcement EnforcementSpec `yaml:"enforcement" json:"enforcement"`
	Verify      VerifySpec      `yaml:"verify" json:"verify"`
	Release     ReleaseSpec     `yaml:"release" json:"release"`
	Research    ResearchSpec    `yaml:"research" json:"research"`
}

type ProjectSpec struct {
	Name          string   `yaml:"name" json:"name"`
	Stack         []string `yaml:"stack" json:"stack"`
	DefaultBranch string   `yaml:"default_branch" json:"default_branch"`
}

type RiskSpec struct {
	Axes             map[Axis]AxisSpec   `yaml:"axes" json:"axes"`
	Modes            map[Mode]ModeBand   `yaml:"modes" json:"modes"`
	HardFloors       []HardFloor         `yaml:"hard_floors" json:"hard_floors"`
	HotPaths         []string            `yaml:"hot_paths" json:"hot_paths"`
	Domain           map[string][]string `yaml:"domain" json:"domain"`
	Reversibility    ReversibilitySpec   `yaml:"reversibility" json:"reversibility"`
	Rescore          RescoreSpec         `yaml:"rescore" json:"rescore"`
	PolicyFileWeight map[Axis]int        `yaml:"policy_file_weight" json:"policy_file_weight"`
}

type AxisSpec struct {
	Measured      string   `yaml:"measured" json:"measured,omitempty"` // refs | paths | tests
	Declared      *bool    `yaml:"declared" json:"declared,omitempty"`
	Bands         []int    `yaml:"bands" json:"bands,omitempty"`
	Keywords      []string `yaml:"keywords" json:"keywords,omitempty"`
	ManifestFloor *int     `yaml:"manifest_floor" json:"manifest_floor,omitempty"`
	TestGlobs     []string `yaml:"test_globs" json:"test_globs,omitempty"`
}

type ModeBand struct {
	Min     *int     `yaml:"min" json:"min,omitempty"`
	Max     *int     `yaml:"max" json:"max,omitempty"`
	Trigger []string `yaml:"trigger" json:"trigger,omitempty"`
}

// HardFloor forces a mode when an axis (or every axis in Both) reaches Value.
type HardFloor struct {
	Axis   Axis   `yaml:"axis" json:"axis,omitempty"`
	Both   []Axis `yaml:"both" json:"both,omitempty"`
	Value  int    `yaml:"value" json:"value"`
	Mode   Mode   `yaml:"mode" json:"mode"`
	Review string `yaml:"review" json:"review,omitempty"`
}

type ReversibilitySpec struct {
	NeedsStep           []string `yaml:"needs_step" json:"needs_step"`
	Irreversible        []string `yaml:"irreversible" json:"irreversible"`
	IrreversibleContent []string `yaml:"irreversible_content" json:"irreversible_content"`
}

type RescoreSpec struct {
	Axes      []Axis   `yaml:"axes" json:"axes"`
	When      []string `yaml:"when" json:"when"`
	Direction string   `yaml:"direction" json:"direction"` // only "up_only" is valid
}

type ModelsSpec struct {
	TiersAllowed []Tier                       `yaml:"tiers_allowed" json:"tiers_allowed"`
	ByRuntime    map[string]map[Tier][]string `yaml:"by_runtime" json:"by_runtime"`
	Ladder       LadderSpec                   `yaml:"ladder" json:"ladder"`
	Effort       map[Tier]string              `yaml:"effort" json:"effort"`
	Budgets      map[Mode]TokenCount          `yaml:"budgets" json:"budgets"`
	Probe        ProbeSpec                    `yaml:"probe" json:"probe"`
}

type LadderSpec struct {
	Missing                map[Tier]Tier     `yaml:"missing" json:"missing"`
	OnError                map[string]string `yaml:"on_error" json:"on_error"`
	NeverDowngradeThinking *bool             `yaml:"never_downgrade_thinking" json:"never_downgrade_thinking"`
}

type ProbeSpec struct {
	TTLHours *int   `yaml:"ttl_hours" json:"ttl_hours"`
	On4xx    string `yaml:"on_4xx" json:"on_4xx"`
	Cache    string `yaml:"cache" json:"cache"`
}

type AutonomySpec struct {
	Ceiling    *Level         `yaml:"ceiling" json:"ceiling"`
	ByMode     map[Mode]Level `yaml:"by_mode" json:"by_mode"`
	Output     string         `yaml:"output" json:"output"` // only "pr_only" is valid
	KillSwitch KillSwitchSpec `yaml:"kill_switch" json:"kill_switch"`
	Unattended UnattendedSpec `yaml:"unattended" json:"unattended"`
}

type KillSwitchSpec struct {
	RemoteFile  string `yaml:"remote_file" json:"remote_file"`
	PollSeconds *int   `yaml:"poll_seconds" json:"poll_seconds"`
	OnReadError string `yaml:"on_read_error" json:"on_read_error"` // only "halt" is valid
}

type UnattendedSpec struct {
	Container      string `yaml:"container" json:"container"`
	MaxWallMinutes *int   `yaml:"max_wall_minutes" json:"max_wall_minutes"`
	MaxTasksPerDay *int   `yaml:"max_tasks_per_day" json:"max_tasks_per_day"`
}

type EnforcementSpec struct {
	ProtectedPaths []string     `yaml:"protected_paths" json:"protected_paths"`
	SecretReads    []string     `yaml:"secret_reads" json:"secret_reads"`
	Commands       CommandsSpec `yaml:"commands" json:"commands"`
	Egress         EgressSpec   `yaml:"egress" json:"egress"`
	FailClosed     *bool        `yaml:"fail_closed" json:"fail_closed"`
	Sandbox        SandboxSpec  `yaml:"sandbox" json:"sandbox"`
}

type CommandsSpec struct {
	Deny     []string  `yaml:"deny" json:"deny"`
	Ask      []string  `yaml:"ask" json:"ask"`
	Allow    []string  `yaml:"allow" json:"allow"`
	Parser   string    `yaml:"parser" json:"parser"` // only "ast" is valid
	Unlisted *Decision `yaml:"unlisted" json:"unlisted"`
}

type EgressSpec struct {
	Allow       []string `yaml:"allow" json:"allow"`
	DenyDefault *bool    `yaml:"deny_default" json:"deny_default"`
}

// SandboxSpec is compiled to each runtime's native OS sandbox (DES §3.4 step 0).
// Entries may reference other lists with "$name" (e.g. "$secret_reads").
type SandboxSpec struct {
	RequiredFrom *Level   `yaml:"required_from" json:"required_from"`
	Readonly     []string `yaml:"readonly" json:"readonly"`
	NoRead       []string `yaml:"no_read" json:"no_read"`
	NoWrite      []string `yaml:"no_write" json:"no_write"`
}

type VerifySpec struct {
	Adapters              []VerifyAdapterSpec `yaml:"adapters" json:"adapters"`
	FullRunWhen           []string            `yaml:"full_run_when" json:"full_run_when"`
	SuiteBudget           *int                `yaml:"suite_budget" json:"suite_budget"`
	NightlyFull           *bool               `yaml:"nightly_full" json:"nightly_full"`
	SelectionMissesMetric *bool               `yaml:"selection_misses_metric" json:"selection_misses_metric"`
}

type VerifyAdapterSpec struct {
	Name     string `yaml:"name" json:"name"`
	Cmd      string `yaml:"cmd" json:"cmd"`
	Affected string `yaml:"affected" json:"affected,omitempty"`
}

type ReleaseSpec struct {
	Ecosystem  string   `yaml:"ecosystem" json:"ecosystem"`
	Channel    string   `yaml:"channel" json:"channel"`
	Preflight  []string `yaml:"preflight" json:"preflight"`
	PublishVia string   `yaml:"publish_via" json:"publish_via"`
}

type ResearchSpec struct {
	ByMode         map[Mode][]string `yaml:"by_mode" json:"by_mode"`
	Tier           Tier              `yaml:"tier" json:"tier"`
	BudgetPerScout TokenCount        `yaml:"budget_per_scout" json:"budget_per_scout"`
	Cache          ResearchCacheSpec `yaml:"cache" json:"cache"`
	TechDocs       TechDocsSpec      `yaml:"tech_docs" json:"tech_docs"`
}

type ResearchCacheSpec struct {
	Key []string `yaml:"key" json:"key"`
	Dir string   `yaml:"dir" json:"dir"`
}

type TechDocsSpec struct {
	Sources  []string `yaml:"sources" json:"sources"`
	PinFrom  string   `yaml:"pin_from" json:"pin_from"`
	Context7 *bool    `yaml:"context7" json:"context7"` // owner decision §14.4: off unless true
}

// TokenCount is a token budget written as 150k, 3M or a plain integer.
type TokenCount int64

func (t TokenCount) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(t), 10)), nil
}

func (t *TokenCount) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "K"):
		mult, s = 1_000, s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		mult, s = 1_000_000, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid token count %q", b)
	}
	*t = TokenCount(n * mult)
	return nil
}
