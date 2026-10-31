package core

// AlwaysProtected are paths no policy can unprotect: rr's own control files,
// runtime hook configs and git internals an agent could use to disable or
// re-point enforcement. Guard denies agent writes to them and generators add
// them to every runtime's sandbox write-deny list, whatever the policy says.
var AlwaysProtected = []string{
	"riskrails.yaml",
	".rr/**",
	".claude/**",
	".codex/**",
	".gemini/**",
	".cursor/**",
	".kiro/**",
	".mcp.json",
	".git/config",
	".git/HEAD",
	".git/packed-refs",
	".git/refs/**",
	".git/hooks/**",
	".github/workflows/**",
}

// StrictDefaults is the single source of default values: an empty
// riskrails.yaml resolves to exactly this (DES §3.1 "empty file = strictest").
// internal/policy fills every absent project field from here; its tests assert
// Load("") == StrictDefaults(). Values follow DES §3.2 with no project-specific
// paths, autonomy L0 and no allowed commands or egress.
func StrictDefaults() Policy {
	return Policy{
		Schema:  1,
		Project: ProjectSpec{DefaultBranch: "main", Stack: []string{}},
		Risk: RiskSpec{
			Axes: map[Axis]AxisSpec{
				AxisScope:         {Measured: "refs", Bands: []int{0, 5}},
				AxisBehaviour:     {Declared: ptr(true), Keywords: []string{"transaction", "lock", "queue", "async", "cron", "state"}},
				AxisReversibility: {Measured: "paths"},
				AxisDomain:        {Measured: "paths", Declared: ptr(true)},
				AxisNovelty:       {Declared: ptr(true), ManifestFloor: ptr(1)},
				AxisCoverage:      {Measured: "tests", TestGlobs: []string{}},
			},
			Modes: map[Mode]ModeBand{
				ModeLight:     {Max: ptr(2)},
				ModeGuarded:   {Min: ptr(3), Max: ptr(7)},
				ModeFull:      {Min: ptr(8)},
				ModeProgramme: {Trigger: []string{"spec", ">1 session", "files > 25"}},
			},
			HardFloors: []HardFloor{
				{Axis: AxisReversibility, Value: 2, Mode: ModeFull},
				{Axis: AxisDomain, Value: 2, Mode: ModeFull, Review: "security"},
				{Both: []Axis{AxisReversibility, AxisDomain}, Value: 2, Mode: ModeFullIrreversible},
			},
			HotPaths: []string{"riskrails.yaml", ".github/workflows/**"},
			Domain:   map[string][]string{},
			Reversibility: ReversibilitySpec{
				NeedsStep:           []string{".env*"},
				Irreversible:        []string{"migrations/**", "infra/**"},
				IrreversibleContent: []string{"DROP ", "TRUNCATE", "DELETE FROM", "ALTER TABLE .* DROP"},
			},
			Rescore:          RescoreSpec{Axes: []Axis{AxisReversibility, AxisDomain}, When: []string{"verify", "close"}, Direction: "up_only"},
			PolicyFileWeight: map[Axis]int{AxisBehaviour: 2, AxisDomain: 2},
		},
		Models: ModelsSpec{
			TiersAllowed: []Tier{TierFast, TierBalanced, TierStrong},
			ByRuntime:    map[string]map[Tier][]string{},
			Ladder: LadderSpec{
				Missing:                map[Tier]Tier{TierExpert: TierStrong, TierStrong: TierBalanced, TierFast: TierBalanced},
				OnError:                map[string]string{"rate_limit": "wait_then_same", "permission": "mark_unavailable", "not_found": "mark_unavailable"},
				NeverDowngradeThinking: ptr(true),
			},
			Effort: map[Tier]string{TierFast: "low", TierBalanced: "medium", TierStrong: "high"},
			Budgets: map[Mode]TokenCount{
				ModeLight: 150_000, ModeGuarded: 900_000, ModeFull: 3_000_000, ModeProgramme: 10_000_000,
			},
			Probe: ProbeSpec{TTLHours: ptr(24), On4xx: "refresh", Cache: "~/.cache/riskrails/models.json"},
		},
		Autonomy: AutonomySpec{
			Ceiling: ptr(L0),
			ByMode:  map[Mode]Level{ModeLight: L0, ModeGuarded: L0, ModeFull: L0, ModeFullIrreversible: L0, ModeProgramme: L0},
			Output:  "pr_only",
			KillSwitch: KillSwitchSpec{
				RemoteFile: ".rr/HALT", PollSeconds: ptr(60), OnReadError: "halt",
			},
			Unattended: UnattendedSpec{Container: "required", MaxWallMinutes: ptr(90), MaxTasksPerDay: ptr(10)},
		},
		Enforcement: EnforcementSpec{
			ProtectedPaths: []string{"riskrails.yaml", ".env*", ".github/workflows/**"},
			SecretReads:    []string{".env*", "~/.ssh/**", "~/.aws/**"},
			Commands: CommandsSpec{
				Deny:     []string{"git push --force*", "rm -rf /"},
				Ask:      []string{},
				Allow:    []string{},
				Parser:   "ast",
				Unlisted: ptr(Ask),
			},
			Egress:     EgressSpec{Allow: []string{}, DenyDefault: ptr(true)},
			FailClosed: ptr(true),
			Sandbox: SandboxSpec{
				RequiredFrom: ptr(L2),
				Readonly:     []string{"riskrails.yaml", ".git/config", ".git/refs/remotes/**", ".github/**"},
				NoRead:       []string{"$secret_reads", "~/.config/riskrails/**", "~/.cache/riskrails/**"},
				NoWrite:      []string{"~/.config/riskrails/**", "~/.cache/riskrails/**"},
			},
		},
		Verify: VerifySpec{
			Adapters:              []VerifyAdapterSpec{},
			FullRunWhen:           []string{"lockfile", ".github/**", "migrations/**", "uncovered_file", "mode>=full", "close"},
			SuiteBudget:           ptr(2),
			NightlyFull:           ptr(true),
			SelectionMissesMetric: ptr(true),
		},
		Release: ReleaseSpec{Channel: "tag", Preflight: []string{}, PublishVia: "ci_oidc"},
		Research: ResearchSpec{
			ByMode: map[Mode][]string{
				ModeLight:     {},
				ModeGuarded:   {"code", "test"},
				ModeFull:      {"code", "project-docs", "tech-docs", "prior-art", "history"},
				ModeProgramme: {"code", "project-docs", "tech-docs", "prior-art", "history", "test"},
			},
			Tier:           TierFast,
			BudgetPerScout: ptr(TokenCount(80_000)),
			Cache:          ResearchCacheSpec{Key: []string{"commit_sha", "role", "question_hash"}, Dir: "~/.cache/riskrails/research/<repo-hash>"},
			TechDocs:       TechDocsSpec{Sources: []string{"vendor", "llms_txt"}, Context7: ptr(false)},
		},
	}
}

func ptr[T any](v T) *T { return &v }
