// Package core holds the frozen contracts shared by every RiskRails module:
// enums, the policy schema, events and the interfaces between modules.
// Logic lives in the owning packages; core only defines shapes and ordering.
package core

import (
	"fmt"
	"strconv"
	"strings"
)

// Tier is a model capability class. Tasks speak in tiers, never model names.
type Tier string

const (
	TierFast     Tier = "FAST"
	TierBalanced Tier = "BALANCED"
	TierStrong   Tier = "STRONG"
	TierExpert   Tier = "EXPERT"
)

// Tiers lists all tiers from cheapest to strongest.
var Tiers = []Tier{TierFast, TierBalanced, TierStrong, TierExpert}

// Rank orders tiers: FAST=0 … EXPERT=3; unknown = -1.
func (t Tier) Rank() int { return indexOf(Tiers, t) }

func (t *Tier) UnmarshalText(b []byte) error {
	v := Tier(strings.ToUpper(string(b)))
	if v.Rank() < 0 {
		return fmt.Errorf("unknown tier %q", b)
	}
	*t = v
	return nil
}

// Mode is the process selected by triage.
type Mode string

const (
	ModeLight            Mode = "light"
	ModeGuarded          Mode = "guarded"
	ModeFull             Mode = "full"
	ModeFullIrreversible Mode = "full_irreversible"
	ModeProgramme        Mode = "programme"
)

// Modes lists modes from least to most process. Mode only ever grows.
var Modes = []Mode{ModeLight, ModeGuarded, ModeFull, ModeFullIrreversible, ModeProgramme}

func (m Mode) Rank() int { return indexOf(Modes, m) }

func (m *Mode) UnmarshalText(b []byte) error {
	v := Mode(b)
	if v.Rank() < 0 {
		return fmt.Errorf("unknown mode %q", b)
	}
	*m = v
	return nil
}

// Level is the autonomy level L0–L4. Lower is stricter.
type Level int

const (
	L0 Level = iota
	L1
	L2
	L3
	L4
)

func (l Level) String() string { return "L" + strconv.Itoa(int(l)) }

func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

func (l *Level) UnmarshalText(b []byte) error {
	s := string(b)
	if len(s) != 2 || (s[0] != 'L' && s[0] != 'l') || s[1] < '0' || s[1] > '4' {
		return fmt.Errorf("unknown autonomy level %q", s)
	}
	*l = Level(s[1] - '0')
	return nil
}

// Decision is a guard verdict. Order of strictness: deny > ask > allow.
type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

var decisions = []Decision{Allow, Ask, Deny}

// Rank orders decisions allow=0 < ask=1 < deny=2. Unknown or zero values rank
// strictest (3), so a forgotten field can never read as allow.
func (d Decision) Rank() int {
	if i := indexOf(decisions, d); i >= 0 {
		return i
	}
	return len(decisions)
}

func (d *Decision) UnmarshalText(b []byte) error {
	v := Decision(b)
	if indexOf(decisions, v) < 0 {
		return fmt.Errorf("unknown decision %q", b)
	}
	*d = v
	return nil
}

// Stricter returns the stricter of two decisions; unknown values win as deny.
func Stricter(a, b Decision) Decision {
	r := a
	if b.Rank() > a.Rank() {
		r = b
	}
	if indexOf(decisions, r) < 0 {
		return Deny
	}
	return r
}

// Axis is one of the six risk axes, each scored 0..2.
type Axis string

const (
	AxisScope         Axis = "scope"
	AxisBehaviour     Axis = "behaviour"
	AxisReversibility Axis = "reversibility"
	AxisDomain        Axis = "domain"
	AxisNovelty       Axis = "novelty"
	AxisCoverage      Axis = "coverage"
)

var Axes = []Axis{AxisScope, AxisBehaviour, AxisReversibility, AxisDomain, AxisNovelty, AxisCoverage}

func (a *Axis) UnmarshalText(b []byte) error {
	v := Axis(b)
	if indexOf(Axes, v) < 0 {
		return fmt.Errorf("unknown risk axis %q", b)
	}
	*a = v
	return nil
}

// Weight is a scored task: per-axis values plus the resulting mode.
type Weight struct {
	Axes     map[Axis]int `json:"axes"`
	Mode     Mode         `json:"mode"`
	Reasons  []string     `json:"reasons,omitempty"`
	Measured bool         `json:"measured"` // false = declared-only (before a diff exists)
}

func (w Weight) Total() int {
	n := 0
	for _, v := range w.Axes {
		n += v
	}
	return n
}

// Actor is who caused an event.
type Actor string

const (
	ActorHuman    Actor = "human"
	ActorAgent    Actor = "agent"
	ActorAutonomy Actor = "autonomy"
	ActorCI       Actor = "ci"
)

// WorkerStatus is the report status of an implementer or scout.
type WorkerStatus string

const (
	StatusDone             WorkerStatus = "DONE"
	StatusDoneWithConcerns WorkerStatus = "DONE_WITH_CONCERNS"
	StatusBlocked          WorkerStatus = "BLOCKED"
	StatusNeedsContext     WorkerStatus = "NEEDS_CONTEXT"
)

// Enforcement describes which layer actually enforces policy for a runtime.
type Enforcement string

const (
	EnforcementSandbox  Enforcement = "sandbox"   // OS sandbox + hooks
	EnforcementHookOnly Enforcement = "hook_only" // hooks, no OS sandbox → autonomy ≤ L1
	EnforcementCIOnly   Enforcement = "ci_only"   // no hooks → autonomy ≤ L1, no exceptions
)

// Direction is the result of comparing two policies.
type Direction string

const (
	Equal   Direction = "EQUAL"
	Tighten Direction = "TIGHTEN"
	Loosen  Direction = "LOOSEN"
	Mixed   Direction = "MIXED" // treated as LOOSEN by every caller
)

// Loosens is the only check callers may use: anything that is not EQUAL or
// TIGHTEN (LOOSEN, MIXED, "" from a zero value or an error path) loosens.
func (d Direction) Loosens() bool { return d != Equal && d != Tighten }

// Refusal is the error for every REFUSE {CODE} in DES (NO_TIER, TASK_IN_FLIGHT,
// CEILING_CHANGED, TIER_LOST, QUOTA, REVIEW_BUDGET, …). Match with errors.As.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return "REFUSE {" + r.Code + "}"
	}
	return "REFUSE {" + r.Code + "}: " + r.Detail
}

// ModelState is the availability of one model.
type ModelState string

const (
	ModelPass    ModelState = "PASS"
	ModelFail    ModelState = "FAIL"
	ModelUnknown ModelState = "UNKNOWN"
)

func indexOf[T comparable](list []T, v T) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}
