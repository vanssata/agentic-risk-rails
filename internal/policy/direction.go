package policy

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

// This file holds the direction table (DES §3.4 step 1): for every policy
// field the meaning of "stricter" and how to merge two values into the
// strictest one. Fields without a defined direction use the opaque rule: any
// change is LOOSEN and a ceiling value replaces the project value. A field
// missing from the table behaves as opaque (fail-safe); a test fails if a
// core.Policy field is missing.

// cmpCtx is what comparisons need besides the two values.
type cmpCtx struct {
	files      []string
	base, cand *core.Policy
}

type rule struct {
	// cmp reports the direction of c relative to b, with a human detail.
	cmp func(x *cmpCtx, b, c reflect.Value) (core.Direction, string, error)
	// merge returns the strictest of a and b. Both are present. a wins ties and
	// opaque fields (a is the higher-precedence layer).
	merge func(a, b reflect.Value) reflect.Value
}

// directions maps a field path (map entries written as "*") to its rule.
// opaqueRule is the rule of every field without a defined direction.
var opaqueRule = opaque()

var directions = func() map[string]rule {
	var (
		opq    = opaqueRule
		lower  = numRule(false, intNum, nil)
		higher = numRule(true, intNum, nil)
		// declared/manifest_floor only raise a score; nil means "not applicable" = lowest.
		raise  = numRule(true, intNum, new(int64))
		more   = setRule(true)  // more entries = stricter (deny, triggers, keywords)
		allow  = setRule(false) // fewer entries = stricter (allow lists)
		glob   = globRule()
		effort = numRule(true, rankNum(map[string]int{"low": 0, "medium": 1, "high": 2}), nil)
		decide = numRule(true, rankNum(map[string]int{"allow": 0, "ask": 1, "deny": 2}), nil)
	)
	return map[string]rule{
		"remote":                 opq,
		"schema":                 opq,
		"project.name":           opq,
		"project.stack":          opq,
		"project.default_branch": opq,

		"risk.axes.*.measured":                    opq,
		"risk.axes.*.declared":                    raise,
		"risk.axes.*.bands":                       bandsRule(),
		"risk.axes.*.keywords":                    more,
		"risk.axes.*.manifest_floor":              raise,
		"risk.axes.*.test_globs":                  allow, // more test globs = more coverage assumed = looser
		"risk.modes.*.min":                        lower,
		"risk.modes.*.max":                        lower,
		"risk.modes.*.trigger":                    more,
		"risk.hard_floors":                        hardFloorsRule(),
		"risk.hot_paths":                          glob,
		"risk.domain":                             perKey(glob, true),
		"risk.reversibility.needs_step":           glob,
		"risk.reversibility.irreversible":         glob,
		"risk.reversibility.irreversible_content": more,
		"risk.rescore.axes":                       more,
		"risk.rescore.when":                       more,
		"risk.rescore.direction":                  opq,
		"risk.policy_file_weight":                 perKey(higher, false),

		"models.tiers_allowed":                   allow,
		"models.by_runtime":                      opq,
		"models.ladder.missing":                  opq,
		"models.ladder.on_error":                 opq,
		"models.ladder.never_downgrade_thinking": higher,
		"models.effort":                          perKey(effort, false),
		"models.budgets":                         perKey(lower, false),
		"models.probe.ttl_hours":                 lower,
		"models.probe.on_4xx":                    opq,
		"models.probe.cache":                     opq,

		"autonomy.ceiling":                      lower,
		"autonomy.by_mode":                      perKey(lower, false),
		"autonomy.output":                       opq,
		"autonomy.kill_switch.remote_file":      opq,
		"autonomy.kill_switch.poll_seconds":     lower,
		"autonomy.kill_switch.on_read_error":    opq,
		"autonomy.unattended.container":         opq,
		"autonomy.unattended.max_wall_minutes":  lower,
		"autonomy.unattended.max_tasks_per_day": lower,

		"enforcement.protected_paths":       glob,
		"enforcement.secret_reads":          glob,
		"enforcement.commands.deny":         more,
		"enforcement.commands.ask":          more,
		"enforcement.commands.allow":        allow,
		"enforcement.commands.parser":       opq,
		"enforcement.commands.unlisted":     decide,
		"enforcement.egress.allow":          allow,
		"enforcement.egress.deny_default":   higher,
		"enforcement.fail_closed":           higher,
		"enforcement.sandbox.required_from": lower,
		"enforcement.sandbox.readonly":      glob,
		"enforcement.sandbox.no_read":       glob,
		"enforcement.sandbox.no_write":      glob,

		"verify.adapters":                opq,
		"verify.full_run_when":           more,
		"verify.suite_budget":            opq,
		"verify.nightly_full":            higher,
		"verify.selection_misses_metric": higher,

		"release.ecosystem":   opq,
		"release.channel":     opq,
		"release.preflight":   more,
		"release.publish_via": opq,

		"research.by_mode":            opq,
		"research.tier":               opq,
		"research.budget_per_scout":   opq,
		"research.cache.key":          opq,
		"research.cache.dir":          opq,
		"research.tech_docs.sources":  opq,
		"research.tech_docs.pin_from": opq,
		"research.tech_docs.context7": opq,
	}
}()

// ---- rule constructors ----

func opaque() rule {
	return rule{
		cmp: func(_ *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			if reflect.DeepEqual(b.Interface(), c.Interface()) {
				return core.Equal, "", nil
			}
			return core.Loosen, "no defined direction: " + show(b) + " -> " + show(c), nil
		},
		merge: func(a, _ reflect.Value) reflect.Value { return a },
	}
}

type numFn func(v reflect.Value) (n int64, ok bool)

// intNum reads ints, bools and pointers to them; a nil pointer is not ok.
func intNum(v reflect.Value) (int64, bool) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, false
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Bool {
		if v.Bool() {
			return 1, true
		}
		return 0, true
	}
	return v.Int(), true
}

// rankNum reads (pointers to) strings through a rank table; unknown = -1.
func rankNum(ranks map[string]int) numFn {
	return func(v reflect.Value) (int64, bool) {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return 0, false
			}
			v = v.Elem()
		}
		r, ok := ranks[v.String()]
		if !ok {
			r = -1
		}
		return int64(r), true
	}
}

// numRule compares ordered scalars. higherStricter picks the direction. A nil
// pointer is read as *nilAs when given, otherwise a nil/non-nil mismatch is LOOSEN.
func numRule(higherStricter bool, num numFn, nilAs *int64) rule {
	read := func(v reflect.Value) (int64, bool) {
		n, ok := num(v)
		if !ok && nilAs != nil {
			return *nilAs, true
		}
		return n, ok
	}
	stricter := func(a, b int64) bool { return (a > b) == higherStricter } // a stricter than b
	return rule{
		cmp: func(_ *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			bn, bok := read(b)
			cn, cok := read(c)
			switch {
			case !bok && !cok:
				return core.Equal, "", nil
			case bok != cok:
				return core.Loosen, "set/unset: " + show(b) + " -> " + show(c), nil
			case bn == cn:
				return core.Equal, "", nil
			case stricter(cn, bn):
				return core.Tighten, show(b) + " -> " + show(c), nil
			}
			return core.Loosen, show(b) + " -> " + show(c), nil
		},
		merge: func(a, b reflect.Value) reflect.Value {
			an, aok := read(a)
			bn, bok := read(b)
			if !aok || (bok && stricter(bn, an)) {
				return b
			}
			return a
		},
	}
}

func strs(v reflect.Value) []string {
	out := make([]string, v.Len())
	for i := range out {
		out[i] = v.Index(i).String()
	}
	return out
}

func fromStrs(t reflect.Type, ss []string) reflect.Value {
	out := reflect.MakeSlice(t, 0, len(ss))
	for _, s := range ss {
		out = reflect.Append(out, reflect.ValueOf(s).Convert(t.Elem()))
	}
	return out
}

// diffSets returns the entries only in b (removed) and only in c (added).
func diffSets(b, c []string) (removed, added []string) {
	for _, s := range b {
		if !slices.Contains(c, s) && !slices.Contains(removed, s) {
			removed = append(removed, s)
		}
	}
	for _, s := range c {
		if !slices.Contains(b, s) && !slices.Contains(added, s) {
			added = append(added, s)
		}
	}
	return removed, added
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func intersect(a, b []string) []string {
	out := []string{}
	for _, s := range b {
		if slices.Contains(a, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// setRule compares string lists as sets. moreStricter: deny-like lists where
// removing an entry loosens. Otherwise allow-like: adding an entry loosens.
func setRule(moreStricter bool) rule {
	return rule{
		cmp: func(_ *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			bl := strs(b)
			rem, add := diffSets(bl, strs(c))
			if !moreStricter { // a new allow entry already covered by a base entry adds nothing
				add = slices.DeleteFunc(add, func(a string) bool { return subsumedByAny(bl, a) })
			}
			return setDirection(moreStricter, rem, add)
		},
		merge: func(a, b reflect.Value) reflect.Value {
			if moreStricter {
				return fromStrs(b.Type(), union(strs(b), strs(a)))
			}
			return fromStrs(b.Type(), intersect(strs(a), strs(b)))
		},
	}
}

func setDirection(moreStricter bool, removed, added []string) (core.Direction, string, error) {
	loosening, tightening, lw, tw := removed, added, "removed: ", "added: "
	if !moreStricter {
		loosening, tightening, lw, tw = added, removed, "added: ", "removed: "
	}
	switch {
	case len(loosening) > 0:
		return core.Loosen, lw + strings.Join(loosening, ", "), nil
	case len(tightening) > 0:
		return core.Tighten, tw + strings.Join(tightening, ", "), nil
	}
	return core.Equal, "", nil
}

// globRule compares deny-semantics glob lists. Every base pattern must be
// textually present in the candidate or subsumed by a broader candidate
// pattern; anything else is LOOSEN whatever the file sets say (narrowing can
// match the same files today and fewer tomorrow). The file sets only confirm a
// syntactic cover.
func globRule() rule {
	return rule{
		cmp: func(x *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			bl, cl := expand(strs(b), x.base), expand(strs(c), x.cand)
			rem, add := diffSets(bl, cl)
			var lost []string
			for _, p := range rem {
				if !subsumedByAny(cl, p) || !stillMatched(p, cl, x.files) {
					lost = append(lost, p)
				}
			}
			return setDirection(true, lost, add)
		},
		merge: setRule(true).merge,
	}
}

// subsumes reports whether pattern q matches everything pattern p matches,
// judged on the text alone. Conservative: false when unsure.
func subsumes(q, p string) bool {
	if !utf8.ValidString(q) || !utf8.ValidString(p) { // byte prefixes are not rune prefixes
		return false
	}
	switch {
	case q == p, q == "**":
		return true
	case strings.HasSuffix(q, "/**"):
		pre := strings.TrimSuffix(q, "**")
		return len(p) > len(pre) && strings.HasPrefix(p, pre)
	case strings.HasSuffix(q, "*") && !strings.HasSuffix(q, "**"):
		// "pre*" covers "pre<literal>" only: a wildcard, class or "/" in the
		// remainder of p can match what "*" cannot (it never crosses "/").
		pre := strings.TrimSuffix(q, "*")
		if !strings.HasPrefix(p, pre) || strings.ContainsAny(pre, "*?[{\\") {
			return false
		}
		return !strings.ContainsAny(p[len(pre):], "*?[{\\/")
	}
	return false
}

func subsumedByAny(list []string, p string) bool {
	return slices.ContainsFunc(list, func(q string) bool { return subsumes(q, p) })
}

// expand resolves "$secret_reads" and "$protected_paths" references in
// sandbox lists against the same policy; other entries stay literal.
func expand(list []string, p *core.Policy) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		switch s {
		case "$secret_reads":
			out = append(out, p.Enforcement.SecretReads...)
		case "$protected_paths":
			out = append(out, p.Enforcement.ProtectedPaths...)
		default:
			out = append(out, s)
		}
	}
	return out
}

// stillMatched confirms that every file matched by p is matched by a remaining pattern.
func stillMatched(p string, remaining, files []string) bool {
	for _, f := range files {
		if globs.Match(p, f) && !slices.ContainsFunc(remaining, func(q string) bool { return globs.Match(q, f) }) {
			return false
		}
	}
	return true
}

// perKey applies elem to every key of a map. zeroAbsent: a missing key reads as
// the zero value (list maps). Otherwise a key only in the candidate is TIGHTEN
// (a new cap) and a key only in the base is LOOSEN.
func perKey(elem rule, zeroAbsent bool) rule {
	return rule{
		cmp: func(x *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			var loosen, tighten []string
			for _, k := range mapKeys(b, c) {
				bv, cv := b.MapIndex(k), c.MapIndex(k)
				switch {
				case zeroAbsent && !bv.IsValid():
					bv = reflect.Zero(c.Type().Elem())
				case zeroAbsent && !cv.IsValid():
					cv = reflect.Zero(b.Type().Elem())
				case !bv.IsValid():
					tighten = append(tighten, fmt.Sprint(k)+": added")
					continue
				case !cv.IsValid():
					loosen = append(loosen, fmt.Sprint(k)+": removed")
					continue
				}
				d, detail, err := elem.cmp(x, bv, cv)
				if err != nil {
					return core.Loosen, "", err
				}
				entry := fmt.Sprint(k) + ": " + detail
				switch d {
				case core.Tighten:
					tighten = append(tighten, entry)
				case core.Equal:
				default:
					loosen = append(loosen, entry)
				}
			}
			switch {
			case len(loosen) > 0:
				return core.Loosen, strings.Join(loosen, "; "), nil
			case len(tighten) > 0:
				return core.Tighten, strings.Join(tighten, "; "), nil
			}
			return core.Equal, "", nil
		},
		merge: func(a, b reflect.Value) reflect.Value {
			out := reflect.MakeMap(b.Type())
			for _, k := range mapKeys(a, b) {
				av, bv := a.MapIndex(k), b.MapIndex(k)
				switch {
				case !av.IsValid():
					out.SetMapIndex(k, bv)
				case !bv.IsValid():
					out.SetMapIndex(k, av)
				default:
					out.SetMapIndex(k, elem.merge(av, bv))
				}
			}
			return out
		},
	}
}

// mapKeys returns the sorted union of the keys of two maps of one type.
func mapKeys(a, b reflect.Value) []reflect.Value {
	keys := a.MapKeys()
	for _, k := range b.MapKeys() {
		if !a.MapIndex(k).IsValid() {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	return keys
}

// bandsRule: lower band thresholds score more tasks higher; the lists must keep their length.
func bandsRule() rule {
	return rule{
		cmp: func(_ *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			if b.Len() == 0 && c.Len() == 0 {
				return core.Equal, "", nil
			}
			if b.Len() != c.Len() {
				return core.Loosen, "length changed: " + show(b) + " -> " + show(c), nil
			}
			d := core.Equal
			for i := range b.Len() {
				switch bi, ci := b.Index(i).Int(), c.Index(i).Int(); {
				case ci > bi:
					return core.Loosen, show(b) + " -> " + show(c), nil
				case ci < bi:
					d = core.Tighten
				}
			}
			return d, show(b) + " -> " + show(c), nil
		},
		merge: func(a, b reflect.Value) reflect.Value {
			if a.Len() != b.Len() {
				return a
			}
			out := reflect.MakeSlice(a.Type(), a.Len(), a.Len())
			for i := range a.Len() {
				v := a.Index(i)
				if b.Index(i).Int() < v.Int() {
					v = b.Index(i)
				}
				out.Index(i).Set(v)
			}
			return out
		},
	}
}

// floorModeRank orders the modes a hard floor may force; full_irreversible
// (the human gate) is strictest.
var floorModeRank = map[core.Mode]int{
	core.ModeLight: 0, core.ModeGuarded: 1, core.ModeFull: 2, core.ModeProgramme: 3, core.ModeFullIrreversible: 4,
}

// hardFloorsRule: a floor g covers f when it triggers on the same axes at an
// equal or lower value and forces an equal or heavier mode.
func hardFloorsRule() rule {
	key := func(f core.HardFloor) string {
		axes := []string{string(f.Axis)}
		for _, a := range f.Both {
			axes = append(axes, string(a))
		}
		sort.Strings(axes)
		return strings.Join(axes, "+")
	}
	covers := func(g, f core.HardFloor) bool {
		return key(g) == key(f) && g.Value <= f.Value && floorModeRank[g.Mode] >= floorModeRank[f.Mode] &&
			(f.Review == "" || g.Review == f.Review)
	}
	floors := func(v reflect.Value) []core.HardFloor { return v.Interface().([]core.HardFloor) }
	return rule{
		cmp: func(_ *cmpCtx, b, c reflect.Value) (core.Direction, string, error) {
			bf, cf := floors(b), floors(c)
			for _, f := range bf {
				if !slices.ContainsFunc(cf, func(g core.HardFloor) bool { return covers(g, f) }) {
					return core.Loosen, "weakened or removed floor " + key(f), nil
				}
			}
			for _, g := range cf {
				if !slices.ContainsFunc(bf, func(f core.HardFloor) bool { return reflect.DeepEqual(f, g) }) {
					return core.Tighten, "added or strengthened floor " + key(g), nil
				}
			}
			return core.Equal, "", nil
		},
		merge: func(a, b reflect.Value) reflect.Value {
			out := reflect.MakeSlice(b.Type(), 0, a.Len()+b.Len())
			out = reflect.AppendSlice(out, b)
			for _, g := range floors(a) {
				if !slices.ContainsFunc(floors(b), func(f core.HardFloor) bool { return reflect.DeepEqual(f, g) }) {
					out = reflect.Append(out, reflect.ValueOf(g))
				}
			}
			return out
		},
	}
}

func show(v reflect.Value) string {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "<unset>"
		}
		v = v.Elem()
	}
	return fmt.Sprint(v.Interface())
}

// ---- walking ----

func yamlName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return name
}

func isStructMap(t reflect.Type) bool {
	return t.Kind() == reflect.Map && t.Elem().Kind() == reflect.Struct
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// leafPaths lists the table paths of every leaf field of t.
func leafPaths(t reflect.Type, prefix string) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		p := join(prefix, yamlName(f))
		switch {
		case f.Type.Kind() == reflect.Struct:
			out = append(out, leafPaths(f.Type, p)...)
		case isStructMap(f.Type):
			out = append(out, leafPaths(f.Type.Elem(), p+".*")...)
		default:
			out = append(out, p)
		}
	}
	return out
}

// walker visits the leaf fields of two Policy values in lockstep. With mutate
// set, b is modified in place (map entries are copied back).
type walker struct {
	leaf func(r rule, pat, disp string, b, c reflect.Value) error
	// entry sees every key of a map of structs; be/ce are invalid when absent.
	// It returns true to descend (both present).
	entry  func(disp string, m, key, be, ce reflect.Value) bool
	mutate bool
}

func (w *walker) walk(pat, disp string, b, c reflect.Value) error {
	t := b.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name := yamlName(f)
		fp, fd := join(pat, name), join(disp, name)
		bf, cf := b.Field(i), c.Field(i)
		var err error
		switch {
		case f.Type.Kind() == reflect.Struct:
			err = w.walk(fp, fd, bf, cf)
		case isStructMap(f.Type):
			err = w.walkMap(fp, fd, bf, cf)
		default:
			r, ok := directions[fp]
			if !ok {
				r = opaqueRule // unknown fields fail safe
			}
			err = w.leaf(r, fp, fd, bf, cf)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) walkMap(pat, disp string, bm, cm reflect.Value) error {
	for _, k := range mapKeys(bm, cm) {
		be, ce := bm.MapIndex(k), cm.MapIndex(k)
		kd := disp + "." + fmt.Sprint(k)
		if !w.entry(kd, bm, k, be, ce) {
			continue
		}
		x := reflect.New(be.Type()).Elem()
		x.Set(be)
		if err := w.walk(pat+".*", kd, x, ce); err != nil {
			return err
		}
		if w.mutate {
			bm.SetMapIndex(k, x)
		}
	}
	return nil
}

// ---- Diff ----

// Diff compares candidate to base per field by the direction table. files is
// `git ls-files`, used for glob-set comparison. An error must be treated as LOOSEN.
func Diff(base, candidate core.Policy, files []string) (core.Direction, []core.FieldChange, error) {
	x := &cmpCtx{files: files, base: &base, cand: &candidate}
	var changes []core.FieldChange
	w := &walker{
		leaf: func(r rule, _, disp string, b, c reflect.Value) error {
			d, detail, err := r.cmp(x, b, c)
			if err != nil {
				return err
			}
			if d != core.Equal {
				changes = append(changes, core.FieldChange{Path: disp, Direction: d, Detail: detail})
			}
			return nil
		},
		entry: func(disp string, _, _, be, ce reflect.Value) bool {
			switch {
			case !be.IsValid():
				changes = append(changes, core.FieldChange{Path: disp, Direction: core.Tighten, Detail: "added"})
			case !ce.IsValid():
				changes = append(changes, core.FieldChange{Path: disp, Direction: core.Loosen, Detail: "removed"})
			default:
				return true
			}
			return false
		},
	}
	if err := w.walk("", "", reflect.ValueOf(&base).Elem(), reflect.ValueOf(&candidate).Elem()); err != nil {
		return core.Loosen, nil, fmt.Errorf("policy diff: %w", err)
	}
	var loosen, tighten bool
	for _, ch := range changes {
		loosen = loosen || ch.Direction.Loosens()
		tighten = tighten || ch.Direction == core.Tighten
	}
	switch {
	case loosen && tighten:
		return core.Mixed, changes, nil
	case loosen:
		return core.Loosen, changes, nil
	case tighten:
		return core.Tighten, changes, nil
	}
	return core.Equal, changes, nil
}
