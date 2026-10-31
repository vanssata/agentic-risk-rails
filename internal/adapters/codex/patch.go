package codex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// fileEdit is one file touched by an apply_patch envelope, with its post-edit
// content ("" for a deletion).
type fileEdit struct {
	Path    string // absolute, Clean'ed (new path for a move)
	From    string // absolute old path for a move, else ""
	Content string
	Delete  bool
}

const (
	patchBegin  = "*** Begin Patch"
	patchEnd    = "*** End Patch"
	hdrAdd      = "*** Add File: "
	hdrDelete   = "*** Delete File: "
	hdrUpdate   = "*** Update File: "
	hdrMove     = "*** Move to: "
	hdrEOF      = "*** End of File"
	hunkContext = "@@"
)

// readFile is replaceable in tests.
var readFile = os.ReadFile

func abs(cwd, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// parsePatch applies a Codex apply_patch envelope (source: codex-rs apply-patch
// grammar, see docs/research/verified/codex.md) against the files on disk and
// returns the post-edit content per file. Any inconsistency is an error.
func parsePatch(cwd, patch string) ([]fileEdit, error) {
	lines := strings.Split(strings.TrimRight(patch, "\n"), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != patchBegin || strings.TrimSpace(lines[len(lines)-1]) != patchEnd {
		return nil, errors.New("apply_patch: missing Begin/End Patch markers")
	}
	lines = lines[1 : len(lines)-1]
	var out []fileEdit
	for i := 0; i < len(lines); {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, hdrAdd):
			j := i + 1
			var b strings.Builder
			for ; j < len(lines) && !strings.HasPrefix(lines[j], "*** "); j++ {
				if !strings.HasPrefix(lines[j], "+") {
					return nil, fmt.Errorf("apply_patch: bad Add File line %q", lines[j])
				}
				b.WriteString(lines[j][1:] + "\n")
			}
			out = append(out, fileEdit{Path: abs(cwd, l[len(hdrAdd):]), Content: b.String()})
			i = j
		case strings.HasPrefix(l, hdrDelete):
			out = append(out, fileEdit{Path: abs(cwd, l[len(hdrDelete):]), Delete: true})
			i++
		case strings.HasPrefix(l, hdrUpdate):
			src := abs(cwd, l[len(hdrUpdate):])
			j := i + 1
			dst := ""
			if j < len(lines) && strings.HasPrefix(lines[j], hdrMove) {
				dst = abs(cwd, lines[j][len(hdrMove):])
				j++
			}
			start := j
			for ; j < len(lines) && !isFileHeader(lines[j]); j++ {
			}
			cur, err := readFile(src)
			if err != nil {
				return nil, fmt.Errorf("apply_patch: read %s: %w", src, err)
			}
			content, err := applyHunks(string(cur), lines[start:j])
			if err != nil {
				return nil, fmt.Errorf("apply_patch: %s: %w", src, err)
			}
			if dst == "" {
				out = append(out, fileEdit{Path: src, Content: content})
			} else {
				out = append(out, fileEdit{Path: dst, From: src, Content: content})
			}
			i = j
		default:
			return nil, fmt.Errorf("apply_patch: unexpected line %q", l)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("apply_patch: empty patch")
	}
	return out, nil
}

func isFileHeader(l string) bool {
	return strings.HasPrefix(l, hdrAdd) || strings.HasPrefix(l, hdrDelete) || strings.HasPrefix(l, hdrUpdate)
}

type chunk struct {
	ctx      string // text after "@@", may be empty
	old, new []string
	eof      bool
}

func parseChunks(lines []string) ([]chunk, error) {
	var cs []chunk
	var cur *chunk
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, hunkContext):
			cs = append(cs, chunk{ctx: strings.TrimSpace(strings.TrimPrefix(l, hunkContext))})
			cur = &cs[len(cs)-1]
		case l == hdrEOF:
			if cur == nil {
				return nil, errors.New("end-of-file marker outside a hunk")
			}
			cur.eof = true
		default:
			if cur == nil { // the first hunk may omit its @@ line
				cs = append(cs, chunk{})
				cur = &cs[len(cs)-1]
			}
			switch {
			case l == "":
				cur.old, cur.new = append(cur.old, ""), append(cur.new, "")
			case l[0] == ' ':
				cur.old, cur.new = append(cur.old, l[1:]), append(cur.new, l[1:])
			case l[0] == '-':
				cur.old = append(cur.old, l[1:])
			case l[0] == '+':
				cur.new = append(cur.new, l[1:])
			default:
				return nil, fmt.Errorf("bad hunk line %q", l)
			}
		}
	}
	if len(cs) == 0 {
		return nil, errors.New("update without hunks")
	}
	return cs, nil
}

func applyHunks(orig string, hunkLines []string) (string, error) {
	cs, err := parseChunks(hunkLines)
	if err != nil {
		return "", err
	}
	file := strings.Split(strings.TrimSuffix(orig, "\n"), "\n")
	if orig == "" {
		file = nil
	}
	pos, copied := 0, 0 // pos: search cursor, copied: file lines already in res
	var res []string
	for _, c := range cs {
		if c.ctx != "" {
			k := seek(file, []string{c.ctx}, pos, false)
			if k < 0 {
				return "", fmt.Errorf("context %q not found", c.ctx)
			}
			pos = k + 1
		}
		at := len(file)
		if len(c.old) > 0 {
			at = seek(file, c.old, pos, c.eof)
			if at < 0 {
				return "", fmt.Errorf("hunk does not apply: %q", strings.Join(c.old, "\n"))
			}
		}
		res = append(res, file[copied:at]...)
		res = append(res, c.new...)
		pos = at + len(c.old)
		copied = pos
	}
	res = append(res, file[copied:]...)
	if len(res) == 0 {
		return "", nil
	}
	return strings.Join(res, "\n") + "\n", nil
}

// seek finds needle in file at or after from, trying exact, trim-right and
// trim-both comparisons (the lenience Codex applies itself).
func seek(file, needle []string, from int, atEOF bool) int {
	norm := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.TrimRight(s, " \t") },
		strings.TrimSpace,
	}
	for _, n := range norm {
		last := len(file) - len(needle)
		start := from
		if atEOF {
			start = last
		}
		for i := start; i >= 0 && i <= last; i++ {
			ok := true
			for j := range needle {
				if n(file[i+j]) != n(needle[j]) {
					ok = false
					break
				}
			}
			if ok {
				return i
			}
		}
	}
	return -1
}
