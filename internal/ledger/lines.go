package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// eachLine unmarshals every JSONL line into a fresh value and calls
// fn. A line that does not parse is an error, except an unterminated last
// line (a live session still being written), which is skipped. Errors name
// the line number only, never its content.
func eachLine[T any](r io.Reader, fn func(*T)) error {
	br := bufio.NewReaderSize(r, 1<<20)
	for n := 1; ; n++ {
		b, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		terminated := err == nil
		if len(bytes.TrimSpace(b)) > 0 {
			var v T
			if jerr := json.Unmarshal(b, &v); jerr != nil {
				if !terminated {
					return nil
				}
				return fmt.Errorf("line %d: invalid JSON", n)
			}
			fn(&v)
		}
		if !terminated {
			return nil
		}
	}
}
