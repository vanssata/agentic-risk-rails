package projection_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
)

func e(typ, data string, sec int) core.Event {
	return core.Event{Type: typ, Task: "t1", Time: time.Unix(int64(sec), 0).UTC(), Data: json.RawMessage(data)}
}

func TestStatusAndSummary(t *testing.T) {
	evs := []core.Event{e("task_started", `{"mode":"build"}`, 1), e("verify_run", ``, 2), e("verify_run", ``, 3)}
	st := projection.BuildStatus(evs, 2)
	assert.Equal(t, "build", st.Mode)
	assert.Equal(t, 2, st.Counts["verify_run"])
	assert.Len(t, st.Recent, 2)
	assert.Equal(t, 3, st.Total)
}

func TestRisks(t *testing.T) {
	evs := []core.Event{
		e("risk_recorded", `{"id":"a"}`, 1), e("risk_recorded", `{"id":"b"}`, 2), e("risk_resolved", `{"id":"a"}`, 3),
	}
	r := projection.Risks(evs)
	assert.Len(t, r, 1)
	assert.JSONEq(t, `{"id":"b"}`, string(r[0].Data))
}

func TestTaskMDDeterministic(t *testing.T) {
	evs := []core.Event{e("task_started", `{"mode":"fix"}`, 1), e("task_closed", `{"cost":1}`, 2)}
	a := projection.TaskMD(projection.Summarize(evs))
	assert.Equal(t, a, projection.TaskMD(projection.Summarize(evs)))
	assert.Contains(t, a, "- task_closed: 1")
	assert.Contains(t, a, `{"cost":1}`)
}
