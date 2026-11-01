package github

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
)

type failingReviews struct{ core.Hosting }

func (failingReviews) Reviews(context.Context, int) ([]core.Review, error) {
	return nil, errors.New("API 500")
}

func TestHumanApproved(t *testing.T) {
	const head = "headsha"
	pr := core.PullRequest{Number: 7, Author: "alice", HeadSHA: head}
	owners := []string{"@acme/owners"}
	rv := func(login, state, commit string, bot bool) core.Review {
		return core.Review{Login: login, State: state, CommitID: commit, IsBot: bot}
	}
	tests := []struct {
		name    string
		reviews []core.Review
		want    bool
	}{
		{"no review", nil, false},
		{"label only is invisible: comment review", []core.Review{rv("bob", "COMMENTED", head, false)}, false},
		{"app approves", []core.Review{rv("rr-app[bot]", "APPROVED", head, true)}, false},
		{"author approves", []core.Review{rv("alice", "APPROVED", head, false)}, false},
		{"non-member approves", []core.Review{rv("mallory", "APPROVED", head, false)}, false},
		{"stale approval", []core.Review{rv("bob", "APPROVED", "old", false)}, false},
		{"approved then changes requested", []core.Review{rv("bob", "APPROVED", head, false), rv("bob", "CHANGES_REQUESTED", head, false)}, false},
		{"approved then dismissed", []core.Review{rv("bob", "APPROVED", head, false), rv("bob", "DISMISSED", head, false)}, false},
		{"owner human on head", []core.Review{rv("bob", "APPROVED", head, false)}, true},
		{"approval then comment", []core.Review{rv("bob", "APPROVED", head, false), rv("bob", "COMMENTED", head, false)}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakes.Hosting{
				ReviewsM: map[int][]core.Review{7: tc.reviews},
				Teams:    map[string][]string{"acme/owners": {"bob", "alice"}},
			}
			got, err := HumanApproved(context.Background(), h, pr, owners)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHumanApprovedUserOwnerAndErrors(t *testing.T) {
	pr := core.PullRequest{Number: 1, Author: "a", HeadSHA: "h"}
	h := &fakes.Hosting{ReviewsM: map[int][]core.Review{1: {{Login: "Boss", State: "APPROVED", CommitID: "h"}}}}
	ok, err := HumanApproved(context.Background(), h, pr, []string{"@boss"})
	require.NoError(t, err)
	assert.True(t, ok)

	_, err = HumanApproved(context.Background(), failingReviews{h}, pr, []string{"@boss"})
	assert.Error(t, err)

	ok, err = HumanApproved(context.Background(), h, pr, nil)
	require.NoError(t, err)
	assert.False(t, ok, "no code owners ⇒ nobody can approve")
}

func TestOwnersAndBots(t *testing.T) {
	co := []byte("# c\n* @acme/all\nriskrails.yaml @acme/owners\n/riskrails.yaml @acme/last # x\nsrc/ @bot-user\n")
	assert.Equal(t, []string{"@acme/last"}, Owners(co, "riskrails.yaml"))
	assert.Nil(t, Owners([]byte("src/ @x\n"), "riskrails.yaml"))
	assert.Empty(t, BotOwners(co))
	assert.Equal(t, []string{"@rr-app[bot]", "@apps/rr"}, BotOwners([]byte("riskrails.yaml @acme/o @rr-app[bot]\nx @apps/rr\n")))
}

func TestMissingRules(t *testing.T) {
	good := `[{"type":"pull_request","parameters":{"require_code_owner_review":true,"dismiss_stale_reviews_on_push":true,"require_last_push_approval":true,"required_approving_review_count":1}},
	{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"rr-policy-check"}]}}]`
	m, err := MissingRules([]byte(good), "rr-policy-check")
	require.NoError(t, err)
	assert.Empty(t, m)

	m, err = MissingRules([]byte(`[]`), "rr-policy-check")
	require.NoError(t, err)
	assert.Len(t, m, 6)

	weak := `[{"type":"pull_request","parameters":{"require_code_owner_review":true,"required_approving_review_count":0}}]`
	m, err = MissingRules([]byte(weak), "rr-policy-check")
	require.NoError(t, err)
	assert.Equal(t, []string{"dismiss_stale_reviews_on_push", "require_last_push_approval", "required_approving_review_count>=1", "required_status_check rr-policy-check"}, m)

	_, err = MissingRules([]byte(`{`), "x")
	assert.Error(t, err)
}
