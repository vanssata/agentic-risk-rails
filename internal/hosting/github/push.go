package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

// Push pushes refs/heads/<branch> of the repository at root to
// https://github.com/<owner>/<repo>.git. Only rr/* branches, never forced.
// The remote URL is built here, never read from the (agent-controlled)
// .git/config; the token goes to the child git only through GIT_CONFIG_*
// environment variables, not argv or the URL.
func (c *Client) Push(ctx context.Context, root, branch string) error {
	if c.token == "" {
		return errors.New("github: push needs a token")
	}
	if err := checkBranch(ctx, branch); err != nil {
		return err
	}
	if err := checkRepoConfig(ctx, root); err != nil {
		return err
	}
	cmd := c.pushCmd(ctx, root, branch)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("github: push %s: %w: %s", branch, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// checkBranch accepts only rr/<something> that git itself accepts as a branch name.
func checkBranch(ctx context.Context, branch string) error {
	if !strings.HasPrefix(branch, "rr/") || len(branch) == len("rr/") || strings.ContainsAny(branch, " :+\\\x00") {
		return fmt.Errorf("github: push refused: branch %q is not rr/*", branch)
	}
	if _, err := gitx.Run(ctx, "", "check-ref-format", "refs/heads/"+branch); err != nil {
		return fmt.Errorf("github: push refused: branch %q: %w", branch, err)
	}
	return nil
}

// checkRepoConfig refuses a repository whose config could redirect or
// intercept the push (url.*.insteadOf, http.* such as proxy or CA).
func checkRepoConfig(ctx context.Context, root string) error {
	out, err := gitx.Run(ctx, "", "-C", root, "config", "--list", "--local", "--includes")
	if err != nil {
		return fmt.Errorf("github: push refused: %w", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		k := strings.ToLower(l)
		if strings.HasPrefix(k, "url.") || strings.HasPrefix(k, "http.") || strings.HasPrefix(k, "include") {
			return fmt.Errorf("github: push refused: repository config sets %s", strings.SplitN(l, "=", 2)[0])
		}
	}
	return nil
}

func (c *Client) pushCmd(ctx context.Context, root, branch string) *exec.Cmd {
	args := append([]string{}, gitx.Hardening...)
	args = append(args,
		"-c", "protocol.https.allow=always",
		"-c", "http.sslVerify=true",
		"-C", root,
		"push", "--no-verify", "--no-recurse-submodules",
		fmt.Sprintf("https://github.com/%s/%s.git", c.owner, c.repo),
		"refs/heads/"+branch+":refs/heads/"+branch, // no leading "+": never forced
	)
	cmd := exec.CommandContext(ctx, "git", args...)
	cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + c.token))
	cmd.Env = append(gitx.Env(),
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+cred,
	)
	return cmd
}
