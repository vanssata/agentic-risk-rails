package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

// Push pushes refs/heads/<branch> of the repository at root to
// https://github.com/<owner>/<repo>.git. Only rr/* branches, never forced.
//
// The agent controls root's config (.git/config, config.worktree, alternates),
// so nothing is pushed from root: the branch is fetched into a fresh bare
// repository with our own (empty) config and pushed from there. The remote URL
// is built here, and the token reaches the child git only through GIT_CONFIG_*
// environment variables, not argv or the URL.
func (c *Client) Push(ctx context.Context, root, branch string) error {
	if c.token == "" {
		return errors.New("github: push needs a token")
	}
	if err := checkBranch(ctx, branch); err != nil {
		return err
	}
	src, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("github: push refused: %w", err)
	}
	if err := checkSource(src); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "rr-push-")
	if err != nil {
		return fmt.Errorf("github: push: %w", err)
	}
	defer os.RemoveAll(tmp)
	if _, err := gitx.Run(ctx, "", "init", "-q", "--bare", "--template=", tmp); err != nil {
		return fmt.Errorf("github: push: %w", err)
	}
	// upload-pack runs in root and reads its config; the -c hardening reaches it via
	// GIT_CONFIG_PARAMETERS, and uploadpack.packObjectsHook is ignored in repo config [V].
	ref := "refs/heads/" + branch
	if _, err := gitx.Run(ctx, "", "-C", tmp, "-c", "protocol.file.allow=always",
		"fetch", "-q", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", src, ref+":"+ref); err != nil {
		return fmt.Errorf("github: push %s: %w", branch, err)
	}
	cmd := c.pushCmd(ctx, tmp, branch)
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

// checkSource refuses a repository whose objects may come from elsewhere:
// a linked worktree (.git file, commondir) or alternates.
func checkSource(root string) error {
	g := filepath.Join(root, ".git")
	if fi, err := os.Stat(g); err != nil || !fi.IsDir() {
		return fmt.Errorf("github: push refused: %s is not a plain git directory", g)
	}
	for _, p := range []string{"commondir", "objects/info/alternates", "objects/info/http-alternates"} {
		if _, err := os.Lstat(filepath.Join(g, p)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("github: push refused: %s present", p)
		}
	}
	return nil
}

func (c *Client) pushCmd(ctx context.Context, dir, branch string) *exec.Cmd {
	url := fmt.Sprintf("https://github.com/%s/%s.git", c.owner, c.repo)
	if c.pushURL != "" { // tests only
		url = c.pushURL
	}
	fileAllow := "never"
	if c.pushURL != "" {
		fileAllow = "always"
	}
	args := append([]string{}, gitx.Hardening...)
	args = append(args,
		"-c", "protocol.https.allow=always",
		"-c", "protocol.file.allow="+fileAllow,
		"-c", "http.sslVerify=true",
		"-c", "push.followTags=false",
		"-c", "push.gpgSign=false",
		"-C", dir,
		"push", "--no-verify", "--no-follow-tags", "--no-signed", "--no-recurse-submodules",
		url,
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
