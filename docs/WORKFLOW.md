# Working rules

How Claude Code should work with the maintainer on this repo. (Also mirrored in the local,
git-ignored `CLAUDE.md` so it loads automatically each session; this file is the tracked,
pushable copy.)

1. **Confirm understanding before acting.** Before starting a task, restate what the maintainer
   wants in your own words and wait for the go-ahead. If anything looks wrong, inconsistent, or
   unclear — or there is any doubt — stop and ask immediately. Do not act on assumptions, and do
   not do extra work on your own initiative.
2. **Commit (and push) after every change.** Every edit gets its own Conventional Commit and is
   pushed, so history stays granular and the remote is always current. Do not batch many unrelated
   changes into one commit.
3. **Sync the remote on session start.** Run `git fetch` and compare against `origin/main`; pull
   new commits before continuing.
