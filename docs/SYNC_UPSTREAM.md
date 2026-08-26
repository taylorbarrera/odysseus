# Syncing this fork with upstream

This fork carries one local customization on top of upstream `dev`: the
`cloudflare-tunnel` service + `cf-net`/`odysseus-net` networks in
`docker-compose.yml`, and the SearXNG host port remapped to 8088 to avoid a
local port conflict (see the "feat(docker): add cloudflare tunnel service..."
commit).

## One-time setup (already done)
```
git remote add upstream https://github.com/odysseus-dev/odysseus.git
```
This fork (`taylorbarrera/odysseus`) is forked directly from the true root
repo, `odysseus-dev/odysseus`.

## Repeatable update steps
1. Commit or stash any local changes first:
   ```
   git status
   git add -A && git commit -m "wip: local changes before sync"
   ```
2. Fetch latest from both remotes:
   ```
   git fetch upstream
   git fetch origin
   ```
3. Rebase your dev branch onto upstream/dev (keeps history linear and your
   cloudflare-tunnel commit(s) on top, avoiding merge commits and duplicate
   history):
   ```
   git rebase upstream/dev
   ```
   If `docker-compose.yml` conflicts (likely, since upstream may touch the
   same file), resolve by keeping upstream's changes plus your
   cloudflare-tunnel / cf-net / port-8088 additions. Use:
   ```
   git diff  # inspect the conflict markers
   # edit docker-compose.yml to merge both sides
   git add docker-compose.yml
   git rebase --continue
   ```
4. Validate the compose file parses:
   ```
   docker compose config -q
   ```
5. Push (force-with-lease is required after a rebase; requires a PAT/token
   with the `workflow` scope since upstream may touch
   `.github/workflows/*.yml`):
   ```
   git push --force-with-lease origin dev
   ```

## Why rebase instead of merge
A rebase replays only your unique commits (the cloudflare tunnel addition)
on top of upstream's latest history, keeping the fork's history clean and
identical to upstream plus a small, reviewable diff — instead of accumulating
merge commits and duplicate-content commits over time.
