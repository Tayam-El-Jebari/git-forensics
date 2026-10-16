---
name: git-forensics-scan
description: 'Run scan_repo.py (git-forensics red-flag scanner) against one or more git repositories (URLs, local checkouts, or a parent folder of checkouts), triage red flags safely without exposing secrets, and write a plain-language summary. Use when asked to scan a repo or a team''s repos for tampering, compromise, leaked secrets, suspicious commits, risky CI workflows, or to rerun the forensics scan.'
---

# Git-Forensics Scan

## Inputs

- **Targets** (required): repository URL(s), local checkout(s), a parent folder of checkouts, or `@file.txt` (one target per line). Ask only if none is given.
- **Activity window** (optional): `--days N`, default 14.

## Prerequisites

- `git` (>= 2.38 for clean-merge comparison) with read access to the repos (SSO authorized if the org requires it)
- Python 3 (`py` on Windows, `python3` elsewhere); no packages needed
- Optional, for Actions runs and force-pushes: `gh auth login` or `GITHUB_TOKEN` / `GH_TOKEN`

## Execution rules

- Run steps 1-5 autonomously in one turn. Do not ask for confirmation for read-only `git` commands on the clones or for deleting the temporary clones.
- Keep waiting on the same terminal until every repo prints its `SUMMARY:` line (and `Overview:` for multiple repos). Large repos take minutes.
- Exit code `2` = a clone failed: report which repo and tell the user to check access / SSO. Continue triaging the repos that succeeded.

## Procedure

### 1. Run the scan

Use the script next to this repo's root (`scan_repo.py`). Write reports to `results/` (never commit them):

```sh
python3 scan_repo.py <target> [<target> ...] --keep --out results
```

- `--keep` retains the mirror clones so red flags can be verified; the clone path is on the `clone:` line of each report.
- Local checkouts are re-cloned from `origin` (fresh, not stale). Add `--local` only if the user wants offline/as-is.
- Output per repo: `<repo>.forensicreport.<ts>.html` (summary on top) and `.txt`; with multiple targets also `index.forensicreport.<ts>.html`.
- If the clone hangs, a credential/SSO prompt is probably waiting.

### 2. Triage red flags (never print secret values)

Read the `.txt` report (the summary block at the top lists every red flag).

| Flag | How to verify |
|---|---|
| Secret kinds (`github-pat`, `aws-access-key`, ...) | The object is a **blob** (or commit message). Print only match **length** and whether it looks like a placeholder (`xxx`, `000`, `your...`), e.g. `git -C <clone> cat-file -p <blob> \| python3 -c "import re,sys;[print(len(m),m[:3]) for m in re.findall(r'<pattern>',sys.stdin.read())]"`. Find commits with `git -C <clone> log --all --oneline --find-object=<blob>`. |
| History-rewrite / replace ref | `git -C <clone> for-each-ref refs/original refs/replace` |
| Timestamp | `git -C <clone> show -s --format=fuller <sha>` |
| Orphaned tag | `git -C <clone> for-each-ref --format='%(refname:short) %(objecttype) %(creatordate:iso)' refs/tags`. Tags created by a PR-deploy/build workflow on squash-merged, deleted PR branches are usually benign. |
| Merge tree differs | `git -C <clone> show --cc <sha>` shows changes from neither parent. |

A confirmed real secret must be **rotated/revoked**; removing it from history is not enough. Never paste the value.

### 3. Classify review items

Usually benign:

- One identity with several emails (noreply + work). `example.com` addresses are a hygiene issue.
- `obfuscated` hits in generated/minified files or on `gh-pages`-style branches.
- `curl ... | bash` from official vendor installers (minor supply-chain risk).
- Merges touching lock files in both parents (dependency-bot conflict resolution).
- `mutable-action-ref` on version tags (SHA pinning is stricter).
- `pull_request_target` / `id-token: write` in workflows that only call the organisation's own approved shared workflows.

Escalate anything else, especially recent workflow changes, `write-all`, unknown committers in the activity window, and force-pushes.

For each recent commit whose author is not a bot or a known company/noreply address:

```sh
git -C <clone> show --stat --format=fuller <sha>
git -C <clone> branch --contains <sha>
```

Note what it changes (workflows, build files, deployment values) and whether it is on the default branch.

### 4. Clean up

Delete each `--keep` clone (path from its `clone:` line). Never delete a user's local checkout.

### 5. Write the summary

Save `results/<repo>_summary.md` per repo (or one `results/summary.md` for several repos, one section each):

```markdown
# Git-forensics scan summary: <repo>

- **Repo:** <url> · **Scan:** <time> UTC (window <N> days)
- **Report:** [html](<file>.html) · [txt](<file>.txt)

**Verdict:** <one line: tampering signs yes/no, red flags real vs false positive>

## Red flags (<n>)
| Finding | Reality |
## Review items
## Clean checks
## Follow-up
- [ ] ...
```

Reply in chat with a short plain-language verdict per repo and links to the summaries.

## Rules

- Never print, log or paste secret values: kind, path, object/commit and masked preview only.
- Every flag is a lead, not proof of compromise; a clean scan does not prove the repo is safe.
- Reports contain internal paths and identities: treat them as sensitive and do not commit them.
