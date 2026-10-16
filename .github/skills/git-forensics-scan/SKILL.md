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

- Run steps 1-5 autonomously in one turn. The only reason to ask the user anything is missing targets. Do not ask for confirmation for read-only `git` commands on the clones or for deleting the temporary clones.
- Do **not** end the turn while the scan runs. Run it in async mode with a short timeout and keep reading the same terminal until every repo prints its `SUMMARY:` line (and `Overview:` for multiple repos). Large repos take minutes.
- Combine several read-only triage commands into one terminal call where possible.
- Only reply to the user after the summary file is written (step 5).
- Exit code `2` = a clone failed: report which repo and tell the user to check access / SSO. Continue triaging the repos that succeeded.

## Procedure

### 1. Run the scan

Use `scan_repo.py` in this repo's root. Write reports to `results/<repo>/` for one repo or `results/` for several (never commit them). Do not redirect or pipe the output.

```sh
python3 scan_repo.py <target> [<target> ...] --keep --out results/<repo>   # Windows: py scan_repo.py ...
```

- stderr shows clone progress, one line per step (`step 6/14: secrets`) and progress bars for the slow history scans.

- `--keep` retains the mirror clones so red flags can be verified; the clone path is on the `clone:` line of each report.
- Local checkouts are re-cloned from `origin` (fresh, not stale). Add `--local` only if the user wants offline/as-is.
- Output per repo: `<repo>.forensicreport.<ts>.html` (summary on top) and `.txt`; with multiple targets also `index.forensicreport.<ts>.html`.
- If the clone hangs, a credential/SSO prompt is probably waiting.

### 2. Triage red flags (never print secret values)

Read the `.txt` report (the summary block at the top lists every red flag).

| Flag | How to verify |
|---|---|
| Secret kinds (`github-pat`, `aws-access-key`, ...) | The object is a **blob** (or commit message). Print only match **length** and whether it looks like a placeholder (`xxx`, `000`, `your...`), e.g. `git -C <clone> cat-file -p <blob> \| python3 -c "import re,sys;[print(len(m),m[:3]) for m in re.findall(r'<pattern>',sys.stdin.read())]"`. A real GitHub classic PAT is 40 chars (`ghp_` + 36). The report already names a related commit; list all with `git -C <clone> log --all --oneline --find-object=<blob>`. |
| History-rewrite / replace ref | `git -C <clone> for-each-ref refs/original refs/replace` |
| Timestamp | `git -C <clone> show -s --format=fuller <sha>` |
| Orphaned tag | `git -C <clone> for-each-ref --format='%(refname:short) %(objecttype) %(creatordate:iso)' refs/tags` and `git -C <clone> log -1 --format='%h \| %an <%ae> \| %ad \| %s' <sha>` for a few samples. Tags like `pr-<N>-deployment` or `<ver>-pr-<N>-build-<M>` on "Deploying ... in PR N" commits come from a PR-deploy workflow on squash-merged, deleted branches: benign. |
| Merge tree differs | `git -C <clone> show --cc <sha>` shows changes from neither parent. |

A confirmed real secret must be **rotated/revoked**; removing it from history is not enough. Never paste the value.

### 3. Classify review items

Usually benign:

- One identity with several emails (noreply + work). `example.com` addresses are a hygiene issue.
- `obfuscated` hits on deployment branches such as `log-files` or `gh-pages`: minified JS in generated reports.
- `curl ... | bash` from official vendor installers, e.g. `aka.ms/InstallAzureCLIDeb`: minor supply-chain risk.
- Merges touching lock files (`uv.lock`, `package-lock.json`) in both parents: dependency-bot conflict resolution.
- `mutable-action-ref` on version tags (SHA pinning is stricter).
- `pull_request_target` / `id-token: write` in workflows that only call the organisation's own approved shared workflows.

Escalate anything else, especially recent workflow changes, `write-all`, unknown committers in the activity window, and force-pushes.

For each recent commit whose author is not a bot or a known company/noreply address:

```sh
git -C <clone> show --stat --format=fuller <sha>
git -C <clone> branch --contains <sha>
```

Note what it changes (workflows, helm values, build files) and whether it is merged into the default branch. Report it as a review item with that context.

### 4. Clean up

Delete each `--keep` clone (path from its `clone:` line): `rm -rf <path>` or `Remove-Item -Recurse -Force <path>`. Never delete a user's local checkout.

### 5. Write the summary

Save `results/<repo>/<repo>_<yyyy-MM-dd>_summary.md` next to the report (or one `results/summary.md` for several repos, one section each):

```markdown
# Git-forensics scan summary: <repo>

- **Repo:** <url> · **Scan:** <time> UTC (window <N> days)
- **Report:** [html](<file>.html) · [txt](<file>.txt)

**Verdict:** <one line: tampering signs yes/no, red flags real vs false positive>

## Red flags (<n>)
| Finding | Reality |
## Clean checks
## Review items (low risk)
## Operational notes (not security)
## Follow-up
- [ ] ...
```

Reply in chat with a short plain-language verdict per repo and links to the summaries.

## Rules

- Never print, log or paste secret values: kind, path, object/commit and masked preview only.
- Every flag is a lead, not proof of compromise; a clean scan does not prove the repo is safe.
- Reports contain internal paths and identities: treat them as sensitive and do not commit them.
- `scan_repo.py` is a heuristic backup tool, not an authoritative forensic verdict. Say so if the user needs one.
