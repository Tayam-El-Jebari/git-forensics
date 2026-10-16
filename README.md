# git-forensics scanner

A standalone, dependency-free (Python 3 + git) scanner for signs of compromise
in git repositories. A Copilot/agent skill that drives it lives in
[.github/skills/git-forensics-scan/SKILL.md](.github/skills/git-forensics-scan/SKILL.md).

Do not treat a lack of flags as no issues found please, but see this as a tool which saves you some manual check work.

## Run it

Pass one or more targets: repository URLs, local checkouts, a parent folder
containing checkouts, or `@file.txt` with one target per line.

```bash
python3 scan_repo.py https://github.com/org/repo.git
python3 scan_repo.py https://github.com/org/a.git https://github.com/org/b.git
python3 scan_repo.py ~/code/team-repos          # every repo directly inside
python3 scan_repo.py @repos.txt --out reports --days 30
```

- URLs are cloned fresh as a full mirror (all history, all refs). Local
  checkouts are re-cloned from their `origin` URL, because a laptop clone can
  be stale. `--local` scans checkouts as-is instead (faster, offline).
- Fresh clones are deleted after the run. Pass `--keep` to retain them so a
  human can open a flagged commit directly. Local checkouts are never deleted.
- The activity appendix defaults to a 14-day window (`--days N`). This does
  not limit the full-history checks.
- Progress is shown on stderr; `--print` also prints the text report.

Each repository gets an **HTML report** (summary and red flags on top,
sections collapsible) and a plain-text copy in `--out` (default: current
directory). Scanning more than one repo also writes an `index` overview page:

```text
my-service.forensicreport.20261015T193000.123456Z.html
my-service.forensicreport.20261015T193000.123456Z.txt
index.forensicreport.20261015T193000.123456Z.html
```

Files are UTF-8, owner-only read/write on macOS/Linux, and never overwritten.
Exit codes: `0` ok, `1` a report could not be saved, `2` a clone failed.

## Reading the report

The summary (counts and every red flag) is at the top. Markers:

- `[RED FLAG]` - a finding needing priority investigation, not proof of tampering.
- `[review]` - a lead worth reading, often benign noise.
- `[ok]` - no match in the stated scope, not a guarantee of safety.
- `[info]` - explanation, scope, or activity context, not an additional finding.
- `[skipped]` / `[error]` - part of the check was not completed; coverage is incomplete.

Findings explain what was observed, why it deserves attention, and what to
inspect. Where a commit is known, the report includes its full SHA, subject
(the first line of its message), author, committer, both dates, and a GitHub
commit link or a local inspection command. Author and committer are separate,
self-declared Git identities; neither identifies who pushed the change.
GitHub activity identifies the triggering/pushing account separately.

Merge overlaps can be ordinary merged work or conflict resolution. Even a
difference from a reconstructed clean merge requires reviewing the approved
change and merge strategy before drawing conclusions. Conflicts, unsupported
merge reconstruction and read failures are reported explicitly.

Secret findings distinguish object IDs from commit IDs. A related change can
add **or remove** an object; it is not necessarily the introducing commit.
Workflow findings identify the last file-changing commit, not necessarily the
commit that introduced the matched rule. Missing metadata is stated explicitly.
History is read with a few streamed/batched git processes (one `git log`
for added lines, one `cat-file --batch` for objects), so large repos scan in
minutes rather than hours.

## What it checks

1. **History rewrite** - `refs/original` backup refs left by `filter-branch`.
2. **Author impersonation** - homoglyph/unicode email local-parts, non-ascii
   author names, outlier email domains, one name using many emails, bad
   signatures.
3. **Timestamp forgery** - future dates, dates before git existed, commit date
   earlier than author date, commit date earlier than its parent, unusual
   timezone offsets.
4. **Replace refs** - `refs/replace/*` history substitution.
5. **Suspicious commands** - curl-to-shell, reverse shells, base64 eval, secret
   dumps, obfuscation patterns in added lines of non-merge commits.
6. **Secrets in history** - AWS keys, GitHub PATs, private keys, Slack tokens,
   cloud API keys, JWTs, password assignments in blobs and commit/tag
   messages. Values are always masked.
7. **Moved tags** - a tag whose target commit is reachable from no branch.
8. **Merge review** - files differing from both parents, plus comparison with
  a reconstructed clean `git merge-tree` result; neither alone proves intent.
9. **CI / GitHub Actions workflows** - Inspects .github/workflows/*.ya?ml for dangerous triggers (pull_request_target, workflow_dispatch, schedule), mutable action tags (@main, @master), overly broad permissions (write-all, id-token: write), and embedded payload signatures.

## The activity appendix

After the checks, under its own header and clearly separated from them, the
scanner prints five informational lists. These are not checks, so they never
produce a flag. They are here so you can see who has been doing what recently:

- **Branches** - every branch, newest tip first, with tip commit details.
- **Commits in the last N days** - filtered by committer date, with message,
  author, committer, both dates and inspection link.
- **Recorded authors and committers** - distinct identities with separate
  authorship and committer counts in the window.
- **GitHub Actions runs** - status, title, trigger, GitHub actor, branch, commit
  context and run link. Only one API page of up to 50 runs is fetched.
- **Force-pushes** - GitHub actor, ref, previous/new tip context and comparison
  link when available. Only the most recent page of up to 50 events is fetched;
  a previous tip may no longer exist in the clone.

GitHub API lists are skipped for local `file://` and non-GitHub URLs. API and
metadata failures are marked as unavailable, not treated as absence of activity.

The window is 14 days by default and is set with `--days N`.

## What it cannot check

- **GitHub Actions run history.** Even with the GitHub API
listing recent workflow runs, the scanner does not download execution logs or
reveal which runtime secrets were accessed during a run.
- No single check is proof of compromise. Every flag is a lead to inspect.

## Security rules

- The scanner masks secret values (first three characters only). If a masked
  hit matters, inspect the cloned object locally. Never paste a secret
  anywhere.
- Known secret patterns are also masked in report messages and code excerpts
  before the same report is printed and saved. Treat the file as sensitive:
  it still contains internal repository paths, identities and change details.
- Never write passwords, tokens, keys or connection strings into notes,
  tickets or chats. Secret names and usernames only.

## Local regression tests

```bash
python3 -m unittest test_scan_repo -v
```

These use mocked scan/API responses and a tiny temporary Git fixture. They
do not clone or scan a service repository and make no network requests.
