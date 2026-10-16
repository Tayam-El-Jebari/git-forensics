#!/usr/bin/env python3
"""
scan_repo.py - git-forensics red-flag scanner.

Scans one or more git repositories for signs of tampering: history rewrites,
identity spoofing, forged timestamps, replace refs, suspicious commands,
secrets in history, orphaned tags, evil merges and risky CI workflows.

Targets can be any mix of:
    - repository URLs                    (cloned fresh as a full mirror)
    - local checkouts                    (re-cloned fresh from their origin URL)
    - a parent folder of checkouts       (every repo directly inside it)
    - @file.txt                          (one target per line)

Run:
    python3 scan_repo.py https://github.com/org/repo.git
    python3 scan_repo.py ~/code/team-repos --days 30
    python3 scan_repo.py @repos.txt --out reports

Each repo gets an HTML report (summary on top) plus a plain-text copy; scanning
several repos also writes an index.html overview. Fresh clones are removed after
the scan unless --keep is given. --local scans checkouts as-is without cloning.

Secret matches are masked. Treat every flag as "look at this", not as proof of
compromise, and do not treat a lack of flags as proof that nothing is wrong.
"""

import argparse
import datetime as _dt
import functools
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict


def _utcnow():
    """Return timezone-naive UTC datetime (avoids Python 3.12+ utcnow deprecation)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def progress(msg):
    print("[%s] %s" % (_dt.datetime.now().strftime("%H:%M:%S"), msg), file=sys.stderr, flush=True)


def progress_bar(i, total, label):
    if total <= 0 or (i % 25 and i != total):
        return
    width = 30
    filled = width * i // total
    sys.stderr.write("\r    [%s%s] %3d%% %s %d/%d" % ("#" * filled, "." * (width - filled),
                                                   i * 100 // total, label, i, total))
    if i == total:
        sys.stderr.write("\n")
    sys.stderr.flush()


# --------------------------------------------------------------------------
# plumbing helpers
# --------------------------------------------------------------------------

BULK_TIMEOUT = 3600


def git(repo, *args, _input=None, _ok=(), _timeout=120):
    """Run a git command in `repo`. Return (rc, stdout_str, stderr_str)."""
    cmd = ["git", "-C", repo, *args]
    # bytes mode: text-mode stdin on Windows turns \n into \r\n, which breaks --stdin parsers
    try:
        p = subprocess.run(
            cmd, input=_input.encode("utf-8") if _input is not None else None,
            capture_output=True, timeout=_timeout
        )
        return (p.returncode, p.stdout.decode("utf-8", errors="replace"),
                p.stderr.decode("utf-8", errors="replace"))
    except FileNotFoundError:
        return 127, "", "git not found"
    except subprocess.TimeoutExpired:
        return 124, "", "git timed out"


def git_stream(repo, *args, status=None):
    """Yield stdout lines of a long-running git command; store its exit code in status['rc']."""
    p = subprocess.Popen(["git", "-C", repo, *args], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, encoding="utf-8", errors="replace")
    try:
        for ln in p.stdout:
            yield ln.rstrip("\n")
    finally:
        p.stdout.close()
        rc = p.wait()
        if status is not None:
            status["rc"] = rc


def cat_file_batch(repo, shas):
    """Yield (sha, raw bytes or None) for each sha using one `git cat-file --batch` process."""
    p = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # feed stdin from a thread so a full stdout pipe can't deadlock us
    def feed():
        try:
            for s in shas:
                p.stdin.write((s + "\n").encode())
            p.stdin.close()
        except OSError:
            pass

    t = threading.Thread(target=feed, daemon=True)
    t.start()
    try:
        for _ in shas:
            header = p.stdout.readline()
            if not header:
                break
            parts = header.split()
            if len(parts) < 3:
                yield parts[0].decode() if parts else "", None
                continue
            data = p.stdout.read(int(parts[2]))
            p.stdout.read(1)
            yield parts[0].decode(), data
    finally:
        p.stdout.close()
        p.kill()
        p.wait()
        t.join(timeout=5)


@functools.lru_cache(maxsize=1)
def _github_headers():
    """Build GitHub API headers with token fallback (env -> gh CLI -> git credentials)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "git-forensics-scanner",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if not token:
        try:
            p = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, text=True, timeout=5
            )
            if p.returncode == 0 and p.stdout.strip():
                token = p.stdout.strip()
        except Exception:
            pass

    if not token:
        try:
            p = subprocess.run(
                ["git", "credential", "fill"],
                input="protocol=https\nhost=github.com\n\n",
                capture_output=True,
                text=True,
                timeout=5,
            )
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    if line.startswith("password="):
                        token = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass

    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers, bool(token)


# --------------------------------------------------------------------------
# report model
# --------------------------------------------------------------------------

TAGS = {"RED": "RED FLAG", "REVIEW": "review", "SKIP": "skipped", "ERROR": "error", "INFO": "info", "ok": "ok"}

HTML_CSS = """
body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:24px auto;max-width:1100px;color:#222;padding:0 16px}
h1{margin:0 0 4px}.meta{color:#666;font-size:13px}
.cards{display:flex;gap:10px;margin:16px 0}.card{flex:1;border-radius:8px;padding:10px 14px;color:#fff}
.card b{display:block;font-size:26px}.c-RED{background:#c62828}.c-REVIEW{background:#ef8f00}
.c-SKIP{background:#757575}.c-ERROR{background:#6a1b9a}.c-ok{background:#2e7d32}
.verdict{padding:10px 14px;border-radius:8px;margin:8px 0 16px;font-weight:600}
.v-red{background:#fdecea;color:#b71c1c}.v-review{background:#fff4e0;color:#8a5300}.v-ok{background:#e8f5e9;color:#1b5e20}
details{border:1px solid #ddd;border-radius:8px;margin:8px 0;padding:6px 12px}summary{cursor:pointer;font-weight:600}
.badge{display:inline-block;min-width:64px;text-align:center;border-radius:4px;color:#fff;font-size:11px;padding:1px 6px;margin-right:6px}
.b-RED{background:#c62828}.b-REVIEW{background:#ef8f00}.b-SKIP{background:#757575}.b-ERROR{background:#6a1b9a}
.b-INFO{background:#1565c0}.b-ok{background:#2e7d32}
.entry{margin:6px 0}.entry pre{margin:2px 0 0 76px;white-space:pre-wrap;font-size:12px;color:#444}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left}
.small{color:#666;font-size:12px}
"""


class Report:
    def __init__(self, url, path, keep=False):
        self.url = url
        self.path = path
        self.keep = keep
        self.sections = []  # list of (title, [ (status, text) ])
        self.activity = []  # list of (title, [ plain-text lines ])
        self.time = _utcnow().isoformat(timespec="seconds")
        self._commits = None
        self._object_commits = {}
        match = re.fullmatch(
            r"(?:https?://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/]+?)(?:\.git)?/?",
            url,
        )
        self.web_url = "https://github.com/" + match.group(1) if match else None

    def add(self, title):
        self.sections.append([title, []])
        return self.sections[-1][1]

    def add_activity(self, title):
        self.activity.append([title, []])
        return self.activity[-1][1]

    def counts(self):
        return Counter(status for _, entries in self.sections for status, _ in entries)

    def commit_info(self, sha):
        if self._commits is None:
            self._commits = {}
            fmt = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%cI%x00%s"
            rc, output, _ = git(self.path, "--no-replace-objects", "log", "--all", "-z", "--format=" + fmt,
                                _timeout=BULK_TIMEOUT)
            if rc == 0:
                fields = output.split("\0")
                for offset in range(0, len(fields) - 7, 8):
                    commit, author, author_email, committer, committer_email, authored, committed, subject = fields[offset:offset + 8]
                    self._commits[commit] = {
                        "author": "%s <%s>" % (author, author_email),
                        "committer": "%s <%s>" % (committer, committer_email),
                        "authored": authored,
                        "committed": committed,
                        "subject": subject or "(no commit message)",
                    }
        return self._commits.get(sha)

    def commit_context(self, sha, label="Commit"):
        info = self.commit_info(sha)
        details = ["%s: %s" % (label, sha)]
        if info:
            details.extend([
                "Message: %s" % info["subject"],
                "Author: %s" % info["author"],
                "Committer: %s" % info["committer"],
                "Authored: %s; committed: %s" % (info["authored"], info["committed"]),
            ])
        else:
            details.append("Message/identity unavailable in this clone; no author or committer inferred.")
        if self.web_url:
            details.append("Inspect: %s/commit/%s" % (self.web_url, sha))
        else:
            details.append("Inspect in a retained clone (--keep): git show --format=fuller %s" % sha)
        return "\n".join(details)

    def object_context(self, sha):
        if self.commit_info(sha):
            return self.commit_context(sha, "Matching commit object")
        details = ["Object: %s (not assumed to be a commit ID)" % sha]
        if sha not in self._object_commits:
            rc, output, _ = git(self.path, "--no-replace-objects", "log", "--all", "-1",
                                "--find-object=" + sha, "--format=%H", _timeout=BULK_TIMEOUT)
            commits = output.splitlines() if rc == 0 else []
            self._object_commits[sha] = commits[0] if commits else None
        related = self._object_commits[sha]
        if related:
            details.append(self.commit_context(related, "Related change (may add or remove this object)"))
            details.append("This is one related change, not proof of who first introduced the content.")
        else:
            details.append("Related commit unavailable; no identity inferred from the object ID.")
        details.append("Inspect the object privately in a retained clone (--keep): git cat-file -p %s" % sha)
        return "\n".join(details)

    def summary_line(self):
        c = self.counts()
        return ("SUMMARY: %d red flag(s), %d review item(s), %d skipped check(s), %d error(s)."
                % (c["RED"], c["REVIEW"], c["SKIP"], c["ERROR"]))

    def render(self):
        w = 72
        out = ["=" * w, "GIT-FORENSICS SCAN",
               "url:   %s" % self.url,
               "clone: %s%s" % (self.path, "" if self.keep else " (removed after scan)"),
               "time:  %s UTC" % self.time,
               "=" * w, self.summary_line()]
        for title, entries in self.sections:
            for status, text in entries:
                if status == "RED":
                    out.append("  ! %s -- %s" % (title.split(" (")[0], text.splitlines()[0]))
        out.append("Every line is a lead to inspect, not proof of compromise.")
        out.append("No findings does not prove the repository is safe; read scope and coverage notes below.")
        out.append("=" * w)
        out.append("RED FLAG = priority review; review = a lead, often benign; ok = no hit in the stated scope.")
        out.append("skipped/error = incomplete coverage; info = context, not a finding.")
        out.append("Author and committer are recorded Git identities, not verified accounts or proof of who pushed.")
        for title, entries in self.sections:
            out.append("")
            out.append("# %s" % title)
            out.append("-" * w)
            if not entries:
                out.append("  (no findings recorded)")
            for status, text in entries:
                text_lines = text.splitlines() or [""]
                out.append("  [%-8s] %s" % (TAGS.get(status, status), text_lines[0]))
                out.extend("             " + line for line in text_lines[1:])
        if self.activity:
            out.append("")
            out.append("=" * w)
            out.append("RECENT ACTIVITY (informational, not a check)")
            out.append("=" * w)
            for title, entries in self.activity:
                out.append("")
                out.append("# %s" % title)
                out.append("-" * w)
                if not entries:
                    out.append("  (nothing)")
                for line in entries:
                    out.append("  %s" % line.replace("\n", "\n    "))
        return _redact("\n".join(out))

    def render_html(self):
        def esc(s):
            return html.escape(_redact(s))

        def entry(status, text):
            first, _, rest = text.partition("\n")
            body = "<pre>%s</pre>" % esc(rest) if rest else ""
            return '<div class="entry"><span class="badge b-%s">%s</span>%s%s</div>' % (
                status, TAGS.get(status, status), esc(first), body)

        c = self.counts()
        if c["RED"]:
            verdict = ("v-red", "%d red flag(s) need priority review." % c["RED"])
        elif c["REVIEW"] or c["ERROR"]:
            verdict = ("v-review", "No red flags; %d review item(s) and %d error(s) to look at." % (c["REVIEW"], c["ERROR"]))
        else:
            verdict = ("v-ok", "No red flags or review items in the stated scope (this is not proof of safety).")
        out = ["<!doctype html><html><head><meta charset='utf-8'><title>git-forensics: %s</title><style>%s</style></head><body>"
               % (esc(self.url), HTML_CSS),
               "<h1>Git-forensics scan</h1><div class='meta'>%s<br>clone: %s%s &middot; %s UTC</div>"
               % (esc(self.url), esc(self.path), "" if self.keep else " (removed after scan)", self.time),
               "<div class='cards'>"]
        for key, label in (("RED", "red flags"), ("REVIEW", "review"), ("ERROR", "errors"), ("SKIP", "skipped"), ("ok", "ok")):
            out.append("<div class='card c-%s'><b>%d</b>%s</div>" % (key, c[key], label))
        out.append("</div><div class='verdict %s'>%s</div>" % verdict)
        reds = [(t, s, x) for t, ents in self.sections for s, x in ents if s == "RED"]
        if reds:
            out.append("<h2>Red flags</h2>")
            out.extend(entry(s, "%s\n%s" % (x.split("\n")[0], "Check: " + t + "\n" + x.partition("\n")[2]))
                       for t, s, x in reds)
        out.append("<h2>Checks</h2><p class='small'>RED FLAG = priority review; review = a lead, often benign; "
                   "ok = no hit in the stated scope; skipped/error = incomplete coverage; info = context. "
                   "Identities are recorded Git metadata, not verified accounts.</p>")
        for title, entries in self.sections:
            sc = Counter(s for s, _ in entries)
            badges = "".join("<span class='badge b-%s'>%d %s</span>" % (k, sc[k], TAGS[k])
                             for k in ("RED", "REVIEW", "ERROR", "SKIP") if sc[k]) or "<span class='badge b-ok'>ok</span>"
            is_open = " open" if sc["RED"] or sc["ERROR"] else ""
            out.append("<details%s><summary>%s %s</summary>" % (is_open, esc(title), badges))
            out.extend(entry(s, x) for s, x in entries)
            out.append("</details>")
        if self.activity:
            out.append("<h2>Recent activity <span class='small'>(informational, not a check)</span></h2>")
            for title, entries in self.activity:
                out.append("<details><summary>%s <span class='small'>(%d)</span></summary>" % (esc(title), len(entries)))
                out.extend(entry("INFO", x) for x in entries)
                out.append("</details>")
        out.append("<p class='small'>Every line is a lead to inspect, not proof of compromise. "
                   "No findings does not prove the repository is safe.</p></body></html>")
        return "\n".join(out)


# --------------------------------------------------------------------------
# check 1: history rewrite
# --------------------------------------------------------------------------

def check_history_rewrite(repo, R):
    entries = R.add("1. History rewrite (filter-branch / refs/original)")
    entries.append(("INFO", "Backup refs can result from intentional history maintenance.\n"
                    "Review: confirm the rewrite was authorized and compare it with a trusted backup."))

    rc, out, _ = git(repo, "for-each-ref", "--format=%(refname) %(objectname)", "refs/original")
    if rc != 0:
        entries.append(("ERROR", "Could not list refs/original; history-rewrite check incomplete."))
    elif out.strip():
        for line in out.splitlines():
            ref, sha = line.split(" ", 1)
            entries.append(("RED", "History-rewrite backup ref present: %s\n%s" % (ref, R.commit_context(sha, "Backup target"))))
    else:
        entries.append(("ok", "No refs/original backup refs found in the clone; rewrites that left no such refs remain undetectable here."))


# --------------------------------------------------------------------------
# check 2: author impersonation
# --------------------------------------------------------------------------

HOMOGLYPHS = {
    "a": "аα", "c": "сϲ", "e": "е", "i": "іı", "o": "оο",
    "p": "р", "s": "ѕ", "x": "х", "y": "у", "n": "п",
    "m": "м", "k": "к", "h": "н", "l": "ӏ", "g": "ɡ", "t": "т",
}
HOMOGLYPH_CHARS = set("".join(HOMOGLYPHS.values()))


def looks_suspicious(localpart):
    return any(ch in HOMOGLYPH_CHARS for ch in localpart)


def check_author_impersonation(repo, R):
    entries = R.add("2. Author impersonation (homoglyph emails / outlier identities)")
    entries.append(("INFO", "Git names/emails are self-declared. International names, multiple addresses and author/committer differences can be legitimate.\n"
                    "Review: compare flagged identities and example commits with approved contributors and automation accounts."))

    rc, out, _ = git(repo, "log", "--all", "--format=%an%x09%ae%x09%cn%x09%ce%x09%H%x09%G?", _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not read commit identities; identity checks incomplete."))
        return
    if not out.strip():
        entries.append(("ok", "no commits"))
        return

    identities = Counter()
    email_domains = Counter()
    identity_examples = {}
    mismatches = []
    signature_records = []
    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 6:
            continue
        an, ae, cn, ce, sha, sig_result = parts[:6]
        signature_records.append((sha, sig_result))
        identities[(an, ae)] += 1
        identities[(cn, ce)] += 1
        email_domains[ae.split("@")[-1]] += 1
        email_domains[ce.split("@")[-1]] += 1
        identity_examples.setdefault((an, ae), sha)
        identity_examples.setdefault((cn, ce), sha)
        if (an, ae) != (cn, ce) and ce != "noreply@github.com":
            mismatches.append((sha, an, ae, cn, ce))

    for (name, email), count in identities.items():
        local = email.split("@")[0]
        if looks_suspicious(local):
            entries.append(("RED", "Lookalike Unicode character in email: %s <%s> (%d author/committer records).\n%s"
                            % (name, email, count, R.commit_context(identity_examples[(name, email)], "Example commit"))))
        if any(ord(c) > 127 for c in name):
            entries.append(("REVIEW", "Non-ASCII identity name: %r <%s>; often a normal international name.\n%s"
                            % (name, email, R.commit_context(identity_examples[(name, email)], "Example commit"))))

    if len(email_domains) > 1:
        dom = ", ".join("%s (%d)" % (d, c) for d, c in email_domains.most_common())
        entries.append(("REVIEW", "Multiple email domains in author/committer records: %s\n"
                        "Review: confirm personal, company and automation domains are expected." % dom))

    by_name = defaultdict(set)
    for (name, email), _ in identities.items():
        by_name[name].add(email)
    for name, emails in by_name.items():
        if len(emails) > 1:
            examples = [R.commit_context(identity_examples[(name, email)], "Example for " + email)
                        for email in sorted(emails)[:2]]
            entries.append(("REVIEW", "Identity %r used multiple emails: %s\n%s\n"
                            "Examples are limited to two addresses; verify whether these belong to the same contributor."
                            % (name, ", ".join(sorted(emails)), "\n".join(examples))))

    if mismatches:
        for sha, an, ae, cn, ce in mismatches[:10]:
            entries.append(("REVIEW", "Recorded author differs from recorded committer.\n%s\n"
                            "Meaning: this can be an accepted patch, rebase or automation; confirm the workflow is expected."
                            % R.commit_context(sha)))
        if len(mismatches) > 10:
            entries.append(("INFO", "Showing 10 examples; %d more author/committer differences are not displayed."
                            % (len(mismatches) - 10)))

    sig = Counter(result for _, result in signature_records)
    total = sum(sig.values())
    signed = sum(sig.get(result, 0) for result in ("G", "U", "B", "E", "X", "Y", "R"))
    if total:
        entries.append(("INFO", "Git reports signatures on %d/%d commits; signature presence alone does not establish identity." % (signed, total)))
        bad_commits = [sha for sha, result in signature_records if result == "B"]
        for sha in bad_commits[:10]:
            entries.append(("REVIEW", "Git reports a bad signature.\n%s\nReview: verify the signature and signer using your trusted key configuration."
                            % R.commit_context(sha)))
        if len(bad_commits) > 10:
            entries.append(("INFO", "%d additional bad-signature results are not displayed." % (len(bad_commits) - 10)))
        unverifiable = sum(sig.get(result, 0) for result in ("E", "U", "X", "Y", "R"))
        if unverifiable:
            entries.append(("INFO", "%d signature result(s) have verification, trust, expiry or revocation caveats; inspect with git log --show-signature." % unverifiable))


# --------------------------------------------------------------------------
# check 3: timestamp forgery
# --------------------------------------------------------------------------

def tz_from_iso(iso):
    m = re.search(r"([+-])(\d{2}):(\d{2})$", iso.strip())
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    return sign * (int(m.group(2)) * 60 + int(m.group(3)))


def check_timestamp_forgery(repo, R):
    entries = R.add("3. Timestamp forgery (future / pre-git / inverted dates / odd TZ)")
    entries.append(("INFO", "Dates and timezones are recorded metadata, not proof of tampering; rebases, clock errors and travel can explain anomalies.\n"
                    "Review: compare both recorded dates, parent history and the approved change timeline."))

    fmt = "%H%x09%at%x09%ct%x09%aI%x09%P"
    rc, out, _ = git(repo, "log", "--all", "--format=" + fmt, _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not read commit dates; timestamp checks incomplete."))
        return
    if not out.strip():
        entries.append(("ok", "no commits"))
        return

    now = int(_utcnow().timestamp())
    tz_counts = Counter()
    tz_examples = {}
    parent_of = {}
    commit_ts = {}

    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 5:
            continue
        sha, at_s, ct_s, adate_iso, parents = parts
        try:
            a = int(at_s)
            c = int(ct_s)
        except ValueError:
            continue
        commit_ts[sha] = c
        parent_of[sha] = parents.split()
        tz = tz_from_iso(adate_iso)
        if tz is not None:
            tz_counts[tz] += 1
            tz_examples.setdefault(tz, sha)

        if a > now + 86400:
            entries.append(("RED", "Author date is more than one day in the future: %s\n%s" % (adate_iso, R.commit_context(sha))))
        if a < 1104537600:
            entries.append(("RED", "Author date predates 2005: %s; imported older history may explain this.\n%s" % (adate_iso, R.commit_context(sha))))
        if c < a:
            entries.append(("RED", "Committer date is earlier than author date.\n" + R.commit_context(sha)))
        if a - c > 86400 * 2:
            entries.append(("REVIEW", "Author date is more than two days ahead of committer date.\n" + R.commit_context(sha)))

    for sha, c in commit_ts.items():
        for par in parent_of.get(sha, []):
            p_ts = commit_ts.get(par)
            if p_ts is not None and p_ts > c:
                entries.append(("REVIEW", "Committer date is earlier than the parent's committer date.\n%s\n%s"
                                % (R.commit_context(sha), R.commit_context(par, "Parent commit"))))

    total = sum(tz_counts.values())
    if total:
        rare = [tz for tz, n in tz_counts.items() if n <= max(1, total // 20)]
        for tz in rare:
            entries.append(("REVIEW", "Uncommon author timezone: UTC offset %+d minutes (%d/%d commits).\n%s"
                            % (tz, tz_counts[tz], total, R.commit_context(tz_examples[tz], "Example commit"))))
    if not any(status in ("RED", "REVIEW", "ERROR") for status, text in entries):
        entries.append(("ok", "No date-order, date-range or timezone-outlier rules matched the inspected history."))


# --------------------------------------------------------------------------
# check 4: replace refs
# --------------------------------------------------------------------------

def check_replace_refs(repo, R):
    entries = R.add("4. Replace refs (refs/replace history substitution)")
    entries.append(("INFO", "Replacement refs make Git substitute one object for another.\n"
                    "Review: confirm each replacement is authorized; inspect originals with git --no-replace-objects."))

    rc, out, _ = git(repo, "for-each-ref", "--format=%(refname) %(objectname)", "refs/replace")
    if rc != 0:
        entries.append(("ERROR", "Could not list replacement refs; replacement check incomplete."))
    elif out.strip():
        for ln in out.splitlines():
            ref, replacement = ln.split(" ", 1)
            entries.append(("RED", "Replacement ref: %s\nOriginal object: %s\nReplacement details:\n%s"
                            % (ref, ref.rsplit("/", 1)[-1], R.object_context(replacement))))
    else:
        entries.append(("ok", "checked for refs/replace refs that substitute one commit for another: none found"))


# --------------------------------------------------------------------------
# check 5: backdoor payloads
# --------------------------------------------------------------------------

PAYLOAD_PATTERNS = [
    ("curl-to-shell", re.compile(r"curl\s+[^|]*\|\s*(ba|z)?sh|wget\s+[^|]*\|\s*(ba|z)?sh|\|\s*sh\b", re.I)),
    ("reverse-shell", re.compile(r"/dev/tcp/|bash\s+-i\s*>|nc\s+-[a-z]*e\b|mkfifo", re.I)),
    ("base64-exec", re.compile(r"eval\s*\(\s*base64|eval\s+base64", re.I)),
    ("ci-secret-dump", re.compile(r"\bprintenv\b|\benv\s*\||\bset\s*\|", re.I)),
    ("chmod-plusx-download", re.compile(r"chmod\s+\+x.*(curl|wget|/tmp/)", re.I)),
    ("obfuscated", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|fromCharCode|atob\s*\(|String\.fromCharCode", re.I)),
]

WORKFLOW_PATTERNS = [
    ("pull_request_target", re.compile(r"\bpull_request_target\b"), "REVIEW"),
    ("mutable-action-ref", re.compile(r"uses:\s*['\"]?[^'\s]+@(main|master|v\d+)\b"), "REVIEW"),
    ("scheduled-trigger", re.compile(r"(?m)^[ \t]*(?:-\s*)?(schedule|cron)\s*:"), "REVIEW"),
    ("workflow-dispatch", re.compile(r"\bworkflow_dispatch\b"), "REVIEW"),
    ("broad-permissions", re.compile(r"permissions:\s*write-all|id-token:\s*write"), "REVIEW"),
]

WORKFLOW_REVIEW = {
    "pull_request_target": "Verify untrusted pull-request code cannot access secrets or privileged tokens.",
    "mutable-action-ref": "Verify the action source and version; consider pinning the approved commit SHA.",
    "scheduled-trigger": "Confirm the schedule, permissions and access to secrets are expected.",
    "workflow-dispatch": "Confirm who may trigger this workflow and what privileged operations it performs.",
    "broad-permissions": "Confirm each write/OIDC permission is required and constrained to trusted jobs.",
}


def check_backdoors(repo, R):
    entries = R.add("5. Suspicious command patterns (added-line scan)")
    entries.append(("INFO", "Pattern matches may be legitimate installers, scripts or test fixtures; this is not a malware verdict.\n"
                    "Merge commits are not diffed here; changes introduced only by a merge are covered by check 8.\n"
                    "Review: inspect the shown file/line and commit, especially command destinations, inputs and permissions."))

    rc, out, _ = git(repo, "rev-list", "--all", "--no-merges", "--count", _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not list commits; added-line scan not completed."))
        return
    total = int(out.strip()) if out.strip().isdigit() else 0
    if not total:
        entries.append(("ok", "no commits"))
        return

    hits = []
    sha = ""
    path = "<unknown path>"
    line_number = 0
    i = 0
    status = {}
    # one streamed `git log` instead of one `git show` per commit
    for ln in git_stream(repo, "log", "--all", "--no-merges", "--unified=0", "--no-color", "--no-ext-diff",
                         "--no-textconv", "--format=%x00%H", status=status):
        if ln.startswith("\x00"):
            sha = ln[1:]
            path = "<unknown path>"
            i += 1
            progress_bar(i, total, "commits")
        elif ln.startswith("+++ "):
            path = ln[4:]
            if path.startswith("b/"):
                path = path[2:]
        elif ln.startswith("@@ "):
            hunk = re.search(r"\+(\d+)", ln)
            line_number = int(hunk.group(1)) if hunk else 0
        elif ln.startswith("+"):
            body = ln[1:]
            for name, pat in PAYLOAD_PATTERNS:
                if pat.search(body):
                    hits.append((sha, name, path, line_number, _redact(body)[:160]))
                    break
            line_number += 1
    if i != total:
        progress_bar(total, total, "commits")

    if hits:
        seen = set()
        shown = 0
        for sha, name, path, line_number, body in hits:
            if (name, body) in seen:
                continue
            seen.add((name, body))
            entries.append(("REVIEW", "Pattern: %s\nLocation: %s:%d\nAdded line (excerpt): %s\n%s"
                            % (name, path, line_number, body, R.commit_context(sha))))
            shown += 1
            if shown >= 25:
                break
        if len(hits) > shown:
            entries.append(("INFO", "Showing %d distinct of %d matching added lines; duplicates and the rest are not displayed."
                            % (shown, len(hits))))
    else:
        entries.append(("ok", "No matches for %d command patterns in added lines of %d non-merge commits."
                        % (len(PAYLOAD_PATTERNS), i)))
    if status.get("rc") or i < total:
        entries.append(("ERROR", "Only %d/%d commit diffs were read (git exit %s); added-line coverage is incomplete."
                        % (i, total, status.get("rc"))))


# --------------------------------------------------------------------------
# check 6: secrets in history
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "RED"),
    ("github-pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "RED"),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "RED"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "RED"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "RED"),
    ("azure-storage-key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"), "RED"),
    ("azure-sas-token", re.compile(r"\?sv=\d{4}-\d{2}-\d{2}[^\"'\s]*[?&]sig=[A-Za-z0-9%_\-]{20,}"), "RED"),
    ("stripe-live", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"), "RED"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"), "REVIEW"),
    ("password-assign", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\b\s*[:=]\s*['\"](?P<value>[^'\"]{8,})['\"]"), "REVIEW"),
]

SECRET_REFERENCE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_.-]*:?\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|\$\{\{\s*(?:secrets|vars|env)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
)

MAX_BLOB = 1_000_000


def _mask(v):
    v = v.strip()
    if len(v) <= 4:
        return v[:1] + "***"
    return v[:3] + "***"


def _redact(text):
    for _, pattern, _ in SECRET_PATTERNS:
        text = pattern.sub(lambda match: _mask(match.group(0)), text)
    return text


def check_secrets(repo, R):
    entries = R.add("6. Secrets in history (values masked)")
    entries.append(("INFO", "Matches can include examples or test data; confirm privately whether the credential is real and exposed.\n"
                    "Review: if exposure is confirmed, follow credential rotation/revocation procedures. Never paste raw values.\n"
                    "Objects above the size limit are not scanned; encoded/compressed secrets may not match these text patterns."))

    rc, out, _ = git(repo, "rev-list", "--objects", "--all", _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not enumerate historical objects; secret scan not completed."))
        return
    paths = {}
    for ln in out.splitlines():
        sha, _, path = ln.partition(" ")
        if sha and sha not in paths:
            paths[sha] = path

    n_skipped = 0
    to_scan = []
    if paths:
        rc, info, _ = git(repo, "cat-file", "--batch-check",
                          _input="".join(s + "\n" for s in paths), _timeout=BULK_TIMEOUT)
        if rc != 0:
            entries.append(("ERROR", "Could not read object sizes; secret scan not completed."))
            return
        for ln in info.splitlines():
            parts = ln.split()
            # trees are binary listings; blobs, commit and tag messages can hold secrets
            if len(parts) != 3 or parts[1] == "tree":
                continue
            if int(parts[2]) > MAX_BLOB:
                n_skipped += 1
                continue
            to_scan.append(parts[0])

    findings = []
    n_read = 0
    n_references = 0
    for i, (sha, data) in enumerate(cat_file_batch(repo, to_scan), 1):
        progress_bar(i, len(to_scan), "objects")
        if data is None:
            continue
        n_read += 1
        content = data.decode("utf-8", errors="replace")
        for kind, pat, sev in SECRET_PATTERNS:
            for m in pat.finditer(content):
                if kind == "password-assign" and SECRET_REFERENCE.fullmatch(m.group("value").strip()):
                    n_references += 1
                    continue
                findings.append((sev, kind, paths.get(sha, ""), sha, m.group(0)))
                break

    if findings:
        findings.sort(key=lambda f: (0 if f[0] == "RED" else 1, f[1]))
        seen = set()
        shown = 0
        for sev, kind, path, sha, val in findings:
            key = (kind, path, sha)
            if key in seen:
                continue
            seen.add(key)
            where = path or "<object metadata; no file path>"
            entries.append((sev, "%s at %s\nMatched value (masked): %s\n%s"
                            % (kind, where, _mask(val), R.object_context(sha))))
            shown += 1
            if shown >= 30:
                if len(findings) > shown:
                    entries.append(("INFO", "Showing %d of %d secret-pattern matches; remaining matches are not displayed." % (shown, len(findings))))
                break
    else:
        entries.append(("ok", "No matches for %d secret patterns in %d readable Git objects at or below %d bytes."
                        % (len(SECRET_PATTERNS), n_read, MAX_BLOB)))

    if n_references:
        entries.append(("INFO", "Ignored %d password assignment(s) containing only variable/secret references, not literal values." % n_references))
    if n_skipped:
        entries.append(("SKIP", "%d object(s) larger than %d bytes were not scanned for secrets." % (n_skipped, MAX_BLOB)))
    if n_read < len(to_scan):
        entries.append(("ERROR", "%d object(s) could not be read; secret-scan coverage is incomplete." % (len(to_scan) - n_read)))


# --------------------------------------------------------------------------
# check 7: moved tags
# --------------------------------------------------------------------------

def check_moved_tags(repo, R):
    entries = R.add("7. Moved tags (orphaned tags)")
    entries.append(("INFO", "This checks current reachability, not historical tag movement; a fresh clone has no prior tag positions to compare.\n"
                    "Review: compare orphaned tags with approved releases, deleted branches and a trusted earlier snapshot."))
    rc, out, _ = git(repo, "for-each-ref", "--format=%(refname)", "refs/tags")
    if rc != 0:
        entries.append(("ERROR", "Could not list tags; tag-reachability check incomplete."))
        return
    tags = [tag for tag in out.splitlines() if tag.strip()]
    if not tags:
        entries.append(("ok", "no tags present, so nothing to check for orphaned tags"))
        return

    rc, out, _ = git(repo, "rev-list", "--branches", _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not list branch history; tag-reachability check incomplete."))
        return
    on_branches = set(out.split())

    # ^{commit} peels nested annotated tags; non-commit targets come back as "missing"
    rc, info, _ = git(repo, "cat-file", "--batch-check",
                      _input="".join(t + "^{commit}\n" for t in tags), _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not resolve tag targets; tag-reachability check incomplete."))
        return

    n_ok = 0
    for tag, ln in zip(tags, info.splitlines()):
        parts = ln.split()
        if len(parts) != 3 or parts[1] != "commit":
            entries.append(("SKIP", "Tag %s does not resolve to a commit; branch reachability is not applicable." % tag))
        elif parts[0] not in on_branches:
            entries.append(("RED", "Tag %s points to a commit reachable from no cloned branch.\n%s\n"
                            "Meaning: a deleted branch or retained release tag can also explain this; it does not prove the tag moved."
                            % (tag, R.commit_context(parts[0], "Tag target"))))
        else:
            n_ok += 1
    if n_ok:
        entries.append(("ok", "%d/%d tag(s) are reachable from a cloned branch (not orphaned)." % (n_ok, len(tags))))


# --------------------------------------------------------------------------
# check 8: evil merges
# --------------------------------------------------------------------------

def check_evil_merges(repo, R):
    entries = R.add("8. Merge review (overlapping changes / clean-merge comparison)")
    entries.append(("INFO", "Overlapping files can be normal merged work or conflict resolution, not evidence of injected changes.\n"
                    "Review: compare the merge with both parents and the approved pull request."))
    rc, out, _ = git(repo, "log", "--all", "--min-parents=2", "--format=%H %T %P", _timeout=BULK_TIMEOUT)
    if rc != 0:
        entries.append(("ERROR", "Could not list merge commits; merge checks were not completed."))
        return
    merges = []
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 4:
            merges.append(parts)
        elif len(parts) > 4:
            entries.append(("SKIP", "Clean-merge comparison supports exactly two parents; this commit has %d.\n%s"
                            % (len(parts) - 2, R.commit_context(parts[0], "Merge commit"))))
    if not merges:
        entries.append(("ok", "No two-parent merge commits found across the cloned refs; no merge trees to compare."))
        return

    progress("    %d merge(s): resolving parent trees" % len(merges))
    parents = sorted({p for m in merges for p in m[2:4]})
    rc, info, _ = git(repo, "cat-file", "--batch-check",
                      _input="".join(p + "^{tree}\n" for p in parents), _timeout=BULK_TIMEOUT)
    ptree = {}
    for p, ln in zip(parents, info.splitlines() if rc == 0 else []):
        parts = ln.split()
        if len(parts) == 3 and parts[1] == "tree":
            ptree[p] = parts[0]

    progress("    diffing merges against both parents")
    pairs = {(ptree[p], m[1]) for m in merges for p in m[2:4] if p in ptree}
    rc_diff, dout, _ = git(repo, "diff-tree", "--stdin", "-r", "--name-only",
                           _input="".join("%s %s\n" % pr for pr in pairs), _timeout=BULK_TIMEOUT)
    changed = defaultdict(set)
    key = None
    for ln in dout.splitlines() if rc_diff == 0 else []:
        m = re.fullmatch(r"([0-9a-f]{40,64}) ([0-9a-f]{40,64})", ln)
        if m:
            key = (m.group(1), m.group(2))
        elif key and ln:
            changed[key].add(ln)

    progress("    recomputing clean merges")
    clean_tree = {}
    conflicted = set()
    rc, mout, _ = git(repo, "merge-tree", "--write-tree", "--name-only", "--no-messages", "--stdin",
                      _input="".join("%s %s\n" % (m[2], m[3]) for m in merges), _timeout=BULK_TIMEOUT)
    records = [r.split("\0") for r in mout.split("\0\0") if r.strip("\0")] if rc == 0 else []
    if len(records) == len(merges):
        for m, rec in zip(merges, records):
            if len(rec) >= 2 and rec[0].strip() == "1":
                clean_tree[m[0]] = rec[1]
            else:
                conflicted.add(m[0])
    else:
        # git < 2.40 has no merge-tree --stdin
        for i, m in enumerate(merges, 1):
            progress_bar(i, len(merges), "merges")
            rc, mt, _ = git(repo, "merge-tree", "--write-tree", m[2], m[3])
            if rc == 0 and mt.strip():
                clean_tree[m[0]] = mt.split()[0]
            elif rc == 1:
                conflicted.add(m[0])

    n_ok = 0
    for sha, tree, p0, p1 in merges:
        context = R.commit_context(sha, "Merge commit") + "\nParents: %s, %s" % (p0, p1)
        if rc_diff != 0 or p0 not in ptree or p1 not in ptree:
            entries.append(("ERROR", "Could not compare the merge against both parents.\n" + context))
            continue
        inter = changed[(ptree[p0], tree)] & changed[(ptree[p1], tree)]
        if inter:
            entries.append(("REVIEW", "Files differ from both parents: %s\n%s\n"
                            "Meaning: overlapping changes, not necessarily malicious; inspect the intended merge/conflict resolution."
                            % (", ".join(sorted(inter)), context)))
        if sha in clean_tree:
            if clean_tree[sha] != tree:
                entries.append(("RED", "Recorded merge tree differs from Git's reconstructed clean merge.\n%s\n"
                                "Meaning: additional edits or a different merge strategy/tool may explain the difference.\n"
                                "Review: confirm all differences against the approved pull request; this is not proof of compromise."
                                % context))
            elif not inter:
                n_ok += 1
        elif sha in conflicted:
            entries.append(("SKIP", "Reconstructing this merge produced conflicts, so no clean-tree verdict is available.\n%s\n"
                            "Review: inspect the recorded conflict resolution manually." % context))
        else:
            entries.append(("ERROR", "Could not reconstruct a clean merge (needs git >= 2.38).\n" + context))
    if n_ok:
        entries.append(("ok", "%d/%d merge(s) match the reconstructed clean merge with no files differing from both parents."
                        % (n_ok, len(merges))))


# --------------------------------------------------------------------------
# check 9: CI / GitHub Actions workflows
# --------------------------------------------------------------------------

def check_workflows(repo, R, days):
    entries = R.add("9. CI / GitHub Actions workflows (definitions in the repo)")
    entries.append(("INFO", "Rules inspect workflow text on HEAD; triggers and permissions may be intentional, not evidence of abuse.\n"
                    "Commit context identifies the last change to the file, not necessarily the change that introduced a matched rule.\n"
                    "Recent workflow changes are informational; execution logs and secret access are not inspected."))
    rc, out, _ = git(repo, "ls-tree", "-r", "--name-only", "HEAD")
    if rc != 0:
        entries.append(("ERROR", "Could not list files on HEAD; workflow checks not completed."))
        return
    paths = [ln for ln in out.splitlines()
             if re.search(r"^\.github/workflows/.*\.(ya?ml)$", ln)]
    if not paths:
        entries.append(("ok", "no workflow files under .github/workflows on HEAD"))
    else:
        entries.append(("ok", "%d workflow file(s) present on HEAD" % len(paths)))

    for path in paths:
        rc, lg, _ = git(repo, "log", "-1", "--format=%H", "HEAD", "--", path)
        if rc == 0 and lg.strip():
            context = R.commit_context(lg.splitlines()[0], "Last file-changing commit")
        else:
            context = "Last file-changing commit unavailable; no identity inferred."
            entries.append(("ERROR", "Could not determine the last change to workflow %s." % path))
        rc, content, _ = git(repo, "cat-file", "-p", "HEAD:%s" % path)
        if rc != 0:
            entries.append(("ERROR", "Could not read workflow %s on HEAD; its contents were not checked." % path))
            continue
        findings = []
        for name, pat, sev in WORKFLOW_PATTERNS:
            for line_number, ln in enumerate(content.splitlines(), 1):
                if pat.search(ln):
                    findings.append((sev, "Workflow rule: %s\nLocation: %s:%d (HEAD)\nMatched line: %s\n%s\nReview: %s"
                                     % (name, path, line_number, _redact(ln.strip())[:160], context, WORKFLOW_REVIEW[name])))
        for name, pat in PAYLOAD_PATTERNS:
            for line_number, ln in enumerate(content.splitlines(), 1):
                if pat.search(ln):
                    findings.append(("REVIEW", "Command pattern: %s\nLocation: %s:%d (HEAD)\nMatched line: %s\n%s\n"
                                     "Review: confirm the command, destination and permissions match the approved workflow."
                                     % (name, path, line_number, _redact(ln.strip())[:160], context)))
        if findings:
            entries.extend(findings)
        else:
            entries.append(("ok", "No configured workflow/command patterns matched %s on HEAD.\n%s" % (path, context)))

    rc_all, out_all, _ = git(repo, "log", "--all", "--since=%d.days.ago" % days,
                             "--format=%H", "--", ".github/workflows")
    if rc_all != 0:
        entries.append(("ERROR", "Could not list recent workflow changes; recent-change context is incomplete."))
    elif out_all.strip():
        for sha in out_all.splitlines():
            entries.append(("INFO", "Workflow change in the last %d days (across cloned refs).\n%s"
                            % (days, R.commit_context(sha))))


# --------------------------------------------------------------------------
# recent-activity appendix
# --------------------------------------------------------------------------

def gather_branches(repo, R):
    ent = R.add_activity("Branches (ordered by tip commit date, newest first)")
    rc, out, _ = git(repo, "for-each-ref", "--sort=-committerdate",
                     "--format=%(objectname)%09%(refname:short)", "refs/heads")
    if rc != 0:
        ent.append("Unavailable: could not list branch tips; this is not evidence that no branches exist.")
    elif out.strip():
        for ln in out.splitlines():
            sha, branch = ln.split("\t", 1)
            ent.append("Branch: %s\n%s" % (branch, R.commit_context(sha, "Tip commit")))
    else:
        ent.append("no branches")


def gather_recent_commits(repo, R, days):
    ent = R.add_activity("Commits in the last %d days (filtered by committer date)" % days)
    rc, out, _ = git(repo, "log", "--all", "--since=%d.days.ago" % days,
                     "--format=%H")
    if rc != 0:
        ent.append("Unavailable: could not read recent commits; the activity window was not checked.")
    elif out.strip():
        for sha in out.splitlines():
            ent.append(R.commit_context(sha))
    else:
        ent.append("no commits in the last %d days" % days)


def gather_recent_authors(repo, R, days):
    ent = R.add_activity("Recorded authors and committers in the last %d days" % days)
    rc, out, _ = git(repo, "log", "--all", "--since=%d.days.ago" % days, "--format=%H")
    if rc != 0:
        ent.append("Unavailable: could not read recent identities; no list of active contributors could be established.")
    elif out.strip():
        authors = Counter()
        committers = Counter()
        missing = 0
        for sha in out.splitlines():
            info = R.commit_info(sha)
            if info is None:
                missing += 1
                continue
            authors[info["author"]] += 1
            committers[info["committer"]] += 1
        for identity in sorted(set(authors) | set(committers)):
            ent.append("%s: author of %d commit(s); committer of %d commit(s)"
                       % (identity, authors[identity], committers[identity]))
        if missing:
            ent.append("Unavailable metadata for %d recent commit(s); identity counts are incomplete." % missing)
    else:
        ent.append("no commits in the last %d days" % days)


def _github_get(url, api_path, ent, what):
    """GET a GitHub API path for a github.com repo URL; return parsed JSON or None (reason added to ent)."""
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    if not m:
        ent.append("skipped: not a github.com URL (%s requires GitHub API, not in git clone)" % what)
        return None
    owner, repo_name = m.group(1), m.group(2)
    headers, has_token = _github_headers()
    try:
        req = urllib.request.Request("https://api.github.com/repos/%s/%s/%s" % (owner, repo_name, api_path),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404 and not has_token:
            ent.append("HTTP 404: Private repo and no token found (run `gh auth login` or set GITHUB_TOKEN)")
        elif e.code == 403:
            ent.append("HTTP 403: Token lacks permission or needs SAML SSO authorization for %s" % owner)
        else:
            ent.append(f"could not fetch from GitHub API: {e}")
    except Exception as e:
        ent.append(f"could not fetch from GitHub API (offline / auth required): {e}")
    return None


def gather_workflow_runs(url, R, days):
    ent = R.add_activity("GitHub Actions runs in the last %d days (requires GitHub API)" % days)
    cutoff = (_utcnow() - _dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = _github_get(url, "actions/runs?created=>=%s&per_page=50" % cutoff, ent, "run history")
    if data is None:
        return

    runs = data.get("workflow_runs", [])
    total = data.get("total_count", len(runs))
    ent.append("Coverage: one GitHub API page, up to 50 runs; execution logs and runtime secret access are not inspected.")
    if total > len(runs):
        ent.append("Showing %d of %d matching runs; additional pages were not fetched." % (len(runs), total))
    if not runs:
        ent.append(f"No workflow runs returned for the last {days} days.")
        return

    for run in runs:
        created = run.get("created_at", "")
        name = run.get("name", "<unknown>")
        event = run.get("event", "")
        status = run.get("conclusion") or run.get("status", "")
        actor = (run.get("triggering_actor") or run.get("actor") or {}).get("login", "?")
        sha = run.get("head_sha", "")
        title = run.get("display_title") or name
        branch = run.get("head_branch") or "<unknown>"
        details = [f"{created}  [{status}]  {name} ({event})",
                   f"Run title: {title}", f"Triggered by GitHub account: {actor}; branch: {branch}"]
        if sha:
            details.append(R.commit_context(sha, "Run commit"))
        else:
            details.append("Run commit unavailable in the API response.")
        if run.get("html_url"):
            details.append("Inspect run: " + run["html_url"])
        ent.append("\n".join(details))


def gather_force_pushes(url, R, days):
    ent = R.add_activity("Force-pushes in the last %d days (requires GitHub API)" % days)
    activities = _github_get(url, "activity?activity_type=force_push&per_page=50", ent, "force-push history")
    if activities is None:
        return

    cutoff_dt = _utcnow() - _dt.timedelta(days=days)
    recent = []
    ent.append("Coverage: the most recent API page, up to 50 force-push events; this is not a complete audit log.")
    for act in activities:
        ts_str = act.get("timestamp", "")
        try:
            ts = _dt.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            if ts < cutoff_dt:
                continue
        except ValueError:
            pass
        actor = (act.get("actor") or {}).get("login", "?")
        ref = act.get("ref", "?")
        before = act.get("before") or ""
        after = act.get("after") or ""
        details = [f"{ts_str}  GitHub account {actor} force-pushed {ref}",
                   "Meaning: this may be an approved rebase/rewrite; compare with the agreed change history."]
        for label, sha in (("Previous tip", before), ("New tip", after)):
            if sha and set(sha) != {"0"}:
                details.append(R.commit_context(sha, label))
            else:
                details.append("%s: no commit ID available." % label)
        if act.get("compare_url"):
            details.append("Inspect comparison: " + act["compare_url"])
        recent.append("\n".join(details))

    if not recent:
        ent.append(f"No force-pushes in the last {days} days found in the fetched page; older/unreturned events are not ruled out.")
    else:
        ent.extend(recent)


# --------------------------------------------------------------------------
# targets, cloning, saving
# --------------------------------------------------------------------------

def is_repo(path):
    return os.path.exists(os.path.join(path, ".git")) or (
        os.path.isfile(os.path.join(path, "HEAD")) and os.path.isdir(os.path.join(path, "objects")))


def resolve_targets(targets):
    """Expand targets to a list of (label, url_or_None, local_path_or_None)."""
    out = []
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        p = os.path.abspath(os.path.expanduser(t))
        if os.path.isdir(p):
            repos = [p] if is_repo(p) else [os.path.join(p, d) for d in sorted(os.listdir(p))
                                            if os.path.isdir(os.path.join(p, d)) and is_repo(os.path.join(p, d))]
            if not repos:
                progress("no git repositories found in %s" % p)
            for r in repos:
                rc, origin, _ = git(r, "config", "--get", "remote.origin.url")
                out.append((r, origin.strip() if rc == 0 and origin.strip() else None, r))
        else:
            out.append((t, t, None))
    return out


def clone_from_url(url):
    dest = tempfile.mkdtemp(prefix="git-forensics-")
    # stderr is not captured so git's progress and any auth/SSO prompt stay visible
    cmd = ["git", "clone", "--mirror", "--progress", url, dest]
    try:
        p = subprocess.run(cmd, timeout=600)
    except subprocess.TimeoutExpired:
        print("clone timed out", file=sys.stderr)
        shutil.rmtree(dest, ignore_errors=True)
        return None
    except KeyboardInterrupt:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if p.returncode != 0:
        print("clone failed (exit %d; is access restored? SAML SSO?)" % p.returncode, file=sys.stderr)
        shutil.rmtree(dest, ignore_errors=True)
        return None
    return dest


def repo_name(url):
    name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1])
    name = name.rsplit(":", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-") or "repository"


def save_report(url, content, ext="txt", out_dir=".", stamp=None):
    stamp = stamp or _utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.abspath(os.path.join(out_dir, "%s.forensicreport.%s.%s" % (repo_name(url), stamp, ext)))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(content + "\n")
    return path


def write_index(results, out_dir, stamp):
    rows = []
    for label, counts, report_path, error in results:
        if error:
            rows.append("<tr><td>%s</td><td colspan='4' style='color:#6a1b9a'>%s</td></tr>"
                        % (html.escape(label), html.escape(error)))
            continue
        cls = "b-RED" if counts["RED"] else "b-REVIEW" if counts["REVIEW"] else "b-ok"
        rows.append("<tr><td><a href='%s'>%s</a></td><td><span class='badge %s'>%d</span></td><td>%d</td><td>%d</td><td>%d</td></tr>"
                    % (html.escape(urllib.parse.quote(os.path.basename(report_path))), html.escape(label), cls,
                       counts["RED"], counts["REVIEW"], counts["ERROR"], counts["SKIP"]))
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>git-forensics overview</title><style>%s</style></head><body>"
            "<h1>Git-forensics overview</h1><div class='meta'>%d repositor(y/ies) &middot; %s UTC</div>"
            "<table><tr><th>Repository</th><th>Red flags</th><th>Review</th><th>Errors</th><th>Skipped</th></tr>%s</table>"
            "<p class='small'>Every flag is a lead to inspect, not proof of compromise.</p></body></html>"
            % (HTML_CSS, len(results), _utcnow().isoformat(timespec="seconds"), "".join(rows)))
    return save_report("index", page, "html", out_dir, stamp)


def scan(repo, url, keep, days):
    R = Report(url, repo, keep=keep)
    steps = [
        ("history rewrite", lambda: check_history_rewrite(repo, R)),
        ("author impersonation", lambda: check_author_impersonation(repo, R)),
        ("timestamp forgery", lambda: check_timestamp_forgery(repo, R)),
        ("replace refs", lambda: check_replace_refs(repo, R)),
        ("suspicious commands", lambda: check_backdoors(repo, R)),
        ("secrets", lambda: check_secrets(repo, R)),
        ("moved tags", lambda: check_moved_tags(repo, R)),
        ("merges", lambda: check_evil_merges(repo, R)),
        ("workflows", lambda: check_workflows(repo, R, days)),
        ("branches", lambda: gather_branches(repo, R)),
        ("recent commits", lambda: gather_recent_commits(repo, R, days)),
        ("recent authors", lambda: gather_recent_authors(repo, R, days)),
        ("workflow runs", lambda: gather_workflow_runs(url, R, days)),
        ("force-pushes", lambda: gather_force_pushes(url, R, days)),
    ]
    for i, (label, step) in enumerate(steps, 1):
        progress("step %d/%d: %s" % (i, len(steps), label))
        step()
    return R


def main():
    ap = argparse.ArgumentParser(
        description="git-forensics scanner: scan repositories for red flags",
        fromfile_prefix_chars="@",
    )
    ap.add_argument("targets", nargs="+", metavar="target",
                    help="repository URL, local checkout, parent folder of checkouts, or @file with one target per line")
    ap.add_argument("--keep", action="store_true",
                    help="keep fresh mirror clones on disk for manual inspection (default: delete after the scan)")
    ap.add_argument("--local", action="store_true",
                    help="scan local checkouts as-is instead of re-cloning them from origin (faster, but may be stale)")
    ap.add_argument("--days", type=int, default=14,
                    help="activity window in days for the recent-activity appendix (default: 14)")
    ap.add_argument("--out", default=".", help="directory for the reports (default: current directory)")
    ap.add_argument("--print", action="store_true", dest="print_report", help="also print the text report to stdout")
    args = ap.parse_args()

    stamp = _utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
    targets = resolve_targets(args.targets)
    results = []
    exit_code = 0
    for n, (label, url, local) in enumerate(targets, 1):
        progress("[%d/%d] %s" % (n, len(targets), label))
        cloned = False
        if local and (args.local or not url):
            if not url:
                progress("    no origin remote; scanning the local checkout as-is")
            repo = local
        else:
            progress("cloning %s ..." % url)
            repo = clone_from_url(url)
            cloned = True
            if repo is None:
                results.append((label, None, None, "clone failed (no access / SAML SSO not authorized?)"))
                exit_code = 2
                continue
        try:
            R = scan(repo, url or local, keep=args.keep or not cloned, days=args.days)
            text = R.render()
            if args.print_report:
                print(text)
            try:
                txt_path = save_report(url or local, text, "txt", args.out, stamp)
                html_path = save_report(url or local, R.render_html(), "html", args.out, stamp)
            except OSError as error:
                print(text)
                print("Could not save the report; the complete report is printed above: %s" % error, file=sys.stderr)
                results.append((label, R.counts(), None, "report could not be saved"))
                exit_code = exit_code or 1
                continue
            results.append((label, R.counts(), html_path, None))
            print("%s\n  %s\n  html: %s\n  txt:  %s" % (label, R.summary_line(), html_path, txt_path))
        finally:
            if cloned and repo and not args.keep:
                shutil.rmtree(repo, ignore_errors=True)

    if len(targets) > 1:
        print("\nOverview: %s" % write_index(results, args.out, stamp))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
