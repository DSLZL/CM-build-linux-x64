#!/usr/bin/env python3
"""Trusted worker infrastructure; install in the builder, never run locally."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from record_run import require_hosted_linux

TARGET = "x86_64-unknown-linux-gnu"


def checked(value, pattern, label):
    if not isinstance(value, str) or not re.fullmatch(pattern, value) or "REPLACE" in value:
        raise RuntimeError("Missing or invalid " + label)
    return value


def api(path):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "CM-build-policy"}
    if os.environ.get("CM_POLICY_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["CM_POLICY_TOKEN"]
    request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def output(values):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in str(value) or "\r" in str(value):
                raise RuntimeError("Invalid multiline output")
            stream.write(key + "=" + str(value) + "\n")


def identities():
    require_hosted_linux()
    source = checked(os.environ.get("CM_SOURCE_REPOSITORY"), r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "fixed source repository")
    worker = checked(os.environ.get("CM_BUILDER_REPOSITORY"), r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "fixed builder repository")
    sha = checked(os.environ.get("CM_SOURCE_SHA"), r"[0-9a-f]{40}", "source SHA")
    workflow_sha = checked(os.environ.get("GITHUB_WORKFLOW_SHA"), r"[0-9a-f]{40}", "worker workflow SHA")
    request = checked(os.environ.get("CM_REQUEST_ID"), r"[A-Za-z0-9_.-]{1,128}", "request ID")
    if worker != os.environ.get("GITHUB_REPOSITORY") or worker == source:
        raise RuntimeError("Build must be an actual run in the distinct fixed builder repository")
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise RuntimeError("Only an actual worker workflow_dispatch is enabled")
    if os.environ.get("GITHUB_SHA") != workflow_sha:
        raise RuntimeError("Worker event SHA must match this worker workflow revision")
    return source, worker, sha, workflow_sha, request


def preflight():
    source, worker, sha, workflow_sha, request = identities()
    # These APIs run before any requested CM source is checked out or executed.
    source_info = api("repos/" + source)
    worker_info = api("repos/" + worker)
    if source_info.get("full_name") != source or worker_info.get("full_name") != worker:
        raise RuntimeError("Repository aliases or renames must be reviewed explicitly")
    if source_info.get("private") is not False:
        raise RuntimeError("Private CM source is not wired by this reference template")
    branch = checked(source_info.get("default_branch"), r"[^\r\n]+", "source default branch")
    worker_branch = checked(worker_info.get("default_branch"), r"[^\r\n]+", "worker default branch")
    if os.environ.get("GITHUB_REF") != "refs/heads/" + worker_branch:
        raise RuntimeError("The worker dispatch must use its reviewed default branch")
    worker_head = api("repos/" + worker + "/commits/" + urllib.parse.quote(worker_branch, safe=""))["sha"]
    if worker_head != workflow_sha:
        raise RuntimeError("Worker default branch moved; dispatch again from its current reviewed revision")
    resolved = api("repos/" + source + "/commits/" + sha)
    if resolved.get("sha") != sha:
        raise RuntimeError("Exact requested CM source SHA was not found in the fixed source repository")
    source_head = api("repos/" + source + "/commits/" + urllib.parse.quote(branch, safe=""))["sha"]
    mode = "write" if sha == source_head else "read"
    record = {"source_repository": source, "source_sha": sha, "source_default_branch": branch,
              "observed_source_default_sha": source_head, "builder_repository": worker,
              "workflow_sha": workflow_sha, "worker_default_branch": worker_branch,
              "request_id": request, "target": TARGET, "cache_mode": mode}
    Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json").write_text(json.dumps(record, indent=2) + "\n")
    output({**record, "source_default_sha_verified": "true" if mode == "write" else "false"})
    print(json.dumps(record, indent=2))


def verify_checkout():
    source, worker, sha, workflow_sha, request = identities()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=os.environ["CM_SOURCE_DIR"], text=True).strip()
    if actual != sha:
        raise RuntimeError("Checked-out CM source differs from requested exact source SHA")
    mode = os.environ.get("CM_CACHE_MODE")
    if mode not in {"read", "write"} or os.environ.get("ACTIONS_CACHE_MODE") != mode:
        raise RuntimeError("Required platform-enforced cache token mode is unavailable or mismatched")
    if mode == "write":
        # Recheck trust in this separate job, before requested source code executes.
        source_info = api("repos/" + source)
        current = api("repos/" + source + "/commits/" + urllib.parse.quote(source_info["default_branch"], safe=""))["sha"]
        if source_info.get("private") is not False or current != sha:
            raise RuntimeError("Source default branch changed; retry the dispatch to recalculate cache authority")
    print(json.dumps({"source_repository": source, "source_sha": actual, "repository": worker,
                      "workflow_sha": workflow_sha, "cache_repository": worker, "cache_mode": mode,
                      "request_id": request, "target": TARGET}, indent=2))


def receipt():
    source, worker, sha, workflow_sha, request = identities()
    artifact_id = int(os.environ["CM_ARTIFACT_ID"])
    if artifact_id <= 0:
        raise RuntimeError("Actual upload artifact ID is required")
    digest = os.environ["CM_ARTIFACT_DIGEST"].removeprefix("sha256:")
    checked(digest, r"[0-9a-f]{64}", "actual upload artifact digest")
    artifact_name = "cm-linux-x64-task-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    actual = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    remote_digest = str(actual.get("digest", "")).removeprefix("sha256:")
    if actual.get("name") != artifact_name or remote_digest != digest or actual.get("expired") is not False:
        raise RuntimeError("Uploaded artifact differs from its GitHub artifact record")
    if actual.get("workflow_run", {}).get("id") != int(os.environ["GITHUB_RUN_ID"]):
        raise RuntimeError("Artifact belongs to a different worker run")
    ci = {"provider": "github_actions", "repository": worker, "source_repository": source,
          "head_sha": sha, "source_sha": sha, "workflow_sha": workflow_sha,
          "execution_role": "platform_builder", "cache_repository": worker, "request_id": request,
          "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
          "run_url": "https://github.com/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
          "workflow": ".github/workflows/build.yml", "job": os.environ["CM_BUILD_JOB"],
          "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": "X64",
          "target": TARGET, "conclusion": None, "artifact_name": artifact_name,
          "artifact_id": artifact_id, "artifact_sha256": digest}
    out = Path(os.environ["RUNNER_TEMP"], "cm-worker-receipt")
    out.mkdir(exist_ok=True)
    (out / "worker-receipt.json").write_text(json.dumps({"schema_version": 1, "ci": ci,
        "note": "Artifact identity verified; final workflow conclusion must be fetched after this run completes."}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        {"preflight": preflight, "verify-checkout": verify_checkout, "receipt": receipt}[sys.argv[1]]()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM worker blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
