#!/usr/bin/env python3
"""Trusted worker infrastructure; install in the builder, never run locally."""
import json
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
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
    config_record = api("repos/" + source + "/contents/.github/cm-ci.json?ref=" + sha)
    config = json.loads(base64.b64decode(config_record["content"]))
    consumer_required = "true" if config.get("task_id") in ("CM-P04", "CM-M01", "CM-M02", "CM-M03", "CM-M04") else "false"
    record = {"source_repository": source, "source_sha": sha, "source_default_branch": branch,
              "observed_source_default_sha": source_head, "builder_repository": worker,
              "workflow_sha": workflow_sha, "worker_default_branch": worker_branch,
              "request_id": request, "target": TARGET, "cache_mode": mode, "consumer_required": consumer_required}
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


def verify_consumer():
    source, worker, sha, workflow_sha, request = identities()
    if os.environ.get("CM_CACHE_MODE") != "none" or os.environ.get("ACTIONS_CACHE_MODE") != "none":
        raise RuntimeError("Actual consumer cache authority must be none")
    artifact_id = int(os.environ["CM_INPUT_ARTIFACT_ID"])
    digest = checked(os.environ["CM_INPUT_ARTIFACT_DIGEST"].removeprefix("sha256:"), r"[0-9a-f]{64}", "input artifact digest")
    artifact = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    expected_name = "cm-linux-x64-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    artifact_binding(artifact, artifact_id, expected_name, digest, int(os.environ["GITHUB_RUN_ID"]))
    output({"input_artifact_name": expected_name})
    path = Path(os.environ["CM_CI_LOG_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    (path / "consumer-input-artifact.json").write_text(json.dumps({"artifact": artifact, "source_sha": sha,
        "workflow_sha": workflow_sha, "source_repository": source, "cache_mode": "none", "request_id": request}, indent=2) + "\n")


def artifact_binding(record, artifact_id, name, digest, run_id):
    checked(digest, r"[0-9a-f]{64}", "artifact digest")
    if (artifact_id <= 0 or record.get("id") != artifact_id or record.get("name") != name
        or record.get("expired") is not False or str(record.get("digest", "")).removeprefix("sha256:") != digest
        or record.get("workflow_run", {}).get("id") != run_id):
        raise RuntimeError("Exact same-run artifact binding failed")
    return {"artifact_id": artifact_id, "artifact_name": name, "artifact_sha256": digest}


def successful_job(jobs, name):
    matches = [job for job in jobs if job.get("name") == name]
    if (len(matches) != 1 or matches[0].get("conclusion") != "success"
        or type(matches[0].get("id")) is not int or matches[0]["id"] <= 0):
        raise RuntimeError("Missing, skipped, ambiguous or failed actual job: " + name)
    return {"job": name, "job_id": matches[0]["id"], "job_conclusion": "success"}


def receipt_jobs(path, names):
    # A dependent job can start before its predecessor is visible as completed in the API.
    for attempt in range(12):
        jobs = api(path)["jobs"]
        pending = any(not any(job.get("name") == name and job.get("status") == "completed"
                              for job in jobs) for name in names)
        if not pending:
            for name in names:
                successful_job(jobs, name)
            return jobs
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError("Required receipt jobs did not become completed within 55 seconds")


def archive_members(members, root):
    seen = set()
    for member in members:
        path = Path(member.name)
        if (path.is_absolute() or ".." in path.parts or "\\" in member.name or not path.parts
            or path.parts[0] != root or member.name in seen
            or not (member.isfile() or member.isdir() or member.issym() or member.islnk())
            or member.mode & ~0o777):
            raise RuntimeError("Unexpected consumer archive member")
        seen.add(member.name)
        if member.issym() or member.islnk():
            target = Path(member.linkname)
            resolved = Path(os.path.normpath(str(path.parent / target if member.issym() else target)))
            if (target.is_absolute() or "\\" in member.linkname or not resolved.parts
                or resolved.parts[0] != root or ".." in resolved.parts):
                raise RuntimeError("Consumer archive link escapes its input root: " + repr((member.name, member.linkname)))


def extract_archive(archive, destination):
    if destination.exists():
        raise RuntimeError("Consumer destination must start empty")
    destination.parent.mkdir(parents=True, exist_ok=True)
    archive_members(archive.getmembers(), destination.name)
    archive.extractall(destination.parent, filter="data")


def extract_consumer():
    identities()
    destination = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    with tarfile.open(Path(os.environ["CM_CONSUMER_TRANSFER_DIR"]) / "runtime-inputs.tar", "r:") as archive:
        extract_archive(archive, destination)


def self_check():
    require_hosted_linux()
    from unittest.mock import patch

    record = {"id": 1, "name": "input", "digest": "sha256:" + "a" * 64,
              "expired": False, "workflow_run": {"id": 2}}
    assert artifact_binding(record, 1, "input", "a" * 64, 2)["artifact_id"] == 1
    assert successful_job([{"id": 3, "name": "consumer", "conclusion": "success"}], "consumer")["job_id"] == 3
    ready = {"jobs": [{"id": 3, "name": "producer", "status": "completed", "conclusion": "success"},
                      {"id": 4, "name": "consumer", "status": "completed", "conclusion": "success"}]}
    pending = {"jobs": [ready["jobs"][0], {"id": 4, "name": "consumer", "status": "in_progress", "conclusion": None}]}
    with patch(__name__ + ".api", side_effect=[{"jobs": []}, pending, ready]) as fetch, patch("time.sleep") as pause:
        assert receipt_jobs("jobs", ["producer", "consumer"]) == ready["jobs"]
        assert fetch.call_count == 3 and pause.call_count == 2
    with patch(__name__ + ".api", return_value=pending) as fetch, patch("time.sleep") as pause:
        try:
            receipt_jobs("jobs", ["producer", "consumer"])
        except RuntimeError:
            pass
        else:
            raise AssertionError("Receipt accepted a consumer that never completed")
        assert fetch.call_count == 12 and pause.call_count == 11
    invalid = [lambda: artifact_binding(record, 2, "input", "a" * 64, 2),
               lambda: artifact_binding(record, 1, "wrong", "a" * 64, 2),
               lambda: artifact_binding(record, 1, "input", "b" * 64, 2),
               lambda: artifact_binding(record, 1, "input", "a" * 64, 9)]
    for conclusion in ("skipped", "failure", None):
        invalid.append(lambda conclusion=conclusion: successful_job([{"id": 3, "name": "consumer", "conclusion": conclusion}], "consumer"))
    invalid.extend([lambda: successful_job([], "consumer"),
                    lambda: successful_job([{"id": 1, "name": "consumer", "conclusion": "success"}] * 2, "consumer")])
    for name, kind, link in (("../escape", tarfile.REGTYPE, ""), ("runtime-inputs/socket", tarfile.FIFOTYPE, ""),
                             ("runtime-inputs/link", tarfile.SYMTYPE, "../../outside"),
                             ("runtime-inputs/alias", tarfile.SYMTYPE, "/tmp/original-codex"),
                             ("runtime-inputs/link", tarfile.LNKTYPE, "/etc/passwd")):
        member = tarfile.TarInfo(name)
        member.type, member.linkname = kind, link
        invalid.append(lambda member=member: archive_members([member], "runtime-inputs"))
    for check in invalid:
        try:
            check()
        except RuntimeError:
            continue
        raise AssertionError("Consumer trust boundary accepted an invalid case")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        (source / "cli").write_bytes(b"runtime-only")
        (source / "cli").chmod(0o755)
        (source / "alias").symlink_to("cli")
        (source / "nested").mkdir()
        (source / "nested/alias").symlink_to("../cli")
        os.link(source / "cli", source / "hardlink")
        archive_path = root / "input.tar"
        with tarfile.open(archive_path, "w") as archive:
            archive.add(source, arcname="runtime-inputs")
        destination = root / "extracted/runtime-inputs"
        with tarfile.open(archive_path, "r:") as archive:
            extract_archive(archive, destination)
        assert (destination / "cli").read_bytes() == b"runtime-only"
        assert (destination / "cli").stat().st_mode & 0o777 == 0o755
        assert (destination / "alias").is_symlink() and (destination / "alias").read_bytes() == b"runtime-only"
        assert (destination / "nested/alias").is_symlink() and (destination / "nested/alias").read_bytes() == b"runtime-only"
        assert (destination / "hardlink").samefile(destination / "cli")


def receipt():
    source, worker, sha, workflow_sha, request = identities()
    artifact_id = int(os.environ["CM_ARTIFACT_ID"])
    if artifact_id <= 0:
        raise RuntimeError("Actual upload artifact ID is required")
    digest = os.environ["CM_ARTIFACT_DIGEST"].removeprefix("sha256:")
    checked(digest, r"[0-9a-f]{64}", "actual upload artifact digest")
    artifact_name = "cm-linux-x64-task-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    actual = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    artifact_binding(actual, artifact_id, artifact_name, digest, int(os.environ["GITHUB_RUN_ID"]))
    names = [os.environ["CM_BUILD_JOB"]]
    if os.environ.get("CM_CONSUMER_REQUIRED") == "true":
        names.append("runtime-consumer")
    jobs = receipt_jobs("repos/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", names)
    producer_job = successful_job(jobs, os.environ["CM_BUILD_JOB"])
    ci = {"provider": "github_actions", "repository": worker, "source_repository": source,
          "head_sha": sha, "source_sha": sha, "workflow_sha": workflow_sha,
          "execution_role": "platform_builder", "cache_repository": worker, "request_id": request,
          "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
          "run_url": "https://github.com/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
          "workflow": ".github/workflows/build.yml", "job": os.environ["CM_BUILD_JOB"],
          "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": "X64",
          "target": TARGET, "conclusion": None, "artifact_name": artifact_name,
          "artifact_id": artifact_id, "artifact_sha256": digest, **producer_job}
    consumer = None
    if os.environ.get("CM_CONSUMER_REQUIRED") == "true":
        consumer_id = int(os.environ["CM_CONSUMER_ARTIFACT_ID"])
        consumer_digest = checked(os.environ["CM_CONSUMER_ARTIFACT_DIGEST"].removeprefix("sha256:"), r"[0-9a-f]{64}", "consumer artifact digest")
        consumer_name = "cm-linux-x64-consumer-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        record = api("repos/" + worker + "/actions/artifacts/" + str(consumer_id))
        artifact_binding(record, consumer_id, consumer_name, consumer_digest, int(os.environ["GITHUB_RUN_ID"]))
        actual_job = successful_job(jobs, "runtime-consumer")
        input_id = int(os.environ["CM_INPUT_ARTIFACT_ID"])
        input_digest = os.environ["CM_INPUT_ARTIFACT_DIGEST"].removeprefix("sha256:")
        input_name = "cm-linux-x64-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        input_record = api("repos/" + worker + "/actions/artifacts/" + str(input_id))
        inputs = artifact_binding(input_record, input_id, input_name, input_digest, int(os.environ["GITHUB_RUN_ID"]))
        consumer = {"execution_role": "runtime_consumer", "cache_mode": "none", "job": "runtime-consumer",
            **actual_job, "producer_job_id": producer_job["job_id"], "input_artifact": inputs,
            "artifact_id": consumer_id, "artifact_name": consumer_name,
            "artifact_sha256": consumer_digest, "source_sha": sha, "workflow_sha": workflow_sha,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": request}
    out = Path(os.environ["RUNNER_TEMP"], "cm-worker-receipt")
    out.mkdir(exist_ok=True)
    (out / "worker-receipt.json").write_text(json.dumps({"schema_version": 1, "ci": ci, "consumer": consumer,
        "note": "Artifact identity verified; final workflow conclusion must be fetched after this run completes."}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        {"self-check": self_check, "preflight": preflight, "verify-checkout": verify_checkout, "verify-consumer": verify_consumer,
         "extract-consumer": extract_consumer, "receipt": receipt}[sys.argv[1]]()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM worker blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
