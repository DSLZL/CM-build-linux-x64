#!/usr/bin/env python3
"""Trusted worker infrastructure; install in the builder, never run locally."""
import json
import base64
import hashlib
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
import zipfile
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


def parse_origin(value):
    if not isinstance(value, dict) or set(value) != {"run_id", "run_attempt", "source_sha", "workflow_sha", "request_id",
        *{prefix + suffix for prefix in ("input", "consumer", "receipt") for suffix in ("_artifact_id", "_artifact_sha256")}}:
        raise RuntimeError("Expected an exact qualification origin record")
    for key in ("run_id", "run_attempt", "input_artifact_id", "consumer_artifact_id", "receipt_artifact_id"):
        if type(value[key]) is not int or value[key] <= 0:
            raise RuntimeError("Invalid numeric qualification origin field")
    for key in ("source_sha", "workflow_sha"):
        checked(value[key], r"[0-9a-f]{40}", "qualification revision")
    for prefix in ("input", "consumer", "receipt"):
        checked(value[prefix + "_artifact_sha256"], r"[0-9a-f]{64}", "qualification artifact digest")
    checked(value["request_id"], r"[A-Za-z0-9_.-]{1,128}", "qualification request")
    return value


def build_request():
    kind = os.environ.get("CM_BUILD_KIND", "qualification")
    raw = os.environ.get("CM_HOST_ORIGIN", "")
    if kind not in ("qualification", "mod-only") or (kind == "qualification" and raw):
        raise RuntimeError("Unsupported build kind or unexpected Host origin")
    if kind == "qualification":
        return kind, None
    if not raw or len(raw) > 4096:
        raise RuntimeError("Mod-only requires an explicit bounded qualification origin")
    try:
        origin = json.loads(raw)
    except ValueError as error:
        raise RuntimeError("Invalid qualification origin JSON") from error
    return kind, parse_origin(origin)


def verify_origin(origin, source, worker, workflow_sha):
    parse_origin(origin)
    path = "repos/" + worker + "/actions/runs/" + str(origin["run_id"])
    run = api(path)
    if (run.get("id") != origin["run_id"] or run.get("run_attempt") != origin["run_attempt"]
        or run.get("status") != "completed" or run.get("conclusion") != "success"
        or run.get("head_sha") != origin["workflow_sha"] or run.get("event") != "workflow_dispatch"
        or run.get("repository", {}).get("full_name") != worker
        or run.get("path") != ".github/workflows/build.yml"
        or run.get("display_title") != "CM Linux x64 / " + origin["request_id"]):
        raise RuntimeError("Host origin is not the exact successful qualification run/attempt")
    for repository, base, head in ((worker, origin["workflow_sha"], workflow_sha),
                                   (source, origin["source_sha"], os.environ["CM_SOURCE_SHA"])):
        if api("repos/" + repository + "/compare/" + base + "..." + head).get("status") not in ("ahead", "identical"):
            raise RuntimeError("Qualification origin must belong to the reviewed source/worker ancestry")
    jobs = api(path + "/attempts/" + str(origin["run_attempt"]) + "/jobs?per_page=100")["jobs"]
    producers = [row for row in jobs if row.get("name") in ("build-read / linux-x64", "build-write / linux-x64")
        and row.get("conclusion") == "success"]
    if len(producers) != 1:
        raise RuntimeError("Qualification requires one successful actual producer")
    for name in ("preflight", producers[0]["name"], "runtime-consumer", "receipt"):
        successful_job(jobs, name)
    artifacts = {}
    for prefix, name in (("input", "cm-linux-x64-runtime-inputs-"),
                         ("consumer", "cm-linux-x64-consumer-artifacts-"), ("receipt", "cm-build-receipt-")):
        record = api("repos/" + worker + "/actions/artifacts/" + str(origin[prefix + "_artifact_id"]))
        # A reused input is bound to its original producer after the exact qualification receipt is verified.
        if prefix != "input" or record.get("workflow_run", {}).get("id") == origin["run_id"]:
            artifact_binding(record, origin[prefix + "_artifact_id"],
                name + origin["request_id"] + "-" + str(origin["run_attempt"]),
                origin[prefix + "_artifact_sha256"], origin["run_id"])
        elif record.get("expired") is not False or record.get("id") != origin["input_artifact_id"] or record.get("digest") != "sha256:" + origin["input_artifact_sha256"]:
            raise RuntimeError("Reused qualification input artifact changed or expired")
        artifacts[prefix] = record
    return {"run": run, "jobs": jobs, "artifacts": artifacts}


def download_origin_archive(worker, record, destination):
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, url):
            if not url.startswith("https://"):
                raise RuntimeError("Artifact redirect must remain HTTPS")
            redirected = super().redirect_request(request, fp, code, message, headers, url)
            redirected.remove_header("Authorization")
            return redirected
    request = urllib.request.Request("https://api.github.com/repos/" + worker + "/actions/artifacts/" + str(record["id"]) + "/zip",
        headers={"Authorization": "Bearer " + os.environ["CM_POLICY_TOKEN"], "User-Agent": "CM-build-policy"})
    digest = hashlib.sha256()
    started = heartbeat = time.monotonic()
    size = 0
    with urllib.request.build_opener(Redirect()).open(request, timeout=60) as response, destination.open("xb") as stream:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 4 * 1024 ** 3:
                raise RuntimeError("Oversized qualification artifact")
            digest.update(chunk)
            stream.write(chunk)
            if time.monotonic() - heartbeat >= 30:
                print(json.dumps({"stage": "restore-qualified-origin", "status": "running",
                    "bytes": size, "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
                heartbeat = time.monotonic()
    if "sha256:" + digest.hexdigest() != record["digest"]:
        raise RuntimeError("Downloaded qualification artifact digest differs from GitHub metadata")
    return zipfile.ZipFile(destination)


def archive_json(archive, name):
    entries = [entry for entry in archive.infolist() if entry.filename == name]
    if len(entries) != 1 or entries[0].file_size > 16 * 1024 * 1024 or entries[0].is_dir():
        raise RuntimeError("Missing, duplicate or oversized qualification JSON")
    return json.loads(archive.read(entries[0]))


def qualification_receipt(receipt, origin, jobs, source, worker):
    ci = receipt["ci"]
    if ci.get("job") not in ("build-read / linux-x64", "build-write / linux-x64"):
        raise RuntimeError("Qualification receipt has no actual producer job")
    expected = {"provider": "github_actions", "source_repository": source, "repository": worker,
        "head_sha": origin["source_sha"], "source_sha": origin["source_sha"],
        "workflow_sha": origin["workflow_sha"], "run_id": origin["run_id"], "run_attempt": origin["run_attempt"],
        "request_id": origin["request_id"], "build_kind": "qualification", "execution_role": "platform_builder",
        "cache_repository": worker, "workflow": ".github/workflows/build.yml", "target": TARGET,
        "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": "X64",
        **successful_job(jobs, ci["job"])}
    if any(ci.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Qualification receipt differs from exact origin or actual producer")
    consumer = receipt["consumer"]
    expected_consumer = {"execution_role": "runtime_consumer", "cache_mode": "none",
        **successful_job(jobs, "runtime-consumer"), "producer_job_id": ci["job_id"],
        **{key: expected[key] for key in ("source_sha", "workflow_sha", "run_id", "run_attempt", "request_id")}}
    if (any(consumer.get(key) != value for key, value in expected_consumer.items())
        or consumer["artifact_id"] != origin["consumer_artifact_id"]
        or consumer["artifact_sha256"] != origin["consumer_artifact_sha256"]
        or consumer["input_artifact"]["artifact_id"] != origin["input_artifact_id"]
        or consumer["input_artifact"]["artifact_sha256"] != origin["input_artifact_sha256"]):
        raise RuntimeError("Qualification receipt does not bind the exact consumer job and artifacts")
    production = ci.get("production_origin")
    if production:
        from retry import verify_production_origin
        records = verify_production_origin(production, worker=worker, fetch=api)
        if (consumer.get("production_origin") != production
                or production["input_artifact"]["id"] != origin["input_artifact_id"]
                or production["input_artifact"]["digest"] != "sha256:" + origin["input_artifact_sha256"]
                or production["product_artifact"]["id"] != ci["artifact_id"]
                or production["product_artifact"]["digest"] != "sha256:" + ci["artifact_sha256"]):
            raise RuntimeError("Qualification receipt has a different original producer")
        validation = consumer.get("validation_artifact") or {}
        artifact_binding(api("repos/" + worker + "/actions/artifacts/" + str(validation["artifact_id"])),
            validation["artifact_id"], "cm-linux-x64-validation-inputs-" + origin["request_id"] + "-" + str(origin["run_attempt"]),
            validation["artifact_sha256"], origin["run_id"])
        assert records["input_artifact"]["id"] == origin["input_artifact_id"]
    else:
        record = api("repos/" + worker + "/actions/artifacts/" + str(origin["input_artifact_id"]))
        artifact_binding(record, origin["input_artifact_id"], "cm-linux-x64-runtime-inputs-" + origin["request_id"] + "-" + str(origin["run_attempt"]),
                         origin["input_artifact_sha256"], origin["run_id"])
    return ci


def restore_origin():
    source, worker, sha, workflow_sha, request = identities()
    kind, origin = build_request()
    if kind != "mod-only":
        raise RuntimeError("Origin restore is only available to explicit Mod-only requests")
    remote = verify_origin(origin, source, worker, workflow_sha)
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-host-origin"
    directory.mkdir()
    with download_origin_archive(worker, remote["artifacts"]["receipt"], directory / "receipt.zip") as archive:
        receipt = archive_json(archive, "worker-receipt.json")
    ci = qualification_receipt(receipt, origin, remote["jobs"], source, worker)
    with download_origin_archive(worker, remote["artifacts"]["input"], directory / "input.zip") as archive:
        if archive.namelist() != ["runtime-inputs.tar"]:
            raise RuntimeError("Unexpected qualification input archive")
        with archive.open("runtime-inputs.tar") as stream, (directory / "runtime-inputs.tar").open("xb") as output_stream:
            import shutil
            shutil.copyfileobj(stream, output_stream)
    destination = directory / "runtime-inputs"
    with tarfile.open(directory / "runtime-inputs.tar", "r:") as archive:
        extract_archive(archive, destination)
    producer = json.loads((destination / "producer.json").read_text())
    expected_provenance = {"CM_SOURCE_REPOSITORY": source, "CM_SOURCE_SHA": origin["source_sha"],
        "GITHUB_REPOSITORY": worker, "GITHUB_WORKFLOW_SHA": origin["workflow_sha"],
        "GITHUB_RUN_ID": str(origin["run_id"]), "GITHUB_RUN_ATTEMPT": str(origin["run_attempt"]),
        "CM_REQUEST_ID": origin["request_id"]}
    production = ci.get("production_origin")
    input_provenance = ({**expected_provenance, "CM_SOURCE_SHA": production["source_sha"],
        "GITHUB_WORKFLOW_SHA": production["workflow_sha"], "GITHUB_RUN_ID": str(production["run_id"]),
        "GITHUB_RUN_ATTEMPT": str(production["run_attempt"]), "CM_REQUEST_ID": production["request_id"]}
        if production else expected_provenance)
    if (producer["provenance"] != input_provenance or producer["task_id"] != "CM-M05"
        or producer["m05"]["build_kind"] != "qualification"):
        raise RuntimeError("Frozen producer inputs are not the declared M05 qualification")
    reports = ("author-to-user-workflow.json", "source-only-authoring.json", "runtime-author-diagnostics.json",
        "independent-mod-update.json", "metadata-diagnostics-boundary.json", "zero-build-cli-contract.json")
    with download_origin_archive(worker, remote["artifacts"]["consumer"], directory / "consumer.zip") as archive:
        acceptance = archive_json(archive, "acceptance.json")
        if (acceptance.get("task_id") != "CM-M05" or acceptance.get("status") != "pass"
            or acceptance.get("implementation_commit") != origin["source_sha"]
            or {row["id"] for row in acceptance["checks"]} != {"CM-M05-AC0" + str(i) for i in range(1, 7)}
            or any(row.get("status") != "pass" or not row.get("command") for row in acceptance["checks"])):
            raise RuntimeError("All six actual M05 qualification checks are required")
        for name in reports:
            report = archive_json(archive, "evidence/" + name)
            if (report.get("status") != "pass" or report.get("provenance") != expected_provenance
                or report.get("host") != producer["host"] or report.get("consumer_cache_mode") != "none"
                or report.get("outer_audit", {}).get("compiler_linker_jit_build_service_calls") != 0):
                raise RuntimeError("Qualification behavior report has a different Host or execution origin")
            if production and report.get("production_origin") != production:
                raise RuntimeError("Qualification behavior report has a different frozen producer origin")
    binary = destination / "host/bin/codex"
    with binary.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != producer["host"]["executable_sha256"]:
        raise RuntimeError("Restored qualification Host bytes changed")
    verified = {"origin": origin, "ci": ci, "host": producer["host"],
        "sdk_revision": producer["m05"]["sdk_revision"], "qualification_acceptance": acceptance,
        "verified": True, "worker_jobs": remote["jobs"]}
    (directory / "verified-origin.json").write_text(json.dumps(verified, indent=2) + "\n")
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
        stream.write("CM_VERIFIED_ORIGIN_DIR=" + str(directory) + "\n")
    print("Restored exact successful qualification Host and runtime fixtures; no compiler or rebuild fallback.", flush=True)


def preflight():
    source, worker, sha, workflow_sha, request = identities()
    kind, origin = build_request()
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
    consumer_required = "true" if config.get("task_id") in ("CM-P04", "CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A") else "false"
    if kind == "mod-only":
        if config.get("task_id") != "CM-M05":
            raise RuntimeError("Mod-only requires the reviewed M05 mapping")
        verify_origin(origin, source, worker, workflow_sha)
    record = {"source_repository": source, "source_sha": sha, "source_default_branch": branch,
              "observed_source_default_sha": source_head, "builder_repository": worker,
              "workflow_sha": workflow_sha, "worker_default_branch": worker_branch,
              "request_id": request, "target": TARGET, "cache_mode": mode, "consumer_required": consumer_required,
              "build_kind": kind}
    Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json").write_text(json.dumps(record, indent=2) + "\n")
    output({**record, "source_default_sha_verified": "true" if mode == "write" else "false"})
    print(json.dumps(record, indent=2))


def verify_checkout():
    source, worker, sha, workflow_sha, request = identities()
    build_request()
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
    origin = production_origin()
    input_run = origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"])
    expected_name = origin["input_artifact"]["name"] if origin else "cm-linux-x64-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    artifact_binding(artifact, artifact_id, expected_name, digest, input_run)
    if origin and (artifact_id != origin["input_artifact"]["id"] or "sha256:" + digest != origin["input_artifact"]["digest"]):
        raise RuntimeError("Consumer input differs from the verified producer origin")
    validation = validation_artifact()
    output({"input_artifact_name": expected_name, "input_run_id": input_run,
            "validation_artifact_name": validation["artifact_name"]})
    path = Path(os.environ["CM_CI_LOG_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    (path / "consumer-input-artifact.json").write_text(json.dumps({"artifact": artifact, "source_sha": sha,
        "workflow_sha": workflow_sha, "source_repository": source, "cache_mode": "none", "request_id": request,
        "production_origin": origin, "validation_artifact": validation}, indent=2) + "\n")


def production_origin():
    value = os.environ.get("CM_PRODUCTION_ORIGIN")
    if not value:
        return None
    origin = json.loads(value)
    from retry import verify_production_origin
    verify_production_origin(origin)
    return origin


def validation_artifact():
    _, worker, _, _, request = identities()
    artifact_id = int(os.environ["CM_VALIDATION_ARTIFACT_ID"])
    digest = os.environ["CM_VALIDATION_ARTIFACT_DIGEST"].removeprefix("sha256:")
    name = "cm-linux-x64-validation-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    return artifact_binding(api("repos/" + worker + "/actions/artifacts/" + str(artifact_id)),
                            artifact_id, name, digest, int(os.environ["GITHUB_RUN_ID"]))


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
    origin = {"run_id": 12, "run_attempt": 1, "source_sha": "a" * 40,
        "workflow_sha": "b" * 40, "request_id": "cm-fixture-origin"}
    for index, prefix in enumerate(("input", "consumer", "receipt"), 20):
        origin.update({prefix + "_artifact_id": index, prefix + "_artifact_sha256": "c" * 64})
    assert parse_origin(origin) == origin
    invalid.extend([lambda: parse_origin({**origin, "run_attempt": True}),
        lambda: parse_origin({**origin, "source_sha": "main"}),
        lambda: parse_origin({**origin, "unexpected": "field"})])
    for kind, raw in (("unknown", ""), ("qualification", "{}"), ("mod-only", ""), ("mod-only", "{")):
        def reject_request(kind=kind, raw=raw):
            with patch.dict(os.environ, {"CM_BUILD_KIND": kind, "CM_HOST_ORIGIN": raw}):
                build_request()
        invalid.append(reject_request)
    with patch.dict(os.environ, {"CM_BUILD_KIND": "mod-only", "CM_HOST_ORIGIN": json.dumps(origin)}):
        assert build_request() == ("mod-only", origin)
    run_path = "repos/DSLZL/CM-build-linux-x64/actions/runs/12"
    run = {"id": 12, "run_attempt": 1, "status": "completed", "conclusion": "success",
        "head_sha": "b" * 40, "event": "workflow_dispatch", "repository": {"full_name": "DSLZL/CM-build-linux-x64"},
        "path": ".github/workflows/build.yml", "display_title": "CM Linux x64 / cm-fixture-origin"}
    jobs = [{"id": index, "name": name, "conclusion": "success"} for index, name in enumerate(
        ("preflight", "build-write / linux-x64", "runtime-consumer", "receipt"), 30)]
    ci = {"provider": "github_actions", "repository": "DSLZL/CM-build-linux-x64", "source_repository": "DSLZL/CM",
        "head_sha": "a" * 40, "source_sha": "a" * 40, "workflow_sha": "b" * 40,
        "run_id": 12, "run_attempt": 1, "request_id": "cm-fixture-origin", "build_kind": "qualification",
        "execution_role": "platform_builder", "cache_repository": "DSLZL/CM-build-linux-x64",
        "workflow": ".github/workflows/build.yml", "target": TARGET, "runner_environment": "github-hosted",
        "runner_os": "Linux", "runner_arch": "X64", **successful_job(jobs, "build-write / linux-x64")}
    consumer = {"execution_role": "runtime_consumer", "cache_mode": "none", "producer_job_id": 31,
        **successful_job(jobs, "runtime-consumer"),
        **{key: ci[key] for key in ("source_sha", "workflow_sha", "run_id", "run_attempt", "request_id")},
        "artifact_id": 21, "artifact_sha256": "c" * 64,
        "input_artifact": {"artifact_id": 20, "artifact_sha256": "c" * 64}}
    receipt = {"ci": ci, "consumer": consumer}
    for section, key, value in (("ci", "job_id", 999), ("ci", "cache_repository", "DSLZL/CM"),
                                ("consumer", "job_id", 999), ("consumer", "cache_mode", "read"),
                                ("consumer", "source_sha", "f" * 40), ("consumer", "producer_job_id", 999)):
        changed = {**receipt, section: {**receipt[section], key: value}}
        invalid.append(lambda changed=changed: qualification_receipt(
            changed, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64"))
    responses = {run_path: run, run_path + "/attempts/1/jobs?per_page=100": {"jobs": jobs},
        "repos/DSLZL/CM-build-linux-x64/compare/" + "b" * 40 + "..." + "d" * 40: {"status": "ahead"},
        "repos/DSLZL/CM/compare/" + "a" * 40 + "..." + "e" * 40: {"status": "ahead"}}
    for prefix, name in (("input", "cm-linux-x64-runtime-inputs-"),
                         ("consumer", "cm-linux-x64-consumer-artifacts-"), ("receipt", "cm-build-receipt-")):
        identifier = origin[prefix + "_artifact_id"]
        responses["repos/DSLZL/CM-build-linux-x64/actions/artifacts/" + str(identifier)] = {
            "id": identifier, "name": name + "cm-fixture-origin-1", "digest": "sha256:" + "c" * 64,
            "expired": False, "workflow_run": {"id": 12}}
    with patch.dict(os.environ, {"CM_SOURCE_SHA": "e" * 40}), patch(__name__ + ".api", side_effect=responses.__getitem__):
        assert qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64") == ci
        assert verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-linux-x64", "d" * 40)["run"] == run
        for key, value in (("run_attempt", 2), ("conclusion", "failure"), ("head_sha", "f" * 40)):
            changed = {**responses, run_path: {**run, key: value}}
            with patch(__name__ + ".api", side_effect=changed.__getitem__):
                try:
                    verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-linux-x64", "d" * 40)
                    qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64")
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Unqualified Host origin accepted")
        for mutation in ("expired", "wrong-run", "wrong-digest", "skipped-consumer", "unrelated-source"):
            changed = json.loads(json.dumps(responses))
            artifact_key = "repos/DSLZL/CM-build-linux-x64/actions/artifacts/20"
            if mutation == "expired":
                changed[artifact_key]["expired"] = True
            elif mutation == "wrong-run":
                changed[artifact_key]["workflow_run"]["id"] = 999
            elif mutation == "wrong-digest":
                changed[artifact_key]["digest"] = "sha256:" + "f" * 64
            elif mutation == "skipped-consumer":
                changed[run_path + "/attempts/1/jobs?per_page=100"]["jobs"][2]["conclusion"] = "skipped"
            else:
                changed["repos/DSLZL/CM/compare/" + "a" * 40 + "..." + "e" * 40]["status"] = "diverged"
            with patch(__name__ + ".api", side_effect=changed.__getitem__):
                try:
                    verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-linux-x64", "d" * 40)
                    qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64")
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Invalid qualification artifact or job accepted")
    production = {"run_id": 11, "run_attempt": 1, "source_sha": "9" * 40, "workflow_sha": "8" * 40,
        "request_id": "cm-original-producer", "job": "build-write / linux-x64", "job_id": 19}
    reused_responses = json.loads(json.dumps(responses))
    for key, identifier, name in (("input_artifact", 20, "runtime-inputs"), ("product_artifact", 23, "task-artifacts")):
        record = {"id": identifier, "name": "cm-linux-x64-" + name + "-cm-original-producer-1",
            "digest": "sha256:" + "c" * 64, "size_in_bytes": 1, "expired": False, "workflow_run": {"id": 11}}
        reused_responses["repos/DSLZL/CM-build-linux-x64/actions/artifacts/" + str(identifier)] = record
        production[key] = {key: record[key] for key in ("id", "name", "digest", "size_in_bytes")}
    reused_responses["repos/DSLZL/CM-build-linux-x64/actions/runs/11"] = {
        **run, "id": 11, "head_sha": "8" * 40, "display_title": "CM Linux x64 / cm-original-producer"}
    reused_responses["repos/DSLZL/CM-build-linux-x64/actions/runs/11/attempts/1/jobs?per_page=100"] = {
        "jobs": [{"id": 19, "name": "build-write / linux-x64", "conclusion": "success"}]}
    reused_responses["repos/DSLZL/CM-build-linux-x64/actions/artifacts/24"] = {
        "id": 24, "name": "cm-linux-x64-validation-inputs-cm-fixture-origin-1", "digest": "sha256:" + "c" * 64,
        "expired": False, "workflow_run": {"id": 12}}
    reused_receipt = {"ci": {**ci, "artifact_id": 23, "artifact_sha256": "c" * 64, "production_origin": production},
        "consumer": {**consumer, "production_origin": production,
            "validation_artifact": {"artifact_id": 24, "artifact_sha256": "c" * 64}}}
    with patch.dict(os.environ, {"CM_SOURCE_SHA": "e" * 40}), patch(__name__ + ".api", side_effect=reused_responses.__getitem__):
        assert verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-linux-x64", "d" * 40)["run"] == run
        assert qualification_receipt(reused_receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64") == reused_receipt["ci"]
        for key, value in (("production_origin", {}), ("validation_artifact", {"artifact_id": 24, "artifact_sha256": "f" * 64})):
            changed = {**reused_receipt, "consumer": {**reused_receipt["consumer"], key: value}}
            try:
                qualification_receipt(changed, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-linux-x64")
            except RuntimeError:
                pass
            else:
                raise AssertionError("Reused qualification accepted mismatched producer or current validation")
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
    origin = production_origin()
    artifact_name = origin["product_artifact"]["name"] if origin else "cm-linux-x64-task-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    actual = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    artifact_binding(actual, artifact_id, artifact_name, digest, origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"]))
    if origin and (artifact_id != origin["product_artifact"]["id"] or "sha256:" + digest != origin["product_artifact"]["digest"]):
        raise RuntimeError("Receipt product differs from the verified producer origin")
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
          "build_kind": build_request()[0],
          "target": TARGET, "conclusion": None, "artifact_name": artifact_name,
          "artifact_id": artifact_id, "artifact_sha256": digest, **producer_job,
          "production_origin": origin}
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
        input_name = origin["input_artifact"]["name"] if origin else "cm-linux-x64-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        input_record = api("repos/" + worker + "/actions/artifacts/" + str(input_id))
        inputs = artifact_binding(input_record, input_id, input_name, input_digest, origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"]))
        consumer = {"execution_role": "runtime_consumer", "cache_mode": "none", "job": "runtime-consumer",
            **actual_job, "producer_job_id": producer_job["job_id"], "input_artifact": inputs,
            "artifact_id": consumer_id, "artifact_name": consumer_name,
            "artifact_sha256": consumer_digest, "source_sha": sha, "workflow_sha": workflow_sha,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": request,
            "production_origin": origin, "validation_artifact": validation_artifact()}
    out = Path(os.environ["RUNNER_TEMP"], "cm-worker-receipt")
    out.mkdir(exist_ok=True)
    (out / "worker-receipt.json").write_text(json.dumps({"schema_version": 1, "ci": ci, "consumer": consumer,
        "note": "Artifact identity verified; final workflow conclusion must be fetched after this run completes."}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        {"self-check": self_check, "preflight": preflight, "verify-checkout": verify_checkout, "verify-consumer": verify_consumer,
         "extract-consumer": extract_consumer, "restore-origin": restore_origin, "receipt": receipt}[sys.argv[1]]()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM worker blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
