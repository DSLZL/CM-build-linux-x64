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
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from record_run import require_hosted_linux, require_hosted_worker
import cm_platforms
from cm_platforms import linux_native
import stat

TARGET = cm_platforms.linux_native()["target"]


def checked(value, pattern, label):
    if not isinstance(value, str) or not re.fullmatch(pattern, value) or "REPLACE" in value:
        raise RuntimeError("Missing or invalid " + label)
    return value


def api(path):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "CM-build-policy"}
    if os.environ.get("CM_POLICY_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["CM_POLICY_TOKEN"]
    request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
            transient = (error.code in (502, 503, 504) if isinstance(error, urllib.error.HTTPError)
                         else isinstance(getattr(error, "reason", error), (ConnectionError, TimeoutError)))
            if not transient or attempt == 2:
                raise
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            delay = 5 * (attempt + 1)
            print(f"CM policy: GitHub API {error}; retry {attempt + 1}/2 in {delay}s", flush=True)
            time.sleep(delay)


def output(values):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in str(value) or "\r" in str(value):
                raise RuntimeError("Invalid multiline output")
            stream.write(key + "=" + str(value) + "\n")


def identities(*, enabled=True):
    entry = require_hosted_worker(enabled=enabled)
    source = checked(os.environ.get("CM_SOURCE_REPOSITORY"), r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "fixed source repository")
    worker = checked(os.environ.get("CM_BUILDER_REPOSITORY"), r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "fixed builder repository")
    sha = checked(os.environ.get("CM_SOURCE_SHA"), r"[0-9a-f]{40}", "source SHA")
    workflow_sha = checked(os.environ.get("GITHUB_WORKFLOW_SHA"), r"[0-9a-f]{40}", "worker workflow SHA")
    request = checked(os.environ.get("CM_REQUEST_ID"), r"[A-Za-z0-9_.-]{1,128}", "request ID")
    if source != "DSLZL/CM" or worker != entry["repository"] or worker == source:
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
    if kind not in ("qualification", "mod-only", "program") or (kind in ("qualification", "program") and raw):
        raise RuntimeError("Unsupported build kind or unexpected Host origin")
    if kind in ("qualification", "program"):
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
        or run.get("display_title") != f"CM {linux_native()['label']} / " + origin["request_id"]):
        raise RuntimeError("Host origin is not the exact successful qualification run/attempt")
    for repository, base, head in ((worker, origin["workflow_sha"], workflow_sha),
                                   (source, origin["source_sha"], os.environ["CM_SOURCE_SHA"])):
        if api("repos/" + repository + "/compare/" + base + "..." + head).get("status") not in ("ahead", "identical"):
            raise RuntimeError("Qualification origin must belong to the reviewed source/worker ancestry")
    jobs = api(path + "/attempts/" + str(origin["run_attempt"]) + "/jobs?per_page=100")["jobs"]
    producers = [row for row in jobs if row.get("name") in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"])
        and row.get("conclusion") == "success"]
    if len(producers) != 1:
        raise RuntimeError("Qualification requires one successful actual producer")
    for name in ("preflight", producers[0]["name"], "runtime-consumer", "receipt"):
        successful_job(jobs, name)
    artifacts = {}
    for prefix, name in (("input", f"cm-{linux_native()['key']}-runtime-inputs-"),
                         ("consumer", f"cm-{linux_native()['key']}-consumer-artifacts-"), ("receipt", "cm-build-receipt-")):
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


def download_origin_archive(worker, record, destination, *, maximum=4 * 1024 ** 3):
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
            if size > maximum:
                raise RuntimeError("Oversized qualification artifact")
            digest.update(chunk)
            stream.write(chunk)
            if time.monotonic() - heartbeat >= 30:
                print(json.dumps({"stage": "restore-qualified-origin", "status": "running",
                    "bytes": size, "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
                heartbeat = time.monotonic()
    if size != record["size_in_bytes"] or "sha256:" + digest.hexdigest() != record["digest"]:
        raise RuntimeError("Downloaded qualification artifact digest differs from GitHub metadata")
    return zipfile.ZipFile(destination)


def archive_json(archive, name):
    entries = [entry for entry in archive.infolist() if entry.filename == name]
    if len(entries) != 1 or entries[0].file_size > 16 * 1024 * 1024 or entries[0].is_dir():
        raise RuntimeError("Missing, duplicate or oversized qualification JSON")
    return json.loads(archive.read(entries[0]))


def qualification_receipt(receipt, origin, jobs, source, worker):
    ci = receipt["ci"]
    if ci.get("job") not in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"]):
        raise RuntimeError("Qualification receipt has no actual producer job")
    expected = {"provider": "github_actions", "source_repository": source, "repository": worker,
        "head_sha": origin["source_sha"], "source_sha": origin["source_sha"],
        "workflow_sha": origin["workflow_sha"], "run_id": origin["run_id"], "run_attempt": origin["run_attempt"],
        "request_id": origin["request_id"], "build_kind": "qualification", "execution_role": "platform_builder",
        "cache_repository": worker, "workflow": ".github/workflows/build.yml", "target": TARGET,
        "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": linux_native()["runner_arch"],
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
            validation["artifact_id"], f"cm-{linux_native()['key']}-validation-inputs-" + origin["request_id"] + "-" + str(origin["run_attempt"]),
            validation["artifact_sha256"], origin["run_id"])
        assert records["input_artifact"]["id"] == origin["input_artifact_id"]
    else:
        record = api("repos/" + worker + "/actions/artifacts/" + str(origin["input_artifact_id"]))
        artifact_binding(record, origin["input_artifact_id"], f"cm-{linux_native()['key']}-runtime-inputs-" + origin["request_id"] + "-" + str(origin["run_attempt"]),
                         origin["input_artifact_sha256"], origin["run_id"])
    if receipt.get("index") is not None:
        verify_index_receipt(receipt["index"], jobs=jobs, ci=ci, consumer=consumer)
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


def preflight(*, mechanism_only=False):
    source, worker, sha, workflow_sha, request = identities(enabled=not mechanism_only)
    entry = cm_platforms.worker(enabled=not mechanism_only)
    kind, origin = build_request()
    if mechanism_only and (entry["key"] != "linux-arm64" or os.environ.get("GITHUB_JOB") != "native-preflight"
            or kind != "qualification" or origin is not None
            or os.environ.get("CM_CACHE_MODE") != "none" or os.environ.get("ACTIONS_CACHE_MODE") != "none"):
        raise RuntimeError("Only the cache-none Linux ARM64 mechanism preflight may inspect a disabled target")
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
    if mechanism_only and (worker_info.get("private") is not False or branch != "main" or worker_branch != "main" or sha != source_head):
        raise RuntimeError("Mechanism preflight requires public main repositories and the exact current source head")
    mode = "write" if sha == source_head else "read"
    config_record = api("repos/" + source + "/contents/.github/cm-ci.json?ref=" + sha)
    config = json.loads(base64.b64decode(config_record["content"]))
    consumer_required = "true" if config.get("task_id") in ("CM-P04", "CM-M01", "CM-M02", "CM-M03", "CM-M04", "CM-M05", "CM-G02A", "CM-G02B", "CM-G03", "CM-G04", "CM-G01", "CM-G05", "CM-G06", "CM-S01", "CM-S02", "CM-S03") else "false"
    if kind == "program":
        if config.get("task_id") != "CM-S03":
            raise RuntimeError("Program validation requires the frozen S03 product mapping")
        mode = "none"
    if kind == "mod-only":
        if config.get("task_id") != "CM-M05":
            raise RuntimeError("Mod-only requires the reviewed M05 mapping")
        verify_origin(origin, source, worker, workflow_sha)
    if mechanism_only:
        mode, consumer_required = "none", "false"
    record = {"source_repository": source, "source_sha": sha, "source_default_branch": branch,
              "observed_source_default_sha": source_head, "builder_repository": worker,
              "workflow_sha": workflow_sha, "worker_default_branch": worker_branch,
              "request_id": request, "platform": entry["key"], "target": entry["target"], "cache_mode": mode, "consumer_required": consumer_required,
              "build_kind": kind, "distribution_required": "true" if not mechanism_only and kind != "program" and config.get("task_id") in ("CM-S01", "CM-S02", "CM-S03") else "false",
              "index_required": "true" if not mechanism_only and kind != "program" and config.get("task_id") == "CM-S03" else "false"}
    if mechanism_only:
        record["execution_role"] = "platform_preflight"
    Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json").write_text(json.dumps(record, indent=2) + "\n")
    output({**record, "source_default_sha_verified": "true" if mode == "write" else "false"})
    print(json.dumps(record, indent=2))


def native_preflight():
    preflight(mechanism_only=True)


def native_preflight_self_check():
    from unittest.mock import patch
    entry = cm_platforms.select("linux-arm64")
    source, worker, sha, workflow_sha, request = "DSLZL/CM", entry["repository"], "a" * 40, "b" * 40, "mechanism-check"
    env = {"GITHUB_JOB": "native-preflight", "GITHUB_REF": "refs/heads/main", "CM_CACHE_MODE": "none",
        "ACTIONS_CACHE_MODE": "none", "CM_BUILD_KIND": "qualification", "CM_HOST_ORIGIN": ""}
    records = {"repos/" + name: {"full_name": name, "private": False, "default_branch": "main"} for name in (source, worker)}
    records.update({"repos/" + worker + "/commits/main": {"sha": workflow_sha},
        "repos/" + source + "/commits/" + sha: {"sha": sha}, "repos/" + source + "/commits/main": {"sha": sha},
        "repos/" + source + "/contents/.github/cm-ci.json?ref=" + sha:
            {"content": base64.b64encode(json.dumps({"task_id": "CM-S03"}).encode()).decode()}})
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {**env, "RUNNER_TEMP": directory}, clear=True), \
            patch(__name__ + ".identities", return_value=(source, worker, sha, workflow_sha, request)) as identity, \
            patch.object(cm_platforms, "worker", return_value=entry), patch(__name__ + ".api", side_effect=records.__getitem__), \
            patch(__name__ + ".output") as emitted:
        native_preflight()
        identity.assert_called_with(enabled=False)
        value = emitted.call_args.args[0]
        assert value["cache_mode"] == "none" and value["execution_role"] == "platform_preflight"
        assert all(value[key] == "false" for key in ("consumer_required", "distribution_required", "index_required"))
        for changes in ({"GITHUB_JOB": "build-write"}, {"CM_CACHE_MODE": "write"}, {"ACTIONS_CACHE_MODE": "read"},
                {"CM_BUILD_KIND": "program"}, {"CM_HOST_ORIGIN": "{}"}, {"GITHUB_REF": "refs/heads/other"}):
            with patch.dict(os.environ, changes):
                try:
                    native_preflight()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Invalid mechanism preflight authority accepted: " + repr(changes))
        for path, changed in (("repos/" + worker, {"full_name": worker, "private": True, "default_branch": "main"}),
                ("repos/" + worker + "/commits/main", {"sha": "c" * 40}),
                ("repos/" + source + "/commits/main", {"sha": "c" * 40})):
            with patch.dict(records, {path: changed}):
                try:
                    native_preflight()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Changed mechanism preflight origin accepted")
        with patch.object(cm_platforms, "worker", return_value=cm_platforms.select("linux-x64")):
            try:
                native_preflight()
            except RuntimeError:
                pass
            else:
                raise AssertionError("Mechanism exception escaped its reviewed ARM64 target")
    print("CM ARM64 mechanism authority self-check passed; product routing requires an enabled exact native worker", flush=True)


def benchmark_capacity(cache, pending_bytes=None, *, usage_floor=0):
    result = {"status": "unavailable", "save_allowed": False, "billing_expansion": False, "deletion": False}
    try:
        limit = cache["repository_limit_bytes"]
        free, planned = cache["free_limit_bytes"], cache["planned_new_bytes"]
        reserve = planned if pending_bytes is None else pending_bytes
        assert cache["repository_limit_source"] == "owner-confirmed-free-tier", "Repository limit needs owner confirmation"
        assert all(type(value) is int and value > 0 for value in (limit, free, planned, reserve)), "Invalid cache byte limits"
        assert type(usage_floor) is int and usage_floor >= 0, "Invalid reserved cache usage"
        maximum = min(limit, free)
        usage = api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/cache/usage")
        used = usage["active_caches_size_in_bytes"]
        assert type(used) is int and used >= 0, "Invalid live cache usage"
        used = max(used, usage_floor)
        allowed = used + reserve <= maximum
        result.update(status="available", save_allowed=allowed, usage=usage,
            limit={"max_cache_size_bytes": limit, "source": cache["repository_limit_source"]},
            maximum_bytes=maximum, reserved_new_bytes=reserve, effective_usage_bytes=used,
            reason=None if allowed else "Insufficient confirmed headroom; no eviction or paid expansion")
    except (urllib.error.URLError, ConnectionError, TimeoutError, KeyError, AssertionError, TypeError, ValueError) as error:
        result.update(reason=str(error) or type(error).__name__,
            http_status=error.code if isinstance(error, urllib.error.HTTPError) else None)
    return result


def cache_archive_bound(paths, temporary):
    """Conservative tar/PAX + gzip/zstd allowance; inspect metadata, never archive twice."""
    temporary = temporary.resolve(strict=True)
    total, entries = 1024 * 1024, 0
    heartbeat = time.monotonic()
    for raw in paths:
        if not raw or any(char in raw for char in "*?[]!\r\n"):
            raise RuntimeError("Cache paths must be explicit runner-temporary paths without globbing")
        root = Path(raw)
        if not root.is_absolute() or root.is_symlink() or not root.resolve().is_relative_to(temporary) or root.resolve() == temporary:
            raise RuntimeError("Cache root must stay inside its runner temporary directory")
        if not root.exists():
            continue
        pending = [root]
        while pending:
            path = pending.pop()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
            elif stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError("Cache symlink escapes its explicit root")
            elif not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Cache candidate contains a special file")
            size = info.st_size if stat.S_ISREG(info.st_mode) else 0
            total += (size + 511) // 512 * 512 + 8192 + 8 * len(str(path).encode("utf-8"))
            entries += 1
            if time.monotonic() - heartbeat >= 5:
                print("Cache capacity inventory:", entries, "entries", total, "reserved tar bytes", flush=True)
                heartbeat = time.monotonic()
    if not entries:
        raise RuntimeError("No existing cache candidate paths")
    return {"entries": entries, "archive_upper_bound_bytes": total + total // 16 + 1024 * 1024}


def live_cache_bytes():
    # The aggregate usage endpoint can lag; also enumerate every currently visible cache.
    seen, total, page = set(), 0, 1
    while True:
        result = api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/caches?per_page=100&page=" + str(page))
        rows = result["actions_caches"]
        count = result["total_count"]
        if not isinstance(rows, list) or type(count) is not int or count < 0:
            raise RuntimeError("Live cache listing is unavailable or malformed")
        for row in rows:
            cache_id, size = row["id"], row["size_in_bytes"]
            if type(cache_id) is not int or cache_id <= 0 or cache_id in seen or type(size) is not int or size < 0:
                raise RuntimeError("Ambiguous live cache inventory")
            seen.add(cache_id)
            total += size
        if len(rows) < 100:
            if len(seen) != count:
                raise RuntimeError("Cache inventory changed during pagination; skip saving")
            return total
        page += 1
        if page > 1000:
            raise RuntimeError("Cache inventory exceeds the reviewed bounded listing")


def cache_save_plan():
    key = os.environ.get("CM_CACHE_SAVE_KEY", "")
    result = {"schema_version": 1, "save_allowed": False, "billing_expansion": False, "deletion": False,
        "repository": os.environ.get("GITHUB_REPOSITORY"), "cache_key": key}
    try:
        if os.environ.get("CM_CACHE_MODE") != "write" or os.environ.get("ACTIONS_CACHE_MODE") != "write":
            raise RuntimeError("Cache save requires actual reviewed write authority")
        verify_checkout()
        checked(key, r"[A-Za-z0-9_.-]{1,512}", "cache save key")
        limit = cm_platforms.load()["cache_limit_bytes"]
        temporary = Path(os.environ["RUNNER_TEMP"])
        context = {name: os.environ[name] for name in
            ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")}
        journal_path = temporary / "cm-repository-cache-reservation.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8")) if journal_path.exists() else {
            "context": context, "usage_floor": 0}
        if not isinstance(journal, dict) or journal.get("context") != context or type(journal.get("usage_floor")) is not int or journal["usage_floor"] < 0:
            raise RuntimeError("Cache reservation journal has a different or invalid job identity")
        result.update(cache_archive_bound(os.environ["CM_CACHE_SAVE_PATHS"].splitlines(), temporary))
        listed = live_cache_bytes()
        capacity = benchmark_capacity({"repository_limit_bytes": limit, "free_limit_bytes": limit,
            "planned_new_bytes": result["archive_upper_bound_bytes"],
            "repository_limit_source": "owner-confirmed-free-tier"},
            usage_floor=max(listed, journal["usage_floor"]))
        result.update(capacity, listed_cache_bytes=listed, previous_usage_floor=journal["usage_floor"])
        if result["save_allowed"]:
            # Reserve before upload and retain the reservation even when that upload fails.
            journal["usage_floor"] = result["effective_usage_bytes"] + result["reserved_new_bytes"]
            journal_path.write_text(json.dumps(journal) + "\n", encoding="utf-8")
    except (RuntimeError, KeyError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        result.update(save_allowed=False, reason=str(error) or type(error).__name__)
    directory = Path(os.environ["CM_CI_LOG_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    name = hashlib.sha256(key.encode()).hexdigest()[:20]
    (directory / ("cache-save-plan-" + name + ".json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    output({"save_allowed": str(result["save_allowed"]).lower()})


def cache_budget_self_check():
    from unittest.mock import patch
    cache = {"repository_limit_bytes": 100, "free_limit_bytes": 100, "planned_new_bytes": 10,
        "repository_limit_source": "owner-confirmed-free-tier"}
    for used, allowed in ((89, True), (90, True), (91, False)):
        with patch(__name__ + ".api", return_value={"active_caches_size_in_bytes": used}):
            assert benchmark_capacity(cache)["save_allowed"] is allowed
            assert not benchmark_capacity(cache, usage_floor=91)["save_allowed"]
    for usage in ({}, {"active_caches_size_in_bytes": -1}, {"active_caches_size_in_bytes": True}):
        with patch(__name__ + ".api", return_value=usage):
            assert not benchmark_capacity(cache)["save_allowed"]
    with patch(__name__ + ".api", side_effect=TimeoutError("controlled unavailable")):
        assert not benchmark_capacity(cache)["save_allowed"]
    first_page = [{"id": number, "size_in_bytes": 2} for number in range(1, 101)]
    with patch(__name__ + ".api", side_effect=[{"actions_caches": first_page, "total_count": 101},
            {"actions_caches": [{"id": 101, "size_in_bytes": 3}], "total_count": 101}]) as transport:
        assert live_cache_bytes() == 203 and transport.call_count == 2
    for rows in ({"actions_caches": [], "total_count": 1},
            {"actions_caches": [{"id": 1, "size_in_bytes": -1}], "total_count": 1},
            {"actions_caches": [{"id": 1, "size_in_bytes": 1}] * 2, "total_count": 2}):
        with patch(__name__ + ".api", return_value=rows):
            try:
                live_cache_bytes()
            except RuntimeError:
                pass
            else:
                raise AssertionError("An ambiguous cache listing was accepted")
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory).resolve()
        candidate = temporary / "candidate"
        candidate.mkdir()
        (candidate / "object").write_bytes(b"bounded compiler object")
        bound = cache_archive_bound([str(candidate)], temporary)["archive_upper_bound_bytes"]
        assert bound > (candidate / "object").stat().st_size
        invalid = (temporary, temporary.parent, temporary / "candidate/*")
        for path in invalid:
            try:
                cache_archive_bound([str(path)], temporary)
            except RuntimeError:
                pass
            else:
                raise AssertionError("An unbounded cache path was accepted")
        (candidate / "escape").symlink_to(temporary.parent, target_is_directory=True)
        try:
            cache_archive_bound([str(candidate)], temporary)
        except RuntimeError:
            pass
        else:
            raise AssertionError("An escaping cache symlink was accepted")
        (candidate / "escape").unlink()
        os.mkfifo(candidate / "pipe")
        try:
            cache_archive_bound([str(candidate)], temporary)
        except RuntimeError:
            pass
        else:
            raise AssertionError("A cache special file was accepted")
        (candidate / "pipe").unlink()
        limit = cm_platforms.load()["cache_limit_bytes"]
        used = limit - bound * 2
        listing = {"total_count": 2, "actions_caches": [
            {"id": 1, "key": "unrelated-cargo-cache", "size_in_bytes": used - 1},
            {"id": 2, "key": "other-namespace", "size_in_bytes": 1}]}
        def fetch(path):
            return listing if "/actions/caches?" in path else {"active_caches_size_in_bytes": 0}
        env = {"RUNNER_TEMP": str(temporary), "CM_CI_LOG_DIR": str(temporary / "evidence"),
            "CM_CACHE_MODE": "write", "ACTIONS_CACHE_MODE": "write", "CM_CACHE_SAVE_PATHS": str(candidate),
            "CM_CACHE_SAVE_KEY": "cm-budget-fixture", "GITHUB_REPOSITORY": "DSLZL/CM-build-" + linux_native()["key"],
            "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "fixture"}
        outputs = []
        with patch.dict(os.environ, env, clear=True), patch(__name__ + ".verify_checkout"), \
                patch(__name__ + ".api", side_effect=fetch), patch(__name__ + ".output", side_effect=outputs.append), \
                patch("builtins.print"):
            for _ in range(3):
                cache_save_plan()
            assert [row["save_allowed"] for row in outputs] == ["true", "true", "false"]
            journal = temporary / "cm-repository-cache-reservation.json"
            assert json.loads(journal.read_text())["usage_floor"] == limit
            value = json.loads(journal.read_text())
            value["context"]["GITHUB_RUN_ATTEMPT"] = "2"
            journal.write_text(json.dumps(value))
            cache_save_plan()
            assert outputs[-1]["save_allowed"] == "false"
            journal.unlink()
            with patch(__name__ + ".api", side_effect=urllib.error.URLError("controlled unknown capacity")):
                cache_save_plan()
                assert outputs[-1]["save_allowed"] == "false" and not journal.exists()
            with patch.dict(os.environ, {"CM_CACHE_MODE": "read"}), patch(__name__ + ".api") as transport:
                cache_save_plan()
                assert outputs[-1]["save_allowed"] == "false" and transport.call_count == 0


def benchmark_preflight():
    preflight()
    source, worker, sha, workflow_sha, _ = identities()
    record_path = Path(os.environ["RUNNER_TEMP"], "cm-worker-preflight.json")
    record = json.loads(record_path.read_text())
    assert record["cache_mode"] == "write", "Measurements require the current reviewed source default SHA"
    definition = json.loads(base64.b64decode(api("repos/" + source + "/contents/ci/benchmarks/scenarios.json?ref=" + sha)["content"]))
    assert definition["task_id"] == "CM-S04" and definition["required_checks"] == ["CM-S04-AC0" + str(i) for i in range(1, 7)]
    number = checked(os.environ.get("CM_BENCHMARK_PR_NUMBER"), r"[1-9][0-9]*", "real source PR number")
    pull = api("repos/" + source + "/pulls/" + number)
    assert pull["state"] == "open" and pull["base"]["repo"]["full_name"] == source
    assert pull["head"]["repo"]["full_name"] == source and pull["head"]["sha"] != sha
    assert pull["base"]["ref"] == record["source_default_branch"] and pull["head"]["ref"] != pull["base"]["ref"]
    pr_sha = checked(pull["head"]["sha"], r"[0-9a-f]{40}", "actual PR head SHA")
    runtime = json.loads(base64.b64decode(api("repos/" + source + "/contents/ci/benchmarks/runtime-loading.json?ref=" + sha)["content"]))
    qualified = parse_origin(runtime["qualification"]["origin"])
    verify_origin(qualified, source, worker, workflow_sha)
    record.update(task_id="CM-S04", pr_number=int(number), pr_sha=pr_sha, real_pr_url=pull["html_url"])
    capacity = benchmark_capacity(definition["cache"])
    record["cache_capacity"] = capacity
    seed = definition["host_seed"]
    seed_status = {"status": "unavailable", "usable": False}
    try:
        assert seed["repository"] == worker and seed["save"] is False
        assert seed["image_os"] == os.environ["ImageOS"] and seed["image_version"] == os.environ["ImageVersion"], "Pinned H seed runner image drifted"
        rows = api("repos/" + worker + "/actions/caches?key=" + seed["key"] + "&per_page=100")["actions_caches"]
        exact = [row for row in rows if row["key"] == seed["key"] and row["ref"] == "refs/heads/main"]
        assert len(exact) == 1 and exact[0]["size_in_bytes"] > 0, "Exact H compiler seed is unavailable"
        run_path = "repos/" + worker + "/actions/runs/" + str(seed["run_id"])
        run = api(run_path)
        assert run["head_sha"] == seed["worker_sha"] and run["event"] == "workflow_dispatch"
        assert run["path"] == ".github/workflows/build.yml" and run["run_attempt"] == seed["run_attempt"]
        jobs = api(run_path + "/attempts/" + str(seed["run_attempt"]) + "/jobs?per_page=100")["jobs"]
        producer = successful_job(jobs, "build-write / " + linux_native()["key"])
        seed_status.update(status="available", usable=True, cache=exact[0], producer=producer)
    except (urllib.error.URLError, KeyError, AssertionError, TypeError, RuntimeError) as error:
        seed_status.update(reason=str(error) or type(error).__name__)
    record["host_seed_preflight"] = seed_status
    record["author_allowed"] = capacity["save_allowed"] and seed_status["usable"]
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    output({"pr_sha": pr_sha, "pr_number": number, "capacity_allowed": str(capacity["save_allowed"]).lower(),
        "author_allowed": str(record["author_allowed"]).lower()})
    print(json.dumps(record, indent=2), flush=True)


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
                      "request_id": request, "target": cm_platforms.worker()["target"]}, indent=2))


def verify_consumer():
    source, worker, sha, workflow_sha, request = identities()
    if os.environ.get("CM_CACHE_MODE") != "none" or os.environ.get("ACTIONS_CACHE_MODE") != "none":
        raise RuntimeError("Actual consumer cache authority must be none")
    artifact_id = int(os.environ["CM_INPUT_ARTIFACT_ID"])
    digest = checked(os.environ["CM_INPUT_ARTIFACT_DIGEST"].removeprefix("sha256:"), r"[0-9a-f]{64}", "input artifact digest")
    artifact = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    origin = production_origin()
    input_run = origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"])
    expected_name = origin["input_artifact"]["name"] if origin else f"cm-{linux_native()['key']}-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
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
    name = f"cm-{linux_native()['key']}-validation-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
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


def receipt_jobs(path, names, *, fetch=None):
    # A dependent job can start before its predecessor is visible as completed in the API.
    fetch = fetch or api
    for attempt in range(12):
        jobs = fetch(path)["jobs"]
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
    if os.environ.get("GITHUB_REPOSITORY") == "DSLZL/CM":
        require_hosted_linux()
    else:
        require_hosted_worker()
    cm_platforms.self_check()
    from record_run import self_check as record_self_check
    record_self_check()
    cache_budget_self_check()
    import io
    from unittest.mock import patch

    unavailable = urllib.error.HTTPError("https://api.github.com/fixture", 502, "unavailable", {}, None)
    with patch("urllib.request.urlopen", side_effect=[unavailable, io.BytesIO(b'{"ok": true}')]) as fetch, patch("time.sleep") as pause:
        assert api("fixture") == {"ok": True}
        assert fetch.call_count == 2
        pause.assert_called_once_with(5)
    for code, calls in ((403, 1), (404, 1), (429, 1), (502, 3), (503, 3), (504, 3)):
        error = urllib.error.HTTPError("https://api.github.com/fixture", code, "rejected", {}, None)
        with patch("urllib.request.urlopen", side_effect=error) as fetch, patch("time.sleep") as pause:
            try:
                api("fixture")
            except urllib.error.HTTPError as actual:
                assert actual.code == code
            else:
                raise AssertionError("GitHub API failure was accepted")
            assert fetch.call_count == calls and pause.call_count == calls - 1
    with patch("urllib.request.urlopen", return_value=io.BytesIO(b"not JSON")) as fetch, patch("time.sleep") as pause:
        try:
            api("fixture")
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("Malformed GitHub response was accepted")
        assert fetch.call_count == 1 and pause.call_count == 0
    for error in (urllib.error.URLError(ConnectionResetError("reset")), TimeoutError("deadline")):
        with patch("urllib.request.urlopen", side_effect=[error, io.BytesIO(b'{"ok": true}')]) as fetch, patch("time.sleep") as pause:
            assert api("fixture") == {"ok": True}
            assert fetch.call_count == 2
            pause.assert_called_once_with(5)
        with patch("urllib.request.urlopen", side_effect=error) as fetch, patch("time.sleep") as pause:
            try:
                api("fixture")
            except type(error):
                pass
            else:
                raise AssertionError("Persistent network failure was accepted")
            assert fetch.call_count == 3 and pause.call_count == 2
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("certificate rejected")) as fetch, patch("time.sleep") as pause:
        try:
            api("fixture")
        except urllib.error.URLError:
            pass
        else:
            raise AssertionError("Permanent network failure was accepted")
        assert fetch.call_count == 1 and pause.call_count == 0
    record = {"id": 1, "name": "input", "digest": "sha256:" + "a" * 64,
              "expired": False, "workflow_run": {"id": 2}}
    assert artifact_binding(record, 1, "input", "a" * 64, 2)["artifact_id"] == 1
    assert successful_job([{"id": 3, "name": "consumer", "conclusion": "success"}], "consumer")["job_id"] == 3
    index_binding_self_check()
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
    run_path = f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/runs/12"
    run = {"id": 12, "run_attempt": 1, "status": "completed", "conclusion": "success",
        "head_sha": "b" * 40, "event": "workflow_dispatch", "repository": {"full_name": "DSLZL/CM-build-" + linux_native()["key"]},
        "path": ".github/workflows/build.yml", "display_title": f"CM {linux_native()['label']} / cm-fixture-origin"}
    jobs = [{"id": index, "name": name, "conclusion": "success"} for index, name in enumerate(
        ("preflight", "build-write / " + linux_native()["key"], "runtime-consumer", "receipt"), 30)]
    ci = {"provider": "github_actions", "repository": "DSLZL/CM-build-" + linux_native()["key"], "source_repository": "DSLZL/CM",
        "head_sha": "a" * 40, "source_sha": "a" * 40, "workflow_sha": "b" * 40,
        "run_id": 12, "run_attempt": 1, "request_id": "cm-fixture-origin", "build_kind": "qualification",
        "execution_role": "platform_builder", "cache_repository": "DSLZL/CM-build-" + linux_native()["key"],
        "workflow": ".github/workflows/build.yml", "target": TARGET, "runner_environment": "github-hosted",
        "runner_os": "Linux", "runner_arch": linux_native()["runner_arch"], **successful_job(jobs, "build-write / " + linux_native()["key"])}
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
            changed, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"]))
    responses = {run_path: run, run_path + "/attempts/1/jobs?per_page=100": {"jobs": jobs},
        f"repos/DSLZL/CM-build-{linux_native()['key']}/compare/" + "b" * 40 + "..." + "d" * 40: {"status": "ahead"},
        "repos/DSLZL/CM/compare/" + "a" * 40 + "..." + "e" * 40: {"status": "ahead"}}
    for prefix, name in (("input", f"cm-{linux_native()['key']}-runtime-inputs-"),
                         ("consumer", f"cm-{linux_native()['key']}-consumer-artifacts-"), ("receipt", "cm-build-receipt-")):
        identifier = origin[prefix + "_artifact_id"]
        responses[f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/artifacts/" + str(identifier)] = {
            "id": identifier, "name": name + "cm-fixture-origin-1", "digest": "sha256:" + "c" * 64,
            "expired": False, "workflow_run": {"id": 12}}
    with patch.dict(os.environ, {"CM_SOURCE_SHA": "e" * 40}), patch(__name__ + ".api", side_effect=responses.__getitem__):
        assert qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"]) == ci
        assert verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"], "d" * 40)["run"] == run
        for key, value in (("run_attempt", 2), ("conclusion", "failure"), ("head_sha", "f" * 40)):
            changed = {**responses, run_path: {**run, key: value}}
            with patch(__name__ + ".api", side_effect=changed.__getitem__):
                try:
                    verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"], "d" * 40)
                    qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"])
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Unqualified Host origin accepted")
        for mutation in ("expired", "wrong-run", "wrong-digest", "skipped-consumer", "unrelated-source"):
            changed = json.loads(json.dumps(responses))
            artifact_key = f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/artifacts/20"
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
                    verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"], "d" * 40)
                    qualification_receipt(receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"])
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Invalid qualification artifact or job accepted")
    production = {"run_id": 11, "run_attempt": 1, "source_sha": "9" * 40, "workflow_sha": "8" * 40,
        "request_id": "cm-original-producer", "job": "build-write / " + linux_native()["key"], "job_id": 19}
    reused_responses = json.loads(json.dumps(responses))
    for key, identifier, name in (("input_artifact", 20, "runtime-inputs"), ("product_artifact", 23, "task-artifacts")):
        record = {"id": identifier, "name": f"cm-{linux_native()['key']}-" + name + "-cm-original-producer-1",
            "digest": "sha256:" + "c" * 64, "size_in_bytes": 1, "expired": False, "workflow_run": {"id": 11}}
        reused_responses[f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/artifacts/" + str(identifier)] = record
        production[key] = {key: record[key] for key in ("id", "name", "digest", "size_in_bytes")}
    reused_responses[f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/runs/11"] = {
        **run, "id": 11, "head_sha": "8" * 40, "display_title": f"CM {linux_native()['label']} / cm-original-producer"}
    reused_responses[f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/runs/11/attempts/1/jobs?per_page=100"] = {
        "jobs": [{"id": 19, "name": "build-write / " + linux_native()["key"], "status": "completed", "conclusion": "success"}]}
    reused_responses[f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/artifacts/24"] = {
        "id": 24, "name": f"cm-{linux_native()['key']}-validation-inputs-cm-fixture-origin-1", "digest": "sha256:" + "c" * 64,
        "expired": False, "workflow_run": {"id": 12}}
    reused_receipt = {"ci": {**ci, "artifact_id": 23, "artifact_sha256": "c" * 64, "production_origin": production},
        "consumer": {**consumer, "production_origin": production,
            "validation_artifact": {"artifact_id": 24, "artifact_sha256": "c" * 64}}}
    with patch.dict(os.environ, {"CM_SOURCE_SHA": "e" * 40}), patch(__name__ + ".api", side_effect=reused_responses.__getitem__):
        assert verify_origin(origin, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"], "d" * 40)["run"] == run
        assert qualification_receipt(reused_receipt, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"]) == reused_receipt["ci"]
        for key, value in (("production_origin", {}), ("validation_artifact", {"artifact_id": 24, "artifact_sha256": "f" * 64})):
            changed = {**reused_receipt, "consumer": {**reused_receipt["consumer"], key: value}}
            try:
                qualification_receipt(changed, origin, jobs, "DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"])
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


def index_binding_self_check():
    from copy import deepcopy
    ci = {"source_sha": "a" * 40, "workflow_sha": "b" * 40, "production_origin": {"run_id": 1},
        "repository": "DSLZL/CM-build-" + linux_native()["key"], "run_id": 20, "run_attempt": 2, "request_id": "cm-fixture"}
    consumer = {"artifact_id": 21, "job_id": 22}
    jobs, records = [], {}
    value = {"status": "pass", "source_sha": ci["source_sha"], "workflow_sha": ci["workflow_sha"],
        "production_origin": ci["production_origin"], "main_consumer_artifact_id": 21,
        "main_consumer_job_id": 22, "release_ready": False}
    for number, role, prefix, job in ((23, "qualification", "index-qualification", "attest-index-qualification"),
            (24, "proof_consumer", "index-proof-consumer", "index-proof-consumer")):
        name = f"cm-{linux_native()['key']}-" + prefix + "-cm-fixture-2"
        jobs.append({"id": number, "name": job, "conclusion": "success"})
        records[str(number)] = {"id": number, "name": name, "digest": "sha256:" + "c" * 64,
            "expired": False, "workflow_run": {"id": 20}}
        value[role] = {"job": job, "job_id": number, "job_conclusion": "success",
            "artifact": {"artifact_id": number, "artifact_name": name, "artifact_sha256": "c" * 64}}
    def verify(candidate, selected_jobs=jobs):
        return verify_index_receipt(candidate, jobs=selected_jobs, ci=ci, consumer=consumer,
            fetch=lambda path: records[path.rsplit("/", 1)[1]])
    assert verify(value) == value
    invalid = [{**value, "source_sha": "d" * 40}, {**value, "status": "behavior_pass"},
        {**value, "main_consumer_artifact_id": 99}, {**value, "release_ready": True}]
    changed = deepcopy(value)
    changed["proof_consumer"]["artifact"]["artifact_sha256"] = "d" * 64
    invalid.append(changed)
    for candidate in invalid:
        try:
            verify(candidate)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Index receipt accepted a different identity or intermediate result")
    try:
        verify(value, [{**job, "conclusion": "failure"} for job in jobs])
    except RuntimeError:
        pass
    else:
        raise AssertionError("Index receipt accepted a failed proof job")


def verify_index_receipt(value, *, jobs, ci, consumer, fetch=None):
    fetch = fetch or api
    expected = {"status": "pass", "source_sha": ci["source_sha"], "workflow_sha": ci["workflow_sha"],
        "production_origin": ci["production_origin"], "main_consumer_artifact_id": consumer["artifact_id"],
        "main_consumer_job_id": consumer["job_id"], "release_ready": False}
    if any(value.get(key) != item for key, item in expected.items()):
        raise RuntimeError("Index receipt differs from the exact source, producer or main consumer")
    for role, prefix, job in (("qualification", "index-qualification", "attest-index-qualification"),
            ("proof_consumer", "index-proof-consumer", "index-proof-consumer")):
        item = value[role]
        if any(item.get(key) != data for key, data in successful_job(jobs, job).items()):
            raise RuntimeError("Index receipt has no exact successful " + job)
        bound = item["artifact"]
        name = f"cm-{linux_native()['key']}-" + prefix + "-" + ci["request_id"] + "-" + str(ci["run_attempt"])
        record = fetch("repos/" + ci["repository"] + "/actions/artifacts/" + str(bound["artifact_id"]))
        artifact_binding(record, bound["artifact_id"], name, bound["artifact_sha256"], ci["run_id"])
        if bound["artifact_name"] != name:
            raise RuntimeError("Index artifact name differs from the exact run/attempt")
    return value


def index_receipt(jobs, consumer, origin):
    from retry import checked_artifact, small_archive
    _, worker, sha, workflow_sha, request = identities()
    artifacts = {}
    for role, prefix, job in (("INDEX_QUALIFICATION", "index-qualification", "attest-index-qualification"),
            ("INDEX_PROOF", "index-proof-consumer", "index-proof-consumer")):
        artifact_id = int(os.environ["CM_" + role + "_ARTIFACT_ID"])
        record = checked_artifact(api("repos/" + worker + "/actions/artifacts/" + str(artifact_id)), int(os.environ["GITHUB_RUN_ID"]))
        bound = artifact_binding(record, artifact_id, f"cm-{linux_native()['key']}-" + prefix + "-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"],
            os.environ["CM_" + role + "_ARTIFACT_DIGEST"].removeprefix("sha256:"), int(os.environ["GITHUB_RUN_ID"]))
        artifacts[role] = {"artifact": bound, **successful_job(jobs, job)}
        if role == "INDEX_PROOF":
            with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
                with small_archive(worker, record, Path(directory) / "index-proof.zip") as archive:
                    acceptance = archive_json(archive, "acceptance.json")
                    binding = archive_json(archive, "proof-consumer-binding.json")
            assert acceptance["task_id"] == "CM-S03" and acceptance["status"] == "pass"
            assert acceptance["implementation_commit"] == sha and acceptance["post_consumer_qualification"] is True
            assert {row["id"] for row in acceptance["checks"]} == {"CM-S03-AC0" + str(index) for index in range(1, 7)}
            assert all(row["status"] == "pass" and row["post_consumer_qualification"] is True for row in acceptance["checks"])
            assert binding["production_origin"] == origin
            assert binding["provenance"] == {"CM_SOURCE_REPOSITORY": os.environ["CM_SOURCE_REPOSITORY"], "CM_SOURCE_SHA": sha,
                "GITHUB_REPOSITORY": worker, "GITHUB_WORKFLOW_SHA": workflow_sha, "GITHUB_RUN_ID": os.environ["GITHUB_RUN_ID"],
                "GITHUB_RUN_ATTEMPT": os.environ["GITHUB_RUN_ATTEMPT"], "CM_REQUEST_ID": request}
            assert binding["audit"]["status"] == "pass" and binding["audit"]["cache_mode"] == "none"
            assert binding["audit"]["isolation_probes"] == "pass" and not binding["audit"]["canary_hits"]
            assert all(row["compiler_linker_jit_build_service_calls"] == 0 for row in binding["audit"]["steps"].values())
            qualification = binding["qualification_artifact"]["artifact"]
            expected = artifacts["INDEX_QUALIFICATION"]["artifact"]
            assert qualification["id"] == expected["artifact_id"]
            assert qualification["digest"] == "sha256:" + expected["artifact_sha256"]
    return {"status": "pass", "source_sha": sha, "workflow_sha": workflow_sha, "production_origin": origin,
        "main_consumer_artifact_id": consumer["artifact_id"], "main_consumer_job_id": consumer["job_id"],
        "qualification": artifacts["INDEX_QUALIFICATION"], "proof_consumer": artifacts["INDEX_PROOF"], "release_ready": False}


def receipt():
    source, worker, sha, workflow_sha, request = identities()
    artifact_id = int(os.environ["CM_ARTIFACT_ID"])
    if artifact_id <= 0:
        raise RuntimeError("Actual upload artifact ID is required")
    digest = os.environ["CM_ARTIFACT_DIGEST"].removeprefix("sha256:")
    checked(digest, r"[0-9a-f]{64}", "actual upload artifact digest")
    origin = production_origin()
    artifact_name = origin["product_artifact"]["name"] if origin else f"cm-{linux_native()['key']}-task-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    actual = api("repos/" + worker + "/actions/artifacts/" + str(artifact_id))
    artifact_binding(actual, artifact_id, artifact_name, digest, origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"]))
    if origin and (artifact_id != origin["product_artifact"]["id"] or "sha256:" + digest != origin["product_artifact"]["digest"]):
        raise RuntimeError("Receipt product differs from the verified producer origin")
    names = [os.environ["CM_BUILD_JOB"]]
    if os.environ.get("CM_CONSUMER_REQUIRED") == "true":
        names.append("runtime-consumer")
    if os.environ.get("CM_DISTRIBUTION_REQUIRED") == "true":
        names.append("attest-distribution")
    if os.environ.get("CM_INDEX_REQUIRED") == "true":
        names.extend(("attest-index-qualification", "index-proof-consumer"))
    jobs = receipt_jobs("repos/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", names)
    producer_job = successful_job(jobs, os.environ["CM_BUILD_JOB"])
    ci = {"provider": "github_actions", "repository": worker, "source_repository": source,
          "head_sha": sha, "source_sha": sha, "workflow_sha": workflow_sha,
          "execution_role": "platform_builder", "cache_repository": worker, "request_id": request,
          "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
          "run_url": "https://github.com/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
          "workflow": ".github/workflows/build.yml", "job": os.environ["CM_BUILD_JOB"],
          "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": linux_native()["runner_arch"],
          "build_kind": build_request()[0],
          "target": TARGET, "conclusion": None, "artifact_name": artifact_name,
          "artifact_id": artifact_id, "artifact_sha256": digest, **producer_job,
          "production_origin": origin}
    consumer = None
    if os.environ.get("CM_CONSUMER_REQUIRED") == "true":
        consumer_id = int(os.environ["CM_CONSUMER_ARTIFACT_ID"])
        consumer_digest = checked(os.environ["CM_CONSUMER_ARTIFACT_DIGEST"].removeprefix("sha256:"), r"[0-9a-f]{64}", "consumer artifact digest")
        consumer_name = f"cm-{linux_native()['key']}-consumer-artifacts-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        record = api("repos/" + worker + "/actions/artifacts/" + str(consumer_id))
        artifact_binding(record, consumer_id, consumer_name, consumer_digest, int(os.environ["GITHUB_RUN_ID"]))
        actual_job = successful_job(jobs, "runtime-consumer")
        input_id = int(os.environ["CM_INPUT_ARTIFACT_ID"])
        input_digest = os.environ["CM_INPUT_ARTIFACT_DIGEST"].removeprefix("sha256:")
        input_name = origin["input_artifact"]["name"] if origin else f"cm-{linux_native()['key']}-runtime-inputs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        input_record = api("repos/" + worker + "/actions/artifacts/" + str(input_id))
        inputs = artifact_binding(input_record, input_id, input_name, input_digest, origin["run_id"] if origin else int(os.environ["GITHUB_RUN_ID"]))
        consumer = {"execution_role": "runtime_consumer", "cache_mode": "none", "job": "runtime-consumer",
            **actual_job, "producer_job_id": producer_job["job_id"], "input_artifact": inputs,
            "artifact_id": consumer_id, "artifact_name": consumer_name,
            "artifact_sha256": consumer_digest, "source_sha": sha, "workflow_sha": workflow_sha,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": request,
            "production_origin": origin, "validation_artifact": validation_artifact()}
        from retry import checked_artifact, small_archive, verify_test_build
        validation_ref = consumer["validation_artifact"]
        validation_record = checked_artifact(api("repos/" + worker + "/actions/artifacts/" +
            str(validation_ref["artifact_id"])), int(os.environ["GITHUB_RUN_ID"]))
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
            with small_archive(worker, validation_record, Path(directory) / "validation.zip") as archive:
                validation = archive_json(archive, "validation.json")
        assert validation["schema_version"] == 2 and validation["production_origin"] == origin
        expected = {"CM_SOURCE_REPOSITORY": source, "CM_SOURCE_SHA": sha, "GITHUB_REPOSITORY": worker,
            "GITHUB_WORKFLOW_SHA": workflow_sha, "GITHUB_RUN_ID": os.environ["GITHUB_RUN_ID"],
            "GITHUB_RUN_ATTEMPT": os.environ["GITHUB_RUN_ATTEMPT"], "CM_REQUEST_ID": request}
        assert validation["provenance"] == expected
        for label, test_build in validation["test_builds"].items():
            assert label == test_build["target"]
            verify_test_build(test_build)
        consumer["test_builds"] = validation["test_builds"]
    distribution = None
    if os.environ.get("CM_DISTRIBUTION_REQUIRED") == "true":
        proof_id = int(os.environ["CM_DISTRIBUTION_ARTIFACT_ID"])
        proof_digest = checked(os.environ["CM_DISTRIBUTION_ARTIFACT_DIGEST"].removeprefix("sha256:"),
            r"[0-9a-f]{64}", "distribution artifact digest")
        proof_name = f"cm-{linux_native()['key']}-distribution-proofs-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        record = api("repos/" + worker + "/actions/artifacts/" + str(proof_id))
        proof_ref = artifact_binding(record, proof_id, proof_name, proof_digest, int(os.environ["GITHUB_RUN_ID"]))
        distribution = {"job": "attest-distribution", **successful_job(jobs, "attest-distribution"),
            "artifact": proof_ref, "production_origin": origin, "consumer_job_id": consumer["job_id"]}
    index = index_receipt(jobs, consumer, origin) if os.environ.get("CM_INDEX_REQUIRED") == "true" else None
    out = Path(os.environ["RUNNER_TEMP"], "cm-worker-receipt")
    out.mkdir(exist_ok=True)
    (out / "worker-receipt.json").write_text(json.dumps({"schema_version": 1, "ci": ci, "consumer": consumer,
        "distribution": distribution, "index": index,
        "note": "Artifact identity verified; final workflow conclusion must be fetched after this run completes."}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        {"self-check": self_check, "preflight": preflight, "native-preflight": native_preflight,
         "native-preflight-self-check": native_preflight_self_check, "benchmark-preflight": benchmark_preflight,
         "verify-checkout": verify_checkout, "cache-save-plan": cache_save_plan, "verify-consumer": verify_consumer,
         "extract-consumer": extract_consumer, "restore-origin": restore_origin, "receipt": receipt}[sys.argv[1]]()
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM worker blocked/failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
