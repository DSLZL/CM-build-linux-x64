#!/usr/bin/env python3
"""Record an exact reviewed GitHub-hosted native run; never a local test entry point."""
import datetime
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import sysconfig
import cm_platforms


def require_hosted_linux():
    if os.environ.get("CM_EXECUTION_ROLE", "source_checks") != "source_checks":
        entry = require_hosted_worker()
        if entry["runner_os"] != "Linux":
            raise RuntimeError("This recipe requires a native GNU Linux worker")
        return
    required = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    wrong = [key for key, value in required.items() if os.environ.get(key) != value]
    if wrong:
        raise RuntimeError("CM compilation and tests require a GitHub-hosted Linux x64 job; missing/mismatched: " + ", ".join(wrong))


def require_hosted_worker(*, enabled=True):
    entry = cm_platforms.worker(root=Path(__file__).resolve().parents[2], enabled=enabled)
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": entry["runner_os"], "RUNNER_ARCH": entry["runner_arch"]}
    machine = platform.machine().lower()
    native_arch = "ARM64" if machine in ("aarch64", "arm64") else "X64" if machine in ("x86_64", "amd64") else None
    if (any(os.environ.get(key) != value for key, value in required.items())
            or platform.system() != {"macOS": "Darwin"}.get(entry["runner_os"], entry["runner_os"])
            or native_arch != entry["runner_arch"] or struct.calcsize("P") != 8
            or entry["runner_os"] == "Windows" and sysconfig.get_platform() !=
                {"X64": "win-amd64", "ARM64": "win-arm64"}[entry["runner_arch"]]):
        raise RuntimeError("Product work requires the exact GitHub-hosted native OS/architecture for " + entry["key"])
    return entry


def record(output):
    role = os.environ.get("CM_EXECUTION_ROLE", "source_checks")
    if role == "source_checks":
        require_hosted_linux()
        entry = cm_platforms.select()
    else:
        entry = require_hosted_worker(enabled=role != "platform_preflight")
        if role == "platform_preflight" and (entry["key"] != "linux-arm64" or os.environ.get("GITHUB_JOB") != "native-preflight"):
            raise RuntimeError("Disabled targets are restricted to the reviewed ARM64 mechanism preflight")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    source_root = os.environ.get("CM_SOURCE_DIR", os.environ["GITHUB_WORKSPACE"])
    head = (os.environ["CM_SOURCE_SHA"] if role == "runtime_consumer" else
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip())
    repository = os.environ["GITHUB_REPOSITORY"]
    source_repository = os.environ.get("CM_SOURCE_REPOSITORY", repository)
    source_sha = os.environ.get("CM_SOURCE_SHA", head)
    if source_sha != head:
        raise RuntimeError("Requested source SHA does not match the checked-out CM source")
    if role not in {"source_checks", "platform_builder", "runtime_consumer", "runtime_validation", "platform_preflight"}:
        raise RuntimeError("Unknown execution role")
    if source_repository != "DSLZL/CM":
        raise RuntimeError("Execution must bind the sole reviewed CM source repository")
    if role == "source_checks" and source_repository != repository:
        raise RuntimeError("Source checks must run in their source repository")
    if role in {"platform_builder", "runtime_consumer", "runtime_validation", "platform_preflight"} and (source_repository == repository or os.environ.get("CM_BUILDER_REPOSITORY") != repository):
        raise RuntimeError("Product builds require the distinct fixed builder repository")
    if role in {"runtime_consumer", "runtime_validation", "platform_preflight"} and (os.environ.get("CM_CACHE_MODE") != "none" or os.environ.get("ACTIONS_CACHE_MODE") != "none"):
        raise RuntimeError("Runtime consumer requires actual platform-enforced cache-mode none")
    identity = {"provider": "github_actions", "repository": repository,
                "source_repository": source_repository, "source_sha": source_sha, "head_sha": head,
                "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "execution_role": role,
                "cache_repository": repository if role == "platform_builder" else None,
                "source_checkout": role != "runtime_consumer",
                "request_id": os.environ.get("CM_REQUEST_ID"),
                "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                "workflow": os.environ["GITHUB_WORKFLOW_REF"], "job": os.environ["GITHUB_JOB"],
                "runner_environment": "github-hosted", "runner_os": entry["runner_os"], "runner_arch": entry["runner_arch"],
                "target": entry["target"], "conclusion": None}
    fields = ["GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
              "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_EVENT_NAME", "GITHUB_REF",
              "GITHUB_SHA", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"]
    fields += ["CM_PLATFORM", "CM_TARGET", "CM_CACHE_MODE", "ACTIONS_CACHE_MODE", "CM_SOURCE_REPOSITORY", "CM_SOURCE_SHA", "CM_BUILDER_REPOSITORY", "CM_REQUEST_ID", "CM_CARGO_CACHE_HIT", "CM_CARGO_CACHE_MATCH", "CM_SCCACHE_ARCHIVE_HIT", "CM_SCCACHE_ARCHIVE_MATCH"]
    previous = output / "run-metadata.json"
    observed = datetime.datetime.now(datetime.timezone.utc)
    first_observed = json.loads(previous.read_text(encoding="utf-8"))["first_observed_at_utc"] if previous.is_file() else observed.isoformat()
    data = {"schema_version": 2, "ci": identity, "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "first_observed_at_utc": first_observed,
            "elapsed_until_collection_seconds": round((observed - datetime.datetime.fromisoformat(first_observed)).total_seconds(), 3),
            "checkout_head": head, "job_status_at_collection": os.environ.get("CM_JOB_STATUS", "in_progress"),
            "context": {key: os.environ.get(key) for key in fields},
            "run_url": os.environ.get("GITHUB_SERVER_URL", "https://github.com") + "/" + os.environ["GITHUB_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]}
    identity["run_url"] = data["run_url"]
    (output / "run-metadata.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def self_check():
    import tempfile
    from unittest.mock import patch
    for key in cm_platforms.load()["platforms"]:
        entry = cm_platforms.select(key)
        system = {"macOS": "Darwin"}.get(entry["runner_os"], entry["runner_os"])
        machine = "arm64" if entry["runner_arch"] == "ARM64" else "AMD64"
        python_platform = "win-arm64" if entry["runner_arch"] == "ARM64" else "win-amd64"
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": entry["runner_os"], "RUNNER_ARCH": entry["runner_arch"]}
        with patch("cm_platforms.worker", return_value=entry), patch.dict(os.environ, env, clear=True), \
                patch("platform.system", return_value=system), patch("platform.machine", return_value=machine), \
                patch("struct.calcsize", return_value=8), patch("sysconfig.get_platform", return_value=python_platform):
            assert require_hosted_worker() == entry
            with patch.dict(os.environ, {"CM_EXECUTION_ROLE": "platform_builder"}):
                if entry["runner_os"] == "Linux":
                    require_hosted_linux()
                else:
                    try:
                        require_hosted_linux()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("A non-Linux worker entered the Linux recipe")
            for field, bad in (("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                    ("RUNNER_OS", "other"), ("RUNNER_ARCH", "other")):
                with patch.dict(os.environ, {field: bad}):
                    try:
                        require_hosted_worker()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("A mismatched native worker was accepted")
            for target, bad in (("platform.machine", "i386"), ("platform.system", "other"),
                    ("struct.calcsize", 4)):
                with patch(target, return_value=bad):
                    try:
                        require_hosted_worker()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("A non-native process was accepted")
            if entry["runner_os"] == "Windows":
                other = "win-amd64" if entry["runner_arch"] == "ARM64" else "win-arm64"
                for wrong in ("win32", other):
                    with patch("sysconfig.get_platform", return_value=wrong):
                        try:
                            require_hosted_worker()
                        except RuntimeError:
                            pass
                        else:
                            raise AssertionError("An emulated Windows Python was accepted")
    env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": "DSLZL/CM-build-linux-x64",
        "CM_PLATFORM": "linux-x64", "CM_TARGET": "x86_64-unknown-linux-gnu"}
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, env, clear=True), \
            patch("cm_platforms.__file__", str(Path(directory) / "runtime-inputs/cm_platforms.py")), \
            patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
        assert require_hosted_worker()["key"] == "linux-x64"
    entry = cm_platforms.select("linux-arm64")
    env = {"CM_EXECUTION_ROLE": "platform_preflight", "GITHUB_JOB": "native-preflight",
        "GITHUB_REPOSITORY": entry["repository"], "CM_BUILDER_REPOSITORY": entry["repository"],
        "CM_SOURCE_REPOSITORY": "DSLZL/CM", "CM_SOURCE_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40,
        "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": "reviewed",
        "CM_CACHE_MODE": "none", "ACTIONS_CACHE_MODE": "none", "GITHUB_WORKSPACE": "/unused"}
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, env, clear=True), \
            patch(__name__ + ".require_hosted_worker", return_value=entry) as guard, \
            patch("subprocess.check_output", return_value="a" * 40):
        record(directory)
        guard.assert_called_with(enabled=False)
        value = json.loads(Path(directory, "run-metadata.json").read_text())["ci"]
        assert value["execution_role"] == "platform_preflight" and value["cache_repository"] is None
        for changes in ({"GITHUB_JOB": "build-write"}, {"CM_CACHE_MODE": "read"}, {"ACTIONS_CACHE_MODE": "write"},
                {"CM_BUILDER_REPOSITORY": "other/repo"}, {"CM_SOURCE_SHA": "c" * 40}):
            with patch.dict(os.environ, changes):
                try:
                    record(directory)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Invalid native mechanism metadata authority accepted")


if __name__ == "__main__":
    try:
        record(sys.argv[1])
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM CI metadata error: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
