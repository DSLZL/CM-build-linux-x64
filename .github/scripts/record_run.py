#!/usr/bin/env python3
"""Record a GitHub-hosted Linux x64 run; this is not a local test entry point."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys


def require_hosted_linux():
    required = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    wrong = [key for key, value in required.items() if os.environ.get(key) != value]
    if wrong:
        raise RuntimeError("CM compilation and tests require a GitHub-hosted Linux x64 job; missing/mismatched: " + ", ".join(wrong))


def record(output):
    require_hosted_linux()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    role = os.environ.get("CM_EXECUTION_ROLE", "source_checks")
    source_root = os.environ.get("CM_SOURCE_DIR", os.environ["GITHUB_WORKSPACE"])
    head = (os.environ["CM_SOURCE_SHA"] if role == "runtime_consumer" else
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip())
    repository = os.environ["GITHUB_REPOSITORY"]
    source_repository = os.environ.get("CM_SOURCE_REPOSITORY", repository)
    source_sha = os.environ.get("CM_SOURCE_SHA", head)
    if source_sha != head:
        raise RuntimeError("Requested source SHA does not match the checked-out CM source")
    if role not in {"source_checks", "platform_builder", "runtime_consumer"}:
        raise RuntimeError("Unknown execution role")
    if role == "source_checks" and source_repository != repository:
        raise RuntimeError("Source checks must run in their source repository")
    if role in {"platform_builder", "runtime_consumer"} and (source_repository == repository or os.environ.get("CM_BUILDER_REPOSITORY") != repository):
        raise RuntimeError("Product builds require the distinct fixed builder repository")
    if role == "runtime_consumer" and (os.environ.get("CM_CACHE_MODE") != "none" or os.environ.get("ACTIONS_CACHE_MODE") != "none"):
        raise RuntimeError("Runtime consumer requires actual platform-enforced cache-mode none")
    identity = {"provider": "github_actions", "repository": repository,
                "source_repository": source_repository, "source_sha": source_sha, "head_sha": head,
                "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "execution_role": role,
                "cache_repository": repository if role == "platform_builder" else None,
                "source_checkout": role != "runtime_consumer",
                "request_id": os.environ.get("CM_REQUEST_ID"),
                "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                "workflow": os.environ["GITHUB_WORKFLOW_REF"], "job": os.environ["GITHUB_JOB"],
                "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": "X64",
                "target": "x86_64-unknown-linux-gnu", "conclusion": None}
    fields = ["GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
              "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_EVENT_NAME", "GITHUB_REF",
              "GITHUB_SHA", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"]
    fields += ["CM_CACHE_MODE", "ACTIONS_CACHE_MODE", "CM_SOURCE_REPOSITORY", "CM_SOURCE_SHA", "CM_BUILDER_REPOSITORY", "CM_REQUEST_ID", "CM_CARGO_CACHE_HIT", "CM_CARGO_CACHE_MATCH", "CM_SCCACHE_ARCHIVE_HIT", "CM_SCCACHE_ARCHIVE_MATCH"]
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


if __name__ == "__main__":
    try:
        record(sys.argv[1])
    except (RuntimeError, KeyError, IndexError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CM CI metadata error: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
