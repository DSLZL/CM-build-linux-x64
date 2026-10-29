"""Reuse exact remote products and independently audited runtime steps."""
import ast
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error

RUNTIME_FILES = (
    "ci/scripts/mod_author.py", "ci/scripts/mod_manifest.py", "ci/scripts/runtime_sdk.py",
    "ci/scripts/managed_package.py", "ci/scripts/runtime_state.py", "ci/scripts/ci_progress.py",
    "fixtures/runtime-consumer/driver.py", "fixtures/native-loader/core_acceptance.py",
    "fixtures/native-loader/tool_barrier.py", "fixtures/runtime-sdk/driver.py",
    "fixtures/managed-package/driver.py", "fixtures/state/driver.py", "fixtures/mod-author/driver.py",
)
PHASES = {
    "consumer-matrix": (("fixtures/runtime-consumer/driver.py", "matrix"),),
    "consumer-missing-library": (("fixtures/runtime-consumer/driver.py", "missing_library"),),
    "consumer-library-recovery": (("fixtures/runtime-consumer/driver.py", "recovery"),),
    "m01-consumer-matrix": (("ci/scripts/mod_manifest.py", "matrix"),),
    "m02-consumer-matrix": (("ci/scripts/runtime_sdk.py", "matrix"), ("fixtures/runtime-sdk/driver.py", "matrix")),
    "m03-consumer-matrix": (("ci/scripts/managed_package.py", "driver"), ("fixtures/managed-package/driver.py", "matrix")),
    "m04-consumer-matrix": (("ci/scripts/runtime_state.py", "driver"), ("fixtures/state/driver.py", "matrix")),
    "m05-consumer-matrix": (("ci/scripts/mod_author.py", "driver"), ("fixtures/mod-author/driver.py", "matrix")),
}
COMMON_TESTS = ("fixtures/native-loader/core_acceptance.py", "fixtures/native-loader/tool_barrier.py",
                "ci/scripts/ci_progress.py")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy():
    directory = os.environ.get("CM_WORKER_POLICY_DIR")
    if directory:
        sys.path.insert(0, directory)
    return importlib.import_module("worker_policy")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def source(root, revision, path):
    return git(root, "show", revision + ":" + path).decode("utf-8")


def projection(text, entries=None, exclude=()):
    module = ast.parse(text)
    definitions = {node.name: node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    if entries is None:
        wanted = set(definitions) - set(exclude)
    else:
        wanted = set(entries)
        assert wanted <= definitions.keys(), "Unknown runtime test entry point"
        pending = list(wanted)
        while pending:
            for node in ast.walk(definitions[pending.pop()]):
                if isinstance(node, ast.Name) and node.id in definitions and node.id not in wanted:
                    wanted.add(node.id)
                    pending.append(node.id)
    nodes = [node for node in module.body if
             (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in wanted)
             or (not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                 and not (isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"))]
    return digest([ast.dump(node, include_attributes=False) for node in nodes])


def test_inputs(root, revision):
    texts = {path: source(root, revision, path) for path in RUNTIME_FILES}
    common = {path: projection(texts[path]) for path in COMMON_TESTS}
    common["outer_audit"] = projection(source(root, revision, "ci/scripts/runtime_consumer.py"), ("observe",))
    # Control-flow/logging fixes preserve independently audited results; schema changes bump this version.
    common["checkpoint_protocol"] = 1
    result = {}
    for label, entries in PHASES.items():
        files = {path: projection(texts[path], (entry,)) for path, entry in entries}
        # These wrappers call shared metadata and SDK helpers across modules.
        if label.startswith(("m02-", "m03-", "m04-", "m05-")):
            files["ci/scripts/mod_manifest.py"] = projection(texts["ci/scripts/mod_manifest.py"], exclude=("matrix", "self_check"))
        if label.startswith(("m03-", "m04-", "m05-")):
            files["fixtures/runtime-sdk/driver.py"] = projection(texts["fixtures/runtime-sdk/driver.py"], exclude=("matrix", "self_check"))
        if label.startswith(("m04-", "m05-")):
            files["fixtures/managed-package/driver.py"] = projection(texts["fixtures/managed-package/driver.py"], exclude=("matrix", "self_check"))
        result[label] = digest({"protocol": 1, "common": common, "files": files})
    return result


def product_inputs(root, revision):
    tree = git(root, "ls-tree", "-rz", revision).split(b"\0")
    files = {}
    runtime_modules = {"ci/scripts/" + name + ".py": {"matrix", "self_check"} for name in
                       ("mod_author", "mod_manifest", "runtime_sdk", "managed_package", "runtime_state")}
    administrative = {"ci/scripts/retry.py", "ci/scripts/worker_policy.py", "ci/scripts/record_run.py",
                      "ci/scripts/dispatch_build.py", "ci/scripts/ci_progress.py", "ci/scripts/mod_contract.py",
                      "ci/source-files.txt", "ci/worker-files.json", ".github/cm-routing.json"}
    for row in filter(None, tree):
        metadata, name = row.split(b"\t", 1)
        path = name.decode()
        if (path in administrative or path.endswith(".md") or path.startswith(("docs/", ".github/workflows/", "ci/worker/"))
                or path.startswith("fixtures/") and path.endswith(".py")
                or "/.vscode/" in path or "/.github/" in path):
            continue
        if path == "ci/scripts/runtime_consumer.py":
            files[path] = projection(source(root, revision, path), ("produce",))
        elif path in runtime_modules:
            files[path] = projection(source(root, revision, path), exclude=runtime_modules[path])
        else:
            files[path] = metadata.decode()
    # Gate and upload changes do not change a compiler recipe. Commands still do.
    recipe = source(root, revision, "ci/worker/linux-recipe.yml")
    blocks = re.split(r"(?m)^      - name: ", recipe)[1:]
    commands = {"compiler_environment": recipe.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]}
    for block in blocks:
        name = block.splitlines()[0]
        if any(word in name for word in ("toolchain", "native dependencies", "Materialize", "Fetch locked", "bundled sandbox helper", "mapped current-task", "Run actual acceptance", "current author Mod")):
            match = re.search(r"(?m)^        run: ?(.*(?:\n          .*|\n)*)", block)
            commands[name] = match[1].strip() if match else block
    return {"files": files, "compiler_recipes": commands}


def environment():
    result = {name: os.environ.get(name) for name in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}
    assert all(result.values()), "Exact hosted runner image identity is required for reuse"
    return result


def artifact_ref(record):
    return {key: record[key] for key in ("id", "name", "digest", "size_in_bytes")}


def checked_artifact(record, run_id):
    if (record.get("expired") or record.get("workflow_run", {}).get("id") != run_id
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", record.get("digest", ""))):
        raise RuntimeError("Expired or unbound retry artifact")
    return record


def small_archive(worker, record, destination):
    if record["size_in_bytes"] > 64 * 1024 * 1024:
        raise RuntimeError("Oversized retry metadata/checkpoint archive")
    return policy().download_origin_archive(worker, record, destination)


def select(root, logs):
    p = policy()
    source_repo, worker, sha, workflow_sha, request = p.identities()
    plan = {"status": "miss", "production_inputs_sha256": digest(product_inputs(root, "HEAD")),
            "environment": environment(), "reason": "No compatible completed producer"}
    explicit = os.environ.get("CM_REUSE_RUN_ID", "")
    if explicit and not re.fullmatch(r"[1-9][0-9]*", explicit):
        raise RuntimeError("Invalid explicit reuse run ID")
    if os.environ.get("CM_BUILD_KIND") != "qualification":
        candidates = []
    elif explicit:
        candidates = [p.api("repos/" + worker + "/actions/runs/" + explicit)]
    else:
        candidates = p.api("repos/" + worker + "/actions/workflows/build.yml/runs?event=workflow_dispatch&per_page=12")["workflow_runs"]
    for run in candidates:
        if run["id"] == int(os.environ["GITHUB_RUN_ID"]) or run.get("path") != ".github/workflows/build.yml":
            continue
        try:
            jobs = p.api("repos/" + worker + "/actions/runs/" + str(run["id"]) + "/attempts/" + str(run["run_attempt"]) + "/jobs?per_page=100")["jobs"]
            producers = [j for j in jobs if j["name"] in ("build-read / linux-x64", "build-write / linux-x64") and j["conclusion"] == "success"]
            if len(producers) != 1:
                continue
            records = p.api("repos/" + worker + "/actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")["artifacts"]
            indexes = [a for a in records if a["name"].startswith("cm-linux-x64-validation-inputs-") and not a["expired"]]
            evidence = indexes or [a for a in records if a["name"].startswith("cm-linux-x64-evidence-") and not a["expired"]]
            if len(evidence) != 1:
                continue
            record = checked_artifact(evidence[0], run["id"])
            with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
                with small_archive(worker, record, Path(directory) / "metadata.zip") as archive:
                    if indexes:
                        old = p.archive_json(archive, "validation.json")
                        origin = old["production_origin"]
                        old_environment = old["environment"]
                    else:
                        metadata = p.archive_json(archive, "run-metadata.json")
                        ci = metadata["ci"]
                        if ci.get("execution_role") != "platform_builder" or ci["run_id"] != run["id"] or ci["run_attempt"] != run["run_attempt"]:
                            continue
                        origin = {"source_sha": ci["source_sha"], "workflow_sha": ci["workflow_sha"], "run_id": run["id"],
                                  "run_attempt": run["run_attempt"], "request_id": ci["request_id"], "job": producers[0]["name"], "job_id": producers[0]["id"]}
                        for kind, prefix in (("product", "cm-linux-x64-task-artifacts-"), ("input", "cm-linux-x64-runtime-inputs-")):
                            items = [a for a in records if a["name"] == prefix + ci["request_id"] + "-" + str(run["run_attempt"])]
                            if len(items) != 1:
                                raise RuntimeError("Missing exact producer artifact")
                            origin[kind + "_artifact"] = artifact_ref(checked_artifact(items[0], run["id"]))
                        old_environment = {key: metadata["context"].get(key) for key in environment()}
            if old_environment != environment() or digest(product_inputs(root, origin["source_sha"])) != plan["production_inputs_sha256"]:
                continue
            git(root, "merge-base", "--is-ancestor", origin["source_sha"], "HEAD")
            if p.api("repos/" + worker + "/compare/" + origin["workflow_sha"] + "..." + workflow_sha).get("status") not in ("ahead", "identical"):
                continue
            verify_production_origin(origin)
            resume = [a for a in records if a["name"].startswith("cm-linux-x64-consumer-checkpoints-") and not a["expired"]]
            plan.update(status="hit", reason="Exact production inputs and runner image unchanged", production_origin=origin,
                        checkpoint_origin={"run_id": run["id"], "run_attempt": run["run_attempt"],
                                           "source_sha": old["provenance"]["CM_SOURCE_SHA"] if indexes else origin["source_sha"],
                                           "workflow_sha": run["head_sha"],
                                           "artifact": artifact_ref(checked_artifact(resume[0], run["id"]))} if len(resume) == 1 else None)
            break
        except (KeyError, ValueError, RuntimeError, subprocess.SubprocessError, urllib.error.HTTPError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (404, 410):
                raise
            if explicit:
                raise RuntimeError("Explicit reuse origin rejected: " + str(error)) from error
            print("CM retry: rejected candidate", run["id"], type(error).__name__, flush=True)
    if explicit and plan["status"] != "hit":
        raise RuntimeError("Explicit producer environment or inputs changed; refusing an implicit rebuild")
    write(logs / "retry-plan.json", plan)
    outputs = {"reused": str(plan["status"] == "hit").lower()}
    if plan["status"] == "hit":
        origin = plan["production_origin"]
        outputs.update(artifact_id=origin["product_artifact"]["id"], artifact_digest=origin["product_artifact"]["digest"],
                       input_artifact_id=origin["input_artifact"]["id"], input_artifact_digest=origin["input_artifact"]["digest"],
                       production_origin=json.dumps(origin, separators=(",", ":")))
    p.output(outputs)
    print("CM producer reuse:", plan["status"], plan["reason"], flush=True)


def verify_production_origin(origin, *, worker=None, fetch=None):
    p = policy()
    worker = worker or p.identities()[1]
    fetch = fetch or p.api
    assert all(re.fullmatch(r"[0-9a-f]{40}", origin[key]) for key in ("source_sha", "workflow_sha"))
    assert origin["job"] in ("build-read / linux-x64", "build-write / linux-x64")
    assert type(origin["run_id"]) is int and origin["run_id"] > 0
    assert type(origin["run_attempt"]) is int and origin["run_attempt"] > 0
    run_id = int(origin["run_id"])
    run = fetch("repos/" + worker + "/actions/runs/" + str(run_id))
    if run["run_attempt"] != origin["run_attempt"] or run["head_sha"] != origin["workflow_sha"] or run["event"] != "workflow_dispatch" or run["path"] != ".github/workflows/build.yml" or run["display_title"] != "CM Linux x64 / " + origin["request_id"]:
        raise RuntimeError("Producer origin run/attempt/workflow/request changed")
    jobs = fetch("repos/" + worker + "/actions/runs/" + str(run_id) + "/attempts/" + str(origin["run_attempt"]) + "/jobs?per_page=100")["jobs"]
    job = p.successful_job(jobs, origin["job"])
    if job["job_id"] != origin["job_id"]:
        raise RuntimeError("Producer origin job changed")
    records = {}
    for key in ("product_artifact", "input_artifact"):
        expected = origin[key]
        actual = checked_artifact(fetch("repos/" + worker + "/actions/artifacts/" + str(expected["id"])), run_id)
        prefix = "cm-linux-x64-" + ("task-artifacts-" if key == "product_artifact" else "runtime-inputs-")
        if artifact_ref(actual) != expected or actual["name"] != prefix + origin["request_id"] + "-" + str(origin["run_attempt"]):
            raise RuntimeError("Producer artifact identity changed")
        records[key] = actual
    return records


def overlay(root, logs):
    import runtime_consumer
    import runtime_composition
    p = policy()
    plan = read(logs / "retry-plan.json")
    if plan["status"] == "hit":
        origin = plan["production_origin"]
    else:
        for attempt in range(12):
            jobs = p.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100")["jobs"]
            producers = [j for j in jobs if j["name"] in ("build-read / linux-x64", "build-write / linux-x64") and j["status"] == "in_progress"]
            if len(producers) == 1:
                break
            if attempt < 11:
                time.sleep(5)
        assert len(producers) == 1, "Actual producer job identity unavailable"
        producer = producers[0]
        origin = {"source_sha": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
                  "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                  "request_id": os.environ["CM_REQUEST_ID"], "job": producer["name"], "job_id": producer["id"]}
        for key, variable in (("product_artifact", "CM_CURRENT_ARTIFACT_ID"), ("input_artifact", "CM_CURRENT_INPUT_ARTIFACT_ID")):
            origin[key] = artifact_ref(checked_artifact(p.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + os.environ[variable]), origin["run_id"]))
    destination = Path(os.environ["CM_VALIDATION_INPUT_DIR"])
    destination.mkdir()
    for path in RUNTIME_FILES:
        target = destination / "fixture" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / path, target)
    for name in ("runtime_consumer.py", "ci_progress.py", "retry.py"):
        shutil.copyfile(root / "ci/scripts" / name, destination / name)
    (destination / "observer.py").write_text(runtime_consumer.runtime_observer_source(runtime_composition), encoding="utf-8")
    baseline = plan.get("checkpoint_origin")
    write(destination / "validation.json", {"schema_version": 1, "provenance": runtime_consumer.provenance(),
        "environment": environment(), "production_inputs_sha256": plan["production_inputs_sha256"],
        "production_origin": origin, "checkpoint_origin": baseline,
        "test_inputs": test_inputs(root, "HEAD"),
        "baseline_test_inputs": test_inputs(root, baseline["source_sha"]) if baseline else {},
        "files": runtime_consumer.inventory(destination)})
    p.output({"production_origin": json.dumps(origin, separators=(",", ":"))})


def refresh():
    import runtime_consumer as runtime
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    overlay_dir = Path(os.environ["CM_VALIDATION_INPUT_DIR"])
    validation = read(overlay_dir / "validation.json")
    assert validation["provenance"] == runtime.provenance() and validation["environment"] == environment()
    assert validation["production_origin"] == json.loads(os.environ["CM_PRODUCTION_ORIGIN"])
    assert validation["files"] == [e for e in runtime.inventory(overlay_dir) if e["path"] != "validation.json"]
    original = runtime.validate_inputs(inputs)
    old = original["files"]
    for entry in validation["files"]:
        assert "link" not in entry and entry["path"] in {
            "runtime_consumer.py", "ci_progress.py", "retry.py", "observer.py", *("fixture/" + path for path in RUNTIME_FILES)}
        target = inputs / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(overlay_dir / entry["path"], target)
    allowed = {e["path"] for e in validation["files"]}
    assert [e for e in old if e["path"] not in allowed] == [e for e in runtime.inventory(inputs) if e["path"] not in allowed | {"input-manifest.json"}]
    validation["original_input_manifest_sha256"] = original["sha256"]
    write(inputs / "validation.json", validation)
    entries = [e for e in runtime.inventory(inputs) if e["path"] != "input-manifest.json"]
    write(inputs / "input-manifest.json", {"files": entries, "sha256": runtime.digest(entries)})
    checkpoint = validation["checkpoint_origin"]
    if checkpoint:
        worker = os.environ["GITHUB_REPOSITORY"]
        record = checked_artifact(policy().api("repos/" + worker + "/actions/artifacts/" + str(checkpoint["artifact"]["id"])), checkpoint["run_id"])
        assert artifact_ref(record) == checkpoint["artifact"]
        destination = Path(os.environ["RUNNER_TEMP"]) / "cm-runtime-resume"
        destination.mkdir()
        with small_archive(worker, record, destination / "checkpoint.zip") as archive:
            total = 0
            seen = set()
            for entry in archive.infolist():
                path = Path(entry.filename)
                if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename
                        or entry.filename in seen or entry.file_size > 16 * 1024 ** 2
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise RuntimeError("Invalid runtime checkpoint path/size")
                seen.add(entry.filename)
                if entry.is_dir():
                    continue
                total += entry.file_size
                assert total <= 512 * 1024 ** 2
                data = archive.read(entry)
                data.decode("utf-8")
                assert b"\0" not in data
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        with open(os.environ["GITHUB_ENV"], "a") as stream:
            stream.write("CM_RUNTIME_RESUME_DIR=" + str(destination) + "\n")


def rootfs_key(closure):
    return digest({"packages": closure["packages"], "files": [entry for entry in closure["files"]
        if not entry["path"].startswith("fixture/") and entry["path"] != "inputs/producer.json"]})


class Checkpoints:
    """A pass is reusable only after its own outer audit and immutable-input check."""

    def __init__(self, runtime, validation, closure, temp, evidence, logs, reports, canary_hits):
        self.runtime, self.validation, self.closure = runtime, validation, closure
        self.temp, self.evidence, self.logs = temp, evidence, logs
        self.reports, self.canary_hits = reports, canary_hits
        self.directory = Path(os.environ["CM_RUNTIME_CHECKPOINT_DIR"])
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.results = {}
        self.commands = {}
        self.index = {"schema_version": 1, "provenance": runtime.provenance(),
            "environment": validation["environment"], "rootfs_key": rootfs_key(closure),
            "test_inputs": validation["test_inputs"], "steps": {}}
        self.previous = None
        previous = os.environ.get("CM_RUNTIME_RESUME_DIR")
        if previous and (Path(previous) / "index.json").is_file():
            old = read(Path(previous) / "index.json")
            origin = validation["checkpoint_origin"]
            expected = {"GITHUB_RUN_ID": str(origin["run_id"]), "GITHUB_RUN_ATTEMPT": str(origin["run_attempt"]),
                        "GITHUB_WORKFLOW_SHA": origin["workflow_sha"], "CM_SOURCE_SHA": origin["source_sha"]}
            if (old["schema_version"] == 1 and old["environment"] == self.index["environment"]
                    and old["rootfs_key"] == self.index["rootfs_key"]
                    and old["test_inputs"] == validation["baseline_test_inputs"]
                    and all(old["provenance"].get(k) == v for k, v in expected.items())):
                self.previous = (Path(previous), old)
        write(self.directory / "index.json", self.index)

    def owns(self, label, path):
        name = path.as_posix()
        if label == "consumer-missing-library":
            return name == "missing-library.json" or name.startswith("failures/missing-library/")
        if label == "consumer-library-recovery":
            return name in ("actual-missing-library-recovery.json", "recovery-environment.json") or name.startswith("recoveries/actual-missing-library/")
        if label.startswith("m0"):
            prefix = label.split("-")[0]
            return name.startswith(prefix + "/") or name.startswith(prefix + "-") or name in self.reports[label]
        reserved = {p for key, paths in self.reports.items() if key != label for p in paths}
        return (not name.startswith(("m01", "m02", "m03", "m04", "m05", "probe", "syscalls.",
                                     "failures/missing-library/", "recoveries/actual-missing-library/"))
                and name not in reserved | {"outer-runtime-audit.json", "missing-library.json",
                    "actual-missing-library-recovery.json", "recovery-environment.json", "step-results.json", "isolation-probes.json"})

    def files(self, label):
        return [p for p in sorted(self.evidence.rglob("*")) if p.is_file() and not p.is_symlink()
                and p.suffix in {".json", ".jsonl", ".log"}
                and self.owns(label, p.relative_to(self.evidence))]

    def key(self, label):
        return digest({"rootfs": self.index["rootfs_key"], "environment": self.index["environment"],
                       "test": self.index["test_inputs"][label], "command": self.commands[label]})

    def restore(self, label):
        if not self.previous:
            return None
        directory, old = self.previous
        step = old["steps"].get(label)
        if not step or step["status"] != "pass" or step["key"] != self.key(label):
            return None
        source_dir = directory / label
        assert self.runtime.inventory(source_dir) == step["files"], "Checkpoint bytes changed"
        audit = read(source_dir / "audit.json")
        assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
        assert not audit["unclassified_executable_memory"]
        for entry in step["files"]:
            path = Path(entry["path"])
            assert "link" not in entry and (path == Path("audit.json") or path.parts[0] == "evidence")
            if path.parts[0] == "evidence":
                relative = path.relative_to("evidence")
                assert self.owns(label, relative), "Checkpoint crosses a test boundary"
                target = self.evidence / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_dir / path, target)
        shutil.copytree(source_dir, self.directory / label)
        with self.lock:
            self.index["steps"][label] = step
            write(self.directory / "index.json", self.index)
        return {"status": "pass", "kind": "reused", "origin": step["origin"], "audit": audit,
                "checkpoint_artifact": self.validation["checkpoint_origin"]["artifact"]}

    def save(self, label, audit):
        import mod_manifest
        destination = self.directory / label
        destination.mkdir()
        for path in self.files(label):
            assert path.suffix in {".json", ".jsonl", ".log"}, "Unexpected checkpoint file"
            data = path.read_bytes()
            assert b"\0" not in data and len(data) <= 16 * 1024 ** 2
            target = destination / "evidence" / path.relative_to(self.evidence)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(mod_manifest.redact(data.decode("utf-8")), encoding="utf-8")
        write(destination / "audit.json", audit)
        self.runtime.check_evidence_redaction(list(destination.rglob("*")))
        step = {"status": "pass", "key": self.key(label), "origin": self.runtime.provenance(),
                "files": self.runtime.inventory(destination)}
        with self.lock:
            self.index["steps"][label] = step
            write(self.directory / "index.json", self.index)
        return {"status": "pass", "kind": "executed", "origin": step["origin"], "audit": audit}

    def run(self, logs, label, command, timeout):
        import ci_progress
        started = time.monotonic()
        self.commands[label] = [part.replace(str(self.temp), "<consumer-root>")
            .replace(os.environ.get("CM_CONSUMER_INPUT_DIR", "<unset-runtime-inputs>"), "<runtime-inputs>") for part in command]
        try:
            result = self.restore(label)
            if result is None:
                completed = ci_progress.run(logs, label, command, timeout)
                assert completed.returncode == 0, "Runtime step failed: " + label
                for name in self.reports.get(label, ()):
                    assert read(self.evidence / name)["status"] == "behavior_pass", "Incomplete step report: " + name
                paths = self.files(label)
                audit = self.runtime.observe(self.temp / "trusted-observer" / label, self.evidence,
                    consumer_root=self.temp, result_paths=[p for p in paths if p.name == "result.json"])
                assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
                assert not audit["unclassified_executable_memory"]
                assert self.runtime.inventory(self.temp / "rootfs") == self.closure["files"], "Runtime inputs changed"
                assert not self.canary_hits
                result = self.save(label, audit)
            else:
                ci_progress.emit(label + "/reuse", "done", started)
                print("CM runtime reuse:", label, "origin run", result["origin"]["GITHUB_RUN_ID"], flush=True)
            with self.lock:
                self.results[label] = result
            return subprocess.CompletedProcess(command, 0)
        except Exception as error:
            with self.lock:
                self.results[label] = {"status": "failed", "kind": "executed", "error": repr(error)}
            ci_progress.emit(label, "failed", started)
            return subprocess.CompletedProcess(command, 1)
        finally:
            with self.lock:
                write(logs / "runtime-step-results.json", {key: {k: v for k, v in row.items() if k != "audit"}
                    for key, row in self.results.items()})


def self_check():
    from unittest.mock import patch
    text = "X = 1\ndef shared(): return X\ndef passed(): return shared()\ndef failed(): return 0\n"
    assert projection(text, ("passed",)) == projection(text.replace("return 0", "return 1"), ("passed",))
    assert projection(text, ("failed",)) != projection(text.replace("return 0", "return 1"), ("failed",))
    assert projection(text, ("passed",)) != projection(text.replace("X = 1", "X = 2"), ("passed",))
    root = Path(os.environ["GITHUB_WORKSPACE"])
    if not (root / "ci/scripts").is_dir():
        root = Path(os.environ["CM_SOURCE_DIR"])
    assert set(test_inputs(root, "HEAD")) == set(PHASES)
    assert product_inputs(root, "HEAD")["files"]
    base = {"packages": {"libc6": "1"}, "files": [{"path": "usr/bin/python3", "sha256": "a"}, {"path": "fixture/test.py", "sha256": "a"}]}
    changed = json.loads(json.dumps(base))
    changed["files"][1]["sha256"] = "b"
    assert rootfs_key(base) == rootfs_key(changed)
    changed["packages"]["libc6"] = "2"
    assert rootfs_key(base) != rootfs_key(changed)
    with patch.dict(os.environ, {"CM_SOURCE_REPOSITORY": os.environ["GITHUB_REPOSITORY"],
            "CM_SOURCE_SHA": git(root, "rev-parse", "HEAD").decode().strip(), "CM_REQUEST_ID": "retry-self-check"}):
        checkpoint_self_check()
    origin_self_check()
    print("CM retry input/dependency/environment self-checks passed", flush=True)


def checkpoint_self_check():
    from unittest.mock import patch
    import runtime_consumer as runtime
    import ci_progress
    calls = []
    labels = ("consumer-matrix", "m01-consumer-matrix")
    audit = {"status": "pass", "compiler_linker_jit_build_service_calls": 0, "unclassified_executable_memory": []}
    provenance = runtime.provenance()
    origin = {"run_id": int(provenance["GITHUB_RUN_ID"]), "run_attempt": int(provenance["GITHUB_RUN_ATTEMPT"]),
              "source_sha": provenance["CM_SOURCE_SHA"], "workflow_sha": provenance["GITHUB_WORKFLOW_SHA"],
              "artifact": {"id": 1, "digest": "sha256:" + "a" * 64}}
    validation = {"environment": environment(), "test_inputs": {label: "a" for label in labels},
                  "baseline_test_inputs": {label: "a" for label in labels}, "checkpoint_origin": origin}
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        temp, evidence, logs = (directory / name for name in ("temp", "evidence", "logs"))
        for path in (temp / "rootfs", evidence, logs):
            path.mkdir(parents=True)
        closure = {"packages": {}, "files": []}
        reports = {labels[0]: ("passed.json",), labels[1]: ("failed.json",)}

        def run(logs, label, command, timeout):
            calls.append(label)
            if label == labels[1] and calls.count(label) == 1:
                return subprocess.CompletedProcess(command, 1)
            write(evidence / reports[label][0], {"status": "behavior_pass"})
            return subprocess.CompletedProcess(command, 0)

        env = {"CM_RUNTIME_CHECKPOINT_DIR": str(directory / "first"), "CM_RUNTIME_RESUME_DIR": ""}
        with patch.dict(os.environ, env), patch.object(ci_progress, "run", run), patch.object(runtime, "observe", return_value=audit):
            write(evidence / "isolation-probes.json", {"current_probe": 1})
            (evidence / "A.entered").touch()
            first = Checkpoints(runtime, validation, closure, temp, evidence, logs, reports, [])
            assert first.run(logs, labels[0], [], 1).returncode == 0
            assert first.run(logs, labels[1], [], 1).returncode != 0
            assert set(read(directory / "first/index.json")["steps"]) == {labels[0]}
            shutil.rmtree(evidence)
            evidence.mkdir()
            write(evidence / "isolation-probes.json", {"current_probe": 2})
            os.environ.update(CM_RUNTIME_CHECKPOINT_DIR=str(directory / "second"), CM_RUNTIME_RESUME_DIR=str(directory / "first"))
            second = Checkpoints(runtime, validation, closure, temp, evidence, logs, reports, [])
            assert second.run(logs, labels[0], [], 1).returncode == 0
            assert second.run(logs, labels[1], [], 1).returncode == 0
            assert calls == [labels[0], labels[1], labels[1]], "A passed step executed again after a different step failed"
            assert second.results[labels[0]]["kind"] == "reused" and second.results[labels[0]]["origin"] == provenance
            assert read(evidence / "isolation-probes.json") == {"current_probe": 2}
            assert not (directory / "second" / labels[0] / "evidence/A.entered").exists()
            # A changed test reruns only that step; changed bytes and failed audits never become hits.
            validation["test_inputs"][labels[0]] = "changed"
            os.environ["CM_RUNTIME_CHECKPOINT_DIR"] = str(directory / "third")
            third = Checkpoints(runtime, validation, closure, temp, evidence, logs, reports, [])
            third.commands[labels[0]] = []
            assert third.restore(labels[0]) is None
            validation["test_inputs"][labels[0]] = "a"
            third.commands[labels[0]] = ["changed-runtime-command"]
            assert third.restore(labels[0]) is None
            third.commands[labels[0]] = []
            (directory / "first" / labels[0] / "audit.json").write_text("{}")
            try:
                third.restore(labels[0])
            except AssertionError:
                pass
            else:
                raise AssertionError("Tampered checkpoint accepted")
            os.environ.update(CM_RUNTIME_CHECKPOINT_DIR=str(directory / "fourth"), CM_RUNTIME_RESUME_DIR="")
            with patch.object(runtime, "observe", side_effect=AssertionError("Rejected outer audit")):
                fourth = Checkpoints(runtime, validation, closure, temp, evidence, logs, reports, [])
                assert fourth.run(logs, labels[0], [], 1).returncode != 0
                assert not read(directory / "fourth/index.json")["steps"]


def origin_self_check():
    from types import SimpleNamespace
    from unittest.mock import patch
    p = policy()
    origin = {"source_sha": "a" * 40, "workflow_sha": "b" * 40, "request_id": "retry-self-check",
              "run_id": 10, "run_attempt": 1, "job": "build-write / linux-x64", "job_id": 20}
    records = {}
    for number, (key, prefix) in enumerate((("product_artifact", "task-artifacts"), ("input_artifact", "runtime-inputs")), 1):
        records[number] = {"id": number, "name": "cm-linux-x64-" + prefix + "-retry-self-check-1",
            "digest": "sha256:" + "c" * 64, "size_in_bytes": 1, "expired": False, "workflow_run": {"id": 10}}
        origin[key] = artifact_ref(records[number])

    def api(path):
        if path.endswith("/jobs?per_page=100"):
            return {"jobs": [{"name": origin["job"], "id": 20, "conclusion": "success"}]}
        if "/actions/artifacts/" in path:
            return records[int(path.rsplit("/", 1)[1])]
        return {"run_attempt": 1, "head_sha": "b" * 40, "event": "workflow_dispatch",
                "path": ".github/workflows/build.yml", "display_title": "CM Linux x64 / retry-self-check"}

    stub = SimpleNamespace(identities=lambda: ("DSLZL/CM", "DSLZL/CM-build-linux-x64", "a" * 40, "b" * 40, "retry-self-check"),
                           api=api, successful_job=p.successful_job)
    with patch(__name__ + ".policy", return_value=stub):
        verify_production_origin(origin)
        assert verify_production_origin(origin, worker="DSLZL/CM-build-linux-x64", fetch=api)["input_artifact"] == records[2]
        for key, value in (("expired", True), ("workflow_run", {"id": 11}), ("digest", "sha256:" + "d" * 64)):
            original = records[1][key]
            records[1][key] = value
            try:
                verify_production_origin(origin)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Changed/expired/cross-run producer artifact accepted")
            records[1][key] = original


if __name__ == "__main__":
    if sys.argv[1] == "self-check":
        policy().require_hosted_linux()
        self_check()
    elif sys.argv[1] == "refresh":
        refresh()
    else:
        root = Path(os.environ["CM_SOURCE_DIR"])
        logs = Path(os.environ["CM_CI_LOG_DIR"])
        {"plan": select, "overlay": overlay}[sys.argv[1]](root, logs)
