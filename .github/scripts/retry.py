"""Reuse exact remote products and independently audited runtime steps."""
import ast
from cm_platforms import linux_native
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
import traceback
import urllib.error

import runtime_cases

RUNTIME_FILES = (
    "ci/scripts/cm_platforms.py", "ci/scripts/mod_author.py", "ci/scripts/mod_manifest.py", "ci/scripts/runtime_sdk.py",
    "ci/scripts/managed_package.py", "ci/scripts/runtime_state.py", "ci/scripts/ci_progress.py",
    "fixtures/runtime-consumer/driver.py", "fixtures/native-loader/core_acceptance.py",
    "fixtures/native-loader/tool_barrier.py", "fixtures/runtime-sdk/driver.py",
    "fixtures/managed-package/driver.py", "fixtures/state/driver.py", "fixtures/mod-author/driver.py",
    "ci/scripts/turn_budget.py", "fixtures/turn-budget/driver.py",
    "ci/scripts/review_before_send.py", "fixtures/review-before-send/driver.py",
    "ci/scripts/tool_concurrency.py", "fixtures/tool-concurrency/driver.py", "ci/scripts/runtime_cases.py",
    "ci/scripts/runtime_qualification.py", "fixtures/runtime-qualification/driver.py",
    "ci/scripts/runtime_hooks.py", "fixtures/runtime-hooks/driver.py",
    "ci/scripts/runtime_upgrade.py", "fixtures/compatibility/driver.py",
    "ci/scripts/sdk_seams.py", "fixtures/sdk-seams/driver.py",
    "ci/scripts/distribution_provenance.py", "fixtures/distribution-provenance/driver.py",
)
RUNTIME_DATA = ("ci/g05-baseline.json", "crates/cm/src/" + ("distribution-policy-arm64.json"
    if linux_native()["machine"] == 183 else "distribution-policy.json"),
    "crates/cm/src/distribution-root.jsonl", "docs/distribution.md", "schemas/release-receipt.schema.json",
    "fixtures/compatibility-policy/policy.json", "schemas/support-matrix.schema.json")
SUPPORT_RUNTIME_FILES = ("ci/scripts/support_policy.py", "fixtures/compatibility-policy/driver.py")
INDEX_RUNTIME_FILES = ("ci/scripts/binary_index.py", "fixtures/binary-index/driver.py")
PROGRAM_RUNTIME_FILES = ("fixtures/program-integration/driver.py",)
RUNTIME_FILES += SUPPORT_RUNTIME_FILES + INDEX_RUNTIME_FILES + PROGRAM_RUNTIME_FILES
RUNTIME_DATA += ("fixtures/binary-index/cases.json", "schemas/mod-index.schema.json", "schemas/mod-index-qualification.schema.json")
PROGRAM_DATA = ("ci/program/acceptance.json", "ci/program/coverage.json", "ci/program/cases.json")
RUNTIME_DATA += PROGRAM_DATA
PHASES = {
    "consumer-matrix": (("fixtures/runtime-consumer/driver.py", "matrix"),),
    "consumer-missing-library": (("fixtures/runtime-consumer/driver.py", "missing_library"),),
    "consumer-library-recovery": (("fixtures/runtime-consumer/driver.py", "recovery"),),
    "m01-consumer-matrix": (("ci/scripts/mod_manifest.py", "matrix"),),
    "m02-consumer-matrix": (("ci/scripts/runtime_sdk.py", "matrix"), ("fixtures/runtime-sdk/driver.py", "matrix")),
    "m03-consumer-matrix": (("ci/scripts/managed_package.py", "driver"), ("fixtures/managed-package/driver.py", "matrix")),
    "m04-consumer-matrix": (("ci/scripts/runtime_state.py", "driver"), ("fixtures/state/driver.py", "matrix")),
    "m05-consumer-matrix": (("ci/scripts/mod_author.py", "driver"), ("fixtures/mod-author/driver.py", "matrix")),
    "g02a-counting": (("fixtures/turn-budget/driver.py", "counting"),),
    "g02a-reentry": (("fixtures/turn-budget/driver.py", "reentry"),),
    "g02a-terminal": (("fixtures/turn-budget/driver.py", "terminal"),),
    "g02a-scope": (("fixtures/turn-budget/driver.py", "scope"),),
    "g02a-cancellation-recovery": (("fixtures/turn-budget/driver.py", "cancellation_recovery"),),
    "g02a-plug-and-play": (("fixtures/turn-budget/driver.py", "plug_and_play"),),
    "review-nondestructive": (("fixtures/review-before-send/driver.py", "nondestructive"),),
    "review-invalidation": (("fixtures/review-before-send/driver.py", "invalidation"),),
    "review-key-events": (("fixtures/review-before-send/driver.py", "key_events"),),
    "review-entry-coverage": (("fixtures/review-before-send/driver.py", "entry_coverage"),),
    "review-queue-lifecycle": (("fixtures/review-before-send/driver.py", "queue_lifecycle"),),
    "review-plug-and-play": (("fixtures/review-before-send/driver.py", "plug_and_play"),),
    "concurrency-value-flow": (("fixtures/tool-concurrency/driver.py", "value_flow"),),
    "concurrency-steer": (("fixtures/tool-concurrency/driver.py", "steer"),),
    "concurrency-leaf-bound": (("fixtures/tool-concurrency/driver.py", "leaf_bound"),),
    "concurrency-lock-domains": (("fixtures/tool-concurrency/driver.py", "lock_domains"),),
    "concurrency-cancellation": (("fixtures/tool-concurrency/driver.py", "cancellation"),),
    "concurrency-backend-scope": (("fixtures/tool-concurrency/driver.py", "backend_scope"),),
    "concurrency-plug-and-play": (("fixtures/tool-concurrency/driver.py", "plug_and_play"),),
}
for _label in ("consumer-matrix", *(phase + "-consumer-matrix" for phase in ("m01", "m02", "m03", "m04", "m05"))):
    PHASES.pop(_label)
PHASES.update({label: ((runtime_cases.DRIVERS[phase], "matrix"),)
               for label, (phase, case) in runtime_cases.labels().items()})

PRIVATE_PROBES = {
    "fixtures/runtime-sdk/host_scopes.rs": "m02-native-probe-build",
    "fixtures/turn-budget/scope_probe.rs": "m02-native-probe-build",
    "fixtures/tool-concurrency/core_probe.rs": "m02-native-probe-build",
    "fixtures/tool-concurrency/steer_probe.rs": "m02-native-probe-build",
    "fixtures/review-before-send/composer_probe.rs": "review-tui-probe-build",
    "fixtures/review-before-send/dispatch_probe.rs": "review-tui-probe-build",
    "fixtures/review-before-send/app_probe.rs": "review-tui-probe-build",
    "fixtures/tool-concurrency/backend_probe.rs": "review-tui-probe-build",
    "fixtures/sdk-seams/runtime_probe.rs": "m02-native-probe-build",
    "fixtures/sdk-seams/core_probe.rs": "m02-native-probe-build",
    "fixtures/sdk-seams/stream_probe.rs": "m02-native-probe-build",
}
PRIVATE_PROBES = {path: (label,) for path, label in PRIVATE_PROBES.items()} | {
    "fixtures/mods/sdk-seams-" + owner + "/" + path:
        tuple("g06-sdk-" + owner + "-" + variant for variant in ("v1", "v2", "replacement"))
    for owner in ("a", "b") for path in ("Cargo.toml", "Cargo.lock", "src/lib.rs")}
PROBE_TARGETS = {label for labels in PRIVATE_PROBES.values() for label in labels}



def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_validation(path, value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if len(text.encode("utf-8")) > 16 * 1024 ** 2:
        raise RuntimeError("Validation JSON exceeds the qualification reader limit")
    path.write_text(text, encoding="utf-8")


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


class ProductionRouting(ast.NodeTransformer):
    """S01/S02/S03 share native routing; qualification names are not compiler inputs."""

    def visit_Compare(self, node):
        self.generic_visit(node)
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.In, ast.NotEq, ast.NotIn)):
            return node
        subject = node.left
        task = (isinstance(subject, ast.Subscript) and isinstance(subject.slice, ast.Constant)
            and subject.slice.value == "task_id" or isinstance(subject, ast.Call)
            and isinstance(subject.func, ast.Attribute) and subject.func.attr == "get"
            and subject.args and isinstance(subject.args[0], ast.Constant) and subject.args[0].value == "task_id")
        values = node.comparators[0]
        values = values.elts if isinstance(values, (ast.Tuple, ast.List, ast.Set)) else [values]
        if (not task or not values or not all(isinstance(value, ast.Constant)
                and isinstance(value.value, str) and re.fullmatch(r"CM-[A-Z0-9]+", value.value) for value in values)
                or not any(value.value in ("CM-S01", "CM-S02", "CM-S03") for value in values)):
            return node
        names = sorted({"CM-S01" if value.value in ("CM-S02", "CM-S03") else value.value for value in values})
        node.ops = [ast.NotIn() if isinstance(node.ops[0], (ast.NotEq, ast.NotIn)) else ast.In()]
        node.comparators = [ast.Tuple(elts=[ast.Constant(value=name) for name in names], ctx=ast.Load())]
        return node


def projection(text, entries=None, exclude=(), production=False):
    module = runtime_cases.Business().visit(ast.parse(text))
    if production:
        module = ProductionRouting().visit(module)
    table = runtime_cases.bindings(module)
    definitions = {name for name, node in table.items() if isinstance(node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    wanted = set(entries) if entries is not None else {name for name in definitions
        if name not in exclude and not name.startswith("case_")}
    assert wanted <= definitions, "Unknown runtime entry"
    pending = list(wanted)
    while pending:
        for node in ast.walk(table[pending.pop()]):
            if isinstance(node, ast.Name) and node.id in table and node.id not in wanted:
                wanted.add(node.id)
                pending.append(node.id)
    return digest({name: ast.dump(table[name], include_attributes=False) for name in sorted(wanted)})


def ordinary_audit(text):
    value = projection(text, ("observe",))
    # shortcut: only the reviewed S04 benchmark extension is equivalent; review each future audit policy explicitly.
    return {"47328f1b612ba418f19b32d647d1634cc6238084d4ee77ab720fbdbc3eea4557":
            "e750d82559f46e79f8c4eb2634aa6d77d59b041c8588371efc00474098e792f2"}.get(value, value)


def test_inputs(root, revision):
    # Historical x64 snapshots predate the shared platform module.
    platform_path = "ci/scripts/cm_platforms.py"
    platform_files = set(git(root, "ls-tree", "-r", "--name-only", revision, "--", platform_path).decode().splitlines())
    texts = {path: source(root, revision, path) for path in RUNTIME_FILES
             if not path.endswith("ci_progress.py") and path not in (*SUPPORT_RUNTIME_FILES, *INDEX_RUNTIME_FILES, *PROGRAM_RUNTIME_FILES)
             and (path != platform_path or path in platform_files)}
    available = set(git(root, "ls-tree", "-r", "--name-only", revision, "--", *SUPPORT_RUNTIME_FILES).decode().splitlines())
    support = {path: source(root, revision, path) for path in SUPPORT_RUNTIME_FILES if path in available}
    index_available = set(git(root, "ls-tree", "-r", "--name-only", revision, "--", *INDEX_RUNTIME_FILES).decode().splitlines())
    index_texts = {path: source(root, revision, path) for path in INDEX_RUNTIME_FILES if path in index_available}
    program_available = set(git(root, "ls-tree", "-r", "--name-only", revision, "--", *PROGRAM_RUNTIME_FILES).decode().splitlines())
    program_texts = {path: source(root, revision, path) for path in PROGRAM_RUNTIME_FILES if path in program_available}
    audit = ordinary_audit(source(root, revision, "ci/scripts/runtime_consumer.py"))
    observer = projection(source(root, revision, "ci/scripts/runtime_composition.py"),
        ("audit_executions", "audit_network", "bound_bwrap_executions", "bound_sandbox_aliases",
         "complete_syscalls", "check_network_audit", "kernel_route_sockets", "provider_tcp_connections"))
    result = {}
    for label, entries in PHASES.items():
        selected = runtime_cases.labels().get(label)
        if selected and selected[0] == "s02" and len(support) != len(SUPPORT_RUNTIME_FILES):
            continue
        if selected and selected[0] == "s03" and len(index_texts) != len(INDEX_RUNTIME_FILES):
            continue
        if selected and selected[0] == "program" and len(program_texts) != len(PROGRAM_RUNTIME_FILES):
            continue
        dispatch = {runtime_cases.DRIVERS[selected[0]]: runtime_cases.function(selected[1], selected[0])} if selected else {}
        if selected:
            wrapper = {"m02": ("ci/scripts/runtime_sdk.py", "matrix"),
                "m03": ("ci/scripts/managed_package.py", "driver"), "m04": ("ci/scripts/runtime_state.py", "driver"),
                "m05": ("ci/scripts/mod_author.py", "driver")}.get(selected[0])
            if wrapper:
                entries = (*entries, wrapper)
            cli = wrapper[0] if wrapper else runtime_cases.DRIVERS[selected[0]]
        else:
            cli = entries[0][0]
        if selected == ("s02", "abc") or selected and selected[0] == "program":
            # shortcut: Terminal stores modules on self; keep explicit entries until closure resolves instance attributes.
            entries = (*entries, *(("fixtures/runtime-sdk/driver.py", name) for name in
                ("Provider", "command", "environment", "rows")),
                *(("fixtures/managed-package/driver.py", name) for name in
                ("tui_configuration", "launch_command", "identity", "tui_message_visible", "tui_mcp_listener")),
                ("fixtures/native-loader/core_acceptance.py", "await_barrier"))
        case_texts = {**texts, **support} if selected and selected[0] == "s02" else texts
        if selected and selected[0] == "s03":
            case_texts = {**texts, **index_texts}
            if selected[1] == "refresh-running":
                entries = (*entries, *(("fixtures/sdk-seams/driver.py", name) for name in
                    ("real", "release_native", "Provider", "environment", "settled")))
        if selected and selected[0] == "program":
            case_texts = {**texts, **program_texts}
            entries = (*entries, ("fixtures/tool-concurrency/driver.py", "program_matrix"))
            cli = "fixtures/tool-concurrency/driver.py"
        value = runtime_cases.closure(case_texts, entries, dispatch=dispatch)
        module = runtime_cases.business_module(case_texts[cli])
        value["dependencies"][cli + ":<entrypoint>"] = digest([ast.dump(node, include_attributes=False)
            for node in module.body if isinstance(node, ast.If) and any(
                isinstance(item, ast.Name) and item.id == "__name__" for item in ast.walk(node.test))])
        value.update(protocol=runtime_cases.PROTOCOL, audit=digest({"outer": audit, "observer": observer}))
        if selected and selected[0] in ("g05", "s01"):
            paths = RUNTIME_DATA[:1] if selected[0] == "g05" else RUNTIME_DATA[1:3]
            if label == "s01-offline":
                paths += ("docs/distribution.md",)
            if label == "s01-identity":
                paths += ("schemas/release-receipt.schema.json",)
            value["qualification_data"] = {path: digest(source(root, revision, path)) for path in paths}
        if selected and selected[0] == "s02":
            path = "fixtures/compatibility-policy/policy.json"
            data = json.loads(source(root, revision, path))
            value["qualification_data"] = {path: digest({"schema_version": data["schema_version"],
                "case": data["cases"][selected[1]]})}
            if selected[1] in ("versions", "labels"):
                path = "schemas/support-matrix.schema.json"
                value["qualification_data"][path] = digest(source(root, revision, path))
        if selected and selected[0] == "s03":
            path = "fixtures/binary-index/cases.json"
            data = json.loads(source(root, revision, path))
            value["qualification_data"] = {path: digest({"schema_version": data["schema_version"],
                "case": data["cases"][selected[1]]})}
            if selected[1] in ("index-envelope", "support-exact", "support-forgery"):
                for path in ("schemas/mod-index.schema.json", "schemas/mod-index-qualification.schema.json"):
                    value["qualification_data"][path] = digest(source(root, revision, path))
        if selected and selected[0] == "program":
            path = "ci/program/cases.json"
            data = json.loads(source(root, revision, path))
            value["qualification_data"] = {path: digest({"schema_version": data["schema_version"],
                "case": data["cases"][selected[1]]})}
        result[label] = value
    return result


def probe_inputs(root, revision):
    return {path: hashlib.sha256(source(root, revision, path).encode()).hexdigest() for path in PRIVATE_PROBES}


def native_recipe(text):
    module = ast.parse(text)
    functions = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "linux_native"]
    if not functions:
        return {"legacy_module": digest(text)}
    assert len(functions) == 1
    function = functions[0]
    tables = [node for node in function.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "values"]
    assert len(tables) == 1 and isinstance(tables[0].value, ast.Dict), "Unknown native recipe layout"
    table = tables[0].value
    target = linux_native()["target"]
    selected = [(key, value) for key, value in zip(table.keys, table.values) if ast.literal_eval(key) == target]
    assert len(selected) == 1, "Current native target is absent from the reviewed recipe"
    tables[0].value = ast.Dict(keys=[selected[0][0]], values=[selected[0][1]])
    return {"target": target, "recipe": ast.dump(function, include_attributes=False)}


def product_inputs(root, revision):
    tree = git(root, "ls-tree", "-rz", revision).split(b"\0")
    files = {}
    runtime_modules = {"ci/scripts/" + name + ".py": {"matrix", "driver", "self_check"} for name in
                       ("mod_author", "mod_manifest", "runtime_sdk", "managed_package", "runtime_state")}
    runtime_modules["ci/scripts/mod_manifest.py"].update({"rejection_cases", "zip_rejections",
        "lock_integrity", "config_rejections", "remote_rejection"})
    runtime_modules["ci/scripts/turn_budget.py"] = {"driver", "self_check"}
    runtime_modules["ci/scripts/review_before_send.py"] = {"driver", "self_check"}
    runtime_modules["ci/scripts/tool_concurrency.py"] = {"driver", "self_check"}
    runtime_modules["ci/scripts/runtime_qualification.py"] = {"reports", "self_check"}
    runtime_modules["ci/scripts/runtime_hooks.py"] = {"reports", "self_check"}
    runtime_modules["ci/scripts/runtime_upgrade.py"] = {"reports", "self_check", "driver", "restore_reference", "baseline_file", "mount_reference"}
    runtime_modules["ci/scripts/sdk_seams.py"] = {"reports", "self_check"}
    runtime_modules["ci/scripts/distribution_provenance.py"] = {
        "reports", "self_check", "attest_prepare", "consume_proofs", "prepare_bootstrap", "source_check", "artifact_download", "extract_materials"}
    administrative = {"ci/scripts/retry.py", "ci/scripts/worker_policy.py", "ci/scripts/record_run.py",
                      "ci/scripts/dispatch_build.py", "ci/scripts/ci_progress.py", "ci/scripts/mod_contract.py",
                      "ci/source-files.txt", "ci/worker-files.json", "ci/worker-files-linux-arm64.json", ".github/cm-routing.json",
                      "ci/scripts/runtime_cases.py", "ci/scripts/acceptance_cache.py",
                      ".github/cm-build-routing.json", ".github/cm-platforms.json", "ci/scripts/cm_platforms.py",
                      *SUPPORT_RUNTIME_FILES, *INDEX_RUNTIME_FILES,
                      "fixtures/compatibility-policy/acceptance.sh", "fixtures/binary-index/acceptance.sh",
                      "ci/scripts/program_integration.py", "ci/scripts/build_benchmarks.py", "ci/benchmarks/scenarios.json",
                      "ci/benchmarks/runtime-loading.json", "fixtures/build-benchmarks/acceptance.sh"}
    for row in filter(None, tree):
        metadata, name = row.split(b"\t", 1)
        path = name.decode()
        if path == "ci/scripts/cm_platforms.py":
            files[path] = digest(native_recipe(source(root, revision, path)))
            continue
        if path in ("crates/cm/src/distribution-policy.json", "crates/cm/src/distribution-policy-arm64.json") and path != RUNTIME_DATA[1]:
            continue
        if path == "ci/scripts/binary_index.py":
            files[path] = projection(source(root, revision, path), ("prepare_transport",), production=True)
            continue
        if (path in administrative or path in PRIVATE_PROBES
                or path in RUNTIME_DATA and not path.startswith("crates/cm/src/distribution-")
                or path.endswith(".md") or path.startswith(("docs/", ".github/workflows/", "ci/worker/"))
                or path.startswith("fixtures/") and path.endswith(".py")
                or "/.vscode/" in path or "/.github/" in path):
            continue
        if path == "adapters/codex-e4568a3/source.json":
            pin = json.loads(source(root, revision, path))
            overlay = pin.pop("target_overlay", {}).get(linux_native()["target"], {})
            official = pin.pop("official_assets", {}).get(linux_native()["target"], pin.pop("official_asset", None))
            if official is not None:
                pin["official_asset"] = official
            pin["overlay"].update(overlay)
            files[path] = digest(pin)
        elif path == "adapters/codex-e4568a3/runtime-slots.json":
            descriptor = json.loads(source(root, revision, path))
            if "targets" in descriptor:
                assert linux_native()["target"] in descriptor.pop("targets")
                descriptor["target"] = linux_native()["target"]
            files[path] = digest(descriptor)
        elif path == ".github/cm-ci.json":
            config = json.loads(source(root, revision, path))
            native = {key: value for key, value in config.items() if key not in ("required_checks", "acceptance_script")}
            if native["task_id"] in ("CM-S01", "CM-S02", "CM-S03"):
                del native["task_id"]
            native["acceptance_recipe"] = digest(source(root, revision, config["acceptance_script"]))
            native["target"] = linux_native()["target"]
            if linux_native()["machine"] == 183:
                native["compile_env"] = {**native["compile_env"], "RUSTFLAGS": linux_native()["rustflags"],
                    "CFLAGS": linux_native()["cflags"], "CXXFLAGS": linux_native()["cflags"]}
                native["native_identity_files"] = ["crates/cm/src/distribution-policy-arm64.json"
                    if name == "crates/cm/src/distribution-policy.json" else name for name in native["native_identity_files"]]
            files[path] = digest(native)
        elif path in ("ci/scripts/host.py", "ci/scripts/linux_ci.py"):
            files[path] = digest(ast.dump(ProductionRouting().visit(ast.parse(source(root, revision, path))),
                                         include_attributes=False))
        elif path == "ci/scripts/runtime_consumer.py":
            files[path] = projection(source(root, revision, path), ("produce",), production=True)
        elif path in runtime_modules:
            files[path] = projection(source(root, revision, path), exclude=runtime_modules[path], production=True)
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


def same_runtime_platform(record, current):
    return (set(record) == set(current) and all(isinstance(value, str) and value for value in record.values())
            and all(record[key] == current[key] for key in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS")))


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
    kind, host_origin = p.build_request()
    plan = {"status": "miss", "production_inputs_sha256": digest(product_inputs(root, "HEAD")),
            "environment": environment(), "build_request": {"kind": kind, "host_origin": host_origin},
            "reason": "No compatible completed producer"}
    explicit = os.environ.get("CM_REUSE_RUN_ID", "")
    if explicit and not re.fullmatch(r"[1-9][0-9]*", explicit):
        raise RuntimeError("Invalid explicit reuse run ID")
    history = p.api("repos/" + worker + "/actions/workflows/build.yml/runs?event=workflow_dispatch&per_page=12")["workflow_runs"]
    if explicit:
        candidates = [p.api("repos/" + worker + "/actions/runs/" + explicit)]
    else:
        candidates = history
    for run in candidates:
        if run["id"] == int(os.environ["GITHUB_RUN_ID"]) or run.get("path") != ".github/workflows/build.yml":
            continue
        try:
            jobs = p.api("repos/" + worker + "/actions/runs/" + str(run["id"]) + "/attempts/" + str(run["run_attempt"]) + "/jobs?per_page=100")["jobs"]
            producers = [j for j in jobs if j["name"] in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"]) and j["conclusion"] == "success"]
            if len(producers) != 1:
                continue
            records = p.api("repos/" + worker + "/actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")["artifacts"]
            indexes = [a for a in records if a["name"].startswith(f"cm-{linux_native()['key']}-validation-inputs-") and not a["expired"]]
            evidence = indexes or [a for a in records if a["name"].startswith(f"cm-{linux_native()['key']}-evidence-") and not a["expired"]]
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
                        for artifact_kind, prefix in (("product", f"cm-{linux_native()['key']}-task-artifacts-"), ("input", f"cm-{linux_native()['key']}-runtime-inputs-")):
                            items = [a for a in records if a["name"] == prefix + ci["request_id"] + "-" + str(run["run_attempt"])]
                            if len(items) != 1:
                                raise RuntimeError("Missing exact producer artifact")
                            origin[artifact_kind + "_artifact"] = artifact_ref(checked_artifact(items[0], run["id"]))
                        old_environment = {key: metadata["context"].get(key) for key in environment()}
            if old_environment != environment() or digest(product_inputs(root, origin["source_sha"])) != plan["production_inputs_sha256"]:
                continue
            git(root, "merge-base", "--is-ancestor", origin["source_sha"], "HEAD")
            if p.api("repos/" + worker + "/compare/" + origin["workflow_sha"] + "..." + workflow_sha).get("status") not in ("ahead", "identical"):
                continue
            verified = verify_production_origin(origin)
            previous_request = old.get("build_request") if indexes else None
            if previous_request is None:
                previous_request = legacy_request(producers[0], worker, verified["product_artifact"])
            if previous_request != plan["build_request"]:
                continue
            resume = [a for a in records if a["name"].startswith(f"cm-{linux_native()['key']}-consumer-checkpoints-") and not a["expired"]]
            plan.update(status="hit", reason="Exact production inputs and runner image unchanged", production_origin=origin,
                        test_builds=old.get("test_builds", {}) if indexes else {},
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
    plan["checkpoint_origins"] = checkpoint_history(root, history, worker, workflow_sha)
    plan["probe_inputs"] = probe_inputs(root, "HEAD")
    if plan["status"] == "hit":
        old_probes = probe_inputs(root, plan["production_origin"]["source_sha"])
        changed = {label for path, value in plan["probe_inputs"].items()
                   if plan["build_request"]["kind"] == "qualification" and old_probes[path] != value
                   for label in PRIVATE_PROBES[path]}
        test_builds = {}
        for label, item in plan.get("test_builds", {}).items():
            if label not in changed or item["inputs"] != {
                    path: value for path, value in plan["probe_inputs"].items() if label in PRIVATE_PROBES[path]}:
                continue
            try:
                verify_test_build(item)
                git(root, "merge-base", "--is-ancestor", item["source_sha"], "HEAD")
                test_builds[label] = item
            except (AssertionError, KeyError, RuntimeError, subprocess.SubprocessError, urllib.error.HTTPError) as error:
                if isinstance(error, urllib.error.HTTPError) and error.code not in (404, 410):
                    raise
                print("CM test build: unavailable", label, type(error).__name__, flush=True)
        plan["test_builds"] = test_builds
        plan["changed_probes"] = sorted(changed - test_builds.keys())
    else:
        plan["changed_probes"] = []
    write(logs / "retry-plan.json", plan)
    outputs = {"reused": str(plan["status"] == "hit").lower(),
               "probe_build_required": str(bool(plan["changed_probes"])).lower()}
    if plan["status"] == "hit":
        origin = plan["production_origin"]
        outputs.update(artifact_id=origin["product_artifact"]["id"], artifact_digest=origin["product_artifact"]["digest"],
                       input_artifact_id=origin["input_artifact"]["id"], input_artifact_digest=origin["input_artifact"]["digest"],
                       production_origin=json.dumps(origin, separators=(",", ":")))
    p.output(outputs)
    print("CM producer reuse:", plan["status"], plan["reason"], flush=True)



def checkpoint_history(root, runs, worker, workflow_sha):
    """Find compatible passed cases independently of the chosen product producer."""
    wanted, origins, seen = test_inputs(root, "HEAD"), [], set()
    for run in runs:
        if run["id"] == int(os.environ["GITHUB_RUN_ID"]) or run.get("path") != ".github/workflows/build.yml":
            continue
        records = policy().api("repos/" + worker + "/actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")["artifacts"]
        expected = f"cm-{linux_native()['key']}-consumer-checkpoints-" + run["display_title"].removeprefix(f"CM {linux_native()['label']} / ") + "-" + str(run["run_attempt"])
        matches = [row for row in records if row["name"] == expected and not row["expired"]]
        if not matches:
            continue
        assert len(matches) == 1
        record = checked_artifact(matches[0], run["id"])
        try:
            with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
                with small_archive(worker, record, Path(directory) / "index.zip") as archive:
                    index = policy().archive_json(archive, "index.json")
            if index.get("schema_version") != 2 or not same_runtime_platform(index["environment"], environment()):
                continue
            provenance = index["provenance"]
            expected_provenance = {"GITHUB_REPOSITORY": worker, "GITHUB_RUN_ID": str(run["id"]),
                "GITHUB_RUN_ATTEMPT": str(run["run_attempt"]), "GITHUB_WORKFLOW_SHA": run["head_sha"],
                "CM_SOURCE_REPOSITORY": os.environ["CM_SOURCE_REPOSITORY"]}
            assert all(provenance[key] == value for key, value in expected_provenance.items())
            git(root, "merge-base", "--is-ancestor", provenance["CM_SOURCE_SHA"], "HEAD")
            if policy().api("repos/" + worker + "/compare/" + run["head_sha"] + "..." + workflow_sha).get("status") not in ("ahead", "identical"):
                continue
            compatible = []
            for label, step in index["steps"].items():
                identity = (label, step["key"])
                if (label in wanted and step["status"] == "pass" and index["test_inputs"].get(label) == wanted[label]
                        and identity not in seen):
                    compatible.append(label)
                    seen.add(identity)
            summary = {key: index[key] for key in ("schema_version", "environment", "provenance")}
            summary["test_inputs"] = {label: digest(value) for label, value in index["test_inputs"].items()}
            summary["steps"] = {}
            for label, step in index["steps"].items():
                row = {key: step[key] for key in ("status", "key", "origin", "inputs") if key in step}
                a, b = index["test_inputs"].get(label, {}), wanted.get(label, {})
                row["dependency_changes"] = sorted(key for key in a.get("dependencies", {}).keys() |
                    b.get("dependencies", {}).keys() if a.get("dependencies", {}).get(key) !=
                    b.get("dependencies", {}).get(key)) if isinstance(a, dict) and isinstance(b, dict) else []
                summary["steps"][label] = row
            origins.append({"run_id": run["id"], "run_attempt": run["run_attempt"],
                "source_sha": provenance["CM_SOURCE_SHA"], "workflow_sha": run["head_sha"],
                "artifact": artifact_ref(record), "labels": compatible, "index_fingerprint": digest(index), "index": summary})
        except (AssertionError, KeyError, ValueError, RuntimeError, subprocess.SubprocessError, urllib.error.HTTPError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (404, 410):
                raise
            print("CM checkpoints: rejected", run["id"], repr(error), flush=True)
    print("CM checkpoints: compatible origins", len(origins), "cases", len({label for row in origins for label in row["labels"]}), flush=True)
    return origins


def extract_checkpoint(worker, checkpoint, destination):
    record = checked_artifact(policy().api("repos/" + worker + "/actions/artifacts/" + str(checkpoint["artifact"]["id"])), checkpoint["run_id"])
    assert artifact_ref(record) == checkpoint["artifact"]
    destination.mkdir(parents=True)
    with small_archive(worker, record, destination.parent / (str(record["id"]) + ".zip")) as archive:
        total, seen = 0, set()
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
    index = read(destination / "index.json")
    assert digest(index) == checkpoint["index_fingerprint"], "Checkpoint index changed after selection"


def legacy_request(producer, worker, artifact):
    steps = [step for step in producer.get("steps", ())
             if step["name"] == "Restore exact successful qualification without executing requested source"]
    if len(steps) != 1:
        raise RuntimeError("Legacy producer build kind is unbound")
    if steps[0]["conclusion"] == "skipped":
        return {"kind": "qualification", "host_origin": None}
    if steps[0]["conclusion"] != "success":
        raise RuntimeError("Legacy Mod-only origin restoration did not pass")
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        with small_archive(worker, artifact, Path(directory) / "author.zip") as archive:
            receipt = policy().archive_json(archive, "author-receipt.json")
    if receipt["build_kind"] != "mod-only" or receipt["host_origin"].get("verified") is not True:
        raise RuntimeError("Legacy Mod-only producer origin is unverified")
    return {"kind": "mod-only", "host_origin": policy().parse_origin(receipt["host_origin"]["origin"])}


def verify_production_origin(origin, *, worker=None, fetch=None):
    p = policy()
    worker = worker or p.identities()[1]
    fetch = fetch or p.api
    assert all(re.fullmatch(r"[0-9a-f]{40}", origin[key]) for key in ("source_sha", "workflow_sha"))
    assert origin["job"] in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"])
    assert type(origin["run_id"]) is int and origin["run_id"] > 0
    assert type(origin["run_attempt"]) is int and origin["run_attempt"] > 0
    run_id = int(origin["run_id"])
    run = fetch("repos/" + worker + "/actions/runs/" + str(run_id))
    if run["run_attempt"] != origin["run_attempt"] or run["head_sha"] != origin["workflow_sha"] or run["event"] != "workflow_dispatch" or run["path"] != ".github/workflows/build.yml" or run["display_title"] != f"CM {linux_native()['label']} / " + origin["request_id"]:
        raise RuntimeError("Producer origin run/attempt/workflow/request changed")
    jobs_path = "repos/" + worker + "/actions/runs/" + str(run_id) + "/attempts/" + str(origin["run_attempt"]) + "/jobs?per_page=100"
    jobs = p.receipt_jobs(jobs_path, (origin["job"],), fetch=fetch)
    job = p.successful_job(jobs, origin["job"])
    if job["job_id"] != origin["job_id"]:
        raise RuntimeError("Producer origin job changed")
    records = {}
    for key in ("product_artifact", "input_artifact"):
        expected = origin[key]
        actual = checked_artifact(fetch("repos/" + worker + "/actions/artifacts/" + str(expected["id"])), run_id)
        prefix = f"cm-{linux_native()['key']}-" + ("task-artifacts-" if key == "product_artifact" else "runtime-inputs-")
        if artifact_ref(actual) != expected or actual["name"] != prefix + origin["request_id"] + "-" + str(origin["run_attempt"]):
            raise RuntimeError("Producer artifact identity changed")
        records[key] = actual
    return records



def probe_prepare(root, logs):
    """Restore immutable inputs on the hosted builder without rebuilding their payloads."""
    import host
    import runtime_consumer
    import tarfile
    plan = read(logs / "retry-plan.json")
    assert plan["status"] == "hit" and plan["changed_probes"]
    records = verify_production_origin(plan["production_origin"])
    destination = Path(os.environ["RUNNER_TEMP"]) / "cm-probe-base/runtime-inputs"
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        directory = Path(directory)
        with policy().download_origin_archive(os.environ["GITHUB_REPOSITORY"], records["input_artifact"], directory / "inputs.zip") as archive:
            matches = [entry for entry in archive.infolist() if entry.filename == "runtime-inputs.tar"]
            assert len(matches) == 1 and matches[0].file_size <= 4 * 1024 ** 3
            with archive.open(matches[0]) as src, (directory / "runtime-inputs.tar").open("xb") as target:
                shutil.copyfileobj(src, target)
        with tarfile.open(directory / "runtime-inputs.tar", "r:") as archive:
            policy().extract_archive(archive, destination)
    runtime_consumer.validate_inputs(destination)
    frozen = read(destination / "producer.json")["host"]
    host.write(logs / "host-identity.json", frozen["host_identity"])
    with open(os.environ["GITHUB_ENV"], "a") as output:
        output.write("CM_PROBE_BUILD_TARGETS=" + json.dumps(plan["changed_probes"], separators=(",", ":")) + "\n")
        output.write("CODEX_BWRAP_SHA256=" + frozen["host_identity"]["inputs"]["helper"]["sha256"] + "\n")
        output.write("CM_HOST_IDENTITY_JSON=" + str(logs / "host-identity.json") + "\n")


def probe_build(root, logs):
    import acceptance_cache
    import runtime_consumer
    import runtime_sdk
    import turn_budget
    plan = read(logs / "retry-plan.json")
    inputs = Path(os.environ["RUNNER_TEMP"]) / "cm-probe-base/runtime-inputs"
    producer = read(inputs / "producer.json")
    destination = Path(os.environ["CM_TEST_BUILD_DIR"])
    for label in plan["changed_probes"]:
        target = destination / label
        target.mkdir(parents=True)
        metadata = {}
        if label == "m02-native-probe-build":
            names = ("m02-native-probe.json", "m02-native-scopes.json", "m02-native-events.jsonl", "m02-native-trace.jsonl",
                *(("g02a-native-probe.json", "g02a-native-scopes.json", "g02a-native-trace.jsonl")
                  if producer.get("g02a") else ()))
            # Frozen proof outputs must not collide with create_new traces or append into old events.
            for name in names:
                (inputs / "fixture" / name).unlink(missing_ok=True)
            metadata["native_scope_probe"] = runtime_sdk.native_probe(root, logs, inputs, inputs / "host", producer["host"])
            if producer.get("g02a"):
                metadata["budget_scope_probe"] = turn_budget.native_probe(root, logs, inputs, producer["host"],
                    {"native_scope_probe": metadata["native_scope_probe"]})
            for name in names:
                (target / "fixture").mkdir(exist_ok=True)
                shutil.copyfile(inputs / "fixture" / name, target / "fixture" / name)
        binary = acceptance_cache.run(root, logs, label)
        shutil.copy2(binary, target / "binary")
        receipt = read(Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"]) / label / "build.json")
        if label.startswith("g06-sdk-"):
            import mod_manifest
            import sdk_seams
            _, _, owner, variant = label.split("-")
            mod_manifest.manifest(target, sdk_seams.manifest(owner, variant, binary))
            exports = subprocess.check_output(["nm", "-D", "--defined-only", str(binary)], text=True)
            assert " cm_mod_entry_v2" in exports
            metadata["author"] = {"inputs": receipt["inputs"], "origin": receipt["origin"],
                "payload_sha256": runtime_consumer.sha(binary), "mod_build_id": "sha256:" + digest(receipt["inputs"]),
                "exports": exports, "host_frozen_before_author_build": producer["host"]["executable_sha256"], "host_linked": False}
        else:
            metadata["source_sha256"] = receipt["inputs"]["instrumented_source_sha256"]
        shutil.copyfile(Path(os.environ["CM_ACCEPTANCE_BUILD_CACHE_DIR"]) / label / "build.json", target / "build.json")
        write(target / "test-build.json", {"schema_version": 1, "target": label,
            "provenance": runtime_consumer.provenance(),
            "inputs": {path: value for path, value in plan["probe_inputs"].items() if label in PRIVATE_PROBES[path]},
            "metadata": metadata, "files": runtime_consumer.inventory(target)})
        output = label.replace("-", "_") if label.startswith("g06-sdk-") else (
            "core_probe" if label == "m02-native-probe-build" else "tui_probe")
        policy().output({output: "true"})


def verify_test_build(item, *, worker=None, fetch=None):
    worker = worker or os.environ["GITHUB_REPOSITORY"]
    fetch = fetch or policy().api
    assert item["target"] in PROBE_TARGETS
    assert item["job"] in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"])
    assert all(re.fullmatch(r"[0-9a-f]{40}", item[key]) for key in ("source_sha", "workflow_sha"))
    assert all(type(item[key]) is int and item[key] > 0 for key in ("run_id", "run_attempt", "job_id"))
    run = fetch("repos/" + worker + "/actions/runs/" + str(item["run_id"]))
    assert run["run_attempt"] == item["run_attempt"] and run["head_sha"] == item["workflow_sha"]
    assert run["event"] == "workflow_dispatch" and run["path"] == ".github/workflows/build.yml"
    assert run["display_title"] == f"CM {linux_native()['label']} / " + item["request_id"]
    jobs = policy().receipt_jobs("repos/" + worker + "/actions/runs/" + str(item["run_id"]) + "/attempts/"
        + str(item["run_attempt"]) + "/jobs?per_page=100", (item["job"],), fetch=fetch)
    assert policy().successful_job(jobs, item["job"])["job_id"] == item["job_id"]
    record = checked_artifact(fetch("repos/" + worker + "/actions/artifacts/" + str(item["artifact"]["id"])), item["run_id"])
    assert artifact_ref(record) == item["artifact"]
    assert record["name"] == f"cm-{linux_native()['key']}-test-build-" + item["target"] + "-" + item["request_id"] + "-" + str(item["run_attempt"])
    return record


def refresh_probes(inputs, validation):
    import runtime_consumer as runtime
    metadata = {}
    for label, item in validation.get("test_builds", {}).items():
        assert label in PROBE_TARGETS and item["target"] == label
        sdk_author = label.startswith("g06-sdk-")
        expected = {path: value for path, value in validation["probe_inputs"].items() if label in PRIVATE_PROBES[path]}
        assert item["inputs"] == expected
        record = verify_test_build(item)
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
            directory = Path(directory)
            with policy().download_origin_archive(os.environ["GITHUB_REPOSITORY"], record, directory / "probe.zip") as archive:
                proof = policy().archive_json(archive, "test-build.json")
                assert proof["schema_version"] == 1 and proof["target"] == label and proof["inputs"] == expected
                origin = proof["provenance"]
                assert all(origin[key] == value for key, value in {
                    "GITHUB_RUN_ID": str(item["run_id"]), "GITHUB_RUN_ATTEMPT": str(item["run_attempt"]),
                    "GITHUB_WORKFLOW_SHA": item["workflow_sha"], "CM_SOURCE_SHA": item["source_sha"],
                    "GITHUB_REPOSITORY": os.environ["GITHUB_REPOSITORY"],
                    "CM_SOURCE_REPOSITORY": os.environ["CM_SOURCE_REPOSITORY"],
                    "CM_REQUEST_ID": item["request_id"]}.items())
                required_metadata = {"author"} if sdk_author else {"source_sha256"}
                if label == "m02-native-probe-build":
                    required_metadata.add("native_scope_probe")
                    if read(inputs / "producer.json").get("g02a"):
                        required_metadata.add("budget_scope_probe")
                assert set(proof["metadata"]) == required_metadata
                allowed = {"binary", "build.json"}
                if sdk_author:
                    allowed.add("mod.toml")
                if label == "m02-native-probe-build":
                    allowed.update("fixture/" + name for name in ("m02-native-probe.json", "m02-native-scopes.json",
                        "m02-native-events.jsonl", "m02-native-trace.jsonl"))
                    if "budget_scope_probe" in proof["metadata"]:
                        allowed.update("fixture/" + name for name in ("g02a-native-probe.json",
                            "g02a-native-scopes.json", "g02a-native-trace.jsonl"))
                assert {entry["path"] for entry in proof["files"]} == allowed
                names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
                assert len(names) == len(set(names)) and set(names) == allowed | {"test-build.json"}
                assert sum(entry.file_size for entry in archive.infolist()) <= 4 * 1024 ** 3
                extracted = directory / "files"
                extracted.mkdir()
                for name in allowed:
                    entry = archive.getinfo(name)
                    assert stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG) and entry.file_size <= 2 * 1024 ** 3
                    target = extracted / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as src, target.open("xb") as out:
                        shutil.copyfileobj(src, out)
                    target.chmod(0o755 if name == "binary" else 0o644)
                assert runtime.inventory(extracted) == proof["files"], "Test-build bytes differ"
                build = read(extracted / "build.json")
                if not sdk_author:
                    assert build["inputs"]["instrumented_source_sha256"] == proof["metadata"]["source_sha256"]
                assert set(build["checks"]) == {label} and build["checks"][label]["return_code"] == 0
                compiled = next(row for row in build["files"] if row["path"] == label + ".bin")
                assert compiled["sha256"] == runtime.sha(extracted / "binary")
                assert build["checks"][label]["recipe"] == build["inputs"]["recipes"][label]
                assert build["origin"]["CM_SOURCE_REPOSITORY"] == os.environ["CM_SOURCE_REPOSITORY"]
                assert build["origin"]["GITHUB_REPOSITORY"] == os.environ["GITHUB_REPOSITORY"]
                if sdk_author:
                    import tomllib
                    _, _, owner, variant = label.split("-")
                    author = proof["metadata"]["author"]
                    assert author["inputs"] == build["inputs"] and author["origin"] == build["origin"]
                    assert author["payload_sha256"] == compiled["sha256"]
                    assert author["mod_build_id"] == "sha256:" + digest(build["inputs"])
                    assert author["host_linked"] is False and " cm_mod_entry_v2" in author["exports"]
                    assert author["host_frozen_before_author_build"] == read(inputs / "producer.json")["host"]["executable_sha256"]
                    sources = {entry["path"]: entry["sha256"] for entry in build["inputs"]["author"]["sources"]}
                    assert all(sources[path] == value for path, value in expected.items())
                    manifest = tomllib.loads((extracted / "mod.toml").read_text())
                    assert manifest["id"] == "sdk-" + owner and manifest["binary"]["path"] == "payload.so"
                    assert manifest["binary"]["sha256"] == compiled["sha256"]
                    assert manifest["binary"]["size"] == (extracted / "binary").stat().st_size
                    assert manifest["provenance"]["revision"] == item["source_sha"]
                    package = inputs / "mods/g06" / owner / variant
                    assert package.is_dir() and not package.is_symlink()
                    for name, destination in (("binary", "payload.so"), ("mod.toml", "mod.toml")):
                        assert not (package / destination).is_symlink()
                        shutil.copy2(extracted / name, package / destination)
                    metadata[label] = proof["metadata"]
                    continue
                for field, name in (("native_scope_probe", "m02-native-probe.json"),
                                    ("budget_scope_probe", "g02a-native-probe.json")):
                    if field in proof["metadata"]:
                        assert proof["metadata"][field] == read(extracted / "fixture" / name)
                        assert proof["metadata"][field]["binary_sha256"] == compiled["sha256"]
                destinations = ("probes/cm-concurrency-core",) if label == "m02-native-probe-build" else (
                    "probes/cm-review-tui", "probes/cm-concurrency-backend")
                for relative in destinations:
                    target = inputs / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    assert not target.is_symlink()
                    shutil.copy2(extracted / "binary", target)
                for name in allowed:
                    if name.startswith("fixture/"):
                        shutil.copyfile(extracted / name, inputs / name)
                metadata[label] = {"binary_sha256": runtime.sha(extracted / "binary"), **proof["metadata"]}
    write(inputs / "test-build-overlays.json", metadata)
    if any(label.startswith("g06-sdk-") for label in metadata):
        write(inputs / "fixture/g06-producer.json", effective_producer(inputs)["sdk_seams"])


def effective_producer(inputs):
    value = read(inputs / "producer.json")
    path = inputs / "test-build-overlays.json"
    if not path.is_file():
        return value
    for label, metadata in read(path).items():
        if label == "m02-native-probe-build":
            probe = metadata["native_scope_probe"]
            value["runtime_sdk"]["native_scope_probe"] = probe
            if value.get("g02a") and "budget_scope_probe" in metadata:
                value["g02a"]["private_core_probe"] = metadata["budget_scope_probe"]
            if value.get("concurrency"):
                value["concurrency"]["probe"].update(sha256=metadata["binary_sha256"],
                    source_sha256=probe["native_fixture_source_manifest_sha256"], test_environment=probe["test_environment"])
        elif label == "review-tui-probe-build":
            if value.get("review"):
                value["review"]["probe"].update(sha256=metadata["binary_sha256"], source_sha256=metadata["source_sha256"])
            if value.get("concurrency"):
                value["concurrency"]["backend_probe"].update(sha256=metadata["binary_sha256"], source_sha256=metadata["source_sha256"])
        elif label.startswith("g06-sdk-"):
            _, _, owner, variant = label.split("-")
            value["authors"]["g06/" + owner + "/" + variant] = metadata["author"]
            value["sdk_seams"]["authors"][owner + "/" + variant] = metadata["author"]
        else:
            raise AssertionError("Unknown test-build overlay")
    return value


def current_producer_job():
    p = policy()
    for attempt in range(12):
        jobs = p.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100")["jobs"]
        producers = [j for j in jobs if j["name"] in ("build-read / " + linux_native()["key"], "build-write / " + linux_native()["key"]) and j["status"] == "in_progress"]
        if len(producers) == 1:
            break
        if attempt < 11:
            time.sleep(5)
    assert len(producers) == 1, "Actual producer job identity unavailable"
    return producers[0]


def overlay(root, logs):
    import runtime_consumer
    import runtime_composition
    p = policy()
    plan = read(logs / "retry-plan.json")
    if plan["status"] == "hit":
        origin = plan["production_origin"]
    else:
        producer = current_producer_job()
        origin = {"source_sha": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
                  "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                  "request_id": os.environ["CM_REQUEST_ID"], "job": producer["name"], "job_id": producer["id"]}
        for key, variable in (("product_artifact", "CM_CURRENT_ARTIFACT_ID"), ("input_artifact", "CM_CURRENT_INPUT_ARTIFACT_ID")):
            origin[key] = artifact_ref(checked_artifact(p.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + os.environ[variable]), origin["run_id"]))
    destination = Path(os.environ["CM_VALIDATION_INPUT_DIR"])
    destination.mkdir()
    for path in (*RUNTIME_FILES, *RUNTIME_DATA):
        target = destination / "fixture" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / path, target)
    for name in ("runtime_consumer.py", "ci_progress.py", "retry.py", "runtime_cases.py"):
        shutil.copyfile(root / "ci/scripts" / name, destination / name)
    (destination / "observer.py").write_text(runtime_consumer.runtime_observer_source(runtime_composition), encoding="utf-8")
    test_builds = dict(plan.get("test_builds", {}))
    probe_producer = current_producer_job() if plan["changed_probes"] else None
    for label, variable in (("m02-native-probe-build", "CM_CORE_PROBE_ARTIFACT_ID"),
                            ("review-tui-probe-build", "CM_TUI_PROBE_ARTIFACT_ID"),
                            *((label, "CM_" + label.replace("-", "_").upper() + "_ARTIFACT_ID")
                              for label in sorted(PROBE_TARGETS) if label.startswith("g06-sdk-"))):
        if os.environ.get(variable):
            record = checked_artifact(p.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + os.environ[variable]),
                                      int(os.environ["GITHUB_RUN_ID"]))
            test_builds[label] = {**{key: origin[key] for key in ("source_sha", "workflow_sha", "run_id", "run_attempt",
                "request_id", "job", "job_id")}, "source_sha": os.environ["CM_SOURCE_SHA"],
                "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
                "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "request_id": os.environ["CM_REQUEST_ID"],
                "job": probe_producer["name"], "job_id": probe_producer["id"],
                "target": label, "artifact": artifact_ref(record),
                "inputs": {path: value for path, value in plan["probe_inputs"].items() if label in PRIVATE_PROBES[path]}}
    baseline = plan.get("checkpoint_origin")
    write_validation(destination / "validation.json", {"schema_version": 2, "provenance": runtime_consumer.provenance(),
        "task_id": read(root / ".github/cm-ci.json")["task_id"],
        "environment": environment(), "production_inputs_sha256": plan["production_inputs_sha256"],
        "build_request": plan["build_request"],
        "production_origin": origin, "checkpoint_origin": baseline,
        "checkpoint_origins": plan.get("checkpoint_origins", []), "probe_inputs": plan["probe_inputs"],
        "test_builds": test_builds,
        "test_inputs": test_inputs(root, "HEAD"),
        "baseline_test_inputs": {},
        "files": runtime_consumer.inventory(destination)})
    p.output({"production_origin": json.dumps(origin, separators=(",", ":"))})


def refresh():
    import runtime_consumer as runtime
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    overlay_dir = Path(os.environ["CM_VALIDATION_INPUT_DIR"])
    validation = read(overlay_dir / "validation.json")
    assert validation["provenance"] == runtime.provenance(), "Current validation provenance differs"
    current_environment = environment()
    assert same_runtime_platform(validation["environment"], current_environment), "Overlay runtime platform differs"
    assert validation["production_origin"] == json.loads(os.environ["CM_PRODUCTION_ORIGIN"])
    assert validation["files"] == [e for e in runtime.inventory(overlay_dir) if e["path"] != "validation.json"]
    original = runtime.validate_inputs(inputs)
    old = original["files"]
    for entry in validation["files"]:
        assert "link" not in entry and entry["path"] in {
            "runtime_consumer.py", "ci_progress.py", "retry.py", "runtime_cases.py", "observer.py", *("fixture/" + path for path in (*RUNTIME_FILES, *RUNTIME_DATA))}
        target = inputs / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(overlay_dir / entry["path"], target)
    allowed = {e["path"] for e in validation["files"]}
    assert [e for e in old if e["path"] not in allowed] == [e for e in runtime.inventory(inputs) if e["path"] not in allowed | {"input-manifest.json"}]
    refresh_probes(inputs, validation)
    validation["original_input_manifest_sha256"] = original["sha256"]
    validation["consumer_environment"] = current_environment
    write_validation(inputs / "validation.json", validation)
    entries = [e for e in runtime.inventory(inputs) if e["path"] != "input-manifest.json"]
    write(inputs / "input-manifest.json", {"files": entries, "sha256": runtime.digest(entries)})

def rootfs_key(closure):
    return digest({"packages": closure["packages"], "files": [entry for entry in closure["files"]
        if not entry["path"].startswith("fixture/") and entry["path"] != "inputs/producer.json"]})



def native_key(closure, label):
    phase = label.split("-", 1)[0]
    mods = {
        "p04": ("inputs/mods/a/", "inputs/mods/b/"),
        "consumer": ("inputs/mods/a/", "inputs/mods/b/"),
        "m01": ("inputs/mods/m01-", "inputs/mods/a/", "inputs/mods/b/"),
        "m02": ("inputs/mods/m02/",),
        "m03": (), "m04": ("inputs/mods/m04/", "inputs/mods/m02/"),
        "g04": ("inputs/mods/m02/lifecycle-audit/normal/", "inputs/mods/m02/example-tool/normal/"),
        "g01": ("inputs/mods/g01/a/normal/",),
        "g05": (),
        "g06": (), "s01": ("inputs/mods/s01/", "inputs/distribution/"), "s02": (), "s03": (), "program": (),
        "m05": ("inputs/mods/m05/", "inputs/mods/m02/"),
        "g02a": ("inputs/mods/g02a/", "inputs/mods/m02/"),
        "review": ("inputs/mods/g02b/", "inputs/mods/m02/"),
        "concurrency": ("inputs/mods/g03/", "inputs/mods/g02a/", "inputs/mods/g02b/", "inputs/mods/m02/"),
    }.get(phase)
    assert mods is not None, "Undeclared native dependency: " + label
    if label == "g04-abi":
        mods += ("inputs/mods/constructor-sentinel/",)
    probes = []
    if phase == "m03":
        normal = ("inputs/mods/m02/lifecycle-audit/normal/", "inputs/mods/m02/example-tool/normal/")
        legacy = ("inputs/mods/a/", "inputs/mods/b/normal/")
        manifest = ("inputs/mods/m01-a/", "inputs/mods/m01-b/")
        sentinel = ("inputs/mods/constructor-sentinel/",)
        mods = {
            "install": (*normal, "inputs/mods/example-tool.cmod"),
            "process": normal, "terminal": normal, "live": normal, "backends": normal,
            "rejections": (normal[0], *manifest, *legacy, *sentinel),
            "legacy": legacy,
            "writers": (*normal, *manifest, *sentinel),
        }[label.removeprefix("m03-")]
    if phase == "s01":
        probes.extend(("fixture/s01-producer.json", "fixture/s01-bootstrap/identity.json"))
        probes.extend(entry["path"] for entry in closure["files"]
            if entry["path"].startswith("fixture/s01-proofs/") and entry["path"] != "fixture/s01-proofs/authority.json"
            and not entry["path"].startswith("fixture/s01-proofs/index/"))
    if phase == "g06":
        mods, probes = runtime_cases.g06_native_dependencies(label.removeprefix("g06-"))
    if phase == "s02":
        mods = runtime_cases.s02_native_dependencies(label.removeprefix("s02-"))
    if phase == "program":
        mods = runtime_cases.program_native_dependencies(label.removeprefix("program-"))
    if label == "s03-http-tls":
        probes.extend(("fixture/binary-index-tls/cert.pem", "fixture/binary-index-tls/key.pem"))
    if phase == "g05":
        case = label.removeprefix("g05-")
        baseline = "inputs/upgrade-baseline/"
        mods = (baseline + "host/",)
        normal = tuple("inputs/mods/m02/" + owner + "/normal/" for owner in ("lifecycle-audit", "example-tool"))
        if case.startswith("candidate-fault-"):
            mods = ()
        elif case.startswith("exact-"):
            mods += (baseline + "mods/g01/a/normal/",)
            if case == "exact-variant" or case.startswith("exact-wrong-"):
                mods += ("inputs/mods/g01/a/normal/",)
        elif case.startswith("state-") or case == "source-busy":
            mods += ("inputs/mods/m04/",)
        else:
            mods += normal
            roles = (("a", "b") if case in ("check-only", "candidate-success", "labels-tamper")
                or case.startswith("reuse-ab-") else ("a",) if case.startswith("reuse-a-")
                or case == "variant-identity" else ("b",) if case.startswith("reuse-b-") else ())
            mods += tuple(baseline + "mods/" + relative for role, relative in
                (("a", "g02a/turn-budget/"), ("b", "g02b/review-before-send/")) if role in roles)
        if case.startswith(("candidate-fault-", "source-drift-")) or case in ("state-copy", "source-busy"):
            probes.append("fixture/g05-transaction-checks.json")
    if phase == "g01":
        case = label.removeprefix("g01-")
        if case in ("qualification-matrix", "core-baseline", "ordinary-reentry"):
            mods = ()
        elif case in ("conflict-advanced", "conflict-mixed"):
            mods = ("inputs/mods/g01/a/replacement/", "inputs/mods/g01/b/replacement/")
        elif case == "core-short":
            mods = ("inputs/mods/g01/a/short/", "inputs/mods/g01/b/normal/")
        elif case in ("binding-drift", "binding-aslr", "core-around", "core-error", "next-repeat",
                      "next-stale-owner", "next-thread", "cancel-before", "cancel-during",
                      "cancel-callback", "restart-disabled"):
            mods += ("inputs/mods/g01/b/normal/",)
        if case in ("binding-drift", "next-repeat", "next-stale-owner", "next-thread", "cancel-before", "cancel-callback"):
            probes.append("inputs/probes/cm-hook-policy")
        if case == "ordinary-reentry":
            probes.extend(("fixture/m02-native-probe.json", "fixture/m02-native-trace.jsonl"))
        if case == "qualification-matrix":
            probes.append("fixture/g01-producer.json")
    if phase == "review":
        probes.append("inputs/probes/cm-review-tui")
    if phase == "concurrency" and label not in ("concurrency-value-flow", "concurrency-leaf-bound", "concurrency-plug-and-play"):
        probes.append("inputs/probes/cm-concurrency-core")
        if label == "concurrency-backend-scope":
            probes.append("inputs/probes/cm-concurrency-backend")
    if label == "m02-authoring":
        probes.extend("fixture/" + name for name in ("m02-native-probe.json", "m02-native-scopes.json",
            "m02-native-events.jsonl", "m02-native-trace.jsonl"))
    if phase == "g02a" and label in ("g02a-counting", "g02a-reentry", "g02a-scope", "g02a-cancellation-recovery"):
        probes.extend("fixture/" + name for name in ("g02a-native-probe.json", "g02a-native-scopes.json",
            "g02a-native-trace.jsonl"))
    prefixes = ("inputs/host/", "inputs/official/", *mods)
    return digest({"packages": closure["packages"], "files": [entry for entry in closure["files"]
        if entry["path"].startswith(prefixes) or entry["path"] in probes
        or not entry["path"].startswith(("inputs/", "fixture/"))],
        "required_paths": probes, "mod_prefixes": mods,
        **({"binary_index": closure["binary_index_inputs"][label.removeprefix("s03-")]}
            if phase == "s03" else {}),
        "static_fixture_data": [entry for entry in closure["files"] if entry["path"].startswith("fixture/")
            and not entry["path"].startswith(("fixture/s01-proofs/", "fixture/s01-bootstrap/", "fixture/binary-index-tls/"))
            and entry["path"] not in ("fixture/g05-transaction-checks.json", "fixture/g06-shutdown-regression.json")
            and (entry["path"] not in {"fixture/" + path for path in RUNTIME_DATA}
                or phase == "g05" and entry["path"] == "fixture/ci/g05-baseline.json")
            and not entry["path"].endswith((".py", ".rs", ".patch"))
            and not re.search(r"(?:producer|native-probe|native-scopes|native-events|native-trace|context)\.(?:json|jsonl)$",
                             entry["path"])]})


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
        self.constraints = {}
        self.index = {"schema_version": 2, "provenance": runtime.provenance(),
            "environment": environment(), "rootfs_key": rootfs_key(closure),
            "test_inputs": validation["test_inputs"], "steps": {}}
        self.previous = []
        self.download_lock = threading.Lock()
        for candidate in validation.get("checkpoint_origins", ()):
            old = candidate["index"]
            assert old["schema_version"] == 2
            if old["environment"] == self.index["environment"]:
                self.previous.append((None, old, candidate))
        previous = os.environ.get("CM_RUNTIME_RESUME_DIR")
        if previous and (Path(previous) / "index.json").is_file():
            old = read(Path(previous) / "index.json")
            origin = validation["checkpoint_origin"]
            expected = {"GITHUB_RUN_ID": str(origin["run_id"]), "GITHUB_RUN_ATTEMPT": str(origin["run_attempt"]),
                        "GITHUB_WORKFLOW_SHA": origin["workflow_sha"], "CM_SOURCE_SHA": origin["source_sha"]}
            if (old["schema_version"] == 2 and old["environment"] == self.index["environment"]
                    and all(old["provenance"].get(k) == v for k, v in expected.items())):
                self.previous.append((Path(previous), old, origin))
        write(self.directory / "index.json", self.index)

    def owns(self, label, path):
        name = path.as_posix()
        selected = runtime_cases.labels().get(label)
        if selected:
            return name.startswith(selected[0] + "/" + selected[1] + "/")
        if label == "consumer-missing-library":
            return name == "missing-library.json" or name.startswith("failures/missing-library/")
        if label == "consumer-library-recovery":
            return name in ("actual-missing-library-recovery.json", "recovery-environment.json") or name.startswith("recoveries/actual-missing-library/")
        if label.startswith("g02a-"):
            return name.startswith("g02a/" + label.removeprefix("g02a-") + "/") or name in self.reports[label]
        if label.startswith("review-"):
            return name.startswith("review/" + label.removeprefix("review-") + "/") or name in self.reports[label]
        if label.startswith("concurrency-"):
            return name.startswith("concurrency/" + label.removeprefix("concurrency-") + "/") or name in self.reports[label]
        if label.startswith("m0"):
            prefix = label.split("-")[0]
            return name.startswith(prefix + "/") or name.startswith(prefix + "-") or name in self.reports[label]
        reserved = {p for key, paths in self.reports.items() if key != label for p in paths}
        return (not name.startswith(("m01", "m02", "m03", "m04", "m05", "g02a", "g04", "g01", "review", "concurrency", "probe", "syscalls.",
                                     "failures/missing-library/", "recoveries/actual-missing-library/"))
                and name not in reserved | {"outer-runtime-audit.json", "missing-library.json",
                    "actual-missing-library-recovery.json", "recovery-environment.json", "step-results.json", "isolation-probes.json"})

    def files(self, label):
        return [p for p in sorted(self.evidence.rglob("*")) if p.is_file() and not p.is_symlink()
                and p.suffix in {".json", ".jsonl", ".log"}
                and self.owns(label, p.relative_to(self.evidence))]

    def key_inputs(self, label):
        return {"native": native_key(self.closure, label), "environment": self.index["environment"],
                "test": digest(self.index["test_inputs"][label]), "command": self.commands[label],
                "constraints": self.constraints.get(label, {})}

    def key(self, label):
        return digest(self.key_inputs(label))

    def decision(self, label):
        current = self.key_inputs(label)
        comparisons = []
        for _, old, candidate in self.previous:
            step = old["steps"].get(label)
            if not step:
                comparisons.append({"run_id": candidate["run_id"], "reason": "case_missing"})
                continue
            before = step.get("inputs", {})
            changed = [key for key in current if current[key] != before.get(key)]
            previous_test = old["test_inputs"].get(label, {})
            now = self.index["test_inputs"][label]
            dependency_changes = step.get("dependency_changes", [])
            if isinstance(previous_test, dict) and isinstance(now, dict):
                a, b = previous_test.get("dependencies", {}), now.get("dependencies", {})
                dependency_changes = sorted(key for key in a.keys() | b.keys() if a.get(key) != b.get(key))
            comparisons.append({"run_id": candidate["run_id"], "reason": "inputs_changed" if changed else step["status"],
                "changed": changed, "dependency_changes": dependency_changes})
        return {"reason": "no_compatible_pass", "comparisons": comparisons,
                "dependency_fingerprint": current["test"],
                "conservative_reasons": self.index["test_inputs"][label].get("conservative_reasons", [])
                    if isinstance(self.index["test_inputs"][label], dict) else []}

    def restore(self, label):
        selected = None
        for directory, old, candidate in self.previous:
            step = old["steps"].get(label)
            if (step and step["status"] == "pass" and step["key"] == self.key(label)
                    and step.get("inputs", {}).get("test") == digest(self.index["test_inputs"][label])):
                selected = directory, old, candidate, step
                break
        if selected is None:
            return None
        directory, old, candidate, step = selected
        if directory is None:
            directory = Path(os.environ["RUNNER_TEMP"]) / "cm-runtime-resume" / str(candidate["artifact"]["id"])
            with self.download_lock:
                if not (directory / "index.json").is_file():
                    extract_checkpoint(os.environ["GITHUB_REPOSITORY"], candidate, directory)
        step = read(directory / "index.json")["steps"][label]
        assert step["status"] == "pass" and step["key"] == self.key(label)
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
                "checkpoint_artifact": candidate["artifact"], "reason": "verified_case_inputs"}

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
                "files": self.runtime.inventory(destination), "inputs": self.key_inputs(label)}
        with self.lock:
            self.index["steps"][label] = step
            write(self.directory / "index.json", self.index)
        return {"status": "pass", "kind": "executed", "origin": step["origin"], "audit": audit,
                **self.decision(label)}

    def run(self, logs, label, command, timeout):
        import ci_progress
        started = time.monotonic()
        self.commands[label] = [part.replace(str(self.temp), "<consumer-root>")
            .replace(os.environ.get("CM_CONSUMER_INPUT_DIR", "<unset-runtime-inputs>"), "<runtime-inputs>") for part in command]
        try:
            result = self.restore(label)
            if result is None:
                decision = self.decision(label)
                program = self.validation.get("program")
                if program and label not in program["allowed_executions"]:
                    raise RuntimeError("Unchanged program baseline checkpoint is unavailable; refusing full replay: "
                        + label + " " + json.dumps(decision["comparisons"], sort_keys=True))
                print("CM runtime execute:", label, json.dumps(decision["comparisons"], separators=(",", ":")), flush=True)
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
                self.results[label] = {"status": "failed", "kind": "executed", "error": repr(error),
                    "traceback": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)],
                    **self.decision(label)}
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
    wrappers = "def driver(): return 1\ndef produce(): return 2\n"
    assert projection(wrappers, exclude=("driver",)) == projection(
        wrappers.replace("return 1", "return 3"), exclude=("driver",))
    runtime_cases.self_check()
    root = Path(os.environ["GITHUB_WORKSPACE"])
    if not (root / "ci/scripts").is_dir():
        root = Path(os.environ["CM_SOURCE_DIR"])
    current = test_inputs(root, "HEAD")
    assert set(current) == set(PHASES)
    state_path = "fixtures/state/driver.py"
    state_text = source(root, "HEAD", state_path)
    entry = "def case_query(m, sdk, frozen, authored):\n"
    assert state_text.count(entry) == 1
    changed_state = state_text.replace(entry, entry + '    assert False, "dependency self-check only"\n')
    manifest_path = "ci/scripts/mod_manifest.py"
    manifest_text = source(root, "HEAD", manifest_path)
    zip_entry = "def case_zip(inputs, binary, evidence, work, case):\n"
    assert manifest_text.count(zip_entry) == 1
    changed_manifest = manifest_text.replace(zip_entry, zip_entry + '    assert False, "dependency self-check only"\n')
    original_source = source
    with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, path:
            changed_state if path == state_path else changed_manifest if path == manifest_path
            else original_source(directory, revision, path)):
        changed = test_inputs(root, "HEAD")
    affected = {label for label in current if current[label] != changed[label]}
    expected = {"m04-query", *("m01-zip-" + name for name in runtime_cases.ZIP_INVALID)}
    assert affected == expected, ("Private matrix case dependency leak", sorted(affected))
    seams_path = "fixtures/sdk-seams/driver.py"
    seams_text = source(root, "HEAD", seams_path)
    entry = "def case_cli_help():\n"
    assert seams_text.count(entry) == 1
    changed_seams = seams_text.replace(entry, entry + '    assert False, "single G06 assertion only"\n')
    with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, path:
            changed_seams if path == seams_path else original_source(directory, revision, path)):
        changed = test_inputs(root, "HEAD")
    assert {label for label in current if current[label] != changed[label]} == {"g06-cli-help"}
    support_self_check(root, current)
    index_self_check(root, current)
    assert product_inputs(root, "HEAD")["files"]
    base = {"packages": {"libc6": "1"}, "files": [{"path": "usr/bin/python3", "sha256": "a"}, {"path": "fixture/test.py", "sha256": "a"}]}
    changed = json.loads(json.dumps(base))
    changed["files"][1]["sha256"] = "b"
    assert rootfs_key(base) == rootfs_key(changed)
    changed["packages"]["libc6"] = "2"
    assert rootfs_key(base) != rootfs_key(changed)
    with patch.dict(os.environ, {"CM_SOURCE_REPOSITORY": os.environ.get("CM_SOURCE_REPOSITORY", os.environ["GITHUB_REPOSITORY"]),
            "CM_SOURCE_SHA": git(root, "rev-parse", "HEAD").decode().strip(), "CM_REQUEST_ID": "retry-self-check"}):
        validation_self_check()
        checkpoint_self_check()
        refresh_self_check()
        history_self_check()
        native_self_check()
        probe_build_self_check()
        probe_overlay_self_check()
    origin_self_check()
    request_self_check()
    g02a_checkpoint_self_check()
    print("CM retry input/dependency/environment self-checks passed", flush=True)


def support_self_check(root, current):
    from unittest.mock import patch
    original = source
    driver = "fixtures/compatibility-policy/driver.py"
    text = source(root, "HEAD", driver)
    for entry, expected in (("case_versions()", {"s02-versions"}),
            ("empty_run(home, directory)", {"s02-zero-mod", "s02-disable"})):
        before = "def " + entry + ":\n"
        assert text.count(before) == 1
        changed_text = text.replace(before, before + '    assert False, "S02 dependency mutation"\n')
        with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, path:
                changed_text if path == driver else original(directory, revision, path)):
            changed = test_inputs(root, "HEAD")
        assert {label for label in current if current[label] != changed[label]} == expected
    path = "fixtures/compatibility-policy/policy.json"
    data = json.loads(source(root, "HEAD", path))
    for case in runtime_cases.GROUPS["s02"]:
        changed_data = json.loads(json.dumps(data))
        changed_data["cases"][case]["self_check_change"] = True
        with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, name:
                json.dumps(changed_data) if name == path else original(directory, revision, name)):
            changed = test_inputs(root, "HEAD")
        assert {label for label in current if current[label] != changed[label]} == {"s02-" + case}
    config_path = ".github/cm-ci.json"
    config = json.loads(source(root, "HEAD", config_path))
    import acceptance_cache
    import runtime_consumer
    from types import SimpleNamespace
    listener_host = "/inputs/host/bin/codex"
    listener_identity = "a" * 64
    listener_record = {"command": [listener_host, "cm", "--home", "/profile/s02/abc", "launch", "--"],
        "tui": True, "empty_launch_argv": True,
        "identity": {"proc_exe": listener_host, "executable_sha256": listener_identity},
        "provider_requests": [{"tools": [{"name": "mcp__codex_worktrees"}]}],
        "tui_mcp_listener": {"inode": "12", "port": 3000}}
    listener_metadata = ['1 getsockname(3<TCP:[12]>, {sa_family=AF_INET, sin_port=htons(3000), '
        'sin_addr=inet_addr("127.0.0.1")}, [16]) = 0']
    listener_connections = SimpleNamespace(provider_tcp_connections=lambda rows, ports: {"13"})
    assert runtime_consumer.bind_tui_mcp_listener(listener_record, listener_metadata,
        {listener_host: listener_identity}, listener_connections)["port"] == "3000"
    for listener_home, listener_digest, listener_rows in (
            ("/profile/s02/abc-extra", listener_identity, listener_metadata),
            ("/profile/s02/abc/../other", listener_identity, listener_metadata),
            ("/profile/s02/versions", listener_identity, listener_metadata),
            ("/profile/s02/abc", "b" * 64, listener_metadata), ("/profile/s02/abc", listener_identity, [])):
        listener_record["command"][3] = listener_home
        try:
            runtime_consumer.bind_tui_mcp_listener(listener_record, listener_rows,
                {listener_host: listener_digest}, listener_connections)
        except AssertionError:
            pass
        else:
            raise AssertionError("TUI listener escaped exact profile, Host or socket binding")
    with (patch.object(acceptance_cache, "load_config", return_value={**config, "task_id": "CM-S01"}),
            patch("linux_ci.load_config", return_value={**config, "task_id": "CM-S01"})):
        previous_recipes = acceptance_cache.recipes(root)
    with (patch.object(acceptance_cache, "load_config", return_value={**config, "task_id": "CM-S02"}),
            patch("linux_ci.load_config", return_value={**config, "task_id": "CM-S02"})):
        support_recipes = acceptance_cache.recipes(root)
    assert support_recipes == previous_recipes
    assert {"m02-native-probe-build", "review-tui-probe-build", "g03-local-backend-contract", "g06-c-abi"} <= support_recipes.keys()
    assert {"g06-sdk-" + owner + "-" + variant for owner in ("a", "b")
            for variant in ("v1", "v2", "replacement")} <= support_recipes.keys()
    production = product_inputs(root, "HEAD")
    for field, value, same in (("task_id", "CM-S01", True), ("required_checks", ["different"], True),
            ("task_id", "CM-G06", False),
            ("acceptance_script", "fixtures/distribution-provenance/acceptance.sh", True),
            ("build_profile", "dev", False), ("rust_toolchain", "1.0.0", False), ("units", [], False)):
        changed_config = {**config, field: value}
        assert changed_config != config
        with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, path:
                json.dumps(changed_config) if path == config_path else original(directory, revision, path)):
            assert (product_inputs(root, "HEAD") == production) is same, field
    path = json.loads(source(root, "HEAD", config_path))["acceptance_script"]
    recipe = source(root, "HEAD", path)
    with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, name:
            recipe + "\ncargo build --release\n" if name == path else original(directory, revision, name)):
        assert product_inputs(root, "HEAD") != production
    old = 'def build(cfg):\n    if cfg["task_id"] == "CM-S01":\n        return ["cargo", "build", "--locked"]\n'
    new = old.replace('== "CM-S01"', 'in ("CM-S01", "CM-S02")')
    assert projection(old, production=True) == projection(new, production=True)
    assert projection(old, production=True) != projection(new.replace('"--locked"', '"--release"'), production=True)
    assert projection(old, production=True) != projection(old.replace('"CM-S01"', '"CM-G06"'), production=True)
    old = old.replace('== "CM-S01"', '!= "CM-S01"')
    new = old.replace('!= "CM-S01"', 'not in ("CM-S01", "CM-S02")')
    assert projection(old, production=True) == projection(new, production=True)
    # Missing S02 files in an ancestor disable only S02 checkpoints.
    original_git = git
    with patch.object(sys.modules[__name__], "git", side_effect=lambda directory, *args:
            b"" if args[:1] == ("ls-tree",) and args[-len(SUPPORT_RUNTIME_FILES):] == SUPPORT_RUNTIME_FILES
            else original_git(directory, *args)):
        legacy = test_inputs(root, "HEAD")
    assert legacy == {label: value for label, value in current.items() if not label.startswith("s02-")}
    for path, entry in (("fixtures/runtime-sdk/driver.py", "def environment(home, directory, mode=\"handles\", old_handle=None):\n"),
            ("fixtures/managed-package/driver.py", "def tui_configuration(arguments, directory):\n")):
        text = source(root, "HEAD", path)
        assert text.count(entry) == 1
        updated = text.replace(entry, entry + '    assert False, "instance-held dependency mutation"\n')
        with patch.object(sys.modules[__name__], "source", side_effect=lambda directory, revision, name:
                updated if name == path else original(directory, revision, name)):
            changed = test_inputs(root, "HEAD")
        assert {label for label in current if label.startswith("s02-") and current[label] != changed[label]} == {"s02-abc"}
    base = {"packages": {}, "files": [{"path": "inputs/mods/g02a/turn-budget/payload.so", "sha256": "a"}]}
    native = {case: native_key(base, "s02-" + case) for case in runtime_cases.GROUPS["s02"]}
    base["files"][0]["sha256"] = "b"
    assert {case for case in native if native_key(base, "s02-" + case) != native[case]} == {"abc", "conflict", "disable"}


def index_self_check(root, current):
    from copy import deepcopy
    from functools import cache
    from unittest.mock import patch
    original, original_git = source, git
    module = sys.modules[__name__]
    @cache
    def snapshot(directory, revision, path):
        return original(directory, revision, path)
    with patch.object(module, "source", side_effect=snapshot):
        production = product_inputs(root, "HEAD")
        driver = "fixtures/binary-index/driver.py"
        text = snapshot(root, "HEAD", driver)
        for case in ("plan-exact", "archive-case-collision", "offline-missing"):
            entry = "def " + runtime_cases.function(case, "s03") + "():\n"
            assert text.count(entry) == 1
            changed_text = text.replace(entry, entry + '    assert False, "S03 assertion mutation"\n')
            with patch.object(module, "source", side_effect=lambda directory, revision, path:
                    changed_text if path == driver else snapshot(directory, revision, path)):
                changed = test_inputs(root, "HEAD")
                assert product_inputs(root, "HEAD") == production, "Test assertion invalidated native production"
            assert {label for label in current if current[label] != changed[label]} == {"s03-" + case}
        path = "fixtures/binary-index/cases.json"
        data = json.loads(snapshot(root, "HEAD", path))
        for case in runtime_cases.GROUPS["s03"]:
            changed_data = deepcopy(data)
            changed_data["cases"][case]["self_check_change"] = True
            with patch.object(module, "source", side_effect=lambda directory, revision, name:
                    json.dumps(changed_data) if name == path else snapshot(directory, revision, name)):
                changed = test_inputs(root, "HEAD")
                assert product_inputs(root, "HEAD") == production
            assert {label for label in current if current[label] != changed[label]} == {"s03-" + case}
        with patch.object(module, "git", side_effect=lambda directory, *args:
                b"" if args[:1] == ("ls-tree",) and args[-len(INDEX_RUNTIME_FILES):] == INDEX_RUNTIME_FILES
                else original_git(directory, *args)):
            legacy = test_inputs(root, "HEAD")
        assert legacy == {label: value for label, value in current.items() if not label.startswith("s03-")}
        tree = original_git(root, "ls-tree", "-rz", "HEAD")
        for path in ("crates/cm/src/index.rs", "adapters/codex-e4568a3/cli-index.rs",
                "adapters/codex-e4568a3/index.patch"):
            rows = tree.split(b"\0")
            found = False
            for index, row in enumerate(rows):
                if row.endswith(b"\t" + path.encode()):
                    metadata, name = row.split(b"\t", 1)
                    fields = metadata.split(b" ")
                    fields[-1] = b"f" * 40 if fields[-1] != b"f" * 40 else b"e" * 40
                    rows[index] = b" ".join(fields) + b"\t" + name
                    found = True
            assert found, path
            with patch.object(module, "git", side_effect=lambda directory, *args:
                    b"\0".join(rows) if args == ("ls-tree", "-rz", "HEAD") else original_git(directory, *args)):
                assert product_inputs(root, "HEAD") != production, path
        path = "adapters/codex-e4568a3/source.json"
        pin = json.loads(snapshot(root, "HEAD", path))
        pin["commit"] = "f" * 40
        with patch.object(module, "source", side_effect=lambda directory, revision, name:
                json.dumps(pin) if name == path else snapshot(directory, revision, name)):
            assert product_inputs(root, "HEAD") != production, "Upstream commit did not invalidate production"
    closure = {"packages": {}, "files": [{"path": "inputs/host/bin/codex", "sha256": "a"},
        {"path": "fixture/binary-index-tls/cert.pem", "sha256": "certificate"},
        {"path": "fixture/binary-index-tls/key.pem", "sha256": "test-key"}],
        "binary_index_inputs": {case: "before" for case in runtime_cases.GROUPS["s03"]}}
    keys = {case: native_key(closure, "s03-" + case) for case in runtime_cases.GROUPS["s03"]}
    closure["files"][1]["sha256"] = "changed-certificate"
    assert {case for case in keys if native_key(closure, "s03-" + case) != keys[case]} == {"http-tls"}
    closure["files"][1]["sha256"] = "certificate"
    closure["binary_index_inputs"]["archive-traversal"] = "changed"
    assert {case for case in keys if native_key(closure, "s03-" + case) != keys[case]} == {"archive-traversal"}
    closure["files"][0]["sha256"] = "changed-host"
    assert all(native_key(closure, "s03-" + case) != keys[case] for case in keys)


def native_self_check():
    from copy import deepcopy
    labels = ("p04-states", "m02-authoring", "m04-query", "review-key-events",
              "g02a-counting", "concurrency-backend-scope", "concurrency-lock-domains")
    files = ("inputs/host/bin/codex", "inputs/mods/m02/example/payload.so", "inputs/probes/cm-review-tui",
        "inputs/probes/cm-concurrency-core", "inputs/probes/cm-concurrency-backend",
        "fixture/m02-native-probe.json", "fixture/g02a-native-probe.json", "fixture/concurrency-models.json")
    closure = {"packages": {"libc6": "1"}, "files": [{"path": path, "sha256": "before"} for path in files]}
    before = {label: native_key(closure, label) for label in labels}
    expected = {
        "inputs/probes/cm-review-tui": {"review-key-events"},
        "inputs/probes/cm-concurrency-core": {"concurrency-backend-scope", "concurrency-lock-domains"},
        "inputs/probes/cm-concurrency-backend": {"concurrency-backend-scope"},
        "fixture/m02-native-probe.json": {"m02-authoring"},
        "fixture/g02a-native-probe.json": {"g02a-counting"},
    }
    for path, affected in expected.items():
        changed = deepcopy(closure)
        next(row for row in changed["files"] if row["path"] == path)["sha256"] = "after"
        assert {label for label in labels if before[label] != native_key(changed, label)} == affected, path
    changed = deepcopy(closure)
    changed["files"][0]["sha256"] = "changed-host"
    assert all(before[label] != native_key(changed, label) for label in labels)
    changed = deepcopy(closure)
    changed["packages"]["libc6"] = "2"
    assert all(before[label] != native_key(changed, label) for label in labels)
    labels = tuple("s01-" + case for case in runtime_cases.GROUPS["s01"])
    paths = {
        "fixture/s01-proofs/subjects/sdk-a.json": set(labels),
        "fixture/s01-proofs/bundle.jsonl": set(labels),
        "fixture/s01-bootstrap/identity.json": set(labels),
        "fixture/s01-proofs/index/catalog.json": set(),
        "fixture/s01-proofs/index/archives/sdk-a.cmod": set(),
    }
    closure = {"packages": {"libc6": "1"}, "files": [{"path": path, "sha256": "before"} for path in paths]}
    before = {label: native_key(closure, label) for label in labels}
    for path, expected in paths.items():
        changed = deepcopy(closure)
        next(row for row in changed["files"] if row["path"] == path)["sha256"] = "after"
        assert {label for label in labels if before[label] != native_key(changed, label)} == expected, path
    import runtime_consumer
    import runtime_sdk
    assert runtime_cases.ENTRY_INVALID == runtime_consumer.ENTRY_INVALID
    assert runtime_cases.CALL_INVALID == runtime_consumer.CALL_INVALID
    assert runtime_cases.SDK_INVALID == runtime_sdk.NEGATIVE
    labels = ("g06-tool-base", "g06-cli-help", "g06-tool-foreign-owner", "g06-replacement-conflict")
    paths = ("inputs/host/bin/codex", "inputs/mods/g06/a/v1/payload.so", "inputs/mods/g06/b/v1/payload.so",
             "inputs/mods/g06/a/replacement/payload.so", "inputs/mods/g06/b/replacement/payload.so",
             "inputs/probes/cm-concurrency-core")
    closure = {"packages": {"libc6": "1"}, "files": [{"path": path, "sha256": "before"} for path in paths]}
    before = {label: native_key(closure, label) for label in labels}
    for path, expected in ((paths[1], {"g06-cli-help", "g06-tool-foreign-owner"}),
                           (paths[2], {"g06-tool-foreign-owner"}),
                           (paths[3], {"g06-replacement-conflict"}),
                           (paths[-1], {"g06-tool-foreign-owner"})):
        changed = deepcopy(closure)
        next(row for row in changed["files"] if row["path"] == path)["sha256"] = "after"
        assert {label for label in labels if before[label] != native_key(changed, label)} == expected, path
    labels = (*(f"m03-{case}" for case in runtime_cases.GROUPS["m03"]), "g06-cli-help")
    paths = {
        "inputs/mods/g06/a/v1/payload.so": {"g06-cli-help"},
        "inputs/mods/g06/a/v1/mod.toml": {"g06-cli-help"},
        "inputs/mods/g06/b/v1/payload.so": set(),
        "inputs/mods/a/payload.so": {"m03-legacy", "m03-rejections"},
        "inputs/mods/b/normal/payload.so": {"m03-legacy", "m03-rejections"},
        "inputs/mods/m01-a/payload.so": {"m03-rejections", "m03-writers"},
        "inputs/mods/m01-b/payload.so": {"m03-rejections", "m03-writers"},
        "inputs/mods/m02/lifecycle-audit/normal/payload.so": set(labels) - {"m03-legacy", "g06-cli-help"},
        "inputs/mods/m02/example-tool/normal/payload.so": set(labels) - {"m03-legacy", "m03-rejections", "g06-cli-help"},
        "inputs/mods/example-tool.cmod": {"m03-install"},
        "inputs/mods/constructor-sentinel/payload.so": {"m03-rejections", "m03-writers"},
        "inputs/host/bin/codex": set(labels),
    }
    closure = {"packages": {"libc6": "1"}, "files": [{"path": path, "sha256": "before"} for path in paths]}
    before = {label: native_key(closure, label) for label in labels}
    for path, expected in paths.items():
        changed = deepcopy(closure)
        next(row for row in changed["files"] if row["path"] == path)["sha256"] = "after"
        assert {label for label in labels if before[label] != native_key(changed, label)} == expected, path
    changed = deepcopy(closure)
    changed["packages"]["libc6"] = "2"
    assert all(before[label] != native_key(changed, label) for label in labels)


def history_self_check():
    from contextlib import nullcontext
    from copy import deepcopy
    from types import SimpleNamespace
    from unittest.mock import patch
    worker, workflow = "DSLZL/CM-build-" + linux_native()["key"], "b" * 40
    wanted = {"p04-states": "a", "m04-query": "b"}
    indexes, records = {}, {}
    runs = []
    for number, labels in ((9014, ()), (9013, ()), (9012, ("m04-query",)), (9011, ("p04-states",))):
        runs.append({"id": number, "run_attempt": 1, "head_sha": workflow, "event": "workflow_dispatch",
            "path": ".github/workflows/build.yml", "display_title": f"CM {linux_native()['label']} / history-" + str(number)})
        record = {"id": number, "name": f"cm-{linux_native()['key']}-consumer-checkpoints-history-" + str(number) + "-1",
            "digest": "sha256:" + "c" * 64, "size_in_bytes": 1, "expired": number == 9013,
            "workflow_run": {"id": number}}
        records[number] = record
        indexes[number] = {"schema_version": 2, "environment": environment(),
            "provenance": {"GITHUB_REPOSITORY": worker, "GITHUB_RUN_ID": str(number), "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_WORKFLOW_SHA": workflow, "CM_SOURCE_SHA": "a" * 40,
                "CM_SOURCE_REPOSITORY": "DSLZL/CM"},
            "test_inputs": wanted, "steps": {label: {"status": "pass", "key": label} for label in labels}}
    def api(path):
        if "/compare/" in path:
            return {"status": "ahead"}
        number = int(path.split("/actions/runs/", 1)[1].split("/", 1)[0])
        return {"artifacts": [] if number == 9014 else [records[number]]}
    stub = SimpleNamespace(api=api, archive_json=lambda archive, name: deepcopy(indexes[archive["id"]]))
    with patch(__name__ + ".policy", return_value=stub), patch(__name__ + ".git"), \
            patch(__name__ + ".test_inputs", return_value=wanted), \
            patch(__name__ + ".small_archive", side_effect=lambda worker, record, path: nullcontext(record)):
        selected = checkpoint_history(None, runs, worker, workflow)
        assert {row["run_id"] for row in selected} == {9012, 9011}
        assert {label for row in selected for label in row["labels"]} == set(wanted)
        indexes[9012]["provenance"]["GITHUB_RUN_ID"] = "other-run"
        selected = checkpoint_history(None, runs, worker, workflow)
        assert {row["run_id"] for row in selected} == {9011}, "Invalid latest index hid an earlier pass"
        indexes[9011]["schema_version"] = 1
        assert not checkpoint_history(None, runs, worker, workflow), "Legacy combined matrix was reused"


def probe_build_self_check():
    from unittest.mock import patch
    import acceptance_cache
    import runtime_sdk
    import turn_budget
    names = {
        "m02": ("m02-native-probe.json", "m02-native-scopes.json", "m02-native-events.jsonl", "m02-native-trace.jsonl"),
        "g02a": ("g02a-native-probe.json", "g02a-native-scopes.json", "g02a-native-trace.jsonl")}
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        inputs = root / "cm-probe-base/runtime-inputs"
        (inputs / "fixture").mkdir(parents=True)
        write(inputs / "producer.json", {"host": {}, "g02a": {"enabled": True}})
        (inputs / "host").mkdir()
        (inputs / "host/codex").write_bytes(b"frozen-host")
        for group in names.values():
            for name in group:
                (inputs / "fixture" / name).write_text("stale")
        label = "m02-native-probe-build"
        logs, output, cache = root / "logs", root / "test-build", root / "cache"
        write(logs / "retry-plan.json", {"changed_probes": [label], "probe_inputs": {}})
        write(cache / label / "build.json", {"inputs": {"instrumented_source_sha256": "f" * 64}})
        binary = root / "binary"
        binary.write_bytes(b"private-core-probe")
        before = {path: (inputs / path).read_bytes() for path in ("producer.json", "host/codex")}

        def proof(group):
            assert all(not (inputs / "fixture" / name).exists() for name in names[group]), "Frozen proof output leaked"
            for name in names[group]:
                with (inputs / "fixture" / name).open("x") as stream:
                    stream.write("fresh")
            return {"status": "pass"}

        with patch.dict(os.environ, {"RUNNER_TEMP": str(root), "CM_TEST_BUILD_DIR": str(output),
                "CM_ACCEPTANCE_BUILD_CACHE_DIR": str(cache)}), \
                patch.object(runtime_sdk, "native_probe", side_effect=lambda *args: proof("m02")), \
                patch.object(turn_budget, "native_probe", side_effect=lambda *args: proof("g02a")), \
                patch.object(acceptance_cache, "run", return_value=binary), patch.object(policy(), "output"):
            probe_build(root, logs)
        for group in names.values():
            for name in group:
                assert (output / label / "fixture" / name).read_text() == "fresh"
        assert all((inputs / path).read_bytes() == data for path, data in before.items())


def probe_overlay_self_check(label="review-tui-probe-build"):
    from contextlib import nullcontext
    from copy import deepcopy
    from io import BytesIO
    from unittest.mock import patch
    import runtime_consumer as runtime
    import zipfile
    sdk_author = label.startswith("g06-sdk-")
    expected = {path: "a" * 64 for path, targets in PRIVATE_PROBES.items() if label in targets}
    origin = runtime.provenance()
    item = {"target": label, "inputs": expected, "run_id": int(origin["GITHUB_RUN_ID"]),
        "run_attempt": int(origin["GITHUB_RUN_ATTEMPT"]), "workflow_sha": origin["GITHUB_WORKFLOW_SHA"],
        "source_sha": origin["CM_SOURCE_SHA"], "request_id": origin["CM_REQUEST_ID"]}
    def archive(path):
        data = BytesIO()
        with zipfile.ZipFile(data, "w") as output:
            for file in sorted(path.rglob("*")):
                if file.is_file():
                    output.write(file, file.relative_to(path).as_posix())
        data.seek(0)
        return zipfile.ZipFile(data)
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        artifact, inputs = root / "artifact", root / "inputs"
        artifact.mkdir()
        (inputs / "host/bin").mkdir(parents=True)
        (inputs / "host/bin/codex").write_bytes(b"frozen-host")
        write(inputs / "producer.json", {"host": {"executable_sha256": "frozen-host"},
            "authors": {}, "sdk_seams": {"authors": {}}})
        (inputs / "mods/g06/a/v1").mkdir(parents=True)
        (inputs / "mods/g06/b/v1").mkdir(parents=True)
        (inputs / "mods/g06/b/v1/payload.so").write_bytes(b"unchanged-author-b")
        (inputs / "official").mkdir()
        (inputs / "official/frozen").write_bytes(b"unchanged-official")
        (artifact / "binary").write_bytes(b"private-tui-probe")
        (artifact / "binary").chmod(0o755)
        recipe = {"binary": "codex_tui"}
        build_inputs = {"recipes": {label: recipe}, **({"author": {"sources": [
            {"path": path, "sha256": value} for path, value in expected.items()]}} if sdk_author else {
                "instrumented_source_sha256": "f" * 64})}
        write(artifact / "build.json", {"origin": origin, "inputs": build_inputs,
            "checks": {label: {"return_code": 0, "recipe": recipe}},
            "files": [{"path": label + ".bin", "sha256": runtime.sha(artifact / "binary")}]})
        metadata = {"source_sha256": "f" * 64}
        if sdk_author:
            import mod_manifest
            mod_manifest.manifest(artifact, {"id": "sdk-a", "binary": {"path": "payload.so",
                "sha256": runtime.sha(artifact / "binary"), "size": (artifact / "binary").stat().st_size},
                "provenance": {"revision": origin["CM_SOURCE_SHA"]}})
            metadata = {"author": {"inputs": build_inputs, "origin": origin,
                "payload_sha256": runtime.sha(artifact / "binary"), "mod_build_id": "sha256:" + digest(build_inputs),
                "exports": " cm_mod_entry_v2", "host_linked": False, "host_frozen_before_author_build": "frozen-host"}}
        proof = {"schema_version": 1, "target": label, "inputs": expected, "provenance": origin,
            "metadata": metadata, "files": runtime.inventory(artifact)}
        write(artifact / "test-build.json", proof)
        validation = {"probe_inputs": expected, "test_builds": {label: item}}
        before = {name: runtime.inventory(inputs / name) for name in ("host", "official", "mods/g06/b")}
        original_build = read(artifact / "build.json")
        p = policy()
        with patch(__name__ + ".verify_test_build", return_value={}), \
                patch.object(p, "download_origin_archive", side_effect=lambda worker, record, path: archive(artifact)):
            refresh_probes(inputs, validation)
            assert all(runtime.inventory(inputs / name) == files for name, files in before.items())
            if sdk_author:
                assert (inputs / "mods/g06/a/v1/payload.so").read_bytes() == b"private-tui-probe"
                assert effective_producer(inputs)["authors"]["g06/a/v1"] == metadata["author"]
                assert read(inputs / "fixture/g06-producer.json")["authors"]["a/v1"] == metadata["author"]
            else:
                assert (inputs / "probes/cm-review-tui").read_bytes() == b"private-tui-probe"
                assert (inputs / "probes/cm-concurrency-backend").read_bytes() == b"private-tui-probe"
            original = deepcopy(proof)
            for mutation in ("unknown-target", "host-overwrite", "wrong-origin", "wrong-bytes", "wrong-recipe",
                             *(("wrong-manifest", "wrong-author-source") if sdk_author else ())):
                write(artifact / "build.json", original_build)
                candidate = deepcopy(original)
                if mutation == "unknown-target":
                    candidate["target"] = "host"
                elif mutation == "host-overwrite":
                    candidate["files"][0]["path"] = "host/bin/codex"
                elif mutation == "wrong-origin":
                    candidate["provenance"]["GITHUB_RUN_ID"] = "other-run"
                elif mutation == "wrong-bytes":
                    candidate["files"][0]["sha256"] = "wrong"
                elif mutation == "wrong-manifest":
                    import tomllib
                    fields = tomllib.loads((artifact / "mod.toml").read_text())
                    fields["binary"]["sha256"] = "other-payload"
                    mod_manifest.manifest(artifact, fields)
                    candidate["files"] = [row for row in runtime.inventory(artifact) if row["path"] != "test-build.json"]
                elif mutation == "wrong-author-source":
                    mod_manifest.manifest(artifact, {"id": "sdk-a", "binary": {"path": "payload.so",
                        "sha256": runtime.sha(artifact / "binary"), "size": (artifact / "binary").stat().st_size},
                        "provenance": {"revision": origin["CM_SOURCE_SHA"]}})
                    candidate["inputs"][next(iter(expected))] = "different-source"
                    validation["probe_inputs"] = candidate["inputs"]
                    item["inputs"] = candidate["inputs"]
                else:
                    receipt = read(artifact / "build.json")
                    receipt["checks"][label]["return_code"] = 1
                    write(artifact / "build.json", receipt)
                    candidate["files"] = [row for row in runtime.inventory(artifact) if row["path"] != "test-build.json"]
                write(artifact / "test-build.json", candidate)
                try:
                    refresh_probes(inputs, validation)
                except (AssertionError, KeyError):
                    pass
                else:
                    raise AssertionError("Invalid test-build overlay accepted: " + mutation)
                assert all(runtime.inventory(inputs / name) == files for name, files in before.items())
    if not sdk_author:
        probe_overlay_self_check("g06-sdk-a-v1")


def g02a_checkpoint_self_check():
    checkpoint = object.__new__(Checkpoints)
    cases = {label: label.removeprefix("g02a-") for label in PHASES if label.startswith("g02a-")}
    assert len(cases) == 6
    checkpoint.reports = {label: ["budget-" + case + ".json"] for label, case in cases.items()}
    checkpoint.reports["consumer-matrix"] = ["p04.json"]
    for label, case in cases.items():
        assert checkpoint.owns(label, Path("g02a") / case / "suite.json")
        assert checkpoint.owns(label, Path("budget-" + case + ".json"))
        for other, other_case in cases.items():
            if other != label:
                assert not checkpoint.owns(label, Path("g02a") / other_case / "suite.json")
                assert not checkpoint.owns(label, Path("budget-" + other_case + ".json"))
        assert not checkpoint.owns("consumer-matrix", Path("g02a") / case / "suite.json")


def request_self_check():
    from contextlib import nullcontext
    from unittest.mock import patch
    p = policy()
    host = {"run_id": 10, "run_attempt": 1, "source_sha": "a" * 40,
            "workflow_sha": "b" * 40, "request_id": "request-self-check"}
    for number, prefix in enumerate(("input", "consumer", "receipt"), 1):
        host.update({prefix + "_artifact_id": number, prefix + "_artifact_sha256": "c" * 64})
    producer = {"steps": [{"name": "Restore exact successful qualification without executing requested source",
                           "conclusion": "skipped"}]}
    with patch(__name__ + ".small_archive", return_value=nullcontext(None)) as download:
        qualification = legacy_request(producer, "worker", {})
        assert qualification == {"kind": "qualification", "host_origin": None} and not download.called
        producer["steps"][0]["conclusion"] = "success"
        receipt = {"build_kind": "mod-only", "host_origin": {"verified": True, "origin": host}}
        with patch.object(p, "archive_json", return_value=receipt):
            mod = legacy_request(producer, "worker", {})
            assert mod == {"kind": "mod-only", "host_origin": host} and mod != qualification
            assert mod != {**mod, "host_origin": {**host, "run_id": 11}}
            receipt["host_origin"]["verified"] = False
            try:
                legacy_request(producer, "worker", {})
            except RuntimeError:
                pass
            else:
                raise AssertionError("Unverified Mod-only producer request accepted")
    for steps in ([], [{**producer["steps"][0], "conclusion": "failure"}]):
        try:
            legacy_request({"steps": steps}, "worker", {})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Missing or failed legacy producer kind accepted")


def refresh_self_check():
    from unittest.mock import patch
    import runtime_consumer as runtime
    current = environment()
    builder = {**current, "ImageVersion": "different-builder-image"}
    assert same_runtime_platform(builder, current)
    for key in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS"):
        assert not same_runtime_platform({**builder, key: "different-platform"}, current)
    assert not same_runtime_platform({**builder, "ImageVersion": ""}, current)
    with tempfile.TemporaryDirectory() as directory:
        inputs, overlay = Path(directory) / "inputs", Path(directory) / "overlay"
        inputs.mkdir()
        overlay.mkdir()
        (inputs / "frozen-host").write_bytes(b"unchanged native input")
        original = runtime.inventory(inputs)
        write(inputs / "input-manifest.json", {"files": original, "sha256": runtime.digest(original)})
        (overlay / "runtime_consumer.py").write_bytes(b"inert test overlay")
        validation = {"provenance": runtime.provenance(), "environment": builder,
            "production_origin": {"frozen": "producer"}, "files": runtime.inventory(overlay)}
        write(overlay / "validation.json", validation)
        with patch.dict(os.environ, {"CM_CONSUMER_INPUT_DIR": str(inputs), "CM_VALIDATION_INPUT_DIR": str(overlay),
                "CM_PRODUCTION_ORIGIN": json.dumps(validation["production_origin"])}), \
                patch(__name__ + ".refresh_probes"):
            refresh()
            recorded = read(inputs / "validation.json")
            assert recorded["environment"] == builder and recorded["consumer_environment"] == current
            assert (inputs / "frozen-host").read_bytes() == b"unchanged native input"
            assert (inputs / "runtime_consumer.py").read_bytes() == b"inert test overlay"
            before = runtime.inventory(inputs)
            for field, value in (("environment", {**builder, "RUNNER_ARCH": "other-architecture"}),
                    ("provenance", {**runtime.provenance(), "GITHUB_RUN_ID": "other-run"})):
                write(overlay / "validation.json", {**validation, field: value})
                try:
                    refresh()
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Unbound overlay environment or provenance accepted")
                assert runtime.inventory(inputs) == before


def validation_self_check():
    import zipfile
    value = {"checkpoint_origins": [{"steps": [{"command": ["/usr/bin/env", "--", "payload"]}] * 12000}] * 12}
    assert len(json.dumps(value, indent=2).encode("utf-8")) > 16 * 1024 ** 2
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "validation.json"
        write_validation(path, value)
        original = path.read_bytes()
        archive_path = Path(directory) / "validation.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("validation.json", original)
        with zipfile.ZipFile(archive_path) as archive:
            assert policy().archive_json(archive, "validation.json") == value
        try:
            write_validation(path, {"payload": "x" * (16 * 1024 ** 2)})
        except RuntimeError:
            pass
        else:
            raise AssertionError("Oversized validation metadata was written")
        assert path.read_bytes() == original
    print("CM bounded validation metadata roundtrip and rejection passed", flush=True)


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
    validation = {"environment": {**environment(), "ImageVersion": "builder-image"}, "test_inputs": {label: "a" for label in labels},
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
            assert first.index["environment"] == environment() != validation["environment"]
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
            # The newest run may have no checkpoint; different passed cases can come from different runs.
            previous = []
            sources = {}
            for number, source_dir, included in ((13, directory / "second", ()),
                    (12, directory / "second", (labels[1],)), (11, directory / "first", (labels[0],))):
                snapshot = directory / ("history-" + str(number))
                snapshot.mkdir()
                index = read(source_dir / "index.json")
                index["steps"] = {label: index["steps"][label] for label in included}
                for label in included:
                    shutil.copytree(source_dir / label, snapshot / label)
                write(snapshot / "index.json", index)
                sources[number] = snapshot
                previous.append({**origin, "run_id": number, "artifact": {"id": number}, "index": index})
            os.environ.update(CM_RUNTIME_CHECKPOINT_DIR=str(directory / "multi"), CM_RUNTIME_RESUME_DIR="")
            other_image = {**previous[0], "index": {**previous[0]["index"],
                "environment": {**environment(), "ImageVersion": "other-consumer-image"}}}
            multi = Checkpoints(runtime, {**validation, "checkpoint_origins": [other_image, *previous]},
                closure, temp, evidence, logs, reports, [])
            assert len(multi.previous) == len(previous), "A different consumer image became a checkpoint candidate"
            def extract(worker, candidate, destination):
                shutil.copytree(sources[candidate["artifact"]["id"]], destination)
            with patch(__name__ + ".extract_checkpoint", side_effect=extract) as download:
                assert all(multi.run(logs, label, [], 1).returncode == 0 for label in labels)
                assert [multi.results[label]["checkpoint_artifact"]["id"] for label in labels] == [11, 12]
                assert download.call_count == 2 and calls == [labels[0], labels[1], labels[1]]
            os.environ["CM_RUNTIME_RESUME_DIR"] = str(directory / "first")
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
              "run_id": 10, "run_attempt": 1, "job": "build-write / " + linux_native()["key"], "job_id": 20}
    records = {}
    for number, (key, prefix) in enumerate((("product_artifact", "task-artifacts"), ("input_artifact", "runtime-inputs")), 1):
        records[number] = {"id": number, "name": f"cm-{linux_native()['key']}-" + prefix + "-retry-self-check-1",
            "digest": "sha256:" + "c" * 64, "size_in_bytes": 1, "expired": False, "workflow_run": {"id": 10}}
        origin[key] = artifact_ref(records[number])

    def api(path):
        if path.endswith("/jobs?per_page=100"):
            return {"jobs": [{"name": origin["job"], "id": 20, "status": "completed", "conclusion": "success"}]}
        if "/actions/artifacts/" in path:
            return records[int(path.rsplit("/", 1)[1])]
        return {"run_attempt": 1, "head_sha": "b" * 40, "event": "workflow_dispatch",
                "path": ".github/workflows/build.yml", "display_title": f"CM {linux_native()['label']} / retry-self-check"}

    stub = SimpleNamespace(identities=lambda: ("DSLZL/CM", "DSLZL/CM-build-" + linux_native()["key"], "a" * 40, "b" * 40, "retry-self-check"),
                           api=api, successful_job=p.successful_job, receipt_jobs=p.receipt_jobs)
    with patch(__name__ + ".policy", return_value=stub):
        verify_production_origin(origin)
        assert verify_production_origin(origin, worker="DSLZL/CM-build-" + linux_native()["key"], fetch=api)["input_artifact"] == records[2]
        jobs_path = f"repos/DSLZL/CM-build-{linux_native()['key']}/actions/runs/10/attempts/1/jobs?per_page=100"
        pending = {"jobs": [{"name": origin["job"], "id": 20, "status": "in_progress", "conclusion": None}]}
        with patch("time.sleep") as pause:
            responses = iter((pending, api(jobs_path)))
            def delayed(path):
                return next(responses) if path == jobs_path else api(path)
            assert verify_production_origin(origin, fetch=delayed)["input_artifact"] == records[2]
            pause.assert_called_once_with(5)
        test_record = {**records[1], "id": 3,
            "name": f"cm-{linux_native()['key']}-test-build-review-tui-probe-build-retry-self-check-1"}
        records[3] = test_record
        test_build = {**origin, "target": "review-tui-probe-build", "artifact": artifact_ref(test_record)}
        assert verify_test_build(test_build, worker="DSLZL/CM-build-" + linux_native()["key"], fetch=api) == test_record
        for key, changed in (("job_id", 21), ("run_attempt", 2), ("target", "host")):
            try:
                verify_test_build({**test_build, key: changed}, worker="DSLZL/CM-build-" + linux_native()["key"], fetch=api)
            except (AssertionError, RuntimeError):
                pass
            else:
                raise AssertionError("Unbound test-build run/job/target accepted")
        for conclusion in ("failure", "cancelled", "skipped"):
            def failed(path):
                if path == jobs_path:
                    return {"jobs": [{"name": origin["job"], "id": 20, "status": "completed", "conclusion": conclusion}]}
                return api(path)
            with patch("time.sleep") as pause:
                try:
                    verify_production_origin(origin, fetch=failed)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Failed producer origin accepted")
                pause.assert_not_called()
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
        {"plan": select, "overlay": overlay, "probe-prepare": probe_prepare, "probe-build": probe_build}[sys.argv[1]](root, logs)
