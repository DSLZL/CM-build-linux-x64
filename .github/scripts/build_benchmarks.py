#!/usr/bin/env python3
"""CM-S04 measurements. Product execution belongs to the independent hosted worker."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import urllib.error


CONFIG = "ci/benchmarks/scenarios.json"
RUNTIME = "ci/benchmarks/runtime-loading.json"
ROLES = ("H", "A", "B", "C")
STAGES = ("cold", "warm", "mod-change")
TARGET = "x86_64-unknown-linux-gnu"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def root():
    return Path(os.environ["CM_SOURCE_DIR"]).resolve()


def config():
    value = read(root() / CONFIG)
    assert value["schema_version"] == 1 and value["task_id"] == "CM-S04"
    assert value["target"] == TARGET and tuple(value["stages"]) == STAGES
    assert value["repetitions"] == [1, 2, 3] and set(value["roles"]) == set(ROLES)
    assert value["required_checks"] == ["CM-S04-AC0" + str(i) for i in range(1, 7)]
    assert value["host_seed"]["save"] is False
    return value


def origin():
    return {"repository": os.environ["GITHUB_REPOSITORY"], "source_sha": os.environ["CM_SOURCE_SHA"],
        "worker_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "job": os.environ["GITHUB_JOB"],
        "request_id": os.environ["CM_REQUEST_ID"]}


def cohort():
    result = {key: os.environ[key] for key in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}
    assert result["RUNNER_OS"] == "Linux" and result["RUNNER_ARCH"] == "X64"
    return result


def machine():
    return {"cohort": cohort(), "cpu": Path("/proc/cpuinfo").read_text(),
        "load_average": list(os.getloadavg()), "cpu_count": os.cpu_count(),
        "kernel": os.uname().release, "same_physical_runner_assumed": False}


def inventory(directory):
    directory = Path(directory)
    return [{"path": str(path.relative_to(directory)), "size": path.stat().st_size, "sha256": sha(path)}
        for path in sorted(directory.rglob("*")) if path.is_file() and not path.is_symlink()]


def output(values):
    from worker_policy import output as emit
    emit(values)


def paths(role):
    assert role in ROLES
    base = Path(os.environ["RUNNER_TEMP"])
    # Existing H cache archives bind these original paths as well as their keys.
    return {"CARGO_HOME": base / ("cm-cargo-home" if role == "H" else "cm-s04-" + role + "-cargo"),
        "SCCACHE_DIR": base / ("cm-sccache" if role == "H" else "cm-s04-" + role + "-sccache"),
        "CARGO_TARGET_DIR": base / ("cm-target" if role == "H" else "cm-s04-" + role + "-target"),
        "CM_CI_LOG_DIR": base / "cm-s04-evidence" / role}


def set_role(role):
    from linux_ci import append_environment
    values = {key: str(value) for key, value in paths(role).items()}
    os.environ.update(values)
    append_environment(values)
    Path(values["CM_CI_LOG_DIR"]).mkdir(parents=True, exist_ok=True)
    return Path(values["CM_CI_LOG_DIR"])


def apply_environment():
    for line in Path(os.environ["GITHUB_ENV"]).read_text().splitlines():
        if "=" in line and "<<" not in line:
            name, value = line.split("=", 1)
            os.environ[name] = value


def stats(directory, label):
    result = {"status": "unavailable", "reason": "sccache did not return valid statistics"}
    for kind, arguments in (("json", ["--stats-format", "json"]), ("text", [])):
        process = subprocess.run(["sccache", "--show-stats", *arguments], capture_output=True, text=True)
        (directory / (label + "." + kind)).write_text(process.stdout + process.stderr)
        if kind == "json" and process.returncode == 0:
            try:
                result = {"status": "available", "raw": json.loads(process.stdout), "path": label + ".json"}
            except ValueError:
                pass
    return result


def numeric_stats(snapshot):
    values = {}
    def visit(value, prefix=""):
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, prefix + ("." if prefix else "") + key)
        elif type(value) in (int, float):
            values[prefix] = value
    if snapshot["status"] == "available":
        visit(snapshot["raw"])
    return values


def stat_delta(before, after):
    if before["status"] != "available" or after["status"] != "available":
        return {"status": "unavailable", "reason": "before/after statistics unavailable"}
    left, right = numeric_stats(before), numeric_stats(after)
    return {"status": "available", "values": {key: value - left.get(key, 0) for key, value in right.items()}}


def command(directory, label, arguments, *, cwd=None, env=None, trace=False):
    from linux_ci import execute
    import ci_progress
    directory.mkdir(parents=True, exist_ok=True)
    cwd, arguments = Path(cwd or root()), list(arguments)
    if arguments[0] == "cargo" and "--manifest-path" in arguments:
        index = arguments.index("--manifest-path") + 1
        manifest = (cwd / arguments[index]).resolve()
        cwd, arguments[index] = manifest.parent, manifest.name
    actual = arguments
    if trace:
        actual = ["strace", "-f", "-qq", "-s", "4096", "-e", "trace=execve",
            "-o", str(directory / (label + ".exec")), "--", *actual]
    actual = ["/usr/bin/time", "-v", "-o", str(directory / (label + ".usage")), *actual]
    with ci_progress.stage("s04/" + label):
        execute(cwd, directory, label, actual, env)


def phase_metrics(directory):
    events = directory / "phase-results.jsonl"
    result = [json.loads(line) for line in events.read_text().splitlines()] if events.is_file() else []
    for event in result:
        usage = directory / (event["phase"] + ".usage")
        event["resource_usage"] = {"status": "unavailable", "reason": "phase has no GNU time record"}
        if usage.is_file():
            text = usage.read_text()
            def number(pattern):
                match = re.search(pattern, text)
                return float(match[1]) if match else None
            event["resource_usage"] = {"method": "GNU time -v; command and descendants",
                "cpu_user_seconds": number(r"User time \(seconds\): ([0-9.]+)"),
                "cpu_system_seconds": number(r"System time \(seconds\): ([0-9.]+)"),
                "peak_rss_kib": number(r"Maximum resident set size \(kbytes\): ([0-9.]+)")}
    return result


def compiler_executions(directory):
    result = []
    for path in sorted(directory.glob("*.exec")):
        for line in path.read_text(errors="replace").splitlines():
            match = re.search(r'execve\("([^"]+)".*\)\s+= 0$', line)
            if match and Path(match[1]).name in ("rustc", "clippy-driver", "cc", "gcc", "c++", "g++", "ld", "rust-lld", "sccache"):
                crate = re.search(r'"--crate-name", "([^"]+)"', line)
                if Path(match[1]).name == "sccache" and not crate:
                    continue
                result.append({"phase": path.stem, "executable": match[1], "crate": crate[1] if crate else None,
                    "kind": "compiler-wrapper-request" if Path(match[1]).name == "sccache" else "direct-exec"})
    return result


def environment_identity():
    from host import NATIVE_PACKAGES
    result = {"cohort": cohort(), "target": TARGET, "sccache_version": subprocess.check_output(
        ["sccache", "--version"], text=True).strip(), "tools": {}, "flags": {key: os.environ.get(key) for key in
        ("RUSTFLAGS", "CC", "CXX", "AR", "LD", "CFLAGS", "CXXFLAGS", "CARGO_INCREMENTAL", "RUSTC_WRAPPER")}}
    for tool in ("rustc", "cargo", "cc", "c++", "ar", "ld", "pkg-config"):
        binary = (Path(subprocess.check_output(["rustup", "which", tool], text=True).strip())
            if tool in ("rustc", "cargo") else Path(shutil.which(tool))).resolve(strict=True)
        result["tools"][tool] = {"sha256": sha(binary), "version": subprocess.check_output(
            [tool, "-Vv" if tool in ("rustc", "cargo") else "--version"], text=True).strip()}
    result["native_packages"] = subprocess.check_output(["dpkg-query", "-W", *NATIVE_PACKAGES,
        "libgcc-s1", "libstdc++6"], text=True).strip().splitlines()
    return result


def measurement_closure(texts, entries):
    import ast
    import runtime_cases
    class LiteralMember(ast.NodeTransformer):
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if (isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) in (2, 3)
                    and not node.keywords and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str) and node.args[1].value.isidentifier()):
                member = ast.Attribute(value=node.args[0], attr=node.args[1].value, ctx=ast.Load())
                # Keep both the literal member and default in the dependency projection.
                return ast.copy_location(ast.Tuple(elts=[member, *node.args[2:]], ctx=ast.Load()), node)
            return node
    projected = {path: ast.unparse(ast.fix_missing_locations(LiteralMember().visit(ast.parse(text)))) for path, text in texts.items()}
    modules = {Path(path).stem: path for path in texts if path.startswith("ci/scripts/")}
    return runtime_cases.closure(projected, entries, modules=modules)


def selected_method(text, role, stage):
    import ast
    class Select(ast.NodeTransformer):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id in ("method_fingerprint", "frozen_fingerprint"):
                return ast.copy_location(ast.Constant("CM-S04 fingerprint computed separately"), node)
            return self.generic_visit(node)
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant({"role": role, "stage": stage}[node.id]), node) if isinstance(node.ctx, ast.Load) and node.id in ("role", "stage") else node
        def visit_Subscript(self, node):
            if (isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name)
                    and node.value.value.id == "os" and node.value.attr == "environ"
                    and isinstance(node.slice, ast.Constant) and node.slice.value == "CM_BENCHMARK_STAGE"):
                return ast.copy_location(ast.Constant(stage), node)
            return self.generic_visit(node)
        def visit_Compare(self, node):
            node = self.generic_visit(node)
            if len(node.ops) == 1 and isinstance(node.left, ast.Constant) and isinstance(node.comparators[0], ast.Constant) and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                result = node.left.value == node.comparators[0].value
                return ast.copy_location(ast.Constant(result if isinstance(node.ops[0], ast.Eq) else not result), node)
            return node
        def visit_If(self, node):
            node = self.generic_visit(node)
            return (node.body if node.test.value else node.orelse) if isinstance(node.test, ast.Constant) else node
        def visit_IfExp(self, node):
            node = self.generic_visit(node)
            return (node.body if node.test.value else node.orelse) if isinstance(node.test, ast.Constant) else node
    return ast.unparse(ast.fix_missing_locations(Select().visit(ast.parse(text))))


def method_fingerprint(role, stage, environment):
    import ast
    import runtime_cases
    source = root()
    texts = {str(path.relative_to(source)): path.read_text(encoding="utf-8") for path in
        [*source.glob("ci/scripts/*.py"), *source.glob("fixtures/*/*.py")]}
    texts["ci/scripts/build_benchmarks.py"] = selected_method(texts["ci/scripts/build_benchmarks.py"], role, stage)
    entries = [("ci/scripts/build_benchmarks.py", name) for name in
        ("command", "phase_metrics", "compiler_executions", "stats", "stat_delta", "environment_identity",
         "prepare_role", "author_sample", "host_build" if role == "H" else "mod_build", "package_host" if role == "H" else "package_mod")]
    entries += [("ci/scripts/linux_ci.py", name) for name in ("execute", "cargo_args", "build_commands", "append_environment")]
    if role == "H":
        entries.append(("ci/scripts/build_benchmarks.py", "prepare_host"))
        entries.append(("ci/scripts/linux_ci.py", "identify"))
        entries += [("ci/scripts/host.py", name) for name in
            ("prepare", "native", "helper", "schemas", "seal", "verify_sources", "verify_binary")]
    if stage == "mod-change" and role == "A":
        entries.append(("ci/scripts/build_benchmarks.py", "change_a"))
    closure = measurement_closure(texts, entries)
    recipe = config()["roles"][role]
    source_paths = ([source / "adapters/codex-e4568a3/source.json", *[source / "adapters/codex-e4568a3" / p
        for p in read(source / "adapters/codex-e4568a3/source.json")["patches"]],
        source / "adapters/codex-e4568a3" / read(source / "adapters/codex-e4568a3/source.json")["runtime_slots"],
        *[source / p for p in read(source / "adapters/codex-e4568a3/source.json")["overlay"]]] if role == "H" else
        [*(source / recipe["source"]).rglob("*"), *(source / "crates/cm-sdk").rglob("*"), *(source / "crates/cm-abi").rglob("*")])
    data = {"protocol": 1, "role": role, "stage": stage, "recipe": recipe, "environment": environment,
        "native_inputs": {str(path.relative_to(source)): sha(path) for path in sorted(set(source_paths)) if path.is_file()},
        "production_config": read(source / ".github/cm-ci.json"), "python_dependencies": closure["dependencies"],
        "conservative_fallbacks": closure["conservative_reasons"],
        "fingerprint_algorithm": digest([ast.dump(node, include_attributes=False) for node in ast.parse(
            (source / "ci/scripts/build_benchmarks.py").read_text()).body if isinstance(node, ast.FunctionDef) and node.name in ("method_fingerprint", "selected_method", "measurement_closure")]),
        "dependency_engine_sha256": sha(source / "ci/scripts/runtime_cases.py"),
        "change": config()["mod_change"] if stage == "mod-change" and role == "A" else None}
    return {"sha256": digest(data), "inputs": data}


def prepare_role(role):
    logs = set_role(role)
    stage = os.environ["CM_BENCHMARK_STAGE"]
    assert stage in STAGES
    values = paths(role)
    assert not values["CARGO_TARGET_DIR"].exists(), "A measured target must start empty"
    assert not values["CARGO_HOME"].exists() and not values["SCCACHE_DIR"].exists(), "Role cache directories must start empty"
    for key in ("CARGO_HOME", "SCCACHE_DIR"):
        values[key].mkdir(parents=True)
    cfg = read(root() / ".github/cm-ci.json")
    from linux_ci import append_environment
    env = {"RUSTUP_TOOLCHAIN": cfg["rust_toolchain"], **cfg["compile_env"]}
    os.environ.update(env)
    append_environment(env)
    environment = environment_identity()
    compatibility = digest(environment)
    seed_id = os.environ["CM_BENCHMARK_SEED_ID"]
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", seed_id)
    prefix = config()["cache"]["namespace"] + "-" + seed_id + "-" + role + "-" + compatibility
    keys = {"cargo_key": prefix + "-cargo", "compiler_key": prefix + "-compiler"}
    if role == "H":
        seed = config()["host_seed"]
        keys["compiler_key"] = seed["key"]
        if stage == "warm":
            assert seed["image_os"] == cohort()["ImageOS"] and seed["image_version"] == cohort()["ImageVersion"], "H seed image drift; no cold fallback"
    if os.environ.get("CM_BENCHMARK_REUSE_RUN_ID"):
        previous = select_sample(prior_samples(), "author/cold/1/" + role, method_fingerprint(role, "cold", environment))
        if previous:
            keys = {key: previous["archive_restore"][key] for key in ("cargo_key", "compiler_key")}
    write(logs / "prepared.json", {"role": role, "stage": stage, "environment": environment,
        "keys": keys, "fingerprint": method_fingerprint(role, stage, environment), "origin": origin(),
        "target_initially_empty": True, "cache_directories_initially_empty": True})
    output({**keys, "role_logs": str(logs), **{key.lower(): value for key, value in values.items()}})


def prepare_host():
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    for phase in ("prepare", "native"):
        command(logs, "host-" + phase + "-setup", ["python3", "-B", "ci/scripts/host.py", phase])
        apply_environment()
    from linux_ci import identify
    identify(root(), logs, read(root() / ".github/cm-ci.json"))
    assert read(logs / "build-identity.json")["compatibility_fingerprint"] == config()["host_seed"]["compiler_compatibility"], "Pinned H seed is incompatible; stop before any Host compilation"


def host_build(logs):
    import host
    from linux_ci import build_commands, load_config
    cfg = load_config(root())
    command(logs, "host-locked-downloads", ["cargo", "fetch", "--locked", "--manifest-path", cfg["units"][0]["manifest"], "--target", TARGET])
    for phase in ("helper", "schemas", "seal"):
        command(logs, "host-" + phase, ["python3", "-B", "ci/scripts/host.py", phase], trace=phase != "seal")
        apply_environment()
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "host"
    assert not target.exists(), "No linked Host reuse is permitted in an actual build measurement"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_NET_OFFLINE": "true"}
    for phase, args in build_commands(cfg["units"][0], cfg).items():
        command(logs, "host-" + phase, args + (["--timings"] if phase == "build" else []), env=env, trace=True)
    executable = target / TARGET / cfg["build_profile"] / "codex"
    host.verify_sources(root(), logs)
    host.verify_binary(executable, read(logs / "host-identity.json"), env)
    return executable


def change_a(source):
    change = config()["mod_change"]
    path = source / change["relative"]
    text = path.read_text()
    baseline_sha256 = sha(path)
    assert text.count(change["old"]) == 1 and change["new"] not in text
    text = text.replace(change["old"], change["new"])
    text += ('\n#[test]\nfn cm_s04_a1_diagnostic() {\n    assert_eq!(\n'
        '        policy(br#"{"max_main_samples":"invalid"}"#).unwrap_err(),\n'
        '        ' + change["new"] + '\n    );\n}\n')
    path.write_text(text)
    return {"baseline_source_sha256": baseline_sha256,
        "changed_source_sha256": sha(path), "positive_assertion": change["assertion"]}


def mod_build(logs, role):
    from linux_ci import build_commands
    recipe = config()["roles"][role]
    source = root() / recipe["source"]
    lock = sha(source / "Cargo.lock")
    if os.environ["CM_BENCHMARK_STAGE"] == "mod-change":
        assert role == "A"
        write(logs / "a1-source-change.json", change_a(source))
    cfg = read(root() / ".github/cm-ci.json")
    unit = {"id": role.lower(), "manifest": recipe["source"] + "/Cargo.toml", "packages": [recipe["package"]], "features": []}
    command(logs, role + "-locked-downloads", ["cargo", "fetch", "--locked", "--manifest-path", unit["manifest"], "--target", TARGET])
    for phase, args in build_commands(unit, cfg).items():
        command(logs, role + "-" + phase, args + (["--timings"] if phase == "build" else []),
            env={**os.environ, "CARGO_NET_OFFLINE": "true"}, trace=True)
    assert sha(source / "Cargo.lock") == lock, "Author lock changed"
    executions = compiler_executions(logs)
    assert not any((row["crate"] or "").startswith(("codex_", "cm_runtime")) for row in executions), "Mod sample compiled Host or a private Core/TUI probe"
    return Path(os.environ["CARGO_TARGET_DIR"]) / TARGET / cfg["build_profile"] / recipe["payload"]


def package_host(logs, executable, destination):
    import host
    cfg = read(root() / ".github/cm-ci.json")
    binaries = executable.parent
    command(logs, "H-package", ["python3", "-B", str(root() / host.HOST / "scripts/build_codex_package.py"),
        "--target", TARGET, "--package-dir", str(destination), "--package-version", "0.3.0-s04-benchmark",
        "--strip", "none", "--entrypoint-bin", str(executable),
        "--code-mode-host-bin", str(binaries / "codex-code-mode-host"), "--bwrap-bin",
        str(Path(os.environ["CARGO_TARGET_DIR"]) / "helper" / TARGET / cfg["build_profile"] / "bwrap")])
    shutil.copyfile(logs / "host-identity.json", destination / "cm-host.json")
    licenses = destination / "licenses"
    licenses.mkdir()
    for name in ("LICENSE", "NOTICE"):
        if (root() / host.HOST / name).is_file():
            shutil.copyfile(root() / host.HOST / name, licenses / ("codex-" + name))
    assert list(licenses.iterdir()), "Missing original Host license materials"
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--filter-platform", TARGET], cwd=root() / host.HOST / "codex-rs", text=True))
    import distribution_provenance
    distribution_provenance.host_materials(root(), destination, metadata, logs, read(logs / "host-identity.json"))
    return destination / "bin/codex"


def package_mod(logs, role, executable, destination):
    import mod_manifest
    recipe = config()["roles"][role]
    destination.mkdir(parents=True)
    payload = destination / "payload.so"
    shutil.copyfile(executable, payload)
    fields = tomllib.loads((root() / recipe["source"] / "mod.toml").read_text())
    fields["binary"].update(size=payload.stat().st_size, sha256=sha(payload), glibc_min=mod_manifest.native_glibc_min(payload))
    fields["provenance"]["revision"] = os.environ["CM_SOURCE_SHA"]
    mod_manifest.manifest(destination, fields)
    import distribution_provenance
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(root() / recipe["source"] / "Cargo.toml"), "--filter-platform", TARGET], text=True))
    write(destination / "components.json", distribution_provenance.cargo_components(metadata, {recipe["package"]},
        destination / "licenses", "https://github.com/" + os.environ["CM_SOURCE_REPOSITORY"] + "/tree/" + os.environ["CM_SOURCE_SHA"]))
    mod_manifest.zip_package(destination, destination.with_suffix(".cmod"))
    return payload


def author_sample(role):
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    prepared = read(logs / "prepared.json")
    assert prepared["role"] == role and prepared["environment"] == environment_identity()
    stage, repetition = prepared["stage"], int(os.environ["CM_BENCHMARK_REPETITION"])
    assert repetition in (1, 2, 3)
    sample = {"schema_version": 1, "task_id": "CM-S04", "role": role, "stage": stage, "repetition": repetition,
        "slot": "author/" + stage + "/" + str(repetition) + "/" + role,
        "status": "failed", "sample_id": digest([origin(), role, stage, repetition]), "execution_origin": origin(),
        "report_origin": origin(), "fingerprint": prepared["fingerprint"], "machine_before": machine(),
        "archive_restore": {"compiler_key": prepared["keys"]["compiler_key"], "cargo_key": prepared["keys"]["cargo_key"],
            "compiler_exact_hit": os.environ.get("CM_COMPILER_CACHE_HIT", "not_attempted"),
            "cargo_exact_hit": os.environ.get("CM_CARGO_CACHE_HIT", "not_attempted")},
        "initial_target_empty": not Path(os.environ["CARGO_TARGET_DIR"]).exists(), "measurement_reused": False}
    assert sample["initial_target_empty"]
    started = time.monotonic_ns()
    before = None
    try:
        if stage == "warm" or stage == "mod-change":
            assert os.environ.get("CM_COMPILER_CACHE_HIT") == "true", "Exact compiler seed missing; refusing hidden cold fallback"
            assert os.environ.get("CM_CARGO_CACHE_HIT") == "true", "Exact Cargo downloads seed missing"
        command(logs, role + "-cache-start", ["sccache", "--start-server"])
        before = stats(logs, "sccache-before")
        executable = host_build(logs) if role == "H" else mod_build(logs, role)
        command(logs, role + "-elf-material", ["readelf", "--file-header", "--sections", "--notes", "-W", str(executable)])
        destination = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-products" / role
        package_started = time.monotonic_ns()
        packaged = package_host(logs, executable, destination) if role == "H" else package_mod(logs, role, executable, destination)
        archive = destination.with_suffix(".tar.gz")
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(destination, arcname=role)
        sample.update(source_inputs_sha256=digest(prepared["fingerprint"]["inputs"]["native_inputs"]),
            package_elapsed_seconds=(time.monotonic_ns() - package_started) / 1e9,
            executable_sha256=sha(executable), packaged_executable_sha256=sha(packaged),
            package_manifest=inventory(destination), package_sha256=sha(archive),
            behavior={"status": "pass", "method": "actual fmt/clippy/test/build; H embedded identity or A/B/C unit assertions"},
            runtime_lock={"status": "not_applicable", "reason": "author outputs are not frozen runtime qualification inputs"},
            signed_package={"status": "unavailable", "reason": "benchmark-only output is never signed or released"})
        assert sample["executable_sha256"] == sample["packaged_executable_sha256"]
        if stage == "mod-change":
            change = read(logs / "a1-source-change.json")
            sample["actual_source_change"] = change
            sample["source_inputs_sha256"] = digest([sample["source_inputs_sha256"], change["changed_source_sha256"]])
        sample["status"] = "pass"
    except BaseException as error:
        sample.update(status="failed", failure={"type": type(error).__name__, "reason": str(error)})
        raise
    finally:
        after = stats(logs, "sccache-after") if before else {"status": "unavailable", "reason": "server never started"}
        sample.update(elapsed_seconds=(time.monotonic_ns() - started) / 1e9, machine_after=machine(),
            sccache_before=before or {"status": "unavailable", "reason": "server never started"}, sccache_after=after,
            sccache_delta=stat_delta(before, after) if before else {"status": "unavailable", "reason": "no baseline"},
            phases=phase_metrics(logs), compiler_executions=compiler_executions(logs),
            link_time={"status": "unavailable", "reason": "Cargo timings include link work; no unsupported compiler/link split is inferred"})
        if sample["status"] == "pass" and stage in ("warm", "mod-change"):
            left, right = cache_counts(before), cache_counts(after)
            if left is None or right is None or right["hits"] <= left["hits"]:
                sample.update(status="failed", failure={"reason": "Exact archive restored but no real compiler object hit was observed"})
        write(logs / "sample.json", sample)
        subprocess.run(["sccache", "--stop-server"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        timing_root = Path(os.environ["CARGO_TARGET_DIR"])
        for path in timing_root.rglob("cargo-timing*.html") if timing_root.exists() else ():
            shutil.copyfile(path, logs / (role + "-" + path.name))
    assert sample["status"] == "pass", sample.get("failure")


def cache_save_plan(role):
    import worker_policy as policy
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    result = {"status": "denied", "save": False, "role": role, "origin": origin(),
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        assert os.environ["CM_CACHE_MODE"] == os.environ["ACTIONS_CACHE_MODE"] == "write"
        assert os.environ["CM_BENCHMARK_STAGE"] == "cold" and os.environ["CM_BENCHMARK_REPETITION"] == "1"
        sample = read(logs / "sample.json")
        assert sample["status"] == "pass"
        if sample["measurement_reused"]:
            prepared = read(logs / "prepared.json")
            repair = read(logs / "cargo-seed-preparation.json")
            assert role == "H" and repair["status"] == "pass" and repair["origin"] == origin()
            assert repair["keys"] == prepared["keys"] and repair["environment"] == prepared["environment"]
            assert repair["sample_id"] == sample["sample_id"] and repair["execution_origin"] == sample["execution_origin"]
            assert sample["fingerprint"] == prepared["fingerprint"] and not paths(role)["CARGO_TARGET_DIR"].exists()
        cache = config()["cache"]
        directories = [paths(role)["CARGO_HOME"] / part for part in ("registry/index", "registry/cache", "git/db")]
        if role != "H":
            directories.append(paths(role)["SCCACHE_DIR"])
        size = sum(path.stat().st_size for directory in directories for path in directory.rglob("*") if path.is_file())
        previous = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-new-cache-budget.json"
        used = read(previous)["reserved_uncompressed_bytes"] if previous.exists() else 0
        assert size > 0 and type(used) is int and used >= 0, "Invalid pending cache size"
        pending = used + size + cache["canary_reserve_bytes"]
        result.update(estimated_uncompressed_bytes=size, previous_reserved_uncompressed_bytes=used,
            planning_reserve_bytes=cache["planned_new_bytes"], reserved_new_bytes=pending)
        capacity = policy.benchmark_capacity(cache, pending_bytes=pending)
        result["capacity"] = capacity
        assert capacity["save_allowed"], capacity.get("reason")
        assert shutil.disk_usage(Path(os.environ["RUNNER_TEMP"])).free > size + cache["minimum_disk_reserve_bytes"], "Insufficient cache archive disk space"
        policy.verify_checkout()
        write(previous, {"reserved_uncompressed_bytes": used + size})
        result.update(status="allowed", save=True, usage=capacity["usage"], limit=capacity["limit"], estimated_uncompressed_bytes=size,
            billing_expansion=False, eviction_or_deletion=False)
        write(Path(os.environ["RUNNER_TEMP"]) / ("cm-s04-" + role + "-seed.json"), {
            "schema_version": 1, "role": role, "origin": origin(), "environment": read(logs / "prepared.json")["environment"],
            "keys": read(logs / "prepared.json")["keys"], "sample_id": sample["sample_id"], "sample_status": "pass",
            "sample_execution_origin": sample["execution_origin"]})
    except (AssertionError, RuntimeError, OSError, KeyError, urllib.error.HTTPError) as error:
        result["reason"] = str(error) or type(error).__name__
        result["http_status"] = error.code if isinstance(error, urllib.error.HTTPError) else result.get("capacity", {}).get("http_status")
    write(logs / "cache-save-plan.json", result)
    output({"save_allowed": str(result["save"]).lower()})
    print(json.dumps(result), flush=True)


def verify_seed(role):
    import worker_policy as policy
    prepared = read(Path(os.environ["CM_CI_LOG_DIR"]) / "prepared.json")
    worker = os.environ["GITHUB_REPOSITORY"]
    key = prepared["keys"]["compiler_key"]
    records = policy.api("repos/" + worker + "/actions/caches?key=" + key + "&per_page=100")["actions_caches"]
    exact = [record for record in records if record["key"] == key and record["ref"] == "refs/heads/main"]
    assert len(exact) == 1 and exact[0]["size_in_bytes"] > 0, "Missing or ambiguous exact worker seed"
    if role == "H":
        seed = config()["host_seed"]
        assert read(Path(os.environ["CM_CI_LOG_DIR"]) / "build-identity.json")["compatibility_fingerprint"] == seed["compiler_compatibility"], "H compiler seed incompatible"
        assert seed["repository"] == worker and seed["key"] == key
        run = policy.api("repos/" + worker + "/actions/runs/" + str(seed["run_id"]))
        assert run["head_sha"] == seed["worker_sha"] and run["path"] == ".github/workflows/build.yml"
        assert run["event"] == "workflow_dispatch" and run["run_attempt"] == seed["run_attempt"]
        jobs = policy.api("repos/" + worker + "/actions/runs/" + str(seed["run_id"]) + "/attempts/1/jobs?per_page=100")["jobs"]
        assert len([job for job in jobs if job["name"] == "build-write / linux-x64" and job["conclusion"] == "success"]) == 1
    else:
        receipt = read(Path(os.environ["RUNNER_TEMP"]) / ("cm-s04-" + role + "-seed.json"))
        assert receipt["schema_version"] == 1 and receipt["sample_status"] == "pass" and receipt["role"] == role
        assert receipt["environment"] == prepared["environment"] and receipt["keys"] == prepared["keys"]
        assert receipt["origin"]["repository"] == worker
        run = policy.api("repos/" + worker + "/actions/runs/" + str(receipt["origin"]["run_id"]))
        assert run["head_sha"] == receipt["origin"]["worker_sha"] and run["path"] == ".github/workflows/benchmark.yml"
        assert run["event"] == "workflow_dispatch" and run["head_branch"] == "main"
        assert run["display_title"] == "CM-S04 / " + receipt["origin"]["request_id"]
        assert policy.api("repos/" + os.environ["CM_SOURCE_REPOSITORY"] + "/compare/" + receipt["origin"]["source_sha"]
            + "..." + os.environ["CM_SOURCE_SHA"])["status"] in ("ahead", "identical")
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "verified-seed.json", {"status": "pass", "cache": exact[0],
        "role": role, "restore_is_compiler_objects_only": True, "origin": origin()})


def bind_product(role):
    import worker_policy as policy
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    sample = read(logs / "sample.json")
    assert sample["status"] == "pass" and not sample["measurement_reused"]
    artifact_id = int(os.environ["CM_BENCHMARK_PRODUCT_ID"])
    record = policy.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + str(artifact_id))
    policy.artifact_binding(record, artifact_id, "cm-s04-product-" + role + "-" + os.environ["CM_REQUEST_ID"]
        + "-" + os.environ["GITHUB_RUN_ATTEMPT"], os.environ["CM_BENCHMARK_PRODUCT_DIGEST"].removeprefix("sha256:"), int(os.environ["GITHUB_RUN_ID"]))
    sample["product_artifact"] = record
    write(logs / "sample.json", sample)


def prior_samples():
    import worker_policy as policy
    run_id = os.environ.get("CM_BENCHMARK_REUSE_RUN_ID", "")
    if not run_id:
        return []
    assert run_id.isdigit() and int(run_id) > 0 and int(run_id) != int(os.environ["GITHUB_RUN_ID"])
    destination = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-prior-samples.json"
    if destination.is_file():
        return read(destination)
    worker = os.environ["GITHUB_REPOSITORY"]
    run = policy.api("repos/" + worker + "/actions/runs/" + run_id)
    assert run["status"] == "completed" and run["event"] == "workflow_dispatch"
    assert run["path"] == ".github/workflows/benchmark.yml" and run["head_branch"] == "main"
    assert policy.api("repos/" + worker + "/compare/" + run["head_sha"] + "..." + os.environ["GITHUB_WORKFLOW_SHA"])["status"] in ("ahead", "identical")
    records = policy.api("repos/" + worker + "/actions/runs/" + run_id + "/artifacts?per_page=100")
    assert records["total_count"] <= 100, "Benchmark artifact pagination requires review"
    samples = []
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        for record in records["artifacts"]:
            if not record["name"].startswith(("cm-s04-author-evidence-", "cm-s04-runtime-evidence-")):
                continue
            assert record.get("expired") is False and record["workflow_run"]["id"] == int(run_id)
            with policy.download_origin_archive(worker, record, Path(temporary) / (str(record["id"]) + ".zip"), maximum=128 * 1024 ** 2) as archive:
                for member in archive.infolist():
                    if not (member.filename.endswith("/sample.json") or member.filename == "sample.json"):
                        continue
                    assert not member.is_dir() and member.file_size <= 4 * 1024 ** 2
                    sample = json.loads(archive.read(member))
                    current = sample["report_origin"]
                    assert current["run_id"] == int(run_id) and current["worker_sha"] == run["head_sha"]
                    assert current["repository"] == worker and current["run_attempt"] <= run["run_attempt"]
                    assert policy.api("repos/" + os.environ["CM_SOURCE_REPOSITORY"] + "/compare/" + current["source_sha"]
                        + "..." + os.environ["CM_SOURCE_SHA"])["status"] in ("ahead", "identical")
                    sample["checkpoint_artifact"] = record
                    samples.append(sample)
    write(destination, samples)
    return samples


def select_sample(samples, slot, fingerprint):
    matches = [sample for sample in samples if sample.get("slot") == slot and sample.get("status") == "pass"
        and sample.get("fingerprint", {}).get("sha256") == fingerprint["sha256"]]
    if not matches:
        return None
    unique = {sample["sample_id"]: sample for sample in matches}
    assert len(unique) == 1, "Ambiguous previous sample; select an exact prior campaign"
    return next(iter(unique.values()))


def reuse_author(role):
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    prepared = read(logs / "prepared.json")
    slot = "author/" + prepared["stage"] + "/" + os.environ["CM_BENCHMARK_REPETITION"] + "/" + role
    sample = select_sample(prior_samples(), slot, prepared["fingerprint"])
    if sample:
        sample.update(measurement_reused=True, report_origin=origin(), reuse_reason="same reachable method, native inputs and exact environment")
        write(logs / "sample.json", sample)
    output({"reused": str(bool(sample)).lower()})


def repair_cargo_seed(role):
    import worker_policy as policy
    from linux_ci import load_config
    assert role == "H" and os.environ["CM_BENCHMARK_STAGE"] == "cold" and os.environ["CM_BENCHMARK_REPETITION"] == "1"
    assert os.environ["CM_CACHE_MODE"] == os.environ["ACTIONS_CACHE_MODE"] == "write"
    policy.verify_checkout()
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    prepared, sample = read(logs / "prepared.json"), read(logs / "sample.json")
    assert sample["measurement_reused"] and sample["status"] == "pass" and sample["slot"] == "author/cold/1/H"
    original = select_sample(prior_samples(), sample["slot"], prepared["fingerprint"])
    assert original and original["sample_id"] == sample["sample_id"] and original["execution_origin"] == sample["execution_origin"]
    assert sample["fingerprint"] == prepared["fingerprint"]
    key = prepared["keys"]["cargo_key"]
    records = policy.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/caches?key=" + key + "&per_page=100")["actions_caches"]
    exact = [row for row in records if row["key"] == key and row["ref"] == "refs/heads/main"]
    assert len(exact) <= 1 and (not exact or type(exact[0]["size_in_bytes"]) is int and exact[0]["size_in_bytes"] > 0), "Ambiguous or empty Cargo seed"
    if exact:
        output({"seed_prepared": "false"})
        return
    prepare_host()
    cfg = load_config(root())
    # A traced sccache daemon outlives fetch when its idle timeout is disabled.
    command(logs, "H-seed-locked-downloads", ["cargo", "fetch", "--locked", "--manifest-path", cfg["units"][0]["manifest"], "--target", TARGET],
        env={**os.environ, "RUSTC_WRAPPER": ""}, trace=True)
    assert not paths(role)["CARGO_TARGET_DIR"].exists(), "Download-only seed repair created a linked target"
    write(logs / "cargo-seed-preparation.json", {"status": "pass", "role": role, "origin": origin(),
        "keys": prepared["keys"], "environment": prepared["environment"], "sample_id": sample["sample_id"],
        "execution_origin": sample["execution_origin"], "linked_target_present": False})
    output({"seed_prepared": "true"})


def frozen_fingerprint(baseline):
    import ast
    source = root()
    texts = {str(path.relative_to(source)): path.read_text() for path in source.glob("ci/scripts/*.py")}
    original = texts["ci/scripts/build_benchmarks.py"]
    texts["ci/scripts/build_benchmarks.py"] = selected_method(original, baseline["role"], "mod-change")
    closure = measurement_closure(texts, [("ci/scripts/build_benchmarks.py", "freeze_sample")])
    algorithms = [ast.dump(node, include_attributes=False) for node in ast.parse(original).body if isinstance(node, ast.FunctionDef)
        and node.name in ("frozen_fingerprint", "selected_method", "measurement_closure")]
    return {"sha256": digest({"baseline_sample": baseline["sample_id"], "package": baseline["package_sha256"],
        "executable": baseline["executable_sha256"], "closure": closure, "algorithms": algorithms})}


def freeze_sample(role):
    import worker_policy as policy
    assert role in ("H", "B", "C") and os.environ["CM_BENCHMARK_STAGE"] == "mod-change"
    logs = set_role(role)
    samples = current_cold_samples()
    baseline = next(sample for sample in samples if sample["role"] == role and sample["repetition"] == 1)
    assert baseline["status"] == "pass" and baseline["product_artifact"]["expired"] is False
    artifact = baseline["product_artifact"]
    current = policy.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/artifacts/" + str(artifact["id"]))
    assert current["digest"] == artifact["digest"] and current["expired"] is False
    repetition = int(os.environ["CM_BENCHMARK_REPETITION"])
    slot = "author/mod-change/" + str(repetition) + "/" + role
    fingerprint = frozen_fingerprint(baseline)
    previous = select_sample(prior_samples(), slot, fingerprint)
    if previous:
        previous.update(measurement_reused=True, report_origin=origin(), reuse_reason="same original bytes and reachable hash-observation method")
        write(logs / "sample.json", previous)
        return
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-frozen" / role
    directory.mkdir(parents=True)
    with policy.download_origin_archive(os.environ["GITHUB_REPOSITORY"], current, directory / "product.zip") as archive:
        assert archive.namelist() == [role + ".tar.gz"]
        with archive.open(role + ".tar.gz") as stream, (directory / "product.tar.gz").open("xb") as output_stream:
            shutil.copyfileobj(stream, output_stream)
    assert sha(directory / "product.tar.gz") == baseline["package_sha256"]
    with tarfile.open(directory / "product.tar.gz") as archive:
        archive.extractall(directory / "payload", filter="data")
    payload = directory / "payload" / role
    before = inventory(payload)
    assert before == baseline["package_manifest"]
    assert inventory(payload) == before
    write(logs / "sample.json", {"schema_version": 1, "task_id": "CM-S04", "role": role, "stage": "mod-change",
        "repetition": repetition, "slot": slot,
        "sample_id": digest([origin(), role, "frozen", repetition]), "status": "pass", "fingerprint": fingerprint,
        "execution_origin": origin(), "report_origin": origin(), "measurement_reused": False,
        "frozen_production_origin": baseline["execution_origin"], "baseline_sample_id": baseline["sample_id"],
        "source_inputs_sha256": baseline["source_inputs_sha256"], "executable_sha256": baseline["executable_sha256"],
        "package_sha256": baseline["package_sha256"], "package_manifest": before, "package_unchanged": True,
        "compiler_executions": [], "compiler_invocations": 0, "phases": [],
        "build_time": {"status": "skipped", "reason": "unchanged role; deliberately not compiled"},
        "sccache_delta": {"status": "skipped", "reason": "no compiler or cache service contacted"}})


def current_cold_samples():
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-cold-evidence"
    return [read(path) for path in directory.rglob("sample.json")]


def clean_role(role):
    subprocess.run(["sccache", "--stop-server"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    values = paths(role)
    for path in [values[key] for key in ("CARGO_TARGET_DIR", "SCCACHE_DIR", "CARGO_HOME")]:
        assert path.parent.resolve() == temporary and path.resolve().is_relative_to(temporary)
        if path.exists():
            shutil.rmtree(path)
    for path in (temporary / "cm-s04-products" / role, temporary / "cm-s04-frozen" / role):
        assert path.resolve().is_relative_to(temporary)
        if path.exists():
            shutil.rmtree(path)
    archive = temporary / "cm-s04-products" / (role + ".tar.gz")
    archive.unlink(missing_ok=True)


def finish_author_job():
    samples = []
    for role in ROLES:
        path = paths(role)["CM_CI_LOG_DIR"] / "sample.json"
        samples.append(read(path) if path.is_file() else {"role": role, "status": "not_run"})
    write(Path(os.environ["RUNNER_TEMP"]) / "cm-s04-evidence/job-summary.json", {"origin": origin(), "samples": samples})
    assert all(sample["status"] == "pass" for sample in samples), "Author sample failed; independent siblings and failure evidence are retained"


def fetch_runtime_source():
    """Only reviewed text fixtures, without a source checkout or Rust source in the consumer."""
    import base64
    from concurrent.futures import ThreadPoolExecutor
    import worker_policy as policy
    source, _, revision, _, _ = policy.identities()
    destination = root()
    assert not destination.exists()
    destination.mkdir(parents=True)
    def fetch(path):
        record = policy.api("repos/" + source + "/contents/" + path + "?ref=" + revision)
        assert record["type"] == "file" and record["size"] <= 2 * 1024 ** 2
        data = base64.b64decode(record["content"], validate=False)
        assert len(data) == record["size"] and b"\0" not in data
        data.decode("utf-8")
        target = destination / path
        assert target.resolve().is_relative_to(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return path
    fetch("ci/source-files.txt")
    paths_to_fetch = [name for name in (destination / "ci/source-files.txt").read_text().splitlines()
        if name.endswith(".py") and name.startswith(("ci/scripts/", "fixtures/"))]
    paths_to_fetch += [CONFIG, RUNTIME, ".github/cm-ci.json", "crates/cm/src/distribution-policy.json", "crates/cm/src/distribution-root.jsonl"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert len(list(pool.map(fetch, paths_to_fetch))) == len(paths_to_fetch)
    canonical = Path(__file__)
    assert sha(destination / "ci/scripts/build_benchmarks.py") == sha(canonical), "Worker measurement program differs from the exact reviewed source"
    sys.path.insert(0, str(destination / "ci/scripts"))


def runtime_method(state, native):
    import ast
    import runtime_cases
    source = root()
    texts = {str(path.relative_to(source)): path.read_text() for path in
        [*source.glob("ci/scripts/*.py"), *source.glob("fixtures/*/*.py")]}
    entries = [("fixtures/build-benchmarks/driver.py", name) for name in
        ("run_sample", "Monitor", "metrics", "select_state", "save_profile", "restore_profile")]
    entries += [("fixtures/build-benchmarks/driver.py", "check_" + role.lower()) for role in state["enabled"]]
    entries += [("ci/scripts/runtime_consumer.py", name) for name in ("observe", "rootfs", "validate_inputs", "validate_runtime_inventory")]
    entries += [("ci/scripts/runtime_composition.py", name) for name in ("redact_syscalls", "complete_syscalls", "kernel_route_sockets",
        "provider_tcp_connections", "audit_network", "sandbox_path", "bound_sandbox_aliases", "bound_bwrap_executions", "audit_executions", "check_network_audit")]
    entries.append(("ci/scripts/build_benchmarks.py", "consume_runtime"))
    closure = measurement_closure(texts, entries)
    inputs = {"cohort": cohort(), "native": native, "state": state,
        "sampling": read(source / RUNTIME)["sampling"], "profile_policy": "same managed profile per ten-state block"}
    routing = next(node for node in ast.parse(texts["fixtures/build-benchmarks/driver.py"]).body if isinstance(node, ast.FunctionDef) and node.name == "run_block")
    algorithms = [ast.dump(node, include_attributes=False) for node in ast.parse(texts["ci/scripts/build_benchmarks.py"]).body
        if isinstance(node, ast.FunctionDef) and node.name in ("runtime_method", "measurement_closure", "prepare_runtime")]
    return {"sha256": digest({"inputs": inputs, "closure": closure, "routing": ast.dump(routing, include_attributes=False),
        "algorithms": algorithms}), "inputs": inputs, "dependencies": closure}


def verify_runtime_qualification(accepted, binding, receipt, qualified, source, worker):
    import worker_policy as policy
    provenance = {"CM_SOURCE_REPOSITORY": source, "CM_SOURCE_SHA": qualified["source_sha"],
        "GITHUB_REPOSITORY": worker, "GITHUB_WORKFLOW_SHA": qualified["workflow_sha"],
        "GITHUB_RUN_ID": str(qualified["run_id"]), "GITHUB_RUN_ATTEMPT": str(qualified["run_attempt"]),
        "CM_REQUEST_ID": qualified["request_id"]}
    assert accepted["task_id"] == "CM-S03" and accepted["status"] == "pass"
    assert accepted["implementation_commit"] == qualified["source_sha"] and accepted["post_consumer_qualification"] is True
    assert [check["id"] for check in accepted["checks"]] == ["CM-S03-AC0" + str(number) for number in range(1, 7)]
    assert all(check["status"] == "pass" and check["post_consumer_qualification"] is True for check in accepted["checks"])
    assert accepted["proof_consumer"] == binding["provenance"] == provenance
    assert binding["production_origin"] == receipt["ci"]["production_origin"]
    bound = receipt["index"]["qualification"]["artifact"]
    policy.artifact_binding(binding["qualification_artifact"]["artifact"], bound["artifact_id"],
        bound["artifact_name"], bound["artifact_sha256"], qualified["run_id"])
    audit = binding["audit"]
    assert audit["provenance"] == provenance and audit["status"] == "pass" and audit["cache_mode"] == "none"
    assert audit["isolation_probes"] == "pass" and not audit["canary_hits"] and audit["steps"]
    assert all(step["compiler_linker_jit_build_service_calls"] == 0 for step in audit["steps"].values())


def prepare_runtime():
    import worker_policy as policy
    assert os.environ["CM_CACHE_MODE"] == os.environ["ACTIONS_CACHE_MODE"] == "none"
    fetch_runtime_source()
    import runtime_consumer as runtime
    import distribution_provenance as distribution
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    logs.mkdir(parents=True, exist_ok=True)
    definition = read(root() / RUNTIME)
    source, worker, _, workflow, _ = policy.identities()
    qualified = definition["qualification"]["origin"]
    remote = policy.verify_origin(qualified, source, worker, workflow)
    temporary = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-frozen-origin"
    temporary.mkdir()
    with policy.download_origin_archive(worker, remote["artifacts"]["receipt"], temporary / "receipt.zip") as archive:
        receipt = policy.archive_json(archive, "worker-receipt.json")
    policy.qualification_receipt(receipt, qualified, remote["jobs"], source, worker)
    production = receipt["ci"]["production_origin"]
    assert production["run_id"] == definition["production"]["run_id"]
    assert production["source_sha"] == definition["production"]["source_sha"]
    # S03's post-consumer proof is separate from the main consumer's acceptance.
    qualified_proof = receipt["index"]["proof_consumer"]["artifact"]
    record = policy.api("repos/" + worker + "/actions/artifacts/" + str(qualified_proof["artifact_id"]))
    policy.artifact_binding(record, qualified_proof["artifact_id"], qualified_proof["artifact_name"],
        qualified_proof["artifact_sha256"], qualified["run_id"])
    with policy.download_origin_archive(worker, record, temporary / "acceptance.zip", maximum=64 * 1024 ** 2) as archive:
        accepted = policy.archive_json(archive, "acceptance.json")
        binding = policy.archive_json(archive, "proof-consumer-binding.json")
        verify_runtime_qualification(accepted, binding, receipt, qualified, source, worker)
    with policy.download_origin_archive(worker, remote["artifacts"]["input"], temporary / "runtime.zip") as archive:
        assert archive.namelist() == ["runtime-inputs.tar"]
        with archive.open("runtime-inputs.tar") as stream, (temporary / "runtime-inputs.tar").open("xb") as output_stream:
            shutil.copyfileobj(stream, output_stream)
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    inputs.mkdir()
    package_prefixes = ("host/", "official/", "distribution/cm-host/", "mods/g02a/turn-budget/",
        "mods/g02b/review-before-send/", "mods/g03/tool-concurrency/", "mods/m02/lifecycle-audit/normal/", "mods/m02/example-tool/normal/")
    with tarfile.open(temporary / "runtime-inputs.tar") as archive:
        policy.archive_members(archive.getmembers(), "runtime-inputs")
        for member in archive.getmembers():
            relative = Path(member.name).relative_to("runtime-inputs").as_posix()
            if relative == "producer.json" or relative.startswith(package_prefixes):
                assert Path(relative).suffix not in (".rs", ".c", ".h", ".a"), "Source attachment cannot enter S04 runtime inputs"
                archive.extract(member, temporary, filter="data")
        for name in ("s01-producer.json",):
            member = archive.getmember("runtime-inputs/fixture/" + name)
            assert member.isfile() and member.size <= 4 * 1024 ** 2
            write(inputs / "fixture" / name, json.load(archive.extractfile(member)))
    extracted = temporary / "runtime-inputs"
    for name in ("host", "official", "distribution", "mods"):
        shutil.move(str(extracted / name), inputs / name)
    shutil.copyfile(extracted / "producer.json", inputs / "producer.json")
    producer = read(inputs / "producer.json")
    assert sha(inputs / "host/bin/codex") == definition["production"]["host_sha256"] == producer["host"]["executable_sha256"]
    assert producer["host"]["host_identity"]["host_build_id"] == definition["production"]["host_build_id"]
    write(inputs / "fixture/s04-original-producer.json", producer)
    # This consumer deliberately has no private test executables; retain their original receipt separately.
    projected = {key: value for key, value in producer.items()
        if key not in ("hooks", "sdk_seams", "review", "concurrency", "upgrade")}
    projected.update(benchmark_scope="CM-S04", concurrency={"code_mode_helper": producer["concurrency"]["code_mode_helper"]})
    write(inputs / "producer.json", projected)
    import runtime_composition as composition
    (inputs / "observer.py").write_text(runtime.runtime_observer_source(composition), encoding="utf-8")
    selected = ("ci/scripts/ci_progress.py", "ci/scripts/mod_manifest.py", "ci/scripts/runtime_cases.py",
        "ci/scripts/distribution_provenance.py", "ci/scripts/runtime_sdk.py", "ci/scripts/support_policy.py",
        "fixtures/native-loader/core_acceptance.py", "fixtures/native-loader/tool_barrier.py",
        "fixtures/runtime-consumer/driver.py", "fixtures/runtime-sdk/driver.py", "fixtures/managed-package/driver.py",
        "fixtures/turn-budget/driver.py", "fixtures/review-before-send/driver.py", "fixtures/distribution-provenance/driver.py",
        "fixtures/build-benchmarks/driver.py", RUNTIME, "crates/cm/src/distribution-policy.json", "crates/cm/src/distribution-root.jsonl")
    for name in selected:
        target = inputs / "fixture" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root() / name, target)
    proof = receipt["distribution"]["artifact"]
    record = policy.api("repos/" + worker + "/actions/artifacts/" + str(proof["artifact_id"]))
    policy.artifact_binding(record, proof["artifact_id"], proof["artifact_name"], proof["artifact_sha256"], qualified["run_id"])
    with policy.download_origin_archive(worker, record, temporary / "proof.zip", maximum=32 * 1024 ** 2) as archive:
        distribution.extract_materials(archive, inputs / "fixture/s01-proofs")
    bootstrap = inputs / "fixture/s01-bootstrap"
    bootstrap.mkdir()
    pin = read(root() / distribution.POLICY_PATH)["verifier"]
    data = distribution.fetch(pin["url"], 128 * 1024 ** 2)
    assert hashlib.sha256(data).hexdigest() == pin["archive_sha256"]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("gh_" + pin["version"] + "_linux_amd64/bin/gh")
        assert member.isfile() and 0 < member.size <= 128 * 1024 ** 2
        (bootstrap / "gh").write_bytes(archive.extractfile(member).read())
    (bootstrap / "gh").chmod(0o755)
    shutil.copyfile(root() / distribution.ROOT_PATH, bootstrap / "distribution-root.jsonl")
    write(bootstrap / "identity.json", {"archive_sha256": pin["archive_sha256"], "binary_sha256": sha(bootstrap / "gh")})
    native = {name: inventory(inputs / name) for name in ("host", "mods")}
    methods = {state["id"]: runtime_method(state, native) for state in definition["states"]}
    write(inputs / "fixture/s04-context.json", {"origin": origin(), "production_origin": production,
        "qualification_origin": qualified, "host_sha256": definition["production"]["host_sha256"],
        "methods": {str(block): methods for block in definition["blocks"]}})
    entries = [row for row in runtime.inventory(inputs) if row["path"] != "input-manifest.json"]
    write(inputs / "input-manifest.json", {"files": entries, "sha256": runtime.digest(entries)})
    write(logs / "frozen-authority.json", {"qualification": qualified, "qualification_proof": qualified_proof, "production": production, "receipt": receipt,
        "input_manifest_sha256": runtime.digest(entries), "source_checkout": False, "current_fixture_source_sha": os.environ["CM_SOURCE_SHA"]})


def restore_runtime_checkpoints(destination):
    import worker_policy as policy
    previous = os.environ.get("CM_BENCHMARK_REUSE_RUN_ID", "")
    if not previous:
        return
    samples = prior_samples()
    if not samples:
        return
    worker = os.environ["GITHUB_REPOSITORY"]
    record = policy.api("repos/" + worker + "/actions/runs/" + previous + "/artifacts?per_page=100")
    candidates = [row for row in record["artifacts"] if row["name"].startswith("cm-s04-runtime-checkpoints-")]
    assert len(candidates) == 1 and candidates[0]["expired"] is False
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        with policy.download_origin_archive(worker, candidates[0], Path(temporary) / "checkpoints.zip", maximum=512 * 1024 ** 2) as archive:
            total = sum(member.file_size for member in archive.infolist())
            assert total <= 1024 ** 3 and len(archive.infolist()) <= 100
            for member in archive.infolist():
                assert re.fullmatch(r"block-[123]/(?:empty|A|B|C|ABC|disabled|reenabled-ABC|remove-[ABC])/(?:sample.json|before.tar.gz|after.tar.gz)", member.filename)
                target = destination / member.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(member))
    for path in destination.rglob("sample.json"):
        sample = read(path)
        if sample["status"] != "pass":
            continue
        assert any(item["sample_id"] == sample["sample_id"] and item["status"] == "pass" for item in samples)
        for side in ("before", "after"):
            assert sha(path.parent / (side + ".tar.gz")) == sample["profile_" + side]["sha256"]


def consume_runtime():
    sys.path.insert(0, str(root() / "ci/scripts"))
    sys.path.insert(0, os.environ["CM_CONSUMER_INPUT_DIR"])
    import runtime_consumer as runtime
    import ci_progress
    import socket
    import mod_manifest
    assert os.environ["CM_CACHE_MODE"] == os.environ["ACTIONS_CACHE_MODE"] == "none"
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    runtime.validate_inputs(inputs)
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    temporary = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-runtime"
    temporary.mkdir()
    isolated = temporary / "rootfs"
    with ci_progress.stage("s04/rootfs"):
        closure = runtime.rootfs(inputs, isolated, upgrade_baseline=False)
    for name in ("profile", "work", "evidence", "trusted-observer"):
        (temporary / name).mkdir()
    restore_runtime_checkpoints(temporary / "work/s04-previous")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stopped, hits = threading.Event(), []
    def canary():
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
                hits.append("cross-namespace connection")
                connection.close()
            except socket.timeout:
                pass
    thread = threading.Thread(target=canary, daemon=True)
    thread.start()
    context = {"outer_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("user", "mnt", "pid", "ipc", "uts", "net")},
        "canary_port": listener.getsockname()[1], "provenance": runtime.provenance(), "cache_mode": "none",
        "input_manifest_sha256": read(inputs / "input-manifest.json")["sha256"], "image_os": cohort()["ImageOS"],
        "image_version": cohort()["ImageVersion"], "bind_roots": {point: str(temporary / name) for point, name in
            (("/", "rootfs"), ("/profile", "profile"), ("/work", "work"), ("/evidence", "evidence"))}}
    write(isolated / "fixture/context.json", context)
    closure["files"] = runtime.inventory(isolated)
    closure["sha256"] = runtime.digest(closure["files"])
    runtime.validate_runtime_inventory(isolated, closure["files"])
    assert not any(Path(row["path"]).suffix in (".rs", ".c", ".h", ".a") for row in closure["files"]), "S04 permits no source attachment exceptions"
    write(logs / "rootfs-manifest.json", closure)
    base = ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
        "--uid", "1000", "--gid", "1000", "--cap-drop", "ALL", "--new-session", "--die-with-parent", "--hostname", "cm-consumer",
        "--ro-bind", str(isolated), "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", str(temporary / "profile"), "/profile", "--bind", str(temporary / "work"), "/work",
        "--bind", str(temporary / "evidence"), "/evidence", "--chdir", "/work", "--clearenv"]
    for key, value in {"PATH": "/usr/bin:/bin:/inputs/host/codex-path", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TERM": "dumb", "TMPDIR": "/tmp", "HOME": "/home/fixture", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}.items():
        base += ["--setenv", key, value]
    driver = [*runtime.CONSUMER_ENV_PREFIX, "/usr/bin/python3", "-B", "/fixture/fixtures/build-benchmarks/driver.py"]
    audits = {}
    try:
        probe = ci_progress.run(logs, "s04-current-isolation", [*base, "--", *runtime.CONSUMER_ENV_PREFIX,
            "/usr/bin/python3", "-B", "/fixture/fixtures/runtime-consumer/driver.py", "probe"], 180)
        assert probe.returncode == 0 and not hits
        for label, args in [("s04-frozen-verification", ["verify"]), *[("s04-block-" + str(i), ["block", str(i)]) for i in (1, 2, 3)]]:
            trace = temporary / "trusted-observer" / label
            trace.mkdir()
            argv = ["strace", "-ff", "-qq", "-yy", "--pidns-translation", "-s", "1024", "-e",
                "trace=execve,execveat,socket,getsockname,accept,accept4,connect,sendto,recvfrom,socketpair,symlink,symlinkat,open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl,readlink,mmap,mprotect,memfd_create,clone,clone3,fork,vfork,getpid,gettid",
                "-o", str(trace / "syscalls"), "--", *base, "--", *driver, *args]
            result = ci_progress.run(logs, label, argv, 1800)
            paths_to_results = sorted((temporary / "evidence/s04" / label.removeprefix("s04-")).rglob("result.json")) if label.startswith("s04-block-") else []
            audits[label] = runtime.observe(trace, temporary / "evidence", consumer_root=temporary, result_paths=paths_to_results)
            if label == "s04-frozen-verification":
                runtime.audit_offline_bootstrap(audits[label])
            write(logs / (label + "-audit.json"), audits[label])
            if label == "s04-frozen-verification":
                assert result.returncode == 0, "Frozen signature verification failed"
            audits[label]["driver_return_code"] = result.returncode
            assert not hits and runtime.inventory(isolated) == closure["files"]
            assert result.returncode == 0, "Benchmark block failed; completed samples are retained before starting another block"
        write(logs / "runtime-audit.json", {"status": "pass", "origin": origin(), "steps": list(audits),
            "isolation": "fresh", "canary_hits": hits, "compiler_linker_jit_build_service_calls": 0,
            "toolchain_present": False, "cache_mode": "none", "manifest_sha256": closure["sha256"]})
    except BaseException as error:
        write(logs / "runtime-audit.json", {"status": "failed", "origin": origin(), "steps": list(audits),
            "reason": str(error), "canary_hits": hits, "compiler_linker_jit_build_service_calls": None,
            "isolation": "fresh but qualification failed", "cache_mode": "none"})
        raise
    finally:
        stopped.set()
        thread.join(timeout=1)
        listener.close()
        runtime.copy_evidence(temporary / "evidence", logs / "runtime-evidence")
        import observer
        for path in (temporary / "trusted-observer").rglob("syscalls.*"):
            lines = path.read_text().splitlines()
            raw = "\n".join(line if line.startswith(path.suffix[1:] + " ") else path.suffix[1:] + " " + line for line in lines)
            path.write_text(runtime.redact_trace(raw, observer))
        runtime.copy_evidence(temporary / "trusted-observer", logs / "outer-traces")
        checkpoints = temporary / "work/s04-checkpoints"
        if checkpoints.is_dir():
            shutil.copytree(checkpoints, Path(os.environ["RUNNER_TEMP"]) / "cm-s04-runtime-checkpoints")


def cache_counts(snapshot):
    if snapshot["status"] != "available":
        return None
    raw = snapshot["raw"].get("stats", snapshot["raw"])
    assert "cache_hits" in raw and "cache_misses" in raw, "Unknown sccache statistics schema"
    def total(value):
        if isinstance(value, dict):
            # Aggregate and detailed counters describe the same events.
            if "counts" in value:
                return total(value["counts"])
            return sum(total(item) for item in value.values())
        return value if type(value) in (int, float) else 0
    return {"hits": total(raw["cache_hits"]), "misses": total(raw["cache_misses"]),
        "errors": sum(total(value) for key, value in raw.items() if "error" in key),
        "non_cacheable": {key: value for key, value in raw.items() if "not_cached" in key or "non_cacheable" in key}}


def counter_delta(before, after):
    left = cache_counts(before) if before else None
    right = cache_counts(after) if after else None
    if left is None or right is None:
        return {"status": "unavailable", "reason": "before/after cache counters unavailable"}
    return {"status": "available", "values": {name: right[name] - left[name] for name in ("hits", "misses", "errors")}}


def cache_canaries():
    """Actual tiny compilations with fresh targets and independent compiler-object stores."""
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    base = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-canary"
    base.mkdir()
    workspace, target, cache, seed = (base / name for name in ("source", "target", "cache", "seed"))
    workspace.mkdir()
    baseline = {
        "Cargo.toml": '[workspace]\nmembers = ["entry", "leaf", "sdk"]\nresolver = "2"\n'
            '[profile.dev-small]\ninherits = "dev"\ndebug = 0\nincremental = false\n'
            '[profile.measure]\ninherits = "release"\nopt-level = 1\ndebug = 0\nincremental = false\n',
        "entry/Cargo.toml": '[package]\nname="s04-entry"\nversion="0.1.0"\nedition="2021"\n'
            '[dependencies]\ns04-leaf={path="../leaf"}\ns04-sdk={path="../sdk"}\n[features]\nextra=[]\n',
        "entry/src/lib.rs": 'include!(concat!(env!("OUT_DIR"), "/generated.rs"));\npub fn value() -> u32 { s04_leaf::value() + s04_sdk::value() + GENERATED + 1 }\n',
        "entry/build.rs": 'fn main() { println!("cargo:rerun-if-changed=input.txt"); let value = std::fs::read_to_string("input.txt").unwrap(); std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("generated.rs"), format!("const GENERATED: u32 = {};", value.trim())).unwrap(); }\n',
        "entry/input.txt": "1\n"}
    for name in ("leaf", "sdk"):
        baseline[name + "/Cargo.toml"] = '[package]\nname="s04-' + name + '"\nversion="0.1.0"\nedition="2021"\n'
        baseline[name + "/src/lib.rs"] = "pub fn value() -> u32 { 1 }\n"
    primary, secondary = config()["rust_toolchain"], config()["canary_toolchain"]
    command(logs, "canary-second-toolchain", ["rustup", "toolchain", "install", secondary, "--profile", "minimal"])
    results = []
    cases = ("baseline", "warm", "source", "lock", "compiler", "flags", "features", "profile", "native-sdk", "generator", "corrupted-object")
    try:
        for case in cases:
            for path in (target, cache):
                assert path.parent == base and path.resolve().is_relative_to(base.resolve())
                if path.exists():
                    shutil.rmtree(path)
            if case != "baseline":
                shutil.copytree(seed, cache)
            for name, text in baseline.items():
                path = workspace / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            lock = workspace / "Cargo.lock"
            if lock.exists():
                lock.unlink()
            env = {**os.environ, "CARGO_HOME": str(base / "cargo"), "SCCACHE_DIR": str(cache),
                "CARGO_TARGET_DIR": str(target), "RUSTUP_TOOLCHAIN": secondary if case == "compiler" else primary,
                "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0", "RUSTC_WRAPPER": "sccache",
                "SCCACHE_GHA_ENABLED": "false", "SCCACHE_CACHE_SIZE": "16M", "SCCACHE_BASEDIRS": str(workspace)}
            if case == "source":
                (workspace / "entry/src/lib.rs").write_text(baseline["entry/src/lib.rs"].replace("+ 1 }", "+ 2 }"))
            elif case == "lock":
                (workspace / "leaf/Cargo.toml").write_text(baseline["leaf/Cargo.toml"].replace('version="0.1.0"', 'version="0.1.1"'))
            elif case == "native-sdk":
                (workspace / "sdk/src/lib.rs").write_text("pub fn value() -> u32 { 2 }\n")
            elif case == "generator":
                (workspace / "entry/input.txt").write_text("2\n")
            elif case == "flags":
                env["RUSTFLAGS"] = os.environ.get("RUSTFLAGS", "") + " --cfg s04_flag_changed"
            mutations = []
            if case == "corrupted-object":
                objects = [path for path in cache.rglob("*") if path.is_file() and path.stat().st_size > 64 and re.fullmatch(r"[0-9a-f]{16,64}", path.name)]
                assert objects and sum(path.stat().st_size for path in objects) <= config()["cache"]["canary_reserve_bytes"]
                for path in objects:
                    original = sha(path)
                    with path.open("r+b") as stream:
                        stream.write(b"CM-S04-corrupted-cache-object\0" * 2)
                    mutations.append({"path": str(path.relative_to(cache)), "before_sha256": original, "after_sha256": sha(path)})
            command(logs, "canary-" + case + "-lock", ["cargo", "generate-lockfile", "--offline"], cwd=workspace, env=env)
            args = ["cargo", "build", "--locked", "--offline", "--target", TARGET, "-p", "s04-entry", "--profile",
                "measure" if case == "profile" else "dev-small"]
            if case == "features":
                args += ["--features", "extra"]
            command(logs, "canary-" + case + "-start", ["sccache", "--start-server"], env=env)
            original_env = {key: os.environ.get(key) for key in ("SCCACHE_DIR", "SCCACHE_GHA_ENABLED")}
            os.environ.update(SCCACHE_DIR=str(cache), SCCACHE_GHA_ENABLED="false")
            before = stats(logs, "canary-" + case + "-before")
            row = {"case": case, "status": "failed", "origin": origin(), "initial_target_empty": not target.exists(),
                "actual_object_mutations": mutations, "lock_sha256": sha(lock)}
            # Never export credentials or the inherited runner environment.
            row["environment"] = {key: env[key] for key in ("RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_INCREMENTAL", "CARGO_TARGET_DIR", "SCCACHE_DIR") if key in env}
            try:
                command(logs, "canary-" + case + "-build", args, cwd=workspace, env=env, trace=True)
                after = stats(logs, "canary-" + case + "-after")
                left, right = cache_counts(before), cache_counts(after)
                assert left is not None and right is not None
                delta = {key: right[key] - left[key] for key in ("hits", "misses", "errors")}
                assert row["initial_target_empty"]
                if case == "warm":
                    assert delta["hits"] >= 3 and delta["misses"] == 0, delta
                elif case not in ("baseline", "corrupted-object"):
                    assert delta["misses"] > 0, "Changed actual compiler inputs did not miss"
                    if case in ("source", "lock", "features", "native-sdk", "generator"):
                        assert delta["hits"] > 0, "Unchanged dependency object was not reused"
                elif case == "corrupted-object":
                    assert delta["errors"] > 0 or delta["misses"] > 0, "Corrupted object was silently reused"
                row.update(status="pass", before=before, after=after, delta=delta, non_cacheable=right["non_cacheable"])
            except BaseException as error:
                row["failure"] = str(error)
                failed_build = any(event["phase"] == "canary-" + case + "-build" and event["return_code"] != 0 for event in phase_metrics(logs))
                failure_log = logs / ("canary-" + case + "-build.log")
                corruption_reported = failure_log.is_file() and re.search(r"(?i)corrupt|decompress|cache.{0,80}(?:invalid|failed|error)|invalid.{0,80}cache", failure_log.read_text())
                if case == "corrupted-object" and failed_build and corruption_reported:
                    row.update(status="pass", safe_rejection=True, after=stats(logs, "canary-corruption-rejection"))
                else:
                    raise
            finally:
                subprocess.run(["sccache", "--stop-server"], env=env, check=False)
                for key, value in original_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                results.append(row)
                write(logs / "cache-canaries.json", {"status": "pass" if len(results) == len(cases) and all(item["status"] == "pass" for item in results) else "incomplete", "cases": results})
            if case == "baseline":
                assert sum(path.stat().st_size for path in cache.rglob("*") if path.is_file()) <= config()["cache"]["canary_reserve_bytes"]
                shutil.copytree(cache, seed)
    finally:
        write(logs / "cache-canaries.json", {"status": "pass" if len(results) == len(cases) and all(item["status"] == "pass" for item in results) else "incomplete", "cases": results, "origin": origin()})


def trust_key():
    seed = os.environ["CM_BENCHMARK_SEED_ID"]
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", seed)
    return "cm-s04-v1-trust-" + seed + "-" + os.environ["GITHUB_WORKFLOW_SHA"] + "-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]


def trust_prepare():
    import worker_policy as policy
    policy.verify_checkout()
    role = os.environ["CM_BENCHMARK_TRUST_ROLE"]
    mode = "write" if role == "write" else "read"
    assert role in ("write", "read") and os.environ["ACTIONS_CACHE_MODE"] == mode
    destination = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-trust-cache"
    assert not destination.exists()
    destination.mkdir()
    if role == "write":
        capacity = policy.benchmark_capacity(config()["cache"])
        write(Path(os.environ["CM_CI_LOG_DIR"]) / "cache-capacity.json", capacity)
        assert capacity["save_allowed"], capacity.get("reason")
        (destination / "payload.txt").write_text("CM-S04 trusted default-branch seed\n")
        write(destination / "identity.json", {"origin": origin(), "key": trust_key(), "cache_mode": mode})
    output({"trust_key": trust_key(), "trust_path": str(destination)})


def trust_clear():
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-trust-cache"
    assert directory.parent.resolve() == Path(os.environ["RUNNER_TEMP"]).resolve() and directory.is_dir()
    shutil.rmtree(directory)


def trusted_seed(directory):
    assert (directory / "payload.txt").read_text() == "CM-S04 trusted default-branch seed\n"
    receipt = read(directory / "identity.json")
    assert receipt["key"] == trust_key() and receipt["cache_mode"] == "write"
    assert receipt["origin"]["source_sha"] == os.environ["CM_BENCHMARK_MEASUREMENT_SHA"]
    assert receipt["origin"]["run_id"] == int(os.environ["GITHUB_RUN_ID"])
    assert receipt["origin"]["worker_sha"] == os.environ["GITHUB_WORKFLOW_SHA"]
    return receipt


def trust_finish():
    import worker_policy as policy
    import socket
    role = os.environ["CM_BENCHMARK_TRUST_ROLE"]
    expected = "write" if role == "write" else "read"
    assert os.environ["ACTIONS_CACHE_MODE"] == os.environ["CM_CACHE_MODE"] == expected
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-s04-trust-cache"
    assert os.environ["CM_TRUST_RESTORE_HIT"] == "true"
    receipt = trusted_seed(directory)
    original = inventory(directory)
    rejected = []
    for case in ("bytes", "receipt", "source"):
        isolated = Path(os.environ["RUNNER_TEMP"]) / ("cm-s04-poison-" + role + "-" + case)
        shutil.copytree(directory, isolated)
        if case == "bytes":
            (isolated / "payload.txt").write_text("CM-S04 poisoned bytes\n")
        else:
            altered = read(isolated / "identity.json")
            if case == "receipt":
                altered["cache_mode"] = "read"
            else:
                altered["origin"]["source_sha"] = "0" * 40
            write(isolated / "identity.json", altered)
        try:
            trusted_seed(isolated)
        except AssertionError:
            rejected.append({"case": case, "status": "pass", "result": "isolated restored-seed copy rejected",
                "before": original, "after": inventory(isolated)})
        else:
            raise AssertionError("Poisoned restored-seed copy was trusted: " + case)
    assert inventory(directory) == original, "A negative probe changed the original trusted seed"
    worker = os.environ["GITHUB_REPOSITORY"]
    def entries(key):
        return [row for row in policy.api("repos/" + worker + "/actions/caches?key=" + key + "&per_page=100")["actions_caches"] if row["key"] == key]
    trusted = entries(trust_key())
    assert len(trusted) == 1 and trusted[0]["ref"] == "refs/heads/main" and 0 < trusted[0]["size_in_bytes"] < 1024 ** 2
    result = {"status": "pass", "role": role, "origin": origin(), "runner_cache_mode": expected,
        "real_pr_number": int(os.environ["CM_BENCHMARK_PR_NUMBER"]), "restored_seed": receipt,
        "exact_cache": trusted[0], "fixture_sha256": sha(directory / "payload.txt"), "isolated_poison_rejections": rejected}
    if role == "read":
        assert os.environ["CM_SOURCE_SHA"] != os.environ["CM_BENCHMARK_MEASUREMENT_SHA"]
        assert os.environ["CM_TRUST_DENIED_SAVE_OUTCOME"] in ("success", "failure")
        assert not entries(trust_key() + "-denied-pr-save"), "PR read authority wrote a cache"
        result.update(denied_save_attempt=True, save_action_outcome=os.environ["CM_TRUST_DENIED_SAVE_OUTCOME"],
            requested_pr_code_executed=False, requested_pr_source_sha=os.environ["CM_SOURCE_SHA"])
    else:
        assert os.environ["CM_TRUST_MISS_HIT"] != "true" and not entries(trust_key() + "-missing")
        assert os.environ["CM_TRUST_SERVICE_OUTCOME"] == "failure", "Cache service fault was disguised as a successful miss"
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(("127.0.0.1", 9)) != 0, "Fault endpoint unexpectedly accepts connections"
        result.update(trusted_save_attempt=True, exact_restore=True, clean_missing_key=True,
            actual_service_fault={"endpoint": "closed loopback port 9", "action_outcome": "failure"})
    write(Path(os.environ["CM_CI_LOG_DIR"]) / ("trust-" + role + ".json"), result)


def distribution(values):
    import statistics
    return ({"count": len(values), "raw": values, "minimum": min(values), "maximum": max(values),
        "median": statistics.median(values), "mean": statistics.mean(values),
        "sample_stdev": statistics.stdev(values) if len(values) > 1 else None} if values else
        {"count": 0, "status": "unavailable", "reason": "No successful measured samples"})


def actions_timing():
    import worker_policy as policy
    jobs = []
    for page in range(1, 11):
        record = policy.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]
            + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100&page=" + str(page))
        jobs += record["jobs"]
        if len(jobs) >= record["total_count"]:
            break
    assert len(jobs) == record["total_count"]
    def seconds(start, end):
        return (datetime.datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds() if start and end else None
    return [{"job_id": job["id"], "name": job["name"], "conclusion": job["conclusion"],
        "started_at": job["started_at"], "completed_at": job["completed_at"], "seconds": seconds(job["started_at"], job["completed_at"]),
        "steps": [{**step, "seconds": seconds(step.get("started_at"), step.get("completed_at"))} for step in job.get("steps", [])]}
        for job in jobs]


def collect():
    source = Path(os.environ["CM_BENCHMARK_EVIDENCE_DIR"])
    artifact = Path(os.environ["CM_CI_ARTIFACT_DIR"])
    evidence = artifact / "evidence"
    samples = [read(path) for path in source.rglob("sample.json")]
    slots = [item["slot"] for item in samples]
    assert len(slots) == len(set(slots)), "Duplicate logical sample slot"
    assert len({item["sample_id"] for item in samples}) == len(samples), "Original measurements were counted twice"
    for sample in samples:
        assert sample["task_id"] == "CM-S04" and sample["report_origin"]["run_id"] == int(os.environ["GITHUB_RUN_ID"])
        assert sample["report_origin"]["source_sha"] == os.environ["CM_SOURCE_SHA"]
        if not sample["measurement_reused"]:
            assert sample["execution_origin"]["run_id"] == int(os.environ["GITHUB_RUN_ID"])
    definition = read(root() / RUNTIME)
    expected_author = {"author/" + stage + "/" + str(rep) + "/" + role for stage in STAGES for rep in (1, 2, 3) for role in ROLES}
    expected_runtime = {"runtime/" + str(block) + "/" + state["id"] for block in (1, 2, 3) for state in definition["states"]}
    assert set(slots) <= expected_author | expected_runtime
    author = [sample for sample in samples if sample["slot"] in expected_author]
    runtime = [sample for sample in samples if sample["slot"] in expected_runtime]
    author_cohorts = {role: sorted({digest(item["fingerprint"]["inputs"]["environment"]) for item in author
        if item["role"] == role and item["status"] == "pass" and not item.get("package_unchanged")}) for role in ROLES}
    good_author = len(author) == 36 and all(item["status"] == "pass" for item in author) and all(len(values) == 1 for values in author_cohorts.values())
    good_runtime = len(runtime) == 30 and all(item["status"] == "pass" for item in runtime)
    timing = actions_timing()
    common = {"schema_version": 1, "task_id": "CM-S04", "target": TARGET, "report_origin": origin(),
        "source_sha": os.environ["CM_SOURCE_SHA"], "head_sha": os.environ["CM_SOURCE_SHA"],
        "implementation_commit": os.environ["CM_SOURCE_SHA"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "workflow_conclusion": "pending until this collector finishes; verify through the API afterwards"}
    def report(name, passed, data):
        value = {**common, "status": "pass" if passed else "incomplete_or_failed", **data}
        write(evidence / name, value)
        return value
    reports = []
    reports.append(report(config()["reports"][0], good_author, {"expected_slots": sorted(expected_author),
        "missing_slots": sorted(expected_author - set(slots)), "samples": author,
        "environment_cohort_hashes": author_cohorts, "cohort_policy": "One exact compiler/native/image environment per role; mixed cohorts do not satisfy the three-repetition requirement",
        "fresh_observations": sum(not row["measurement_reused"] for row in author),
        "historical_measurements_referenced": sum(row["measurement_reused"] for row in author),
        "native_compilation_samples": sum(row["status"] == "pass" and any(event.get("crate") for event in row.get("compiler_executions", [])) for row in author),
        "frozen_unchanged_observations": [row["slot"] for row in author if row.get("package_unchanged")]}))
    cache_rows = []
    for item in author:
        before, after = item.get("sccache_before"), item.get("sccache_after")
        cache_rows.append({"slot": item["slot"], "sample_id": item["sample_id"], "status": item["status"],
            "archive_restore": item.get("archive_restore", {"status": "skipped" if item.get("package_unchanged") else "unavailable", "reason": "See exact cache action outcomes and original evidence"}),
            "object_before": cache_counts(before) if before else None, "object_after": cache_counts(after) if after else None,
            "raw_before": before, "raw_after": after, "delta": counter_delta(before, after),
            "phases": item.get("phases"), "link_time": item.get("link_time", item.get("build_time")),
            "measurement_reused": item["measurement_reused"], "execution_origin": item["execution_origin"]})
    groups = {stage + "/" + role: distribution([item["elapsed_seconds"] for item in author if item["stage"] == stage
        and item["role"] == role and item["status"] == "pass" and "elapsed_seconds" in item]) for stage in STAGES for role in ROLES}
    metrics_complete = good_author and all(row.get("package_unchanged") or (row.get("sccache_before", {}).get("status") == "available"
        and row.get("sccache_after", {}).get("status") == "available" and row.get("phases") and row.get("link_time")) for row in author)
    reports.append(report(config()["reports"][1], metrics_complete, {"samples": cache_rows, "elapsed_seconds": groups,
        "actions_job_and_step_timings": timing, "historical_timing_is_not_current_execution": True,
        "unavailable_metrics": ["pure linker duration is unavailable; Cargo build duration is never relabelled as link duration",
            "cache sizes and configuration remain raw snapshots; no gauge delta or zero for a null gauge is inferred"],
        "compiler_observer": "direct child execs and typed sccache wrapper requests; daemon compiler processes are not counted as observed execs; object hits/misses use raw server statistics",
        "cost_boundary": "API job/step times include setup, restore/save and upload; phase wall/CPU/RSS retain their own boundaries"}))
    levels = []
    for role in ROLES:
        rows = [item for item in author if item["role"] == role and item["stage"] in ("cold", "warm") and item["status"] == "pass"]
        levels.append({"role": role, "source_inputs": {"hashes": sorted({item["source_inputs_sha256"] for item in rows})},
            "single_elf": {"hashes": sorted({item["executable_sha256"] for item in rows}),
                "equal": len(rows) == 6 and len({item["executable_sha256"] for item in rows}) == 1,
                "difference_material": "per-sample *-elf-material.log, exact compiler environment, Cargo timings and raw file manifests; no byte normalization",
                "difference_cause": "unavailable unless established by those raw materials"},
            "final_archive_and_signed_package": {"archive_hashes": sorted({item["package_sha256"] for item in rows}),
                "archive_equal": len(rows) == 6 and len({item["package_sha256"] for item in rows}) == 1,
                "signed_package": "unavailable: benchmark output is deliberately unsigned and not a release",
                "known_archive_variables": "tar/gzip headers retain actual timestamps; each raw archive digest is preserved"},
            "behavior": [{"sample_id": item["sample_id"], "result": item["behavior"]} for item in rows]})
    locks = {state["id"]: [{"sample_id": item["sample_id"], "structured_plan_sha256": digest(item["runtime_lock"]),
        "runtime_generation": item["runtime_generation"]} for item in runtime if item["state"] == state["id"] and item["status"] == "pass"] for state in definition["states"]}
    reports.append(report(config()["reports"][2], good_author and good_runtime, {"author_levels": levels,
        "runtime_lock": locks, "runtime_behavior": [{"sample_id": row["sample_id"], "result": row.get("behavior")} for row in runtime],
        "judgment": "five levels are assessed independently; unequal ELF/archive bytes do not become equal through normalization"}))
    canaries = [read(path) for path in source.rglob("cache-canaries.json")]
    save_plans = [read(path) for path in source.rglob("cache-save-plan.json")]
    preflights = [read(path) for path in source.rglob("cm-worker-preflight.json")]
    coverage_pass = len(canaries) == 1 and canaries[0]["status"] == "pass" and good_author
    reports.append(report(config()["reports"][3], coverage_pass, {"cache_repository": os.environ["GITHUB_REPOSITORY"],
        "cross_repository_lookup": False, "target": TARGET, "other_platforms": "unsupported; rejected by hosted identity gates",
        "canaries": canaries, "save_plans": save_plans, "capacity_observations": preflights,
        "host_seed": config()["host_seed"], "linked_targets_restored": False,
        "partition": "role-specific Cargo downloads and compiler objects; native/toolchain/flags/profile/SDK/generator inputs stay distinct"}))
    trust = [read(path) for name in ("trust-write.json", "trust-read.json") for path in source.rglob(name)]
    trust_pass = len(trust) == 2 and {row["role"] for row in trust} == {"write", "read"} and all(row["status"] == "pass" for row in trust)
    self_checks = [read(path) for path in source.rglob("cm-s04-self-check.json")]
    current_self_checks = [row for row in self_checks if row.get("status") == "pass" and row.get("source_sha") == os.environ["CM_SOURCE_SHA"]
        and row.get("run_id") == int(os.environ["GITHUB_RUN_ID"]) and row.get("run_attempt") == int(os.environ["GITHUB_RUN_ATTEMPT"])]
    trust_pass = trust_pass and bool(canaries) and canaries[0]["status"] == "pass" and bool(current_self_checks)
    reports.append(report(config()["reports"][4], trust_pass, {"actual_authority_tests": trust, "canaries": canaries,
        "current_self_checks": current_self_checks, "unknown_origin": "see current self-check rejection evidence; no cold fallback",
        "capacity_failure": [row.get("cache_capacity") for row in preflights if not row.get("cache_capacity", {}).get("save_allowed")]}))
    audits = [read(path) for path in source.rglob("runtime-audit.json")]
    runtime_pass = good_runtime and len(audits) == 1 and audits[0]["status"] == "pass"
    runtime_groups = {state["id"]: {metric: distribution([value for item in runtime
        if item["state"] == state["id"] and item["status"] == "pass"
        for value in [item["metrics"].get("peak_rss", {}).get("value") if metric == "peak_rss_kib" else item["metrics"].get(metric)]
        if type(value) in (int, float)]) for metric in ("startup_seconds", "business_seconds", "lifetime_seconds", "peak_rss_kib")}
        for state in definition["states"]}
    reports.append(report(config()["reports"][5], runtime_pass, {"expected_slots": sorted(expected_runtime),
        "missing_slots": sorted(expected_runtime - set(slots)), "samples": runtime, "distributions": runtime_groups,
        "current_isolation_audits": audits, "frozen_production": definition["production"],
        "fresh_process_samples": sum(item["status"] == "pass" and not item["measurement_reused"] for item in runtime),
        "historical_samples_referenced": sum(item["measurement_reused"] for item in runtime),
        "measurement_limitations": definition["sampling"], "hot_unload_claimed": False}))
    checks = [{"id": name, "status": "pass" if result["status"] == "pass" else "failed",
        "command": "python3 -B ci/scripts/build_benchmarks.py collect", "evidence": ["evidence/" + report_name]}
        for name, result, report_name in zip(config()["required_checks"], reports, config()["reports"])]
    write(artifact / "acceptance.json", {**common, "status": "pass" if all(check["status"] == "pass" for check in checks) else "failed",
        "checks": checks, "original_measurements": len({item["sample_id"] for item in samples}), "expected_slots": 66})
    assert all(check["status"] == "pass" for check in checks), "CM-S04 incomplete/failed; all six reports and original failures are retained"


def self_check():
    import ast
    from contextlib import chdir
    from copy import deepcopy
    import runpy
    import tempfile
    from unittest.mock import Mock, patch
    import runtime_cases
    import worker_policy
    import runtime_consumer
    import linux_ci
    import host
    from types import SimpleNamespace
    os.environ.setdefault("CM_SOURCE_DIR", os.environ["GITHUB_WORKSPACE"])
    assert len(STAGES) * len(ROLES) * len(config()["repetitions"]) == 36
    states = read(root() / RUNTIME)["states"]
    assert len(states) == 10 and len(states) * 3 == 30
    assert len({state["id"] for state in states}) == 10
    source = root().resolve()
    published = host.cm_manifest(source)
    with patch.object(host, "git", return_value="\n".join(row["path"] for row in published) + "\nunregistered.rs"):
        try:
            host.cm_manifest(source)
        except RuntimeError as error:
            assert "Host input list must cover exactly" in str(error)
        else:
            raise AssertionError("Unregistered publication inputs reached native preparation")
    expected_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    check_output = subprocess.check_output
    def identity_command(arguments, **kwargs):
        if arguments[0] == "git":
            return check_output(arguments, **kwargs)
        return {"rustc": "self-check rustc", "cargo": "self-check cargo", "sccache": "sccache " + linux_ci.SCCACHE_VERSION}[arguments[0]]
    with tempfile.TemporaryDirectory() as temporary:
        logs = Path(temporary)
        outside = logs / "outside-checkout"
        outside.mkdir()
        cfg = {"native_tools": [], "units": [], "build_profile": "dev", "test_profile": "test", "clippy_profile": "dev"}
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(logs / "outputs"), "GITHUB_REPOSITORY": "worker/repo",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}), patch.object(subprocess, "check_output", side_effect=identity_command), chdir(outside):
            linux_ci.identify(source, logs, cfg)
        assert read(logs / "build-identity.json")["checkout_head"] == expected_head, "Compiler identity used the caller directory instead of its source checkout"
    cache = config()["cache"]
    assert cache["repository_limit_bytes"] == cache["free_limit_bytes"] == 10 ** 10
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": "DSLZL/CM-build-linux-x64"}):
        for used, allowed in ((8836306629, True), (10 ** 10 - cache["planned_new_bytes"], True),
                              (10 ** 10 - cache["planned_new_bytes"] + 1, False)):
            with patch.object(worker_policy, "api", return_value={"active_caches_size_in_bytes": used}) as fetch:
                capacity = worker_policy.benchmark_capacity(cache)
                fetch.assert_called_once_with("repos/DSLZL/CM-build-linux-x64/actions/cache/usage")
                assert capacity["status"] == "available" and capacity["save_allowed"] is allowed
                assert capacity["maximum_bytes"] == 10 ** 10
                assert capacity["billing_expansion"] is capacity["deletion"] is False
        for invalid in ({key: value for key, value in cache.items() if key != "repository_limit_bytes"},
                        {**cache, "repository_limit_source": "assumed-default"},
                        {**cache, "repository_limit_bytes": True}, {**cache, "free_limit_bytes": -1},
                        {**cache, "planned_new_bytes": "unknown"}):
            with patch.object(worker_policy, "api") as fetch:
                capacity = worker_policy.benchmark_capacity(invalid)
                assert capacity["status"] == "unavailable" and not capacity["save_allowed"]
                fetch.assert_not_called()
        for invalid in ({}, {"active_caches_size_in_bytes": True}, {"active_caches_size_in_bytes": -1}):
            with patch.object(worker_policy, "api", return_value=invalid):
                capacity = worker_policy.benchmark_capacity(cache)
                assert capacity["status"] == "unavailable" and not capacity["save_allowed"]
        with patch.object(worker_policy, "api", side_effect=urllib.error.HTTPError("https://api.github.com/usage", 503, "unavailable", {}, None)):
            capacity = worker_policy.benchmark_capacity(cache)
            assert not capacity["save_allowed"] and capacity["http_status"] == 503
        pending = 2 * cache["planned_new_bytes"]
        for used, allowed in ((10 ** 10 - pending, True), (10 ** 10 - pending + 1, False)):
            with patch.object(worker_policy, "api", return_value={"active_caches_size_in_bytes": used}):
                capacity = worker_policy.benchmark_capacity(cache, pending_bytes=pending)
                assert capacity["save_allowed"] is allowed and capacity["reserved_new_bytes"] == pending
        for pending in (0, -1, True, "unknown"):
            with patch.object(worker_policy, "api") as fetch:
                assert not worker_policy.benchmark_capacity(cache, pending_bytes=pending)["save_allowed"]
                fetch.assert_not_called()
    with tempfile.TemporaryDirectory() as temporary:
        logs = Path(temporary) / "logs"
        current = {"run_id": 2, "source_sha": "b" * 40}
        prepared = {"keys": {"cargo_key": "exact-H-seed"}, "environment": {"compiler": "fixed"}, "fingerprint": {"sha256": "a" * 64}}
        original = {"slot": "author/cold/1/H", "sample_id": "original-pass", "status": "pass", "fingerprint": prepared["fingerprint"],
            "execution_origin": {"run_id": 1}, "elapsed_seconds": 123, "measurement_reused": False}
        write(logs / "prepared.json", prepared)
        write(logs / "sample.json", {**original, "measurement_reused": True, "report_origin": current})
        sample_bytes = (logs / "sample.json").read_bytes()
        mocks = {"origin": Mock(return_value=current), "prior_samples": Mock(return_value=[original]),
            "prepare_host": Mock(), "command": Mock(), "output": Mock()}
        with patch.dict(os.environ, {"RUNNER_TEMP": temporary, "CM_CI_LOG_DIR": str(logs), "GITHUB_REPOSITORY": "worker/repo",
                "CM_BENCHMARK_STAGE": "cold", "CM_BENCHMARK_REPETITION": "1", "CM_CACHE_MODE": "write", "ACTIONS_CACHE_MODE": "write",
                "RUSTC_WRAPPER": "sccache"}), \
                patch.dict(globals(), mocks), patch.object(worker_policy, "verify_checkout"), \
                patch.object(worker_policy, "api") as fetch, patch.object(linux_ci, "load_config", return_value={"units": [{"manifest": "locked/Cargo.toml"}]}):
            fetch.return_value = {"actions_caches": [{"key": "exact-H-seed", "ref": "refs/heads/main", "size_in_bytes": 1}]}
            repair_cargo_seed("H")
            mocks["prepare_host"].assert_not_called()
            mocks["command"].assert_not_called()
            mocks["output"].assert_called_once_with({"seed_prepared": "false"})
            fetch.return_value = {"actions_caches": []}
            repair_cargo_seed("H")
            mocks["prepare_host"].assert_called_once_with()
            mocks["command"].assert_called_once_with(logs, "H-seed-locked-downloads",
                ["cargo", "fetch", "--locked", "--manifest-path", "locked/Cargo.toml", "--target", TARGET],
                env={**os.environ, "RUSTC_WRAPPER": ""}, trace=True)
            assert os.environ["RUSTC_WRAPPER"] == "sccache", "Download-only repair changed the build wrapper"
            repair = read(logs / "cargo-seed-preparation.json")
            assert repair["sample_id"] == original["sample_id"] and repair["execution_origin"] == original["execution_origin"]
            assert (logs / "sample.json").read_bytes() == sample_bytes and not paths("H")["CARGO_TARGET_DIR"].exists()
            mocks["prepare_host"].reset_mock()
            mocks["command"].reset_mock()
            for rejected in ({**original, "status": "failed"}, {**original, "fingerprint": {"sha256": "c" * 64}},
                             {**original, "execution_origin": {"run_id": 99}}):
                mocks["prior_samples"].return_value = [rejected]
                try:
                    repair_cargo_seed("H")
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Cargo seed repair accepted an unverified original measurement")
            mocks["prepare_host"].assert_not_called()
            mocks["command"].assert_not_called()
            assert (logs / "sample.json").read_bytes() == sample_bytes
            tiny = {**config(), "cache": {**cache, "planned_new_bytes": 8, "canary_reserve_bytes": 1, "minimum_disk_reserve_bytes": 0}}
            cargo = paths("H")["CARGO_HOME"] / "registry/cache/locked.crate"
            cargo.parent.mkdir(parents=True)
            cargo.write_bytes(b"0123456789abcdef")
            budget = Path(temporary) / "cm-s04-new-cache-budget.json"
            with patch.dict(globals(), {"config": Mock(return_value=tiny)}):
                for usage, allowed in ((10 ** 10 - 20, True), (10 ** 10 - 19, False)):
                    write(budget, {"reserved_uncompressed_bytes": 3})
                    fetch.return_value = {"active_caches_size_in_bytes": usage}
                    cache_save_plan("H")
                    plan = read(logs / "cache-save-plan.json")
                    assert plan["save"] is allowed and plan["estimated_uncompressed_bytes"] == 16 and plan["reserved_new_bytes"] == 20
                (logs / "cargo-seed-preparation.json").unlink()
                fetch.reset_mock()
                cache_save_plan("H")
                assert not read(logs / "cache-save-plan.json")["save"]
                fetch.assert_not_called()
            assert (logs / "sample.json").read_bytes() == sample_bytes
    assert distribution([1, 2, 3])["median"] == 2
    assert distribution([])["status"] == "unavailable"
    counters = cache_counts({"status": "available", "raw": {"stats": {
        "cache_hits": {"counts": {"Rust": 3}, "adv_counts": {"rust": 3}},
        "cache_misses": {"counts": {}, "adv_counts": {}}, "cache_errors": {"counts": {}, "adv_counts": {}}}}})
    assert counters["hits"] == 3 and counters["misses"] == counters["errors"] == 0, "Detailed counters were counted twice"
    before = {"status": "available", "raw": {"cache_size": None, "stats": {
        name: {"counts": {}} for name in ("cache_hits", "cache_misses", "cache_errors")}}}
    after = {"status": "available", "raw": {"cache_size": 1024, "stats": {
        "cache_hits": {"counts": {"Rust": 3}, "adv_counts": {"rust": 3}},
        "cache_misses": {"counts": {"Rust": 2}}, "cache_errors": {"counts": {}}}}}
    assert counter_delta(before, after) == {"status": "available", "values": {"hits": 3, "misses": 2, "errors": 0}}
    assert before["raw"]["cache_size"] is None and after["raw"]["cache_size"] == 1024
    for missing in (None, {"status": "unavailable"}):
        assert counter_delta(missing, after)["status"] == counter_delta(before, missing)["status"] == "unavailable"
    settled = runpy.run_path(str(root() / "fixtures/review-before-send/driver.py"))["turns_settled"]
    no_mods = [{"event": "ready", "detail": {"mod_count": 0, "plan": {"mods": {}}}}]
    assert settled(no_mods) and not settled([])
    assert not settled([*no_mods, {"event": "runtime-request-released"}]), "A no-Mod plan accepted native callbacks"
    assert not settled([{"event": "ready", "detail": {"mod_count": 1, "plan": {"mods": {"mod": {}}}}}])
    driver_path = root() / "fixtures/build-benchmarks/driver.py"
    entrypoint = ast.Module(body=[ast.parse(driver_path.read_text()).body[-1]], type_ignores=[])
    with tempfile.TemporaryDirectory() as temporary:
        profile_root = Path(temporary) / "profile/s04"
        calls = []
        namespace = {"__name__": "__main__", "sys": SimpleNamespace(argv=[str(driver_path), "block", "1"]),
            "Path": lambda value: profile_root if value == "/profile/s04" else Path(value),
            "run_block": lambda block: calls.append((block, profile_root.is_dir()))}
        exec(compile(entrypoint, str(driver_path), "exec"), namespace)
        assert calls == [(1, True)], "A fresh restore started before its profile parent was initialized"
    relocate = runpy.run_path(str(root() / "fixtures/build-benchmarks/driver.py"))["relocate_profile_identity"]
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary)
        namespace = home / "state/cm-files-v1"
        namespace.mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        lease = namespace / ".lease"
        lease.touch(mode=0o600)
        identity_path = namespace / "identity.json"
        identity = {"schema_version": 1, "domain": "cm.state-home.v1", "home_id": "a" * 64,
            **{kind + "_" + field: 0 for kind in ("home", "state", "lease") for field in ("device", "inode")}}
        encoded = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        identity_path.write_bytes(encoded(identity))
        identity_path.chmod(0o600)
        retained = namespace / "retained.txt"
        retained.write_bytes(b"preserve user data")
        changed_identity = relocate(home)
        assert changed_identity["before"] == identity
        for kind, path in (("home", home), ("state", namespace), ("lease", lease)):
            info = path.stat()
            assert changed_identity["after"][kind + "_device"] == info.st_dev
            assert changed_identity["after"][kind + "_inode"] == info.st_ino
        assert changed_identity["after"]["home_id"] == identity["home_id"] and retained.read_bytes() == b"preserve user data"
        assert relocate(home)["before_sha256"] == changed_identity["after_sha256"]
        for poisoned in ({**identity, "domain": "other"}, {**identity, "home_id": "unknown"},
                         {**identity, "lease_inode": True}, {**identity, "extra": 1}):
            identity_path.write_bytes(encoded(poisoned))
            try:
                relocate(home)
            except AssertionError:
                assert identity_path.read_bytes() == encoded(poisoned)
            else:
                raise AssertionError("An unregistered state identity was relocated")
        identity_path.write_bytes(encoded(identity))
        lease.chmod(0o644)
        try:
            relocate(home)
        except AssertionError:
            assert identity_path.read_bytes() == encoded(identity)
        else:
            raise AssertionError("An unsafe state lease was relocated")
    qualified = {"source_sha": "a" * 40, "workflow_sha": "b" * 40, "run_id": 20, "run_attempt": 1, "request_id": "fixture"}
    provenance = {"CM_SOURCE_REPOSITORY": "source/repo", "CM_SOURCE_SHA": qualified["source_sha"],
        "GITHUB_REPOSITORY": "worker/repo", "GITHUB_WORKFLOW_SHA": qualified["workflow_sha"],
        "GITHUB_RUN_ID": "20", "GITHUB_RUN_ATTEMPT": "1", "CM_REQUEST_ID": "fixture"}
    bound = {"artifact_id": 21, "artifact_name": "index-qualification", "artifact_sha256": "c" * 64}
    receipt = {"ci": {"production_origin": {"run_id": 1}}, "index": {"qualification": {"artifact": bound}}}
    accepted = {"task_id": "CM-S03", "status": "pass", "implementation_commit": qualified["source_sha"],
        "post_consumer_qualification": True, "proof_consumer": provenance,
        "checks": [{"id": "CM-S03-AC0" + str(number), "status": "pass", "post_consumer_qualification": True} for number in range(1, 7)]}
    binding = {"provenance": provenance, "production_origin": {"run_id": 1},
        "qualification_artifact": {"artifact": {"id": 21, "name": "index-qualification", "digest": "sha256:" + "c" * 64,
            "expired": False, "workflow_run": {"id": 20}}},
        "audit": {"provenance": provenance, "status": "pass", "cache_mode": "none", "isolation_probes": "pass",
            "canary_hits": [], "steps": {"probe": {"compiler_linker_jit_build_service_calls": 0}}}}
    verify_runtime_qualification(accepted, binding, receipt, qualified, "source/repo", "worker/repo")
    invalid = [({**accepted, "task_id": "CM-S01"}, binding), ({**accepted, "implementation_commit": "d" * 40}, binding),
        (accepted, {**binding, "production_origin": {"run_id": 2}}),
        (accepted, {**binding, "audit": {**binding["audit"], "status": "failed"}})]
    duplicate = deepcopy(accepted)
    duplicate["checks"][1] = deepcopy(duplicate["checks"][0])
    invalid.append((duplicate, binding))
    for candidate, evidence in invalid:
        try:
            verify_runtime_qualification(candidate, evidence, receipt, qualified, "source/repo", "worker/repo")
        except (AssertionError, RuntimeError):
            pass
        else:
            raise AssertionError("Runtime qualification accepted the wrong task, source, producer, checks or audit")
    fingerprint = {"sha256": "a" * 64}
    sample = {"slot": "author/cold/1/A", "sample_id": "old", "status": "pass", "fingerprint": fingerprint}
    assert select_sample([sample, {**sample, "status": "failed"}], sample["slot"], fingerprint)["sample_id"] == "old"
    assert select_sample([sample], "author/cold/2/A", fingerprint) is None
    assert select_sample([sample], sample["slot"], {"sha256": "b" * 64}) is None
    try:
        select_sample([sample, {**sample, "sample_id": "another"}], sample["slot"], fingerprint)
    except AssertionError:
        pass
    else:
        raise AssertionError("Ambiguous original measurements were accepted")
    for invalid in ({}, {"run_id": 1}, {"run_id": "unknown", "input_artifact_id": 1}):
        try:
            worker_policy.parse_origin(invalid)
        except (RuntimeError, ValueError, KeyError):
            pass
        else:
            raise AssertionError("Unknown native origin was accepted")
    original_closure = runtime_cases.closure
    def changed(path, name):
        def closure(texts, entries, dispatch=None, modules=None):
            module = ast.parse(texts[path])
            node = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name)
            node.body.append(ast.Assert(test=ast.Constant(False), msg=ast.Constant("self-check changed assertion")))
            return original_closure({**texts, path: ast.unparse(ast.fix_missing_locations(module))}, entries, dispatch, modules)
        return closure
    environment = {"self_check": "fixed compiler and image"}
    combinations = [("H", "cold"), ("B", "warm"), ("C", "warm"), ("A", "cold"), ("A", "mod-change")]
    baseline = {item: method_fingerprint(*item, environment)["sha256"] for item in combinations}
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", "change_a")):
        actual = {item: method_fingerprint(*item, environment)["sha256"] for item in combinations}
        assert {item for item in combinations if actual[item] != baseline[item]} == {("A", "mod-change")}
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", "collect")):
        assert all(method_fingerprint(*item, environment)["sha256"] == baseline[item] for item in combinations), "Report formatting invalidated a native measurement"
    for name in ("cache_save_plan", "repair_cargo_seed", "counter_delta"):
        with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", name)):
            assert all(method_fingerprint(*item, environment)["sha256"] == baseline[item] for item in combinations), "Cache-only repair invalidated a native measurement"
    frozen_baseline = {"role": "H", "sample_id": "fixed-original", "package_sha256": "a" * 64, "executable_sha256": "b" * 64}
    frozen_method = frozen_fingerprint(frozen_baseline)
    for name in ("collect", "counter_delta"):
        with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", name)):
            assert frozen_fingerprint(frozen_baseline) == frozen_method, "Report formatting invalidated an unchanged package observation"
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", "inventory")):
        assert frozen_fingerprint(frozen_baseline) != frozen_method, "Changed package hashing was omitted"
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/linux_ci.py", "execute")):
        assert all(method_fingerprint(*item, environment)["sha256"] != baseline[item] for item in combinations), "An imported builder dependency was omitted"
    miniature = {"entry.py": "import helper\ndef entry(): return helper.work()\n", "helper.py": "def work(): return 1\n"}
    controlled = original_closure(miniature, [("entry.py", "entry")], modules={"helper": "helper.py"})
    assert "helper.py:work" in controlled["dependencies"]
    assert "helper.py:work" not in original_closure(miniature, [("entry.py", "entry")])["dependencies"], "Default dependency routing changed"
    native = {"host": "fixed", "mods": "fixed"}
    methods = {state["id"]: runtime_method(state, native)["sha256"] for state in states}
    with patch.object(runtime_cases, "closure", side_effect=changed("fixtures/build-benchmarks/driver.py", "check_a")):
        actual = {state["id"]: runtime_method(state, native)["sha256"] for state in states}
        assert {state["id"] for state in states if actual[state["id"]] != methods[state["id"]]} == {state["id"] for state in states if "A" in state["enabled"]}
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/runtime_consumer.py", "observe")):
        assert all(runtime_method(state, native)["sha256"] != methods[state["id"]] for state in states), "A shared isolation audit change was omitted"
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", "collect")):
        assert all(runtime_method(state, native)["sha256"] == methods[state["id"]] for state in states), "Report formatting invalidated a runtime measurement"
    with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/worker_policy.py", "benchmark_capacity")):
        assert all(runtime_method(state, native)["sha256"] == methods[state["id"]] for state in states), "Author cache capacity invalidated a runtime measurement"
    for name in ("cache_save_plan", "repair_cargo_seed", "counter_delta"):
        with patch.object(runtime_cases, "closure", side_effect=changed("ci/scripts/build_benchmarks.py", name)):
            assert all(runtime_method(state, native)["sha256"] == methods[state["id"]] for state in states), "Cache-only repair invalidated a runtime measurement"
    runtime_consumer.benchmark_tui_binding_self_check()
    command = ["/inputs/host/bin/codex", "cm", "--home", "/profile/s04/block-1", "launch", "--"]
    record = {"command": command, "tui": True, "empty_launch_argv": True, "identity": {"pid": 7,
        "proc_exe": command[0], "executable_sha256": "a" * 64}, "provider_requests": [{"tools": [{"name": "mcp__codex_worktrees"}]}],
        "tui_mcp_listener": {"inode": "123", "port": 1234}}
    metadata = ['20 getsockname(3<TCP:[123]>, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0']
    calls = ['20 getpid() = 7', '20 execve("' + command[0] + '", ' + json.dumps(command) + ', 0x1) = 0']
    observer = SimpleNamespace(provider_tcp_connections=lambda *args: {"456"})
    assert runtime_consumer.bind_tui_mcp_listener(record, metadata, {command[0]: "a" * 64}, observer, process_calls=calls)
    for altered in ({**record, "identity": {**record["identity"], "executable_sha256": "b" * 64}},
        {**record, "command": [*command[:3], "/profile/s04/block-1-lookalike", *command[4:]]}):
        try:
            runtime_consumer.bind_tui_mcp_listener(altered, metadata, {command[0]: "a" * 64}, observer, process_calls=calls)
        except AssertionError:
            pass
        else:
            raise AssertionError("TUI binding accepted a hash/profile lookalike")
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "cm-s04-self-check.json", {"schema_version": 1, "task_id": "CM-S04", "status": "pass",
        "source_sha": os.environ.get("CM_SOURCE_SHA", os.environ["GITHUB_SHA"]), "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "job": os.environ["GITHUB_JOB"], "checks": ["66 unique slots", "exact original sample reuse", "target and case dependency invalidation",
            "formatter independence", "imported builder dependencies", "unchanged default dependency routing", "unknown origin rejection", "PID/profile/hash binding",
            "exact S03 post-consumer qualification", "aggregate cache counters counted once", "no-Mod callback barrier",
            "digest-verified fixture state identity relocation", "fresh checkpoint parent before samples",
            "owner-confirmed free cache capacity and usage-only guard", "compiler identity outside its source checkout",
            "exact tracked publication inputs before native work", "actual pending cache bytes within the confirmed total ceiling",
            "download-only repair of a verified reused H seed", "cache-only repair preserves author and runtime measurements",
            "report counter deltas preserve unknown raw gauges without invalidating measurements"]})
    print("CM-S04 self-check: 66 slots, exact reuse, target/case invalidation, formatter independence, unknown origins and PID/profile/hash binding passed", flush=True)


def main():
    from record_run import require_hosted_linux
    require_hosted_linux()
    action = sys.argv[1]
    if action == "self-check":
        os.environ.setdefault("CM_SOURCE_DIR", os.environ["GITHUB_WORKSPACE"])
        sys.path.insert(0, str(root() / "ci/scripts"))
        assert sha(root() / "ci/scripts/build_benchmarks.py") == sha(Path(__file__))
        self_check()
        return
    import worker_policy
    worker_policy.identities()
    if not action.startswith("trust-") and root().is_dir():
        sys.path.insert(0, str(root() / "ci/scripts"))
        assert sha(root() / "ci/scripts/build_benchmarks.py") == sha(Path(__file__)), "Measurement code differs from reviewed worker code"
    Path(os.environ["CM_CI_LOG_DIR"]).mkdir(parents=True, exist_ok=True)
    stopped = threading.Event()
    def heartbeat():
        started = time.monotonic()
        while not stopped.wait(20):
            print("CM-S04 " + action + " running; elapsed=" + str(round(time.monotonic() - started, 1)) + "s", flush=True)
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        roles = {"prepare-role": prepare_role, "author": author_sample, "save-plan": cache_save_plan,
            "verify-seed": verify_seed, "bind-product": bind_product, "reuse-author": reuse_author, "repair-cargo-seed": repair_cargo_seed,
            "freeze": freeze_sample, "clean-role": clean_role}
        commands = {"prepare-host": prepare_host, "runtime-prepare": prepare_runtime, "runtime-consume": consume_runtime,
            "canaries": cache_canaries, "author-finish": finish_author_job, "trust-prepare": trust_prepare,
            "trust-clear": trust_clear, "trust-finish": trust_finish, "collect": collect}
        if action in roles:
            roles[action](sys.argv[2])
        else:
            commands[action]()
    finally:
        stopped.set()
        thread.join(timeout=1)


if __name__ == "__main__":
    main()
