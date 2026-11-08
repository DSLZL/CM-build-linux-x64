#!/usr/bin/env python3
"""Runtime-only final validation; never creates a native producer or a cache entry."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import worker_policy as policy

CONFIG = "ci/program/acceptance.json"
TARGET = "x86_64-unknown-linux-gnu"
REPORTS = ("program-runtime-integration.json",)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def source_root():
    return Path(os.environ["CM_SOURCE_DIR"]).resolve()


def cache_capacity():
    assert os.environ["CM_CACHE_MODE"] == os.environ["ACTIONS_CACHE_MODE"] == "none"
    usage = policy.api("repos/" + os.environ["GITHUB_REPOSITORY"] + "/actions/cache/usage")
    used = usage["active_caches_size_in_bytes"]
    assert type(used) is int and 0 <= used <= 10_000_000_000, "Unknown or exceeded owner-confirmed free cache cap"
    return {"usage": usage, "limit_bytes": 10_000_000_000, "planned_new_bytes": 0,
        "cache_mode": "none", "deletion": False, "billing_expansion": False}


def pinned(pin, run_id, prefix):
    worker = os.environ["GITHUB_REPOSITORY"]
    record = policy.api("repos/" + worker + "/actions/artifacts/" + str(pin["id"]))
    assert record["name"].startswith(prefix), "Unexpected program artifact kind"
    policy.artifact_binding(record, pin["id"], record["name"], pin["sha256"], run_id)
    return record


def checkpoint_contract(index, provenance, count, environment):
    assert index["schema_version"] == 2 and index["provenance"] == provenance
    assert index["environment"] == environment, "Frozen runtime checkpoint image changed; no implicit full replay"
    assert len(index["steps"]) == count and set(index["steps"]) == set(index["test_inputs"])
    assert all(row["status"] == "pass" and row.get("inputs") and row.get("files") for row in index["steps"].values())


def native_inputs(root, revision):
    import retry
    before, after = retry.product_inputs(root, revision), retry.product_inputs(root, "HEAD")
    differences = {name: sorted(path for path in before[name].keys() | after[name].keys()
        if before[name].get(path) != after[name].get(path)) for name in after}
    print("CM program native input differences:", json.dumps(differences), flush=True)
    reviewed = revision
    if before != after:
        reviewed = read(root / CONFIG)["benchmarks"]["source_sha"]
        # S04 added source licenses and corrected only the cwd of the source-HEAD metadata query.
        assert differences == {"compiler_recipes": [], "files": sorted(("ci/scripts/linux_ci.py",
            "crates/cm-abi/LICENSE", "crates/cm-sdk/LICENSE", "examples/mods/review-before-send/LICENSE",
            "examples/mods/tool-concurrency/LICENSE", "examples/mods/turn-budget/LICENSE"))}, "Unreviewed native input changes"
        assert after == retry.product_inputs(root, reviewed), "Native inputs differ from the exact reviewed S04 source"
    return {"projection_sha256": retry.digest(after), "production_source_sha": revision,
        "reviewed_source_sha": reviewed, "non_compiler_differences": differences}


def prepare():
    import retry
    import build_benchmarks as benchmarks
    source, worker, sha, workflow, _ = policy.identities()
    assert policy.build_request() == ("program", None)
    root = source_root()
    assert retry.git(root, "rev-parse", "HEAD").decode().strip() == sha
    definition = read(root / CONFIG)
    assert definition["task_id"] == "CM-PROGRAM" and definition["product_task_id"] == "CM-S03"
    assert definition["target"] == TARGET and definition["repository_cache_limit_bytes"] == 10_000_000_000
    assert definition["new_cache_write_budget_bytes"] == 0 and definition["release_ready"] is False
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    logs.mkdir(parents=True, exist_ok=True)
    capacity = cache_capacity()
    write(logs / "program-capacity.json", capacity)
    reference = read(root / definition["frozen_reference"])
    qualified = policy.parse_origin(reference["qualification"]["origin"])
    remote = policy.verify_origin(qualified, source, worker, workflow)
    provenance = {"CM_SOURCE_REPOSITORY": source, "CM_SOURCE_SHA": qualified["source_sha"],
        "GITHUB_REPOSITORY": worker, "GITHUB_WORKFLOW_SHA": qualified["workflow_sha"],
        "GITHUB_RUN_ID": str(qualified["run_id"]), "GITHUB_RUN_ATTEMPT": str(qualified["run_attempt"]),
        "CM_REQUEST_ID": qualified["request_id"]}
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        temporary = Path(directory)
        with policy.download_origin_archive(worker, remote["artifacts"]["receipt"], temporary / "receipt.zip") as archive:
            receipt = policy.archive_json(archive, "worker-receipt.json")
        policy.qualification_receipt(receipt, qualified, remote["jobs"], source, worker)
        production = receipt["ci"]["production_origin"]
        assert production["run_id"] == reference["production"]["run_id"]
        assert production["source_sha"] == reference["production"]["source_sha"]
        assert production["workflow_sha"] == reference["production"]["worker_sha"]
        # The original whole run failed later; its successful producer is qualified by a separate completed chain.
        original_run = policy.api("repos/" + worker + "/actions/runs/" + str(production["run_id"]))
        proof = receipt["index"]["proof_consumer"]["artifact"]
        record = pinned({"id": proof["artifact_id"], "sha256": proof["artifact_sha256"]},
            qualified["run_id"], "cm-linux-x64-index-proof-consumer-")
        with policy.download_origin_archive(worker, record, temporary / "accepted.zip", maximum=64 * 1024 ** 2) as archive:
            accepted = policy.archive_json(archive, "acceptance.json")
            binding = policy.archive_json(archive, "proof-consumer-binding.json")
        benchmarks.verify_runtime_qualification(accepted, binding, receipt, qualified, source, worker)
        record = pinned(definition["validation"], qualified["run_id"], "cm-linux-x64-validation-inputs-")
        with retry.small_archive(worker, record, temporary / "validation.zip") as archive:
            baseline = policy.archive_json(archive, "validation.json")
        assert baseline["provenance"] == provenance and baseline["production_origin"] == production
        record = pinned(definition["checkpoints"], qualified["run_id"], "cm-linux-x64-consumer-checkpoints-")
        with retry.small_archive(worker, record, temporary / "checkpoint.zip") as archive:
            checkpoint = policy.archive_json(archive, "index.json")
        checkpoint_contract(checkpoint, provenance, definition["checkpoints"]["case_count"], retry.environment())
        s04 = definition["benchmarks"]
        run = policy.api("repos/" + worker + "/actions/runs/" + str(s04["run_id"]))
        assert run["path"] == ".github/workflows/benchmark.yml" and run["event"] == "workflow_dispatch"
        assert run["conclusion"] == "success" and run["run_attempt"] == s04["run_attempt"] and run["head_sha"] == s04["workflow_sha"]
        assert policy.api("repos/" + worker + "/compare/" + s04["workflow_sha"] + "..." + workflow)["status"] in ("ahead", "identical")
        retry.git(root, "merge-base", "--is-ancestor", s04["source_sha"], "HEAD")
        record = pinned(s04, s04["run_id"], "cm-s04-")
        with retry.small_archive(worker, record, temporary / "benchmarks.zip") as archive:
            measured = policy.archive_json(archive, "acceptance.json")
            assert measured["task_id"] == "CM-S04" and measured["status"] == "pass"
            assert measured["report_origin"]["source_sha"] == s04["source_sha"]
            assert measured["report_origin"]["worker_sha"] == s04["workflow_sha"]
            assert measured["report_origin"]["run_id"] == s04["run_id"] and measured["report_origin"]["run_attempt"] == s04["run_attempt"]
            assert measured["original_measurements"] == measured["expected_slots"] == 66
            assert len(measured["checks"]) == 6 and all(row["status"] == "pass" for row in measured["checks"])
            benchmark_reports = {}
            for row in measured["checks"]:
                name = row["evidence"][0]
                entries = [entry for entry in archive.infolist() if entry.filename == name]
                assert len(entries) == 1 and not entries[0].is_dir() and entries[0].file_size <= 32 * 1024 ** 2
                raw = archive.read(entries[0])
                value = json.loads(raw)
                assert value["status"] == "pass"
                benchmark_reports[name] = {"status": value["status"], "sha256": hashlib.sha256(raw).hexdigest(),
                    **{key: value[key] for key in ("elapsed_seconds", "distributions", "unavailable_metrics",
                        "measurement_limitations", "judgment", "expected_slots", "missing_slots") if key in value}}
    native = native_inputs(root, production["source_sha"])
    current_native = native["projection_sha256"]
    probes = retry.probe_inputs(root, "HEAD")
    assert probes == baseline["probe_inputs"], "Private native probe inputs changed; program mode cannot compile"
    current = retry.test_inputs(root, "HEAD")
    old = checkpoint["test_inputs"]
    assert set(old) <= set(current) and len(set(current) - set(old)) == 18
    changed = sorted(label for label in old if current[label] != old[label])
    assert len(changed) < len(old), "Every legacy method changed; refuse an implicit full-suite replay"
    history = policy.api("repos/" + worker + "/actions/workflows/build.yml/runs?event=workflow_dispatch&per_page=12")["workflow_runs"]
    history = [run for run in history if run["id"] != qualified["run_id"]]
    history.append(policy.api("repos/" + worker + "/actions/runs/" + str(qualified["run_id"])))
    origins = retry.checkpoint_history(root, history, worker, workflow)
    assert any(row["artifact"]["id"] == definition["checkpoints"]["id"] for row in origins), "Pinned ordinary checkpoints unavailable"
    plan = {"status": "hit", "reason": "Explicit runtime-only frozen product and separately verified qualification",
        "production_origin": production, "production_inputs_sha256": current_native, "environment": retry.environment(),
        "build_request": {"kind": "program", "host_origin": None}, "checkpoint_origin": None,
        "checkpoint_origins": origins, "probe_inputs": probes, "test_builds": baseline["test_builds"], "changed_probes": []}
    write(logs / "retry-plan.json", plan)
    retry.overlay(root, logs)
    validation_path = Path(os.environ["CM_VALIDATION_INPUT_DIR"]) / "validation.json"
    validation = read(validation_path)
    validation["program"] = {"task_id": "CM-PROGRAM", "production": reference["production"],
        "qualification": qualified, "qualified_acceptance": accepted, "qualification_receipt": receipt,
        "original_run_conclusion": original_run["conclusion"], "capacity": capacity,
        "native_inputs": native,
        "ordinary_audit": {"observed_sha256": retry.projection(
            retry.source(root, "HEAD", "ci/scripts/runtime_consumer.py"), ("observe",)),
            "checkpoint_sha256": retry.ordinary_audit(retry.source(root, "HEAD", "ci/scripts/runtime_consumer.py")),
            "scope": "Exact reviewed S04-only extension; retained case audits keep their original origin"},
        "benchmark": {"artifact": definition["benchmarks"], "acceptance": measured, "reports": benchmark_reports},
        "legacy_case_count": len(old), "changed_legacy_cases": changed,
        "allowed_executions": sorted((set(current) - set(old)) | set(changed)),
        "checkpoint_artifact": definition["checkpoints"]}
    write(validation_path, validation)
    write(logs / "program-plan.json", validation["program"])
    policy.output({"input_artifact_id": production["input_artifact"]["id"],
        "input_artifact_digest": production["input_artifact"]["digest"]})
    print("CM program plan:", json.dumps({"legacy": len(old), "changed": changed,
        "new": sorted(set(current) - set(old)), "native_builds": 0, "product_uploads": 0, "new_cache_bytes": 0}), flush=True)


def bind_proofs():
    import distribution_provenance as distribution
    import runtime_consumer as runtime
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    validation = read(inputs / "validation.json")
    assert validation["provenance"] == runtime.provenance() and validation["program"]["task_id"] == "CM-PROGRAM"
    receipt = validation["program"]["qualification_receipt"]
    proof = receipt["distribution"]["artifact"]
    qualified = validation["program"]["qualification"]
    record = pinned({"id": proof["artifact_id"], "sha256": proof["artifact_sha256"]},
        qualified["run_id"], "cm-linux-x64-distribution-proofs-")
    assert receipt["ci"]["production_origin"] == policy.production_origin()
    definition = distribution.read(Path(distribution.__file__).parent / "distribution-policy.json")
    distribution.artifact_download(definition, record, inputs / "fixture/s01-proofs")
    assert read(inputs / "fixture/s01-proofs/authority.json")["production_origin"] == policy.production_origin()
    distribution.prepare_bootstrap(inputs)
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "program-proof-binding.json",
        {"artifact": record, "qualification": qualified, "signature_gate": "fresh independent offline verification still required"})


def reports(inputs, artifact, evidence, validation, steps, audit, common, acceptance):
    import runtime_cases
    definition = read(inputs / "fixture" / CONFIG)
    coverage = read(inputs / "fixture/ci/program/coverage.json")
    program = validation["program"]
    assert program["task_id"] == definition["task_id"] == coverage["task_id"] == "CM-PROGRAM"
    assert len(steps) == program["legacy_case_count"] + len(runtime_cases.GROUPS["program"]) == 411
    assert all(row["status"] == "pass" for row in steps.values())
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == audit["forbidden_mod_build_or_jit"] == 0
    assert audit["steps"]["s01-current-verification"]["distribution_verifier_executions"]
    assert audit["steps"]["s03-current-verification"]["distribution_verifier_executions"]
    combined = read(evidence / REPORTS[0])
    assert combined["status"] == "behavior_pass"
    assert set(combined) - {"status"} == set(runtime_cases.GROUPS["program"])
    assert all(combined[case]["status"] == "pass" and
        combined[case]["host_sha256"] == program["production"]["host_sha256"] for case in runtime_cases.GROUPS["program"])
    assert len(coverage["nodes"]) == 21 and len(coverage["experiments"]) == 16
    producer = read(inputs / "producer.json")
    node_evidence = {}
    for node in coverage["nodes"]:
        identifier = node["id"]
        labels = [label for label in steps if any(label.startswith(group + "-") for group in node["groups"])]
        if identifier == "CM-000":
            node_evidence[identifier] = {"status": "registration_only", "scope": node["scope"]}
            continue
        if identifier in ("CM-P01", "CM-P02", "CM-P03"):
            result = producer["regressions"][identifier[3:].lower()]
            assert result["implementation_commit"] == common["production_origin"]["source_sha"]
            origin = producer["provenance"]
        elif identifier == "CM-S04":
            result, origin = program["benchmark"]["acceptance"], program["benchmark"]["acceptance"]["report_origin"]
        else:
            name = "s03-behavior-baseline.json" if identifier == "CM-S03" else identifier[3:].lower() + "-baseline-acceptance.json"
            result, origin = read(artifact / name), common["provenance"]
            assert labels
        status = "behavior_pass" if identifier == "CM-S03" else "pass"
        assert result["task_id"] == identifier and result["status"] == status
        assert result["checks"] and all(row["status"] == status for row in result["checks"])
        node_evidence[identifier] = {"status": status, "scope": node["scope"], "report_origin": origin,
            "case_labels": labels, "checks": [{key: row[key] for key in ("id", "status", "evidence")} for row in result["checks"]]}
        if identifier == "CM-S03":
            assert program["qualified_acceptance"]["status"] == "pass"
            node_evidence[identifier]["post_consumer_qualification"] = program["qualification"]
    counts = {"executed": sum(row["kind"] == "executed" for row in steps.values()),
        "reused": sum(row["kind"] == "reused" for row in steps.values())}
    chain = {"production_origin": common["production_origin"], "original_run_conclusion": program["original_run_conclusion"],
        "qualification": program["qualification"], "validation": common["provenance"],
        "consumer_environment": validation["consumer_environment"], "capacity": program["capacity"],
        "ordinary_audit": program["ordinary_audit"],
        "native_inputs": program["native_inputs"],
        "case_origins": {label: {key: row[key] for key in ("status", "kind", "origin")} for label, row in steps.items()},
        "case_counts": counts, "native_product_compilations": 0, "native_product_uploads": 0,
        "fresh_checks": ["API identities", "signed distribution/index materials", "rootfs", "namespace probes", "network canary", "read-only inventories"],
        "nodes": node_evidence, "benchmark": program["benchmark"], "boundaries": coverage["boundaries"], "release_ready": False}
    introduction = ("Target: GNU Linux x64. Frozen H: " + program["production"]["host_sha256"] +
        ". Original production run: " + str(common["production_origin"]["run_id"]) +
        " (whole-run conclusion retained: " + program["original_run_conclusion"] + ").\n\n" +
        "Successful qualification: " + str(program["qualification"]["run_id"]) +
        ". Current validation: " + str(common["provenance"]["GITHUB_RUN_ID"]) + "/" + common["provenance"]["GITHUB_RUN_ATTEMPT"] +
        ". Native product compilations/uploads: 0/0. New cache writes: 0.\n\n" +
        "Per-case original execution identities and fresh verification are bound in program-binding.json.\n\n")
    nodes = "| Node | Acceptance checks | Evidence | Scope |\n|---|---|---|---|\n"
    for node in coverage["nodes"]:
        labels = [label for label in steps if any(label.startswith(group + "-") for group in node["groups"])]
        assert labels or node["id"] in ("CM-000", "CM-S04")
        if node["id"] == "CM-000":
            origin = "registration only"
        elif node["id"] == "CM-S04":
            origin = "retained S04 artifact " + str(program["benchmark"]["artifact"]["id"])
        elif node["id"] in ("CM-P01", "CM-P02", "CM-P03"):
            origin = "original producer regression and " + str(len(labels)) + " current case references"
        else:
            origin = str(len(labels)) + " independently qualified cases"
        checks = ", ".join(row["id"] for row in node_evidence[node["id"]].get("checks", []))
        nodes += "| " + node["id"] + " | " + checks + " | " + origin + " | " + node["scope"] + " |\n"
    experiments = "\n| Experiment | Evidence groups | Scope |\n|---|---|---|\n"
    for row in coverage["experiments"]:
        experiments += "| " + row["id"] + " | " + (", ".join(row["groups"]) or "retained S04 measurements") + " | " + row["scope"] + " |\n"
    p04 = read(evidence / "plug-and-play-matrix.json")
    assert p04["status"] == "pass"
    bodies = [nodes + experiments,
        "Original P04 six states use serial-eligibility/output-limit; these are separate from the business A/B/C.\n\n" + nodes,
        "| Case | Result | Execution | Original run |\n|---|---|---|---|\n" + "".join(
            "| " + case + " | pass | " + steps["program-" + case]["kind"] + " | " +
            steps["program-" + case]["origin"]["GITHUB_RUN_ID"] + " |\n" for case in runtime_cases.GROUPS["program"]),
        "S01-S03 current case evidence and the retained successful S03 post-consumer qualification remain distinct.\n\n" +
        "S04 retains 36 author samples and 30 runtime samples; no measurements are invented or repeated here. " +
        "Unavailable cache gauges remain unavailable in the original artifact.\n\n" +
        "The six reviewed license supplements retain the upstream missing-file fact and separate SPDX text; no upstream copyright was fabricated.\n\n" +
        "Retained build/startup distributions and unavailable metrics:\n\n```json\n" +
        json.dumps(program["benchmark"]["reports"], indent=2) + "\n```\n\n" + json.dumps(coverage["boundaries"], indent=2) + "\n"]
    chain["reports"] = {}
    for name, body in zip(definition["reports"], bodies):
        path = artifact / name
        path.write_text("# " + name.removesuffix(".md") + "\n\n" + introduction + body, encoding="utf-8")
        raw = path.read_bytes()
        chain["reports"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    write(evidence / "program-binding.json", chain)
    acceptance.update(status="pass", checks=[{"id": check, "status": "pass",
        "evidence": [name, "evidence/program-binding.json"], "execution": counts}
        for check, name in zip(definition["required_checks"], definition["reports"])],
        production_origin=common["production_origin"], qualification=program["qualification"],
        validation=common["provenance"], release_ready=False)


def receipt():
    source, worker, sha, workflow, request = policy.identities()
    assert policy.build_request() == ("program", None)
    cache = cache_capacity()
    jobs = policy.receipt_jobs("repos/" + worker + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] +
        "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["preflight", "program-prepare", "runtime-consumer"])
    native_jobs = [row for row in jobs if row["name"].startswith(("build-read", "build-write"))]
    assert all(row["conclusion"] == "skipped" for row in native_jobs), "Runtime-only run entered native production"
    records = {}
    for role, prefix in (("VALIDATION", "validation-inputs"), ("CONSUMER", "consumer-artifacts")):
        record = policy.api("repos/" + worker + "/actions/artifacts/" + os.environ["CM_" + role + "_ARTIFACT_ID"])
        policy.artifact_binding(record, int(os.environ["CM_" + role + "_ARTIFACT_ID"]),
            "cm-linux-x64-" + prefix + "-" + request + "-" + os.environ["GITHUB_RUN_ATTEMPT"],
            os.environ["CM_" + role + "_ARTIFACT_DIGEST"].removeprefix("sha256:"), int(os.environ["GITHUB_RUN_ID"]))
        records[role.lower()] = record
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        with policy.download_origin_archive(worker, records["consumer"], Path(directory) / "reports.zip",
                maximum=128 * 1024 ** 2) as archive:
            accepted = policy.archive_json(archive, "acceptance.json")
            binding = policy.archive_json(archive, "evidence/program-binding.json")
            assert set(binding["reports"]) == {"final-coverage.md", "milestone-mvp.md",
                "milestone-runtime-integration.md", "linux-x64-completion.md"}
            for name, expected in binding["reports"].items():
                entries = [entry for entry in archive.infolist() if entry.filename == name]
                assert len(entries) == 1 and not entries[0].is_dir() and entries[0].file_size == expected["size"] <= 1024 ** 2
                assert hashlib.sha256(archive.read(entries[0])).hexdigest() == expected["sha256"]
        assert accepted["task_id"] == "CM-PROGRAM" and accepted["status"] == "pass"
        assert accepted["implementation_commit"] == sha
        assert [row["id"] for row in accepted["checks"]] == ["CM-PROGRAM-AC0" + str(n) for n in range(1, 5)]
        assert all(row["status"] == "pass" for row in accepted["checks"])
        assert accepted["validation"] == binding["validation"]
        assert binding["validation"] == {"CM_SOURCE_REPOSITORY": source, "CM_SOURCE_SHA": sha,
            "GITHUB_REPOSITORY": worker, "GITHUB_WORKFLOW_SHA": workflow,
            "GITHUB_RUN_ID": os.environ["GITHUB_RUN_ID"], "GITHUB_RUN_ATTEMPT": os.environ["GITHUB_RUN_ATTEMPT"],
            "CM_REQUEST_ID": request}
        assert accepted["production_origin"] == policy.production_origin()
        assert binding["native_product_compilations"] == binding["native_product_uploads"] == 0
    destination = Path(os.environ["RUNNER_TEMP"]) / "cm-program-receipt"
    write(destination / "program-receipt.json", {"task_id": "CM-PROGRAM", "status": "pass",
        "validation": binding["validation"], "jobs": jobs, "artifacts": records,
        "production_origin": accepted["production_origin"], "qualification": accepted["qualification"],
        "reports": binding["reports"], "current_native_producer": None, "cache": cache, "release_ready": False})


def self_check():
    from copy import deepcopy
    from unittest.mock import patch
    import retry
    import runtime_cases
    root = Path(__file__).resolve().parents[2]
    definition, coverage = read(root / CONFIG), read(root / "ci/program/coverage.json")
    assert definition["required_checks"] == ["CM-PROGRAM-AC0" + str(n) for n in range(1, 5)]
    assert definition["reports"] == ["final-coverage.md", "milestone-mvp.md",
        "milestone-runtime-integration.md", "linux-x64-completion.md"]
    assert len(coverage["nodes"]) == len({row["id"] for row in coverage["nodes"]}) == 21
    assert [row["id"] for row in coverage["experiments"]] == ["R" + str(n).zfill(2) for n in range(1, 17)]
    assert set(read(root / "ci/program/cases.json")["cases"]) == set(runtime_cases.GROUPS["program"])
    environment, provenance = {"image": "fixed"}, {"run": "fixed"}
    index = {"schema_version": 2, "provenance": provenance, "environment": environment,
        "steps": {"one": {"status": "pass", "inputs": {"key": "bound"}, "files": ["bound"]}}, "test_inputs": {"one": {}}}
    checkpoint_contract(index, provenance, 1, environment)
    for field, value in (("schema_version", 1), ("provenance", {}), ("environment", {}), ("steps", {})):
        invalid = deepcopy(index)
        invalid[field] = value
        try:
            checkpoint_contract(invalid, provenance, 1, environment)
        except AssertionError:
            pass
        else:
            raise AssertionError("Invalid checkpoint accepted: " + field)
    reference = read(root / definition["frozen_reference"])
    original_native = retry.product_inputs
    reviewed_native = original_native(root, definition["benchmarks"]["source_sha"])
    # Exercise frozen-product reuse against its reviewed source, not future product changes.
    with patch.object(retry, "product_inputs", side_effect=lambda directory, revision:
            reviewed_native if revision == "HEAD" else original_native(directory, revision)):
        assert (native_inputs(root, reference["production"]["source_sha"])["projection_sha256"]
                == retry.digest(reviewed_native))
    for field, path in (("files", "crates/cm/src/lib.rs"), ("files", "crates/cm/Cargo.toml"),
            ("files", "crates/cm/src/index.rs"), ("files", "crates/cm-abi/LICENSE"),
            ("compiler_recipes", "compiler_environment")):
        altered = deepcopy(reviewed_native)
        altered[field][path] = "unreviewed mutation"
        with patch.object(retry, "product_inputs", side_effect=lambda directory, revision:
                altered if revision == "HEAD" else original_native(directory, revision)):
            try:
                native_inputs(root, reference["production"]["source_sha"])
            except AssertionError:
                pass
            else:
                raise AssertionError("Unreviewed native change accepted: " + path)
    base = retry.test_inputs(root, "HEAD")
    previous = retry.test_inputs(root, reference["qualification"]["origin"]["source_sha"])
    assert len(previous) == definition["checkpoints"]["case_count"] == 393
    assert set(previous) <= set(base) and len(set(base) - set(previous)) == 18
    changed_legacy = sorted(label for label in previous if previous[label] != base[label])
    fields = {key for value in previous.values() for key in value}
    print("CM program historical changed fields:", json.dumps({key: sum(
        previous[label].get(key) != base[label].get(key) for label in previous) for key in sorted(fields)}), flush=True)
    print("CM program historical outer audit:", json.dumps({revision: retry.projection(
        retry.source(root, revision, "ci/scripts/runtime_consumer.py"), ("observe",))
        for revision in (reference["qualification"]["origin"]["source_sha"], "HEAD")}), flush=True)
    assert len(changed_legacy) < len(previous), "New registration invalidated every historical case"
    print("CM program historical dependency changes:", json.dumps(changed_legacy), flush=True)
    original_source = retry.source
    audit_path = "ci/scripts/runtime_consumer.py"
    qualified_audit = original_source(root, reference["qualification"]["origin"]["source_sha"], audit_path)
    extended_audit = original_source(root, definition["benchmarks"]["source_sha"], audit_path)
    assert retry.projection(qualified_audit, ("observe",)) != retry.projection(extended_audit, ("observe",))
    assert retry.ordinary_audit(qualified_audit) == retry.ordinary_audit(extended_audit)
    changed_audit = ast.parse(original_source(root, "HEAD", audit_path))
    next(row for row in changed_audit.body if isinstance(row, ast.FunctionDef) and row.name == "observe").body.append(
        ast.Assert(test=ast.Constant(False), msg=ast.Constant("changed ordinary audit rule")))
    changed_audit = ast.unparse(ast.fix_missing_locations(changed_audit))
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            changed_audit if name == audit_path else original_source(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    assert all(value["audit"] != after[label]["audit"] for label, value in base.items()), "Unknown audit policy reused old passes"
    def changed(path, function):
        module = ast.parse(original_source(root, "HEAD", path))
        node = next(row for row in module.body if isinstance(row, ast.FunctionDef) and row.name == function)
        node.body.append(ast.Assert(test=ast.Constant(False), msg=ast.Constant("controlled single-case change")))
        return ast.unparse(ast.fix_missing_locations(module))
    path = "fixtures/program-integration/driver.py"
    text = changed(path, "case_abc_input")
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            text if name == path else original_source(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    assert {label for label in base if base[label] != after[label]} == {"program-abc-input"}, "Single-case edit invalidated unrelated methods"
    text = changed(path, "submit")
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            text if name == path else original_source(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    expected = {label for label, value in base.items() if path + ":submit" in value["dependencies"]}
    assert len(expected) > 1 and all(label.startswith("program-") for label in expected)
    assert {label for label in base if base[label] != after[label]} == expected, "Shared helper edit escaped its actual dependents"
    data_path = "ci/program/cases.json"
    data = read(root / data_path)
    data["cases"]["abc-input"]["self_check"] = "changed"
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            json.dumps(data) if name == data_path else original_source(directory, revision, name)):
        after = retry.test_inputs(root, "HEAD")
    assert {label for label in base if base[label] != after[label]} == {"program-abc-input"}
    report_path = "ci/program/coverage.json"
    report = read(root / report_path)
    report["self_check"] = "report-only change"
    with patch.object(retry, "source", side_effect=lambda directory, revision, name:
            json.dumps(report) if name == report_path else original_source(directory, revision, name)):
        assert retry.test_inputs(root, "HEAD") == base, "Report-only edit invalidated business methods"
    with patch.dict(os.environ, CM_BUILD_KIND="program", CM_HOST_ORIGIN=""):
        assert policy.build_request() == ("program", None)
    with patch.dict(os.environ, CM_BUILD_KIND="program", CM_HOST_ORIGIN="{}"):
        try:
            policy.build_request()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Program request accepted an unrelated Host origin")
    record = {"id": 12, "name": "fixed-artifact", "expired": False, "digest": "sha256:" + "a" * 64,
        "workflow_run": {"id": 34}}
    with patch.dict(os.environ, GITHUB_REPOSITORY="example/worker"), patch.object(policy, "api", return_value=record):
        assert pinned({"id": 12, "sha256": "a" * 64}, 34, "fixed-") == record
    for field, value in (("id", 13), ("name", "wrong-kind"), ("expired", True),
            ("digest", "sha256:" + "b" * 64), ("workflow_run", {"id": 35})):
        invalid = {**record, field: value}
        with patch.dict(os.environ, GITHUB_REPOSITORY="example/worker"), patch.object(policy, "api", return_value=invalid):
            try:
                pinned({"id": 12, "sha256": "a" * 64}, 34, "fixed-")
            except (AssertionError, RuntimeError):
                pass
            else:
                raise AssertionError("Program artifact accepted an invalid " + field)
    with patch.dict(os.environ, CM_CACHE_MODE="none", ACTIONS_CACHE_MODE="none", GITHUB_REPOSITORY="example/worker"):
        for used, good in ((0, True), (10_000_000_000, True), (10_000_000_001, False), (None, False)):
            with patch.object(policy, "api", return_value={"active_caches_size_in_bytes": used}):
                try:
                    assert cache_capacity()["planned_new_bytes"] == 0
                    assert good
                except AssertionError:
                    assert not good
    print("CM program self-check: four AC, 21 nodes, 16 experiments, 18 cases, strict artifact/checkpoint gates, single-case/shared-helper/data/report dependency changes and zero-write cap", flush=True)


if __name__ == "__main__":
    from record_run import require_hosted_linux
    require_hosted_linux()
    actions = {"prepare": prepare, "bind-proofs": bind_proofs, "receipt": receipt, "self-check": self_check}
    assert len(sys.argv) == 2 and sys.argv[1] in actions
    actions[sys.argv[1]]()
