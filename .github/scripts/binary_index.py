#!/usr/bin/env python3
"""S03 reviewed data signer and evidence glue; never executes a candidate in a signing job."""
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import zipfile

import distribution_provenance as distribution
from cm_platforms import foreign_linux_target, linux_native

REPORTS = ("binary-index-identity.json", "binary-discovery-read-only.json", "binary-extraction-boundary.json",
    "binary-index-to-runtime-plan.json", "binary-index-support-display.json", "binary-index-offline-install.json")
TARGET = linux_native()["target"]
NAMESPACE = "github:1430833890"
ARCHIVE_CASES = ("traversal", "absolute", "symlink", "duplicate", "case-collision", "entry-limit", "byte-limit")
INDEX_DATA = "fixtures/binary-index/cases.json"


def digest(value):
    return hashlib.sha256(distribution.canonical(value)).hexdigest()


def prepare_transport(inputs):
    from record_run import require_hosted_linux
    require_hosted_linux()
    directory = inputs / "fixture/binary-index-tls"
    directory.mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "36500",
        "-subj", "/CN=CM untrusted test origin", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem")],
        check=True, capture_output=True, timeout=30)
    for path in directory.iterdir():
        path.chmod(0o600)


def reference(root, path):
    return {"path": str(path.relative_to(root)), "size": path.stat().st_size, "sha256": distribution.sha(path)}


def signer(policy):
    return {"repository": policy["builder_repository"], "repository_id": policy["builder_repository_id"],
        "workflow": policy["workflow"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"])}


def envelope(policy, records):
    return {"schema_version": 1, "domain": "cm.mod-index.v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"repository": policy["source_repository"], "repository_id": policy["source_repository_id"],
            "sha": os.environ["CM_SOURCE_SHA"]}, "signer": signer(policy),
        "policy_sha256": distribution.sha(Path(__file__).parent / "distribution-policy.json"), "records": records}


def zip_files(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert 0 < len(archive.infolist()) <= 256
        assert sum(row.file_size for row in archive.infolist()) <= 16 * 1024 * 1024
        files, names = {}, {}
        for row in archive.infolist():
            assert re.fullmatch(r"[A-Za-z0-9._/-]{1,512}", row.filename)
            parts = row.filename.split("/")
            assert len(parts) <= 16 and all(part not in ("", ".", "..") for part in parts)
            assert row.filename not in files and not row.is_dir()
            assert (row.external_attr >> 16) & 0o170000 in (0, 0o100000)
            for length in range(1, len(parts) + 1):
                path = "/".join(parts[:length])
                is_file = length == len(parts)
                previous = names.get(path.lower())
                assert previous is None or previous == (path, False) and not is_file
                names[path.lower()] = (path, is_file)
            files[row.filename] = archive.read(row)
        return files


def object_hash(files):
    return digest({path: [len(data), hashlib.sha256(data).hexdigest()] for path, data in files.items()})


def archive_bytes(files, case=None):
    result = io.BytesIO()
    def entry(path, mode=0o100644):
        row = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
        row.create_system, row.external_attr = 3, mode << 16
        return row
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, data in sorted(files.items()):
            archive.writestr(entry(path), data)
        if case == "traversal":
            archive.writestr(entry("../escaped"), b"reject")
        elif case == "absolute":
            archive.writestr(entry("/work/escaped"), b"reject")
        elif case == "symlink":
            archive.writestr(entry("escape-link", 0o120777), "/work/escaped")
        elif case == "duplicate":
            archive.writestr(entry("mod.toml"), files["mod.toml"])
        elif case == "case-collision":
            archive.writestr(entry("Assets/value"), b"a")
            archive.writestr(entry("assets/other"), b"b")
        elif case == "entry-limit":
            for index in range(257):
                archive.writestr(entry("entries/" + str(index)), b"x")
        elif case == "byte-limit":
            # A tiny compressed input with an actually excessive uncompressed member.
            archive.writestr(entry("too-large"), b"x" * (64 * 1024 * 1024 + 1), compress_type=zipfile.ZIP_DEFLATED)
    return result.getvalue()


def record(root, name, receipt, files, native):
    fields = tomllib.loads(files["mod.toml"].decode())
    compat = fields["compat"] | {"exact_host": fields["compat"].get("exact_host")}
    return {"record_id": name, "namespace": NAMESPACE, "publisher": "DSLZL/CM", "id": fields["id"],
        "version": fields["version"], "display_name": fields["id"],
        "cargo_package": {"sdk-a": "cm-sdk-seams-a", "sdk-b": "cm-sdk-seams-b"}[fields["id"]],
        "target": TARGET, "status": "available", "archive": reference(root, root / "archives" / (name + ".cmod")),
        "object_sha256": object_hash(files), "manifest_sha256": hashlib.sha256(files["mod.toml"]).hexdigest(),
        "payload_sha256": fields["binary"]["sha256"], "receipt": reference(root, receipt),
        "bundle": reference(root, root / "release-bundle.jsonl"),
        "declarations": {"kind": fields["kind"], "binary": fields["binary"], "compat": compat,
            "dependencies": fields.get("dependencies", []), "conflicts": fields.get("conflicts", []),
            "state": fields.get("state")}, "native_dependencies": native, "qualification": None}


def prepare_archives():
    import worker_policy as worker
    worker.identities()
    root = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-proofs/index"
    if root.exists():
        assert root.is_dir() and not root.is_symlink()
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    for directory in ("archives", "receipts", "negative-subjects", "subjects"):
        (root / directory).mkdir()
    material = root.parent.parent / "cm-distribution-materials"
    policy = distribution.read(Path(__file__).parent / "distribution-policy.json")
    distribution.validate_materials(material, policy)
    shutil.copyfile(root.parent / "bundle.jsonl", root / "release-bundle.jsonl")
    values = {}
    for owner in ("a", "b"):
        name = "sdk-" + owner
        receipt = distribution.read(root.parent / "subjects" / (name + ".json"))
        data = (material / name / "transport.cmod").read_bytes()
        assert len(data) == receipt["artifact"]["archive_size"]
        assert hashlib.sha256(data).hexdigest() == receipt["artifact"]["archive_sha256"]
        files = zip_files(data)
        assert object_hash(files) == receipt["artifact"]["object_sha256"]
        for row in distribution.read(material / name / "assets.json"):
            assert hashlib.sha256(files[row["path"]]).hexdigest() == row["sha256"]
        (root / "archives" / (name + ".cmod")).write_bytes(data)
        shutil.copyfile(root.parent / "subjects" / (name + ".json"), root / "receipts" / (name + ".json"))
        # Actual ELF metadata recorded by the independently built distribution inventory.
        # The per-payload DT_NEEDED list is collected below from the bounded ELF parser.
        values[name] = record(root, name, root / "receipts" / (name + ".json"), files,
            elf_needed(files[tomllib.loads(files["mod.toml"].decode())["binary"]["path"]]))
    source = zip_files((root / "archives/sdk-a.cmod").read_bytes())
    original = distribution.read(root / "receipts/sdk-a.json")
    for case in (*ARCHIVE_CASES, "dependency", "exclusive-a", "exclusive-b", "update", "identity-conflict"):
        files = zip_files((root / "archives/sdk-b.cmod").read_bytes()) if case == "exclusive-b" else dict(source)
        fields = tomllib.loads(files["mod.toml"].decode())
        if case == "dependency":
            fields["dependencies"] = [{"id": "absent-mod", "version": "=9.9.9"}]
        if case.startswith("exclusive-"):
            fields["contributions"][0]["kind"] = "tool_replacement"
        if case == "update":
            fields["version"] = "0.2.0"
        if case == "identity-conflict":
            files["NOTICE"] += b"different bytes\n"
        if case in ("dependency", "exclusive-a", "exclusive-b", "update"):
            files["mod.toml"] = toml_document(fields).encode()
        data = archive_bytes(files, case)
        (root / "archives" / (case + ".cmod")).write_bytes(data)
        receipt = copy.deepcopy(distribution.read(root / "receipts/sdk-b.json") if case == "exclusive-b" else original)
        receipt.update(name=fields["id"], version=fields["version"], signer=signer(policy))
        receipt["artifact"].update(archive_sha256=hashlib.sha256(data).hexdigest(), archive_size=len(data),
            object_sha256=object_hash(files), manifest_sha256=hashlib.sha256(files["mod.toml"]).hexdigest())
        receipt["contracts"]["fixture_derivation"] = case
        path = root / "negative-subjects" / (case + ".json")
        distribution.write(path, receipt)
        values[case] = record(root, case, path, files, values["sdk-b" if case == "exclusive-b" else "sdk-a"]["native_dependencies"])
    distribution.write(root / "records.json", values)
    worker.output({"index_directory": str(root), "negative_subject_path": str(root / "negative-subjects/*.json")})


def toml_document(fields):
    # Same inline TOML representation as the existing fixture helper; no source import in the signer.
    def value(item):
        if isinstance(item, dict):
            return "{ " + ", ".join(key + " = " + value(child) for key, child in item.items()) + " }"
        if isinstance(item, list):
            return "[" + ", ".join(map(value, item)) + "]"
        return json.dumps(item)
    return "\n".join(key + " = " + value(item) for key, item in fields.items()) + "\n"


def elf_needed(data):
    """Read only ELF64 dynamic tables; no subprocess or native loading in the privileged signer."""
    assert data[:6] == b"\x7fELF\x02\x01" and 64 <= len(data) <= 64 * 1024 * 1024
    assert struct.unpack_from("<H", data, 18)[0] == linux_native()["machine"], "Foreign ELF in signing inputs"
    offset, size, count = struct.unpack_from("<Q", data, 32)[0], *struct.unpack_from("<HH", data, 54)
    assert size == 56 and 0 < count <= 128 and offset + size * count <= len(data)
    segments = [struct.unpack_from("<IIQQQQQQ", data, offset + index * size) for index in range(count)]
    assert all(item[2] + item[5] <= len(data) and item[5] <= item[6] for item in segments)
    dynamic = [item for item in segments if item[0] == 2]
    assert len(dynamic) == 1
    segment = dynamic[0]
    assert 0 < segment[5] <= 65536 and segment[5] % 16 == 0
    entries = []
    for position in range(segment[2], segment[2] + segment[5], 16):
        tag, value = struct.unpack_from("<qQ", data, position)
        if tag == 0:
            break
        entries.append((tag, value))
    else:
        raise AssertionError("Unterminated ELF dynamic table")
    strings = [value for tag, value in entries if tag == 5]
    lengths = [value for tag, value in entries if tag == 10]
    assert len(strings) == len(lengths) == 1 and 0 < lengths[0] <= 16 * 1024 * 1024
    loads = [item for item in segments if item[0] == 1
        and item[3] <= strings[0] and strings[0] + lengths[0] <= item[3] + item[5]]
    assert len(loads) == 1
    table = strings[0] - loads[0][3] + loads[0][2]
    names = []
    for tag, value in entries:
        if tag == 1:
            assert value < lengths[0]
            end = data.index(b"\0", table + value, min(table + value + 129, table + lengths[0]))
            name = data[table + value:end].decode("ascii")
            assert re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name)
            names.append(name)
    return sorted(set(names))


def prepare_indexes():
    import worker_policy as worker
    worker.identities()
    policy = distribution.read(Path(__file__).parent / "distribution-policy.json")
    root = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-proofs/index"
    records = distribution.read(root / "records.json")
    for name, row in records.items():
        if name not in ("sdk-a", "sdk-b"):
            row["bundle"] = reference(root, root / "negative-bundle.jsonl")
    variants = {"catalog": [records["sdk-a"], records["sdk-b"]]}
    variants.update({name: [row] for name, row in records.items() if name not in ("sdk-a", "sdk-b")})
    variants["exclusive"] = [records["exclusive-a"], records["exclusive-b"]]
    variants["revoked"] = [dict(records["sdk-a"], status="revoked")]
    missing = copy.deepcopy(records["sdk-a"])
    missing["target"] = missing["declarations"]["binary"]["target"] = foreign_linux_target()
    missing["declarations"]["binary"]["cpu"] = linux_native(missing["target"])["cpu"]
    variants["missing-target"] = [missing]
    namespace = dict(records["sdk-a"], namespace="github:1")
    variants["namespace"] = [namespace]
    for name, rows in variants.items():
        distribution.write(root / "subjects" / (name + ".json"), envelope(policy, rows))
    distribution.write(root / "records.json", records)
    worker.output({"index_subject_path": str(root / "subjects/*.json"), "index_directory": str(root)})


def finish_indexes():
    root = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-proofs/index"
    for path in (root / "subjects").glob("*.json"):
        target = root / path.name
        shutil.copyfile(path, target)
        shutil.copyfile(root / "index-bundle.jsonl", target.with_name(target.name + ".bundle.jsonl"))


def reports(evidence, steps, audit):
    import runtime_cases
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert all(steps["s03-" + case]["status"] == "pass" for case in runtime_cases.GROUPS["s03"])
    for name in REPORTS:
        value = distribution.read(evidence / name)
        value.update(first_party_only=True, qualification_pending=True, program_complete=False)
        distribution.write(evidence / name, value)


def native_inputs(inputs):
    root = inputs / "fixture/s01-proofs/index"
    cases = distribution.read(inputs / "fixture" / INDEX_DATA)["cases"]
    result = {}
    for case, data in cases.items():
        catalogs = {}
        for name in data["catalogs"]:
            value = distribution.read(root / (name + ".json"))
            # Signer/run envelopes refresh every round; their real verification is mandatory before checkpoint reuse.
            catalogs[name] = [{key: item for key, item in row.items() if key not in ("receipt", "bundle", "qualification")}
                for row in value["records"]]
        result[case] = digest(catalogs)
    return result


def qualification_inputs(artifact, evidence, acceptance, common):
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-index-qualification-inputs"
    directory.mkdir()
    distribution.write(directory / "acceptance.json", acceptance)
    for name in (*REPORTS, "outer-runtime-audit.json"):
        target = directory / "evidence" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(evidence / name, target)
    distribution.write(directory / "binding.json", {"production_origin": common["production_origin"],
        "provenance": common["provenance"], "host": common["host"], "input_manifest_sha256": common["input_manifest_sha256"]})
    assert sum(path.stat().st_size for path in directory.rglob("*") if path.is_file()) <= distribution.LIMIT


def bound_artifact(prefix, role):
    import worker_policy as worker
    policy = distribution.read(Path(__file__).parent / "distribution-policy.json")
    artifact_id = int(os.environ["CM_" + role + "_ARTIFACT_ID"])
    record = worker.api("repos/" + policy["builder_repository"] + "/actions/artifacts/" + str(artifact_id))
    worker.artifact_binding(record, artifact_id, f"cm-{linux_native()['key']}-" + prefix + "-" + os.environ["CM_REQUEST_ID"]
        + "-" + os.environ["GITHUB_RUN_ATTEMPT"], os.environ["CM_" + role + "_ARTIFACT_DIGEST"].removeprefix("sha256:"),
        int(os.environ["GITHUB_RUN_ID"]))
    return policy, record


def copy_qualification_index(material, output):
    # Qualification uses sdk-a; keep unrelated distribution subjects and rejection archives out of this bounded package.
    for name in ("subjects/catalog.json", "archives/sdk-a.cmod", "receipts/sdk-a.json", "release-bundle.jsonl"):
        target = output / "index" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(material / "index" / name, target)


def prepare_qualification():
    import worker_policy as worker
    worker.identities()
    policy, consumer_artifact = bound_artifact("consumer-artifacts", "CONSUMER")
    jobs = worker.receipt_jobs("repos/" + policy["builder_repository"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]
        + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["runtime-consumer", "attest-distribution"])
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-index-consumer-data"
    policy, qualification_inputs = bound_artifact("index-qualification-inputs", "INDEX_INPUT")
    distribution.artifact_download(policy, qualification_inputs, directory)
    acceptance = distribution.read(directory / "acceptance.json")
    assert acceptance["task_id"] == "CM-S03" and acceptance["status"] == "behavior_pass"
    assert len(acceptance["checks"]) == 6 and all(row["status"] == "behavior_pass" for row in acceptance["checks"])
    assert {row["id"] for row in acceptance["checks"]} == {"CM-S03-AC0" + str(index) for index in range(1, 7)}
    assert acceptance["implementation_commit"] == os.environ["CM_SOURCE_SHA"]
    evidence = directory / "evidence"
    audit = distribution.read(evidence / "outer-runtime-audit.json")
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert audit["forbidden_mod_build_or_jit"] == 0 and not audit["unclassified_executable_memory"]
    assert audit["packaged_bwrap_fd_executions"]
    assert audit["steps"]["s01-current-verification"]["distribution_verifier_executions"]
    assert audit["steps"]["s03-current-verification"]["distribution_verifier_executions"]
    assert all(row["status"] == "pass" and row["compiler_linker_jit_build_service_calls"] == 0
        and not row["unclassified_executable_memory"] for row in audit["steps"].values())
    report_path = evidence / "binary-index-support-display.json"
    report = distribution.read(report_path)
    assert report["status"] == "behavior_pass" and report["qualification_pending"] is True
    assert report["provenance"]["GITHUB_WORKFLOW_SHA"] == os.environ["GITHUB_WORKFLOW_SHA"]
    assert report["provenance"]["CM_SOURCE_SHA"] == os.environ["CM_SOURCE_SHA"]
    assert report["production_origin"] == worker.production_origin()
    binding = distribution.read(directory / "binding.json")
    assert binding == {key: report[key] for key in ("production_origin", "provenance", "host", "input_manifest_sha256")}
    claim = report["qualification_candidate"]
    assert claim["plan"]["host"]["executable_sha256"] == report["host"]["executable_sha256"]
    assert claim["plan"]["host"]["target"] == TARGET
    actual = distribution.read(evidence / "binary-index-offline-install.json")["refresh_keeps_running_set"]["run"]
    assert actual["original_count"] == 1 and not actual["provider_errors"]
    ready = [item["detail"]["plan"] for item in actual["native"] if item["event"] == "ready"]
    assert len(ready) == 1 and ready[0]["host"] == claim["plan"]["host"]
    assert ready[0]["candidate_contents"] == claim["plan"]["candidate_contents"]
    policy, distribution_artifact = bound_artifact("distribution-proofs", "DISTRIBUTION")
    output = Path(os.environ["RUNNER_TEMP"]) / "cm-index-qualification"
    material = Path(os.environ["RUNNER_TEMP"]) / "cm-index-distribution"
    distribution.artifact_download(policy, distribution_artifact, material)
    copy_qualification_index(material, output)
    shutil.copytree(directory, output / "main-consumer")
    root = output / "index"
    catalog = distribution.read(root / "subjects/catalog.json")
    row = next(value for value in catalog["records"] if value["id"] == "sdk-a")
    assert claim["plan"]["candidate_contents"] == {"sdk-a": row["object_sha256"]}
    assert claim["plan"]["candidate_manifests"] == {"sdk-a": row["manifest_sha256"]}
    for name in ("qualifications", "qualified"):
        (root / name).mkdir()
    consumer = worker.successful_job(jobs, "runtime-consumer")
    subject = {key: value for key, value in row.items() if key != "qualification"}
    qualification = {"schema_version": 1, "domain": "cm.index-qualification.v1", "source": catalog["source"],
        "signer": signer(policy), "policy_sha256": catalog["policy_sha256"], "record_sha256": digest(subject),
        "host": claim["plan"]["host"], "abi_major": row["declarations"]["compat"]["abi_major"],
        "abi_minor_min": row["declarations"]["compat"]["abi_minor_min"],
        "capabilities": row["declarations"]["compat"]["required_capabilities"], "support_level": "sdk",
        "maturity": "experimental" if row["declarations"]["compat"]["abi_minor_min"] == 3 else "stable",
        "consumer": {"run_id": int(os.environ["GITHUB_RUN_ID"]), "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "job_id": consumer["job_id"], "source_sha": os.environ["CM_SOURCE_SHA"],
            "worker_sha": os.environ["GITHUB_WORKFLOW_SHA"], "image_os": claim["image_os"],
            "image_version": claim["image_version"], "report": reference(directory, report_path),
            "audit": reference(directory, evidence / "outer-runtime-audit.json")},
        "production_origin": worker.production_origin(), "conditions": claim["conditions"]}
    distribution.write(root / "qualifications/exact.json", qualification)
    for name in ("host", "state", "environment"):
        variant = copy.deepcopy(qualification)
        if name == "host":
            variant["host"]["executable_sha256"] = "0" * 64
        elif name == "state":
            variant["conditions"]["state_contracts_sha256"] = "0" * 64
        else:
            variant["conditions"]["glibc_version"] = "0.0"
        distribution.write(root / "qualifications" / (name + ".json"), variant)
    distribution.write(output / "qualification-authority.json", {"consumer_artifact": consumer_artifact,
        "qualification_input_artifact": qualification_inputs, "distribution_artifact": distribution_artifact,
        "jobs": jobs, "production_origin": worker.production_origin(),
        "source_sha": os.environ["CM_SOURCE_SHA"], "worker_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "candidate_executed_in_signer": False, "qualification_sha256": distribution.sha(root / "qualifications/exact.json")})
    worker.output({"qualification_subject_path": str(root / "qualifications/*.json"), "qualification_directory": str(output)})


def prepare_qualified_index():
    import worker_policy as worker
    worker.identities()
    policy = distribution.read(Path(__file__).parent / "distribution-policy.json")
    root = Path(os.environ["RUNNER_TEMP"]) / "cm-index-qualification/index"
    row = next(value for value in distribution.read(root / "subjects/catalog.json")["records"] if value["id"] == "sdk-a")
    for name in ("exact", "host", "state", "environment"):
        value = copy.deepcopy(row)
        value["qualification"] = {"statement": reference(root, root / "qualifications" / (name + ".json")),
            "bundle": reference(root, root / "qualification-bundle.jsonl")}
        distribution.write(root / "qualified" / (name + ".json"), envelope(policy, [value]))
    worker.output({"qualified_index_subject_path": str(root / "qualified/*.json")})


def finish_qualified_index():
    output = Path(os.environ["RUNNER_TEMP"]) / "cm-index-qualification"
    root = output / "index"
    for path in (root / "qualified").glob("*.json"):
        target = root / ("qualified-" + path.name)
        shutil.copyfile(path, target)
        shutil.copyfile(root / "qualified-index-bundle.jsonl", target.with_name(target.name + ".bundle.jsonl"))
    files = [path for path in output.rglob("*") if path.is_file()]
    size = sum(path.stat().st_size for path in files)
    assert 0 < len(files) <= 512 and size <= distribution.LIMIT, (len(files), size)
    print(json.dumps({"qualification_files": len(files), "qualification_uncompressed_bytes": size}))


def consume_qualification():
    import worker_policy as worker
    import runtime_consumer as runtime
    worker.identities()
    policy, record = bound_artifact("index-qualification", "INDEX_QUALIFICATION")
    jobs = worker.receipt_jobs("repos/" + policy["builder_repository"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"]
        + "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["attest-index-qualification"])
    destination = Path(os.environ["CM_CONSUMER_INPUT_DIR"]) / "fixture/s03-qualified"
    distribution.artifact_download(policy, record, destination)
    authority = distribution.read(destination / "qualification-authority.json")
    assert authority["production_origin"] == worker.production_origin()
    assert authority["source_sha"] == os.environ["CM_SOURCE_SHA"] and authority["worker_sha"] == os.environ["GITHUB_WORKFLOW_SHA"]
    distribution.write(Path(os.environ["CM_CI_LOG_DIR"]) / "index-qualification-artifact.json", {"artifact": record, "jobs": jobs})
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    entries = [row for row in runtime.inventory(inputs) if row["path"] != "input-manifest.json"]
    distribution.write(inputs / "input-manifest.json", {"files": entries, "sha256": runtime.digest(entries)})


def final_reports(inputs, evidence, artifact, audit):
    import runtime_consumer as runtime
    qualified = inputs / "fixture/s03-qualified"
    authority = distribution.read(qualified / "qualification-authority.json")
    proof = distribution.read(evidence / "index-proof-consumer.json")
    assert proof["status"] == "pass" and proof["platform_verified_positive"]["support"]["sdk-a"]["platform_verified"]
    assert audit["status"] == "pass" and all(row["compiler_linker_jit_build_service_calls"] == 0 for row in audit["steps"].values())
    assert proof["host_sha256"] == distribution.read(inputs / "producer.json")["host"]["executable_sha256"]
    destination = artifact / "evidence"
    destination.mkdir(parents=True, exist_ok=True)
    for name in REPORTS:
        value = distribution.read(qualified / "main-consumer/evidence" / name)
        assert value["status"] == "behavior_pass" and value["qualification_pending"] is True
        value.update(status="pass", qualification_pending=False,
            post_consumer_qualification={"authority": authority, "statement_sha256": distribution.sha(qualified / "index/qualifications/exact.json"),
                "bundle_sha256": distribution.sha(qualified / "index/qualification-bundle.jsonl"),
                "proof_sha256": distribution.sha(evidence / "index-proof-consumer.json"),
                "proof_consumer": runtime.provenance()})
        distribution.write(destination / name, value)
    shutil.copyfile(evidence / "index-proof-consumer.json", destination / "index-proof-consumer.json")
    distribution.write(destination / "index-proof-audit.json", audit)
    acceptance = distribution.read(qualified / "main-consumer/acceptance.json")
    assert acceptance["status"] == "behavior_pass" and acceptance["task_id"] == "CM-S03"
    acceptance.update(status="pass", post_consumer_qualification=True, proof_consumer=runtime.provenance(), release_ready=False)
    for check in acceptance["checks"]:
        assert check["status"] == "behavior_pass"
        check.update(status="pass", post_consumer_qualification=True)
    distribution.write(artifact / "acceptance.json", acceptance)


def self_check(root):
    import runtime_cases
    from unittest.mock import patch
    data = distribution.read(root / INDEX_DATA)
    assert set(data["cases"]) == set(runtime_cases.GROUPS["s03"])
    assert all(value["target"] == "native" for value in data["cases"].values())
    sample = {"mod.toml": b"data", "payload.so": b"native"}
    assert zip_files(archive_bytes(sample)) == sample
    with patch("zipfile.time.localtime", return_value=(2026, 11, 6, 12, 0, 0, 4, 310, 0)):
        first = archive_bytes(sample, "case-collision")
    with patch("zipfile.time.localtime", return_value=(2027, 1, 1, 0, 0, 0, 4, 1, 0)):
        assert first == archive_bytes(sample, "case-collision"), "Fixture ZIP timestamps invalidated independent native keys"
    assert object_hash(sample) != object_hash(sample | {"payload.so": b"different"})
    for case in ("traversal", "absolute", "symlink", "duplicate", "case-collision"):
        try:
            zip_files(archive_bytes(sample, case))
        except AssertionError:
            pass
        else:
            raise AssertionError("Trusted data signer accepted an unsafe upstream archive: " + case)
    assert len(REPORTS) == 6 and len(data["cases"]) == 31
    for case in runtime_cases.GROUPS["s03"]:
        assert "def " + runtime_cases.function(case, "s03") + "(" in (root / "fixtures/binary-index/driver.py").read_text()
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
        inputs = Path(directory)
        material, output = inputs / "material", inputs / "qualification"
        for name in ("subjects/catalog.json", "archives/sdk-a.cmod", "receipts/sdk-a.json", "release-bundle.jsonl",
                "archives/byte-limit.cmod", "unrelated.json"):
            path = material / "index" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        copy_qualification_index(material, output)
        assert len([path for path in output.rglob("*") if path.is_file()]) == 4
        assert not (output / "index/archives/byte-limit.cmod").exists()
        for path in output.rglob("*"):
            if path.is_file():
                assert path.read_bytes() == (material / path.relative_to(output)).read_bytes()
        evidence = inputs / "reports"
        for name in REPORTS:
            distribution.write(evidence / name, {"status": "behavior_pass"})
        reports(evidence, {"s03-" + case: {"status": "pass"} for case in data["cases"]},
            {"status": "pass", "compiler_linker_jit_build_service_calls": 0})
        for name in REPORTS:
            assert "release_ready" not in distribution.read(evidence / name), "Report overwrote shared provenance fields"
        distribution.write(inputs / "fixture" / INDEX_DATA, data)
        catalogs = inputs / "fixture/s01-proofs/index"
        sample = {"records": [{"id": "sample", "archive": {"sha256": "a" * 64},
            "receipt": {"sha256": "b" * 64}, "bundle": {"sha256": "c" * 64}, "qualification": None}]}
        for name in {name for case in data["cases"].values() for name in case["catalogs"]}:
            distribution.write(catalogs / (name + ".json"), sample)
        before = native_inputs(inputs)
        changed = copy.deepcopy(sample)
        changed["records"][0]["archive"]["sha256"] = "d" * 64
        distribution.write(catalogs / "traversal.json", changed)
        after = native_inputs(inputs)
        assert {case for case in before if before[case] != after[case]} == {
            case for case, value in data["cases"].items() if "traversal" in value["catalogs"]}
        changed = copy.deepcopy(sample)
        changed["records"][0]["receipt"]["sha256"] = "e" * 64
        distribution.write(catalogs / "traversal.json", changed)
        assert native_inputs(inputs) == before, "Current proofs must refresh without invalidating identical native bytes"


if __name__ == "__main__":
    commands = {"prepare-archives": prepare_archives, "prepare-indexes": prepare_indexes, "finish-indexes": finish_indexes,
        "prepare-qualification": prepare_qualification, "prepare-qualified-index": prepare_qualified_index,
        "finish-qualified-index": finish_qualified_index, "consume-qualification": consume_qualification}
    if sys.argv[1:] == ["self-check"]:
        self_check(Path.cwd())
    else:
        assert len(sys.argv) == 2 and sys.argv[1] in commands
        commands[sys.argv[1]]()
