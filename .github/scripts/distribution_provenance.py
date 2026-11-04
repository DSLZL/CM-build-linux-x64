"""S01 distribution materials. Signing uses only the reviewed worker copy."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

REPORTS = ("binary-provenance.json", "distribution-sbom-license.json",
    "source-closure-no-install-build.json", "artifact-identity-boundaries.json", "release-runtime-trace.json")
POLICY_PATH = "crates/cm/src/distribution-policy.json"
ROOT_PATH = "crates/cm/src/distribution-root.jsonl"
LIMIT = 32 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMIT, str(path)
    return json.loads(path.read_bytes())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def fetch(url, maximum=LIMIT):
    assert url.startswith("https://"), "Only pinned HTTPS materials"
    with urllib.request.urlopen(url, timeout=90) as response:
        value = response.read(maximum + 1)
    assert 0 < len(value) <= maximum, "Material exceeds bound"
    return value


def text_material(directory, key, source, data):
    assert data and len(data) <= 2 * 1024 * 1024
    data.decode("utf-8")
    name = hashlib.sha256(data).hexdigest() + ".txt"
    destination = directory / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"name": key, "source": source, "path": name, "sha256": sha(destination), "size": len(data)}


def license_text(path, source_root):
    resolved = path.resolve(strict=True)
    assert resolved.is_file() and resolved.is_relative_to(source_root.resolve()), "License escapes its pinned source: " + str(path)
    with resolved.open("rb") as stream:
        return stream.read(2 * 1024 * 1024 + 1)


def licenses(directory, destination, source, source_root=None):
    candidates = [path for path in directory.iterdir() if path.is_file()
        and re.match(r"(?i)^(?:licen[cs]e|copying|copyright|notice)(?:$|[._-])", path.name)]
    result = [text_material(destination, path.name, source, license_text(path, source_root or directory))
        for path in sorted(candidates)]
    assert result, "No actual license text for " + source
    return result


def go_proxy_source(module, version):
    path = re.sub(r"[A-Z]", lambda match: "!" + match[0].lower(), module + "/@v/" + version)
    return "https://proxy.golang.org/" + path + ".zip"


def verifier(root, logs):
    """Download before the Host seal; the compiled pin covers the extracted executable."""
    policy = read(root / POLICY_PATH)
    pin = policy["verifier"]
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-verifier"
    directory.mkdir()
    archive = fetch(pin["url"], 128 * 1024 * 1024)
    assert hashlib.sha256(archive).hexdigest() == pin["archive_sha256"], "Verifier archive pin mismatch"
    name = "gh_" + pin["version"] + "_linux_amd64/bin/gh"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
        member = stream.getmember(name)
        assert member.isfile() and 0 < member.size <= 128 * 1024 * 1024
        data = stream.extractfile(member).read()
    executable = directory / "gh"
    executable.write_bytes(data)
    executable.chmod(0o755)
    material = directory / "licenses"
    official = "https://raw.githubusercontent.com/cli/cli/" + pin["source_commit"]
    records = [text_material(material, "gh/LICENSE", official + "/LICENSE", fetch(official + "/LICENSE"))]
    # The build-info table describes modules embedded in this exact prebuilt executable.
    info = subprocess.check_output(["go", "version", "-m", str(executable)], text=True, timeout=60)
    assert "\tpath\tgithub.com/cli/cli/v2/cmd/gh" in info and "\t=>\t" not in info, "Unknown verifier module graph"
    modules = []
    for line in info.splitlines():
        fields = line.split()
        if fields[:1] != ["dep"]:
            continue
        assert len(fields) == 4 and fields[2].startswith("v") and fields[3].startswith("h1:"), line
        module, version, checksum = fields[1:]
        downloaded = json.loads(subprocess.check_output(["go", "mod", "download", "-json", module + "@" + version],
            cwd=directory, text=True, timeout=180))
        assert downloaded.get("Sum") == checksum and not downloaded.get("Error"), module
        modules.append({"name": module, "version": version, "checksum": checksum,
            "source": go_proxy_source(module, version),
            "source_archive_sha256": sha(Path(downloaded["Zip"])),
            "licenses": licenses(Path(downloaded["Dir"]), material, module + "@" + version)})
    assert modules and len(modules) <= 512
    go_version = re.search(r": (go[0-9.]+)", info)
    assert go_version, "Missing embedded Go toolchain"
    go_license = fetch("https://raw.githubusercontent.com/golang/go/" + go_version[1] + "/LICENSE")
    records.append(text_material(material, "Go/LICENSE", "golang/go@" + go_version[1], go_license))
    value = {"pin": pin, "sha256": sha(executable), "build_info": info, "modules": modules,
        "licenses": records, "policy_sha256": sha(root / POLICY_PATH), "root_sha256": sha(root / ROOT_PATH)}
    write(directory / "verifier.json", value)
    write(logs / "distribution-verifier.json", value)
    return value


def cargo_components(metadata, roots, destination, revision):
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    pending = [(key, "static-or-runtime", value["name"]) for key, value in packages.items() if value["name"] in roots]
    assert len(pending) == len(roots), "Ambiguous/missing production Cargo roots"
    roles, consumers, visited = {}, {}, set()
    while pending:
        key, role, consumer = pending.pop()
        if (key, role, consumer) in visited:
            continue
        visited.add((key, role, consumer))
        roles.setdefault(key, set()).add(role)
        consumers.setdefault(key, set()).add(consumer)
        package = packages[key]
        for edge in nodes[key]["deps"]:
            for kind in edge["dep_kinds"]:
                if kind["kind"] == "dev":
                    continue
                target = packages[edge["pkg"]]
                proc_macro = any("proc-macro" in item["kind"] for item in target["targets"])
                next_role = "build-tool" if role == "build-tool" or kind["kind"] == "build" or proc_macro else role
                pending.append((edge["pkg"], next_role, consumer))
    result = []
    for key, roles_used in sorted(roles.items()):
        package = packages[key]
        source = package["source"] or revision
        directory = Path(package["manifest_path"]).parent
        declared = package.get("license")
        license_file = package.get("license_file")
        assert declared or license_file, "Unknown Cargo license: " + key
        source_root = directory
        if not package["source"] or package["source"].startswith("git+"):
            source_root = next((parent for parent in (directory, *directory.parents)
                if (parent / ".git").exists()), directory)
        license_directory = directory
        if not license_file:
            while not any(path.is_file() and re.match(r"(?i)^(?:licen[cs]e|copying)(?:$|[._-])", path.name)
                          for path in license_directory.iterdir()):
                assert license_directory != source_root, "Missing Cargo license text: " + key
                license_directory = license_directory.parent
        license_path = directory / license_file if license_file else None
        records = licenses(license_directory, destination, source + "#" + key, source_root) if not license_path else [
            text_material(destination, license_path.name, source + "#" + key, license_text(license_path, source_root))]
        notice = [path for path in directory.rglob("*") if path.is_file()
            and re.match(r"(?i)^(?:licen[cs]e|copying|copyright|notice)(?:$|[._-])", path.name)]
        assert len(notice) <= 2048
        records += [text_material(destination, path.relative_to(directory).as_posix(), source + "#" + key, license_text(path, source_root))
                    for path in notice if path.parent != directory]
        checksum_file = directory / ".cargo-checksum.json"
        result.append({"name": package["name"], "version": package["version"], "id": key, "source": source,
            "declared_license": declared or "LicenseRef-" + records[0]["sha256"], "roles": sorted(roles_used),
            "production_roots": sorted(consumers[key]),
            "source_checksum": read(checksum_file).get("package") if checksum_file.is_file() else None,
            "licenses": records, "manifest_sha256": sha(Path(package["manifest_path"]))})
    return result


def archive_licenses(data, destination, source):
    records = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        assert len(members) <= 100000
        for member in members:
            if member.isfile() and re.match(r"(?i)^(?:licen[cs]e|copying|copyright|notice)(?:$|[._-])", Path(member.name).name):
                assert 0 < member.size <= 2 * 1024 * 1024 and len(records) < 4096
                records.append(text_material(destination, member.name, source, archive.extractfile(member).read()))
    assert records, "Native input has no actual license texts: " + source
    return records


def native_components(root, package, destination, native):
    """Pinned upstream recipes identify the separately produced native inputs."""
    import base64
    import host
    upstream = root / host.HOST
    module = (upstream / "MODULE.bazel").read_text()
    patch = (upstream / "patches/v8_module_deps.patch").read_text()
    result = []
    def component(name, version, source, texts, roles, **extra):
        assert texts and source and version
        result.append({"name": name, "version": version, "source": source, "roles": roles,
            "declared_license": "LicenseRef-" + texts[0]["sha256"], "licenses": texts, **extra})
    source = "https://github.com/openai/codex/tree/" + host.read(root / host.ADAPTER / "source.json")["commit"]
    component("vendored-bubblewrap", "Codex-vendored", source,
        licenses(upstream / "codex-rs/vendor/bubblewrap", destination, source), ["native-static-helper"])
    # Checksum and patch pins come from the exact upstream checkout, not a floating dependency list.
    v8 = re.search(r'archive_override\(\s*module_name = "v8",(.*?)\n\)', module, re.S)
    assert v8
    url = re.search(r'urls = \["([^"]+)"\]', v8[1])[1]
    integrity = re.search(r'integrity = "sha256-([^"]+)"', v8[1])[1]
    data = fetch(url, 256 * 1024 * 1024)
    assert hashlib.sha256(data).digest() == base64.b64decode(integrity, validate=True)
    component("V8-native-source", "15.2.124.1", url, archive_licenses(data, destination, url),
        ["native-static-input"], archive_sha256=hashlib.sha256(data).hexdigest(), native_artifacts=native["v8"])
    for name in ("rusty_v8_libcxx", "rusty_v8_libcxxabi", "rusty_v8_llvm_libc", "icu", "dragonbox", "fp16"):
        recipe = re.search(r'\bname = "' + name + r'",(.*?)\n[+]?[)]', module + "\n" + patch, re.S)
        assert recipe, "Missing native recipe: " + name
        revision = re.search(r'commit = "([0-9a-f]{40})"', recipe[1])[1]
        remote = re.search(r'remote = "(https://[^"]+)"', recipe[1])[1]
        # Gitiles provides raw files at a fixed commit; no checkout or generator is executed.
        names = ("LICENSE.TXT",) if name.startswith("rusty_v8_") else ("LICENSE",)
        if name == "dragonbox":
            names = ("LICENSE-Apache2-LLVM", "LICENSE-Boost")
        records = [text_material(destination, name + "/" + path, remote + "@" + revision,
            base64.b64decode(fetch(remote + "/+/" + revision + "/" + path + "?format=TEXT").strip(), validate=True)) for path in names]
        component(name, revision, remote + "@" + revision, records, ["native-static-input"])
    for name in ("highway", "fast_float", "simdutf"):
        recipe = re.search(r'\bname = "' + name + r'",(.*?)\n[+]?[)]', patch, re.S)
        assert recipe
        url = re.search(r'urls = \["([^"]+)"\]', recipe[1])[1]
        expected = re.search(r'sha256 = "([0-9a-f]{64})"', recipe[1])[1]
        data = fetch(url, 128 * 1024 * 1024)
        assert hashlib.sha256(data).hexdigest() == expected
        component(name, url.rsplit("/", 1)[-1], url, archive_licenses(data, destination, url),
            ["native-static-input"], archive_sha256=expected)
    lock = read(upstream / "MODULE.bazel.lock")
    registry_url = "https://bcr.bazel.build/modules/abseil-cpp/20250814.1/source.json"
    metadata = fetch(registry_url)
    assert lock["registryFileHashes"][registry_url] == hashlib.sha256(metadata).hexdigest()
    pin = json.loads(metadata)
    data = fetch(pin["url"], 128 * 1024 * 1024)
    assert pin["integrity"] == "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode()
    component("abseil-cpp", "20250814.1", pin["url"], archive_licenses(data, destination, pin["url"]),
        ["native-static-input"], archive_sha256=hashlib.sha256(data).hexdigest())
    rust = re.search(r"(?m)^commit-hash: ([0-9a-f]{40})$", native["rust_tools"]["rustc"]["version"])[1]
    rust_url = "https://raw.githubusercontent.com/rust-lang/rust/" + rust
    component("rust-std", rust, rust_url, [text_material(destination, path, rust_url, fetch(rust_url + "/" + path))
        for path in ("LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT")], ["runtime-static-standard-library"])
    rg_manifest = (upstream / "scripts/codex_package/rg").read_text()
    rg = json.loads(rg_manifest[rg_manifest.index("{"):])["platforms"]["linux-x86_64"]
    assert rg["hash"] == "sha256" and len(rg["providers"]) == 1
    url = rg["providers"][0]["url"]
    data = fetch(url)
    assert len(data) == rg["size"] and hashlib.sha256(data).hexdigest() == rg["digest"]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        assert hashlib.sha256(archive.extractfile(rg["path"]).read()).hexdigest() == sha(package / "codex-path/rg")
    component("ripgrep-prebuilt", "15.2.0", url, archive_licenses(data, destination, url),
        ["runtime-prebuilt-helper"], archive_sha256=rg["digest"], recipe_sha256=sha(upstream / "scripts/codex_package/rg"))
    version = subprocess.check_output([str(package / "codex-path/rg"), "--version"], text=True, timeout=30)
    assert version.startswith("ripgrep 15.2.0")
    commit = json.loads(fetch("https://api.github.com/repos/BurntSushi/ripgrep/commits/15.2.0"))["sha"]
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    data = fetch("https://codeload.github.com/BurntSushi/ripgrep/tar.gz/" + commit)
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-ripgrep-source"
    directory.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        assert 0 < len(members) <= 16384 and sum(row.size for row in members) <= 128 * 1024 * 1024
        assert all(row.isfile() or row.isdir() for row in members), "Unexpected ripgrep source link"
        archive.extractall(directory, filter="data")
    source = directory / ("ripgrep-" + commit)
    command = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-musl"]
    if "+pcre2" in version:
        command += ["--features", "pcre2"]
    metadata = json.loads(subprocess.check_output(command, cwd=source, text=True, timeout=300))
    dependencies = cargo_components(metadata, {"ripgrep"}, destination, "https://github.com/BurntSushi/ripgrep@" + commit)
    result.extend({**row, "roles": ["ripgrep-" + role for role in row["roles"]]} for row in dependencies)
    published = next(row for row in result if row["name"] == "ripgrep-prebuilt")
    published["published_helper_features"] = version
    published["source_archive_sha256"] = hashlib.sha256(data).hexdigest()
    published["source_commit"] = commit
    return result + system_components(package, destination)


def system_components(package, destination):
    import runtime_qualification as qualification
    from runtime_consumer import system_package_owners
    result = []
    seen, pending = set(), []
    cache = qualification.command("ldconfig", "-p")
    for path in package.rglob("*"):
        if path.is_file():
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    pending.append(path)
    while pending:
        binary = qualification.elf(pending.pop())
        for name in [*binary["needed"], *binary["interpreter"]]:
            path = qualification.system_path(name) if name.startswith("/") else Path(qualification.resolve_library(name, cache))
            path = path.resolve()
            if str(path) in seen:
                continue
            assert len(seen) < 256
            seen.add(str(path))
            pending.append(path)
            for owner in system_package_owners(path):
                version = qualification.command("dpkg-query", "-W", "-f=${Version}", owner)
                copyright = Path("/usr/share/doc") / owner.split(":")[0] / "copyright"
                text = text_material(destination, owner + "/copyright", "Ubuntu package " + owner + "@" + version, copyright.read_bytes())
                records = [text]
                for common in re.findall(r"/usr/share/common-licenses/[A-Za-z0-9_.+-]+", copyright.read_text()):
                    records.append(text_material(destination, common, common, Path(common).read_bytes()))
                source_package = qualification.command("dpkg-query", "-W", "-f=${source:Package}=${source:Version}", owner)
                result.append({"name": owner, "version": version,
                    "source": "https://packages.ubuntu.com/noble/" + owner.split(":")[0], "licenses": records,
                    "declared_license": "LicenseRef-" + records[0]["sha256"],
                    "roles": ["system-runtime-dependency-not-shipped"], "source_package": source_package,
                    "runtime_file": {"path": str(path), "sha256": sha(path)}})
    return result


def host_materials(root, package, metadata, logs, identity):
    """Real texts and resolved production roots; the old Cargo inventory keeps its original meaning."""
    import host
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-verifier"
    verifier_record = read(directory / "verifier.json")
    assert sha(directory / "gh") == verifier_record["sha256"] == os.environ["CM_DISTRIBUTION_GH_SHA256"]
    shutil.copyfile(directory / "gh", package / "codex-resources/gh")
    (package / "codex-resources/gh").chmod(0o755)
    shutil.copyfile(root / ROOT_PATH, package / "licenses/distribution-root.jsonl")
    shutil.copyfile(root / POLICY_PATH, package / "licenses/distribution-policy.json")
    shutil.copytree(directory / "licenses", package / "licenses/components", dirs_exist_ok=True)
    components = cargo_components(metadata, {"codex-cli", "codex-code-mode-host", "codex-bwrap"},
        package / "licenses/components", "https://github.com/" + os.environ["CM_SOURCE_REPOSITORY"] + "/tree/" + os.environ["CM_SOURCE_SHA"])
    # Native archives and generated assets are inputs too, with licenses from their pinned source trees.
    native = read(root / host.ADAPTER / "inputs/native.json")
    native_licenses = licenses(root / host.HOST, package / "licenses/components", "openai/codex")
    v8_roots = [Path(row["manifest_path"]).parent for row in metadata["packages"] if row["name"] in ("v8", "rusty_v8")]
    assert v8_roots, "V8 static archive has no source component"
    for directory in v8_roots:
        native_licenses += licenses(directory, package / "licenses/components", "V8 Rust binding")
    native_rows = native_components(root, package, package / "licenses/components", native)
    v8_consumers = sorted({name for row in components if row["name"] in ("v8", "rusty_v8")
        for name in row["production_roots"]})
    for row in native_rows:
        if "native-static-input" in row["roles"]:
            row["production_roots"] = v8_consumers
        elif "native-static-helper" in row["roles"]:
            row["production_roots"] = ["codex-bwrap"]
        elif row["name"] == "rust-std":
            row["production_roots"] = ["codex-cli", "codex-code-mode-host", "codex-bwrap"]
    components += native_rows
    original = read(logs / "original-source-manifest.json")
    final = read(logs / "host-source-manifest.json")
    before = {row["path"]: row for row in original}
    after = {row["path"]: row for row in final}
    changes = {path: {"before": before.get(path), "after": after.get(path)}
        for path in sorted(before.keys() | after.keys()) if before.get(path) != after.get(path)}
    value = {"components": components, "verifier": verifier_record, "native": native, "source_changes": changes,
        "native_licenses": native_licenses, "host_identity": identity,
        "source": read(logs / "host-source-provenance.json"),
        "upstream_original_manifest": original, "upstream_final_manifest": final}
    write(package / "distribution-components.json", value)


def object_identity(directory):
    files = {path.relative_to(directory).as_posix(): [path.stat().st_size, sha(path)]
        for path in sorted(directory.rglob("*")) if path.is_file() and not path.is_symlink()}
    assert files and len(files) <= 8192
    return hashlib.sha256(canonical(files)).hexdigest()


def sbom(directory, name, components, files, origin):
    packages = []
    relationships = []
    extracted = {}
    for index, row in enumerate(components):
        assert row["source"] and row["licenses"] and row["declared_license"], "Incomplete component"
        identifier = "SPDXRef-Package-" + str(index)
        packages.append({"name": row["name"], "SPDXID": identifier, "versionInfo": row["version"],
            "downloadLocation": ("https://crates.io/crates/" + row["name"] + "/" + row["version"]
                if row["source"].startswith("registry+") else row["source"].removeprefix("git+")), "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": row["declared_license"],
            "copyrightText": "NOASSERTION", "comment": json.dumps({"roles": row["roles"], "source_checksum": row.get("source_checksum")}, sort_keys=True)})
        relationships.append({"spdxElementId": "SPDXRef-Distribution", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier})
        if row["declared_license"].startswith("LicenseRef-"):
            license = next(item for item in row["licenses"] if "LicenseRef-" + item["sha256"] == row["declared_license"])
            path = directory / ("licenses/components" if name == "cm-host" else "") / license["path"]
            extracted[row["declared_license"]] = {"licenseId": row["declared_license"], "extractedText": path.read_text(encoding="utf-8")}
    file_rows = [{"fileName": "./" + row["path"], "SPDXID": "SPDXRef-File-" + str(index),
        "checksums": [{"algorithm": "SHA256", "checksumValue": row["sha256"]}],
        "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
        "comment": json.dumps({"source": row["source"], "components": row["components"]}, sort_keys=True)} for index, row in enumerate(files)]
    packages.insert(0, {"SPDXID": "SPDXRef-Distribution", "name": name, "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION"})
    value = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": name, "documentNamespace": "https://github.com/DSLZL/CM/distribution/" + hashlib.sha256(canonical(
            {row["path"]: [row["size"], row["sha256"]] for row in files})).hexdigest(),
        "creationInfo": {"creators": ["Tool: CM-S01"], "created": origin["created_at"]},
        "documentDescribes": ["SPDXRef-Distribution"], "packages": packages, "files": file_rows,
        "hasExtractedLicensingInfos": list(extracted.values()),
        "relationships": relationships + [{"spdxElementId": "SPDXRef-Distribution", "relationshipType": "CONTAINS",
            "relatedSpdxElement": row["SPDXID"]} for row in file_rows],
        "annotations": [{"annotationDate": origin["created_at"], "annotationType": "OTHER",
            "annotator": "Tool: CM-S01", "comment": "Resolved production dependencies; roles include build tools. License conclusions require separate review."}]}
    assert {row["fileName"][2:] for row in value["files"]} == {row["path"] for row in files}
    return value


def prepare(root, inputs, frozen, logs, authors):
    import datetime
    import host
    import mod_manifest
    output = Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "distribution"
    output.mkdir()
    policy = read(root / POLICY_PATH)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    production = {"created_at": timestamp, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "job": os.environ["GITHUB_JOB"],
        "host_identity": frozen["host_identity"]["host_build_id"]}
    components = read(inputs / "host/distribution-components.json")
    host_rows = read(inputs / "host/cm-runtime-files.json")["files"]
    host_paths = {row["path"] for row in host_rows} | {"cm-runtime-files.json"}
    artifacts = {}
    for role in ("host", "a", "b"):
        name = "cm-host" if role == "host" else "sdk-" + role
        directory = inputs / "host" if role == "host" else inputs / "mods/s01" / role
        material = output / name
        material.mkdir()
        if role == "host":
            closure = components
            cargo = components["components"]
            go = components["verifier"]
            cargo = cargo + [{"name": "gh", "version": policy["verifier"]["version"],
                "source": "https://github.com/cli/cli@" + policy["verifier"]["source_commit"],
                "roles": ["runtime-verifier"], "declared_license": "MIT", "licenses": go["licenses"][:1]},
                {"name": "Go-standard-library", "version": re.search(r": (go[0-9.]+)", go["build_info"])[1],
                "source": "https://github.com/golang/go/tree/" + re.search(r": (go[0-9.]+)", go["build_info"])[1], "roles": ["verifier-static-component"],
                "declared_license": "BSD-3-Clause", "licenses": go["licenses"][1:]}]
            cargo += [{"name": row["name"], "version": row["version"], "source": row["source"],
                "roles": ["verifier-static-component"], "declared_license": "LicenseRef-" + row["licenses"][0]["sha256"],
                "licenses": row["licenses"], "source_checksum": row["checksum"]} for row in go["modules"]]
            rows = [{**row, "size": len(os.readlink(directory / row["path"]).encode())
                     if (directory / row["path"]).is_symlink() else (directory / row["path"]).stat().st_size}
                    for row in host.manifest(directory) if row["path"] in host_paths]
            assert {row["path"] for row in host.manifest(directory)} == host_paths, "Unregistered packaged asset"
            payload = "bin/codex"
            manifest_hash = sha(directory / "cm-runtime-files.json")
            contracts = {key: frozen["host_identity"][key] for key in
                ("host_build_id", "host_release_id", "host_api_version", "abis", "capabilities", "patch_map_sha256")}
            version = frozen["host_identity"]["host_release_id"]
            archive = Path(os.environ["CM_CI_ARTIFACT_DIR"]) / frozen["archive"]
            assert sha(archive) == frozen["artifact_sha256"], "Original Host archive changed"
        else:
            shutil.copytree(inputs / "mods/g06" / role / "v1", directory)
            shutil.copyfile(inputs / "host/licenses/codex-LICENSE", directory / "LICENSE")
            (directory / "NOTICE").write_text("CM independent SDK fixture; Apache-2.0. No installer hooks are run.\n")
            (directory / "build.rs").write_text('fn main() { panic!("installer must not build"); }\n')
            (directory / "proc-macro.rs").write_text('extern crate proc_macro;\n#[proc_macro]\npub fn install(input: proc_macro::TokenStream) -> proc_macro::TokenStream {\n    std::fs::write("/work/proc-macro-executed", b"executed").unwrap();\n    input\n}\n')
            (directory / "post-install.sh").write_text('#!/bin/sh\nprintf executed > /work/install-script-executed\n')
            import tomllib
            fields = tomllib.loads((directory / "mod.toml").read_text())
            version = fields["version"]
            payload = fields["binary"]["path"]
            manifest_hash = sha(directory / "mod.toml")
            contracts = {"compat": fields["compat"], "contributions": fields["contributions"],
                "native_same_process": True, "state_rollback": "M04-owned files only"}
            author = authors["g06/" + role + "/v1"]
            assert author["payload_sha256"] == sha(directory / payload) and author["host_linked"] is False
            closure = {"author": author, "independent_host": frozen["host_identity"],
                "delta_source": {"repository": "DSLZL/CM", "sha": os.environ["CM_SOURCE_SHA"]},
                "license_text": {"path": "LICENSE", "sha256": sha(directory / "LICENSE")},
                "source_attachments_are_data": ["build.rs", "proc-macro.rs", "post-install.sh"]}
            record = {"source": "https://github.com/DSLZL/CM@" + os.environ["CM_SOURCE_SHA"],
                "roles": ["independent-mod-static-component"], "declared_license": "Apache-2.0",
                "licenses": [{"path": "LICENSE", "sha256": sha(directory / "LICENSE")}]}
            cargo = []
            for path in ("crates/cm-abi", "crates/cm-sdk", "fixtures/mods/sdk-seams-" + role):
                manifest = root / path / "Cargo.toml"
                item = tomllib.loads(manifest.read_text())["package"]
                assert item["license"] == "Apache-2.0"
                cargo.append({"name": item["name"], "version": item["version"],
                    "manifest_sha256": sha(manifest), **record})
            standard = next(item for item in components["components"] if item["name"] == "rust-std")
            for license in standard["licenses"]:
                shutil.copyfile(inputs / "host/licenses/components" / license["path"], directory / license["path"])
            cargo.append({**standard, "roles": ["independent-mod-static-standard-library"],
                "production_roots": ["cm-sdk-seams-" + role]})
            cargo += system_components(directory, directory)
            rows = [{**row, "size": (directory / row["path"]).stat().st_size} for row in host.manifest(directory)]
            archive = directory.with_suffix(".cmod")
            mod_manifest.zip_package(directory, archive)
        assert rows and all("sha256" in row and "size" in row for row in rows), "Unmapped distributed link or special file"
        for row in rows:
            binary_roots = {"bin/codex": "codex-cli", "bin/codex-code-mode-host": "codex-code-mode-host",
                "codex-resources/bwrap": "codex-bwrap"}
            path = directory / row["path"]
            with path.open("rb") as stream:
                is_elf = not path.is_symlink() and stream.read(4) == b"\x7fELF"
            if role == "host" and is_elf:
                assert row["path"] in {*binary_roots, "codex-resources/gh", "codex-path/rg"}, "Unknown native asset origin"
            row["source"] = {"repository": policy["source_repository"], "sha": os.environ["CM_SOURCE_SHA"],
                "upstream_commit": host.read(root / host.ADAPTER / "source.json")["commit"] if role == "host" else None}
            selected = [(index, item) for index, item in enumerate(cargo) if
                (row["path"] == "codex-resources/gh" and (item["name"] == "gh" or "verifier-static-component" in item["roles"]))
                or (row["path"] == "codex-path/rg" and (item["name"] == "ripgrep-prebuilt" or any(value.startswith("ripgrep-") for value in item["roles"])))
                or (row["path"] not in ("codex-resources/gh", "codex-path/rg")
                    and "system-runtime-dependency-not-shipped" not in item["roles"]
                    and (role != "host" or not is_elf or (binary_roots[row["path"]] in item.get("production_roots", [])
                        and item["roles"] != ["build-tool"])))]
            license_prefix = "licenses/components/" if role == "host" else ""
            license_owners = [(index, item) for index, item in enumerate(cargo)
                if any(row["path"] == license_prefix + text["path"] for text in item["licenses"])]
            if license_owners:
                selected = license_owners
            assert selected, "Unmapped distributed asset: " + row["path"]
            row["components"] = ["SPDXRef-Package-" + str(index) for index, _ in selected]
        write(material / "source.json", closure)
        notice = {"components": cargo, "native_licenses": components["native_licenses"] if role == "host" else [],
            "scope": "Actual collected texts and declarations; no legal compliance conclusion",
            "assets": rows, "system_runtime_libraries": read(inputs / "fixture/g04-producer.json")["libraries"] if role == "host" else {}}
        texts = {}
        for record in [item for component in cargo for item in component["licenses"]] + notice["native_licenses"]:
            path = directory / ("licenses/components" if role == "host" else "") / record["path"]
            assert path.is_file() and not path.is_symlink() and sha(path) == record["sha256"], "Missing actual license text"
            text = path.read_text(encoding="utf-8")
            assert text.strip() and len(text.encode()) <= 2 * 1024 * 1024
            texts[record["sha256"]] = text
        notice["license_texts"] = texts
        write(material / "NOTICE.json", notice)
        write(material / "sbom.spdx.json", sbom(directory, name, cargo, rows, production))
        write(material / "assets.json", rows)
        draft = {"schema_version": 1, "domain": "cm.release-receipt.v1", "role": "host" if role == "host" else "mod",
            "name": name, "version": version, "target": "x86_64-unknown-linux-gnu",
            "source": {"repository": policy["source_repository"], "repository_id": policy["source_repository_id"],
                "sha": os.environ["CM_SOURCE_SHA"]},
            "production_origin": production, "artifact": {"archive_sha256": sha(archive), "archive_size": archive.stat().st_size,
                "object_sha256": object_identity(directory) if role != "host" else hashlib.sha256(canonical(
                    {row["path"]: [row["size"], row["sha256"]] for row in rows})).hexdigest(),
                "manifest_sha256": manifest_hash, "payload_sha256": sha(directory / payload)},
            "contracts": contracts, "materials": {key: sha(material / path) for key, path in
                (("sbom", "sbom.spdx.json"), ("notice", "NOTICE.json"), ("source", "source.json"))},
            "policy_sha256": sha(root / POLICY_PATH)}
        write(material / "draft.json", draft)
        artifacts[name] = {"directory": str(directory.relative_to(inputs)),
            "archive": archive.name if role == "host" else str(archive.relative_to(inputs)),
            "draft_sha256": sha(material / "draft.json")}
    for relative in ("ci/scripts/distribution_provenance.py", "fixtures/distribution-provenance/driver.py",
                     POLICY_PATH, ROOT_PATH, "docs/distribution.md", "schemas/release-receipt.schema.json"):
        destination = inputs / "fixture" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    value = {"artifacts": artifacts, "policy_sha256": sha(root / POLICY_PATH), "root_sha256": sha(root / ROOT_PATH),
        "production_origin": production}
    write(inputs / "fixture/s01-producer.json", value)
    write(output / "producer.json", value)
    validate_materials(output, policy)
    shutil.copytree(output, inputs / "distribution")
    return value


def validate_materials(directory, policy):
    value = read(directory / "producer.json")
    assert set(value["artifacts"]) == {"cm-host", "sdk-a", "sdk-b"}
    for name in value["artifacts"]:
        material = directory / name
        draft = read(material / "draft.json")
        assert sha(material / "draft.json") == value["artifacts"][name]["draft_sha256"]
        assert draft["name"] == name and draft["source"]["repository"] == policy["source_repository"]
        assert draft["source"]["repository_id"] == policy["source_repository_id"]
        assert set(draft) == {"schema_version", "domain", "role", "name", "version", "target", "source",
            "production_origin", "artifact", "contracts", "materials", "policy_sha256"}
        assert draft["schema_version"] == 1 and draft["domain"] == "cm.release-receipt.v1"
        assert draft["role"] == ("host" if name == "cm-host" else "mod")
        assert draft["target"] == "x86_64-unknown-linux-gnu" and 0 < len(draft["version"]) <= 128
        assert re.fullmatch(r"[0-9a-f]{40}", draft["source"]["sha"])
        assert draft["production_origin"] == value["production_origin"] and draft["contracts"]
        assert set(draft["materials"]) == {"sbom", "notice", "source"}
        artifact = draft["artifact"]
        assert set(artifact) == {"archive_sha256", "archive_size", "object_sha256", "manifest_sha256", "payload_sha256"}
        assert type(artifact["archive_size"]) is int and artifact["archive_size"] > 0
        assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for key, digest in artifact.items() if key != "archive_size")
        assert draft["policy_sha256"] == value["policy_sha256"]
        for key, path in (("sbom", "sbom.spdx.json"), ("notice", "NOTICE.json"), ("source", "source.json")):
            assert sha(material / path) == draft["materials"][key], "Missing or changed distribution material"
        notice = read(material / "NOTICE.json")
        assert notice["components"] and notice["assets"]
        texts = notice["license_texts"]
        assert texts and all(text.strip() and hashlib.sha256(text.encode()).hexdigest() == key for key, text in texts.items())
        for row in notice["components"]:
            assert row["licenses"] and row["source"] and row["declared_license"] not in (None, "", "UNKNOWN", "NOASSERTION")
            assert all(item["sha256"] in texts for item in row["licenses"]), "Component lacks actual license text"
        assert all(item["sha256"] in texts for item in notice["native_licenses"])
        bom = read(material / "sbom.spdx.json")
        assert bom["spdxVersion"] == "SPDX-2.3" and bom["packages"]
        expected_packages = {"SPDXRef-Package-" + str(index): row for index, row in enumerate(notice["components"])}
        assert {row["SPDXID"] for row in bom["packages"]} == {*expected_packages, "SPDXRef-Distribution"}
        for row in bom["packages"]:
            if row["SPDXID"] in expected_packages:
                expected = expected_packages[row["SPDXID"]]
                location = ("https://crates.io/crates/" + expected["name"] + "/" + expected["version"]
                    if expected["source"].startswith("registry+") else expected["source"].removeprefix("git+"))
                assert (row["name"], row["versionInfo"], row["downloadLocation"], row["licenseDeclared"]) == (
                    expected["name"], expected["version"], location, expected["declared_license"])
        extracted = {row["licenseId"]: row["extractedText"] for row in bom["hasExtractedLicensingInfos"]}
        assert all(extracted[row["declared_license"]] == texts[row["declared_license"].removeprefix("LicenseRef-")]
            for row in notice["components"] if row["declared_license"].startswith("LicenseRef-"))
        assets = read(material / "assets.json")
        assert 0 < len(assets) <= 8192 and len({row["path"] for row in assets}) == len(assets)
        component_ids = {"SPDXRef-Package-" + str(index) for index in range(len(notice["components"]))}
        for row in assets:
            path = Path(row["path"])
            assert path.parts and not path.is_absolute() and ".." not in path.parts and "\\" not in row["path"]
            assert row["source"]["repository"] == policy["source_repository"]
            assert row["source"]["sha"] == draft["source"]["sha"]
            assert row["components"] and set(row["components"]) <= component_ids, "Asset has unknown component origin"
            assert type(row["size"]) is int and row["size"] >= 0 and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
        assert notice["assets"] == assets
        assert {row["fileName"][2:]: row["checksums"][0]["checksumValue"] for row in bom["files"]} == {
            row["path"]: row["sha256"] for row in assets}
        assert hashlib.sha256(canonical({row["path"]: [row["size"], row["sha256"]] for row in assets})).hexdigest() == draft["artifact"]["object_sha256"]
    return value


def artifact_download(policy, record, destination):
    import worker_policy as worker
    assert record["expired"] is False and 0 < record["size_in_bytes"] <= LIMIT
    import tempfile
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        archive = worker.download_origin_archive(policy["builder_repository"], record, Path(temporary) / "material.zip", maximum=LIMIT)
        with archive:
            extract_materials(archive, destination)
    return record


def extract_materials(archive, destination):
    assert 0 < len(archive.infolist()) <= 512 and sum(row.file_size for row in archive.infolist()) <= LIMIT
    seen = set()
    for row in archive.infolist():
        path = Path(row.filename)
        assert path.parts and not path.is_absolute() and ".." not in path.parts and "\\" not in row.filename
        assert row.filename not in seen and not row.is_dir()
        assert (row.external_attr >> 16) & 0o170000 in (0, 0o100000)
        seen.add(row.filename)
        target = destination / path
        assert not target.exists(), "Material would overwrite an existing file"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(row))


def source_check(worker, policy, revision):
    path = "repos/" + policy["source_repository"]
    runs = worker.api(path + "/actions/workflows/cm-source-check.yml/runs?head_sha=" + revision + "&status=completed&per_page=100")["workflow_runs"]
    for run in runs:
        if (run["head_sha"] != revision or run["head_branch"] != "main" or run["conclusion"] != "success"
            or run["event"] not in ("push", "workflow_dispatch") or run["path"] != ".github/workflows/cm-source-check.yml"
            or run["repository"]["id"] != policy["source_repository_id"]
            or run["head_repository"]["id"] != policy["source_repository_id"]):
            continue
        jobs = worker.receipt_jobs(path + "/actions/runs/" + str(run["id"]) + "/attempts/" +
            str(run["run_attempt"]) + "/jobs?per_page=100", ["CI infrastructure / Linux x64 / GitHub hosted"])
        return {"run_id": run["id"], "run_attempt": run["run_attempt"], "source_sha": revision, "jobs": jobs}
    raise RuntimeError("No exact successful first-party source CI for the signing inputs")


def attest_prepare():
    """No source checkout, source imports or candidate executables in this privileged job."""
    import worker_policy as worker
    source, repository, source_sha, workflow_sha, request = worker.identities()
    base = Path(__file__).resolve().parent
    policy = read(base / "distribution-policy.json")
    assert source == policy["source_repository"] and repository == policy["builder_repository"]
    assert worker.api("repos/" + source)["id"] == policy["source_repository_id"]
    assert worker.api("repos/" + repository)["id"] == policy["builder_repository_id"]
    origin = worker.production_origin()
    assert origin, "Missing API-verified production origin"
    source_checks = {revision: source_check(worker, policy, revision) for revision in {source_sha, origin["source_sha"]}}
    jobs = worker.receipt_jobs("repos/" + repository + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] +
        "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["preflight", os.environ["CM_BUILD_JOB"]])
    worker.build_request()
    run = worker.api("repos/" + repository + "/actions/runs/" + str(origin["run_id"]))
    name = "cm-linux-x64-distribution-materials-" + origin["request_id"] + "-" + str(origin["run_attempt"])
    records = worker.api("repos/" + repository + "/actions/runs/" + str(origin["run_id"]) + "/artifacts?per_page=100")["artifacts"]
    matches = [row for row in records if row["name"] == name and not row["expired"]]
    assert len(matches) == 1, "Missing/ambiguous original distribution materials"
    directory = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-materials"
    record = artifact_download(policy, matches[0], directory)
    worker.artifact_binding(record, record["id"], name, record["digest"].removeprefix("sha256:"), origin["run_id"])
    value = validate_materials(directory, policy)
    assert value["policy_sha256"] == sha(base / "distribution-policy.json")
    assert value["root_sha256"] == sha(base / "distribution-root.jsonl")
    assert value["production_origin"]["run_id"] == origin["run_id"]
    assert value["production_origin"]["run_attempt"] == origin["run_attempt"]
    assert value["production_origin"]["source_sha"] == origin["source_sha"]
    assert value["production_origin"]["workflow_sha"] == origin["workflow_sha"]
    output = Path(os.environ["RUNNER_TEMP"]) / "cm-distribution-proofs"
    output.mkdir()
    previous_name = "cm-linux-x64-distribution-proofs-" + origin["request_id"] + "-" + str(origin["run_attempt"])
    previous = [row for row in records if row["name"] == previous_name and not row["expired"]]
    reuse = origin["run_id"] != int(os.environ["GITHUB_RUN_ID"]) and len(previous) == 1
    if reuse:
        worker.receipt_jobs("repos/" + repository + "/actions/runs/" + str(origin["run_id"]) +
            "/attempts/" + str(origin["run_attempt"]) + "/jobs?per_page=100", ["attest-distribution"])
        artifact_download(policy, previous[0], output)
        assert read(output / "authority.json")["production_origin"] == origin
        for name in value["artifacts"]:
            signed = read(output / "subjects" / (name + ".json"))
            draft = read(directory / name / "draft.json")
            assert all(signed[key] == item for key, item in draft.items() if key != "production_origin")
            assert all(signed["production_origin"][key] == item for key, item in draft["production_origin"].items())
    subjects = output / "subjects"
    subjects.mkdir(exist_ok=reuse)
    for name in value["artifacts"]:
        if reuse:
            continue
        draft = read(directory / name / "draft.json")
        draft["signer"] = {"repository": repository, "repository_id": policy["builder_repository_id"],
            "workflow": policy["workflow"], "workflow_sha": workflow_sha,
            "run_id": int(os.environ["GITHUB_RUN_ID"]), "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"])}
        # The original product/source is retained when this run only changes Python tests.
        draft["production_origin"]["input_artifact"] = origin["input_artifact"]
        draft["production_origin"]["product_artifact"] = origin["product_artifact"]
        write(subjects / (name + ".json"), draft)
    write(output / "authority.json", {"material_artifact": record, "production_origin": origin,
        "current_source_sha": source_sha, "workflow_sha": workflow_sha, "producer_jobs": jobs, "source_checks": source_checks,
        "candidate_only": True, "consumer_acceptance": "not_run"})
    worker.output({"subject_path": str(subjects / "*.json"), "proof_directory": str(output),
        "sign_required": str(not reuse).lower()})


def consume_proofs():
    import worker_policy as worker
    policy = read(Path(__file__).resolve().parent / "distribution-policy.json")
    worker.identities()
    artifact_id = int(os.environ["CM_DISTRIBUTION_ARTIFACT_ID"])
    record = worker.api("repos/" + policy["builder_repository"] + "/actions/artifacts/" + str(artifact_id))
    worker.artifact_binding(record, artifact_id, "cm-linux-x64-distribution-proofs-" + os.environ["CM_REQUEST_ID"] +
        "-" + os.environ["GITHUB_RUN_ATTEMPT"], os.environ["CM_DISTRIBUTION_ARTIFACT_DIGEST"].removeprefix("sha256:"), int(os.environ["GITHUB_RUN_ID"]))
    jobs = worker.receipt_jobs("repos/" + policy["builder_repository"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] +
        "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["attest-distribution"])
    destination = Path(os.environ["CM_CONSUMER_INPUT_DIR"]) / "fixture/s01-proofs"
    artifact_download(policy, record, destination)
    assert read(destination / "authority.json")["production_origin"] == worker.production_origin()
    assert (destination / "bundle.jsonl").is_file()
    bootstrap = Path(os.environ["CM_CONSUMER_INPUT_DIR"]) / "fixture/s01-bootstrap"
    bootstrap.mkdir()
    pin = policy["verifier"]
    archive = fetch(pin["url"], 128 * 1024 * 1024)
    assert hashlib.sha256(archive).hexdigest() == pin["archive_sha256"]
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
        member = stream.getmember("gh_" + pin["version"] + "_linux_amd64/bin/gh")
        assert member.isfile() and member.size <= 128 * 1024 * 1024
        (bootstrap / "gh").write_bytes(stream.extractfile(member).read())
    (bootstrap / "gh").chmod(0o755)
    shutil.copyfile(Path(__file__).resolve().parent / "distribution-root.jsonl", bootstrap / "distribution-root.jsonl")
    write(bootstrap / "identity.json", {"archive_sha256": pin["archive_sha256"], "binary_sha256": sha(bootstrap / "gh"),
        "source": "independent reviewed worker pin; no candidate Host execution"})
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "distribution-artifact.json", {"artifact": record, "jobs": jobs,
        "signature_gate": "offline consumer must still verify"})
    # Separate from the immutable producer manifest and from native dependency keys.
    import sys
    sys.path.append(str(Path(os.environ["CM_SOURCE_DIR"]) / "ci/scripts"))
    import runtime_consumer as runtime
    inputs = Path(os.environ["CM_CONSUMER_INPUT_DIR"])
    entries = [row for row in runtime.inventory(inputs) if row["path"] != "input-manifest.json"]
    write(inputs / "input-manifest.json", {"files": entries, "sha256": runtime.digest(entries)})


def reports(evidence, steps, audit):
    import runtime_cases
    assert audit["status"] == "pass" and audit["compiler_linker_jit_build_service_calls"] == 0
    assert all(steps["s01-" + case]["status"] == "pass" for case in runtime_cases.GROUPS["s01"])
    for name in REPORTS:
        value = read(evidence / name)
        value.update(first_party_only=True, native_sandbox=False, candidate_signature_is_acceptance=False,
            program_complete=False)
        write(evidence / name, value)


def self_check():
    from record_run import require_hosted_linux
    require_hosted_linux()
    assert canonical({"b": 1, "a": "中"}) == '{"a":"中","b":1}'.encode()
    assert len(REPORTS) == len(set(REPORTS)) == 5
    assert go_proxy_source("golang.org/x/sys", "v0.1.0") == "https://proxy.golang.org/golang.org/x/sys/@v/v0.1.0.zip"
    assert go_proxy_source("example.com/Azure/SDK", "v1.0.0-RC1") == "https://proxy.golang.org/example.com/!azure/!s!d!k/@v/v1.0.0-!r!c1.zip"
    import runtime_consumer
    runtime_consumer.check_distribution_verifier_binding()
    import retry
    import runtime_cases
    root = Path(os.environ["CM_SOURCE_DIR"])
    texts = {path: (root / path).read_text() for path in retry.RUNTIME_FILES if not path.endswith("ci_progress.py")}
    driver = "fixtures/distribution-provenance/driver.py"
    changed = {**texts, driver: texts[driver].replace('"unknown-schema"', '"unknown-schema-regression"')}
    assert changed[driver] != texts[driver]
    affected = set()
    for case in runtime_cases.GROUPS["s01"]:
        dispatch = {driver: runtime_cases.function(case, "s01")}
        entries = [(driver, "matrix")]
        if runtime_cases.closure(texts, entries, dispatch) != runtime_cases.closure(changed, entries, dispatch):
            affected.add(case)
    assert affected == {"proof"}, "A single Python fix invalidated unrelated S01 cases"
    excluded = {"reports", "self_check", "attest_prepare", "consume_proofs", "source_check", "artifact_download", "extract_materials"}
    source = Path(__file__).read_text()
    assert retry.projection(source, exclude=excluded) == retry.projection(
        source.replace("candidate_signature_is_acceptance=False", "candidate_signature_is_acceptance=True"), exclude=excluded)
    import tempfile
    from types import SimpleNamespace
    policy = {"source_repository": "DSLZL/CM", "source_repository_id": 1430833890}
    valid = {"head_sha": "a" * 40, "head_branch": "main", "conclusion": "success", "event": "push",
        "path": ".github/workflows/cm-source-check.yml", "repository": {"id": 1430833890},
        "head_repository": {"id": 1430833890}, "id": 1, "run_attempt": 1}
    worker = SimpleNamespace(api=lambda _: {"workflow_runs": [valid]}, receipt_jobs=lambda *_: ["successful-source-ci"])
    assert source_check(worker, policy, "a" * 40)["run_id"] == 1
    for key, value in (("head_sha", "b" * 40), ("conclusion", "failure"), ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"), ("head_repository", {"id": 1})):
        changed = {**valid, key: value}
        worker.api = lambda _, changed=changed: {"workflow_runs": [changed]}
        try:
            source_check(worker, policy, "a" * 40)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unqualified source CI authorized signing")
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary) / "checkout"
        root.mkdir()
        (root / ".git").mkdir()
        (root / "LICENSE").write_text("shared pinned checkout license\n")
        metadata = {"packages": [], "resolve": {"nodes": []}}
        edges = {"a": [("shared", None), ("builder", "build"), ("dev", "dev")],
            "b": [("shared", None)], "shared": [], "builder": [], "dev": []}
        for name, dependencies in edges.items():
            directory = root / name
            directory.mkdir()
            (directory / "Cargo.toml").write_text("[package]\n")
            (directory / "LICENSE").write_text("self-check license text\n")
            metadata["packages"].append({"id": name, "name": name, "version": "1.0.0", "source": None,
                "license": "MIT", "manifest_path": str(directory / "Cargo.toml"), "targets": [{"kind": ["lib"]}]})
            metadata["resolve"]["nodes"].append({"id": name, "deps": [
                {"pkg": dependency, "dep_kinds": [{"kind": kind}]} for dependency, kind in dependencies]})
        linked_license = root / "shared/LICENSE"
        linked_license.unlink()
        linked_license.symlink_to("../LICENSE")
        next(row for row in metadata["packages"] if row["name"] == "shared")["source"] = "git+https://example.invalid/pinned#" + "a" * 40
        components = {row["name"]: row for row in cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")}
        assert set(components) == {"a", "b", "shared", "builder"}
        assert components["shared"]["production_roots"] == ["a", "b"]
        assert components["shared"]["licenses"][0]["sha256"] == sha(root / "LICENSE")
        assert components["builder"]["roles"] == ["build-tool"] and components["builder"]["production_roots"] == ["a"]
        outside = Path(temporary) / "outside.txt"
        outside.write_text("not part of the pinned checkout\n")
        linked_license.unlink()
        linked_license.symlink_to("../../outside.txt")
        try:
            cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")
        except AssertionError:
            pass
        else:
            raise AssertionError("License symlink escaped its pinned checkout")
        linked_license.unlink()
        inherited = {row["name"]: row for row in cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")}
        assert inherited["shared"]["licenses"][0]["sha256"] == sha(root / "LICENSE")
        metadata["packages"][0]["license"] = None
        try:
            cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")
        except AssertionError:
            pass
        else:
            raise AssertionError("Unknown Cargo license accepted")
        for name in ("../escape.json", "/absolute.json", "linked.json"):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                row = zipfile.ZipInfo(name)
                row.external_attr = (0o120777 if name == "linked.json" else 0o100644) << 16
                archive.writestr(row, b"bounded")
            with zipfile.ZipFile(io.BytesIO(data.getvalue())) as archive:
                try:
                    extract_materials(archive, root / "rejected")
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Unsafe material archive accepted")
    # Actual missing text/source/asset cases mutate rehashed production materials in the consumer.


if __name__ == "__main__":
    import sys
    from record_run import require_hosted_linux
    require_hosted_linux()
    {"attest-prepare": attest_prepare, "consume-proofs": consume_proofs, "self-check": self_check}[sys.argv[1]]()
