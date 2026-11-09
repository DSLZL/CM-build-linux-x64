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
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from cm_platforms import linux_native

REPORTS = ("binary-provenance.json", "distribution-sbom-license.json",
    "source-closure-no-install-build.json", "artifact-identity-boundaries.json", "release-runtime-trace.json")
POLICY_PATH = "crates/cm/src/" + ("distribution-policy-arm64.json"
    if linux_native()["machine"] == 183 else "distribution-policy.json")
ROOT_PATH = "crates/cm/src/distribution-root.jsonl"
LIMIT = 32 * 1024 * 1024
CARGO_BINDING_SOURCE_PIN = ("denoland/rusty_v8", "v8", "152.2.0",
    "a10fe1a92da5c32c7c7f838ce36c0ccfcfd5edf0865b58bdde820aa64cea9888", "2768994f664e8a6e3aba27503606c58339136e2a")
CARGO_LICENSE_PINS = {
    **{("facebookexperimental/allocative", name, "0.3.6"):
        ("fc41670cf9cfebd86ba597925081577897112c51", name)
        for name in ("allocative", "allocative_derive")},
    ("facebookincubator/gazebo", "display_container", "0.9.0"):
        ("13efb6d415c4729178dfccc36fa9c87491f0813d", "display_container"),
    ("cbreeden/fxhash", "fxhash", "0.2.1"): ("537570af68de22d2f4bbdd5bee5d6e07268e6f42", ""),
    ("facebook/buck2", "lock_free_hashtable", "0.1.4"):
        ("48ae5c61c93c808e0831b27104d3bc7262f06bd4", "shed/lock_free_hashtable"),
    ("facebook/buck2", "static_interner", "0.1.2"):
        ("bb9114292d98db0a2919d37d673bb27f930e6aa1", "shed/static_interner"),
    **{("facebook/buck2", name, "0.1.0"):
        ("bb9114292d98db0a2919d37d673bb27f930e6aa1", "gazebo/" + name)
        for name in ("strong_hash", "strong_hash_derive")},
    ("denoland/rusty_v8", "v8", "152.2.0"): ("2768994f664e8a6e3aba27503606c58339136e2a", ""),
    ("pdf-rs/fax", "fax", "0.2.6"): ("5d70a161e33b62305f8bce7af3f7fbd011cfaf5d", ""),
    ("pdf-rs/fax", "fax_derive", "0.2.0"): ("5d70a161e33b62305f8bce7af3f7fbd011cfaf5d", "derive"),
}
CARGO_LICENSE_REPOSITORIES = {
    ("pagable_derive", "0.4.1", "838d17166587914f4e99353766c29160462b681511f08679545a0d07a0dc9415"):
        "https://github.com/facebook/starlark-rust",
    ("zune-core", "0.4.12", "3f423a2c17029964870cfaabb1f13dfab7d092a62a29a89264f4d36990ca414a"):
        "https://github.com/etemesi254/zune-image",
}
CARGO_LICENSE_SUPPLEMENTS = {
    ("marwes/debugserver-types", "debugserver-types", "0.5.0",
        "2bf6834a70ed14e8e4e41882df27190bea150f1f6ecf461f1033f8739cd8af4a", "d444f163123af5b4fbce7375d1afead7e9b8a224"):
        ("MIT", "4411fbf0de2c84a137d47de1c127f418f07ed41a361ae89f4f28bcfdabe304ce"),
    ("denoland/deno_core_icudata", "deno_core_icudata", "0.78.0",
        "b963d2d79672b4c379e4511acccd27bb35b4c1b32a93f596d52ff14a064293bc", "9adfc1019ed4fce2e873c8bc7aebec09928010c8"):
        ("MIT", "151acc78e12d7a849141e0ce714beb64e955cd43f9d9429d17232982de5ea017"),
    ("jpopesculian/eventsource-stream", "eventsource-stream", "0.2.3",
        "74fef4569247a5f429d9156b9d0a2599914385dd189c539334c625d8099d90ab", "3d46f1c758f9ee4681e9da0427556d24c53f9c01"):
        ("MIT OR Apache-2.0", "725711996fb72721abc35595e0703ca2d1b55cb4d98cc5ade959fc0f8c2e86a4"),
    ("cbreeden/fxhash", "fxhash", "0.2.1",
        "c31b6d751ae2c7f11320402d34e41349dd1016f8d5d45e48c4312bc8625af50c", "537570af68de22d2f4bbdd5bee5d6e07268e6f42"):
        ("Apache-2.0/MIT", "42f07fb23f8b37acf45914ccb71df077455a353850e148afeabb5c684f8ebaab"),
    ("theonlymrcat/io_tee", "io_tee", "0.1.1",
        "4b3f7cef34251886990511df1c61443aa928499d598a9473929ab5a90a527304", "8a7adecebf3429cbc58a0368751d1851dfaf58ed"):
        ("MIT OR Apache-2.0", "9556395f55b7c67a6041f84553c7c27b3ab3fe5505769f4f1003a7b0988f2586"),
    ("landhb/linux-keyutils", "linux-keyutils", "0.2.4",
        "761e49ec5fd8a5a463f9b84e877c373d888935b71c6be78f3767fe2ae6bed18e", "2e81f726ffd3c0165e11fcdbde279b5d8638f47d"):
        ("Apache-2.0 OR MIT", "18c658b216c2031f6849f3638cff80f6f42df2280e95ad4d78fbc335d8dc413a"),
}
SPDX_MIT_PIN = (
    "https://raw.githubusercontent.com/spdx/license-list-data/31846481de7ea17d92f2f46fad76abe58b2e9bb0/text/MIT.txt",
    "b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5")
RIPGREP_SOURCE_COMMIT = "e89fff89ac9af12e8d4ce9d5fd07beb408ca730f"
COMMON_LICENSE_PATH = r"/usr/share/common-licenses/[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*"


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
    if url.startswith("https://api.github.com/"):
        import worker_policy
        value = canonical(worker_policy.api(url.removeprefix("https://api.github.com/")))
    else:
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=90) as response:
                    value = response.read(maximum + 1)
                break
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                transient = (error.code in (502, 503, 504) if isinstance(error, urllib.error.HTTPError)
                             else isinstance(getattr(error, "reason", error), (ConnectionError, TimeoutError)))
                if not transient or attempt == 2:
                    raise
                if isinstance(error, urllib.error.HTTPError):
                    error.close()
                delay = 5 * (attempt + 1)
                print(f"CM materials: {error}; retry {attempt + 1}/2 in {delay}s: {url}", flush=True)
                time.sleep(delay)
    assert 0 < len(value) <= maximum, "Material exceeds bound: " + url
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
    for path in directory.iterdir():
        if path.is_dir() and path.name.lower() in ("licenses", "licences"):
            candidates += [entry for entry in path.rglob("*") if entry.is_file()]
    assert len(candidates) <= 128, "Too many license texts"
    result = [text_material(destination, path.relative_to(directory).as_posix(), source, license_text(path, source_root or directory))
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
    name = pin["archive"].removesuffix(".tar.gz") + "/bin/gh"
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
        try:
            downloaded = json.loads(subprocess.check_output(["go", "mod", "download", "-json", module + "@" + version],
                cwd=directory, text=True, timeout=180))
        except subprocess.CalledProcessError as error:
            raise RuntimeError("Go material download failed for " + module + "@" + version + ": " + error.output[-8192:]) from error
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


def registry_licenses(package, directory, destination, checksum):
    # Some published crates omit license files; the locked crate archive pins their VCS metadata.
    repository_url = package.get("repository") or CARGO_LICENSE_REPOSITORIES.get((package["name"], package["version"], checksum), "")
    repository = re.fullmatch(r"https://github\.com/([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/[A-Za-z0-9_./-]+)?/?", repository_url)
    assert package["source"] and package["source"].startswith("registry+") and repository, "Missing pinned Cargo license source: " + package["id"]
    vcs_path = directory / ".cargo_vcs_info.json"
    assert re.fullmatch(r"[0-9a-f]{64}", checksum or ""), "Missing locked Cargo checksum"
    vcs = read(vcs_path) if vcs_path.is_file() else None
    pin = CARGO_LICENSE_PINS.get((repository[1].lower(), package["name"], package["version"]))
    verify_source = vcs is None or not package.get("repository") or bool(vcs["git"].get("dirty"))
    if vcs is not None:
        revision, subpath = vcs["git"]["sha1"], vcs.get("path_in_vcs", "")
        assert not vcs["git"].get("dirty") or pin == (revision, subpath), "Unreviewed dirty Cargo license source"
        if pin and pin != (revision, subpath):
            revision, subpath = pin
            verify_source = True  # A later license-only commit must still match every shipped source file.
    else:
        assert pin, "Missing reviewed Cargo license source: " + package["id"]
        revision, subpath = pin
    assert re.fullmatch(r"[0-9a-f]{40}", revision), "Unpinned Cargo license source"
    assert not subpath or (not Path(subpath).is_absolute() and Path(subpath).as_posix() == subpath
        and ".." not in Path(subpath).parts), "Unsafe Cargo VCS path"
    tree = json.loads(fetch("https://api.github.com/repos/" + repository[1] + "/git/trees/" + revision + "?recursive=1"))
    assert not tree.get("truncated") and len(tree["tree"]) <= 100000, "Incomplete pinned Cargo source tree"
    binding_source = (repository[1].lower(), package["name"], package["version"], checksum, revision) == CARGO_BINDING_SOURCE_PIN
    submodules = [row["path"] for row in tree["tree"] if row["mode"] == "160000"] if binding_source else []
    crate_name = package["name"] + "-" + package["version"]
    maximum = 64 * 1024 * 1024 if binding_source else LIMIT
    cached = (Path(os.environ["CARGO_HOME"]) / "registry/cache" / directory.parent.name / (crate_name + ".crate")) if os.environ.get("CARGO_HOME") else None
    if cached and cached.is_file():
        assert not cached.is_symlink() and 0 < cached.stat().st_size <= maximum, "Invalid cached Cargo archive"
        with cached.open("rb") as stream:
            crate = stream.read(maximum + 1)
    else:
        crate = fetch("https://static.crates.io/crates/" + urllib.parse.quote(package["name"], safe="") + "/"
            + urllib.parse.quote(crate_name, safe="") + ".crate", maximum)
    assert 0 < len(crate) <= maximum, "Invalid Cargo archive size"
    assert hashlib.sha256(crate).hexdigest() == checksum, "Locked Cargo archive checksum mismatch"
    source_files, generated_bindings = {}, {}
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
        if vcs is not None:
            member = archive.getmember(crate_name + "/.cargo_vcs_info.json")
            assert member.isfile() and 0 < member.size <= 65536
            assert json.loads(archive.extractfile(member).read()) == vcs, "Cargo VCS pin differs from locked archive"
        else:
            assert crate_name + "/.cargo_vcs_info.json" not in archive.getnames(), "Published Cargo VCS pin was removed"
        if verify_source:
            members = archive.getmembers()
            assert len(members) <= (32768 if binding_source else 4096)
            total, selected = 0, 0
            for member in members:
                if member.isdir():
                    continue
                relative = member.name.removeprefix(crate_name + "/")
                assert member.isfile() and relative != member.name and not Path(relative).is_absolute() and ".." not in Path(relative).parts
                assert member.size >= 0
                total += member.size
                assert total <= (1024 * 1024 * 1024 if binding_source else LIMIT)
                if relative in ("Cargo.toml", "Cargo.lock", ".cargo_vcs_info.json"):
                    continue  # Cargo generates these; the original manifest and every shipped source file must match.
                if relative == "Cargo.toml.orig":
                    relative = "Cargo.toml"
                path = (Path(subpath) / relative).as_posix()
                if any(path.startswith(module + "/") for module in submodules):
                    continue  # The locked archive pins these bytes; native_components covers the separately built native inputs.
                assert 0 <= member.size <= 2 * 1024 * 1024
                selected += member.size
                assert selected <= LIMIT
                assert path not in source_files and path not in generated_bindings, "Duplicate Cargo source file"
                data = archive.extractfile(member).read()
                if binding_source and re.fullmatch(r"gen/src_binding_[A-Za-z0-9_-]+\.rs", relative):
                    assert len(generated_bindings) < 128
                    generated_bindings[path] = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                    continue  # The pinned publisher downloads these CI outputs into gen before cargo publish --allow-dirty.
                source_files[path] = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            assert (Path(subpath) / "Cargo.toml").as_posix() in source_files and any(path.endswith(".rs") for path in source_files)
    parents = {"", *(parent.as_posix() for parent in (Path(subpath), *Path(subpath).parents))}
    tree_files = {row["path"]: row["sha"] for row in tree["tree"] if row["type"] == "blob" and row["mode"] in ("100644", "100755")}
    differences = [{"path": path, "published_blob": blob, "repository_blob": tree_files.get(path)}
        for path, blob in source_files.items() if tree_files.get(path) != blob]
    assert not differences, "Published Cargo source differs from reviewed pin (" + str(len(differences)) + "): " + canonical(differences[:128]).decode()
    if binding_source:
        print("CM Cargo binding source verified: " + crate_name + "; complete locked archive SHA256 " + checksum
            + "; non-generated binding repository files matched " + revision + "; " + str(len(generated_bindings))
            + " published generated bindings and embedded submodule bytes retain archive identity", flush=True)
    candidates = [row for row in tree["tree"] if row["type"] == "blob" and row["mode"] in ("100644", "100755")
        and ((Path(row["path"]).parent.as_posix() in parents
            and re.match(r"(?i)^(?:licen[cs]e|copying|copyright|notice)(?:$|[._-])", Path(row["path"]).name))
            or (Path(row["path"]).parent.name.lower() in ("licenses", "licences")
                and Path(row["path"]).parent.parent.as_posix() in parents))]
    assert len(candidates) <= 128
    has_license = any(re.match(r"(?i)^(?:licen[cs]e|copying)(?:$|[._-])",
        Path(row["path"]).name) or Path(row["path"]).parent.name.lower() in ("licenses", "licences")
        for row in candidates)
    supplement = CARGO_LICENSE_SUPPLEMENTS.get((repository[1].lower(), package["name"], package["version"], checksum, revision))
    assert has_license or (supplement and package.get("license") == supplement[0]), "No actual license in pinned Cargo source: " + package["id"]
    records = []
    for row in sorted(candidates, key=lambda item: item["path"]):
        path = row["path"]
        assert not Path(path).is_absolute() and ".." not in Path(path).parts
        url = "https://raw.githubusercontent.com/" + repository[1] + "/" + revision + "/" + urllib.parse.quote(path)
        data = fetch(url, 2 * 1024 * 1024)
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        assert hashlib.sha1(blob).hexdigest() == row["sha"], "Pinned Cargo license blob mismatch"
        records.append(text_material(destination, path, url, data))
    if not has_license:
        declaration_url = "https://raw.githubusercontent.com/" + repository[1] + "/" + revision + "/" + (Path(subpath) / "Cargo.toml").as_posix()
        declaration = fetch(declaration_url, 2 * 1024 * 1024)
        assert hashlib.sha256(declaration).hexdigest() == supplement[1], "Reviewed license declaration changed"
        assert tomllib.loads(declaration.decode())["package"]["license"] == supplement[0], "Upstream license declaration differs"
        standard = fetch(SPDX_MIT_PIN[0], 2 * 1024 * 1024)
        assert hashlib.sha256(standard).hexdigest() == SPDX_MIT_PIN[1], "Canonical license text changed"
        records.append({**text_material(destination, "SPDX/MIT.txt", SPDX_MIT_PIN[0], standard),
            "material_kind": "standard-license-supplement", "selected_license": "MIT", "declared_license": supplement[0],
            "upstream_license_file_found": False, "upstream_repository": repository_url, "upstream_revision": revision,
            "locked_source_checksum": checksum, "declaration_source": declaration_url, "declaration_sha256": supplement[1],
            "note": "Separately supplied standard terms; no upstream-authored file, copyright holder or year is invented"})
    if binding_source:
        publisher = ".github/workflows/ci.yml"
        assert re.fullmatch(r"[0-9a-f]{40}", tree_files.get(publisher, "")), "Missing pinned binding publisher recipe"
        records[0]["published_crate_source"] = {"archive_sha256": checksum, "repository_revision": revision,
            "matched_repository_files": len(source_files), "generated_bindings": list(generated_bindings.values()),
            "publisher_workflow": "https://github.com/" + repository[1] + "/blob/" + revision + "/" + publisher,
            "publisher_workflow_blob": tree_files[publisher],
            "embedded_submodules": [{"path": row["path"], "revision": row["sha"]} for row in tree["tree"] if row["mode"] == "160000"],
            "note": "Generated bindings and expanded submodules retain the complete locked archive identity; actual native inputs are verified separately"}
    return records


def cargo_components(metadata, roots, destination, revision):
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    lock = tomllib.loads((Path(metadata["workspace_root"]) / "Cargo.lock").read_text())
    checksums = {(row["name"], row["version"], row.get("source")): row.get("checksum") for row in lock.get("package", [])}
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
    result, failures = [], []
    for key, roles_used in sorted(roles.items()):
        package = packages[key]
        try:
            source = package["source"] or revision
            checksum = checksums.get((package["name"], package["version"], package["source"]))
            if package["source"] and package["source"].startswith("registry+"):
                assert re.fullmatch(r"[0-9a-f]{64}", checksum or ""), "Missing locked Cargo checksum: " + key
            directory = Path(package["manifest_path"]).parent
            declared = package.get("license")
            license_file = package.get("license_file")
            assert declared or license_file, "Unknown Cargo license: " + key
            source_root = directory
            if not package["source"] or package["source"].startswith("git+"):
                source_root = next((parent for parent in (directory, *directory.parents)
                    if (parent / ".git").exists()), directory)
            license_directory = directory
            records = None
            if not license_file:
                while not any((path.is_file() and re.match(r"(?i)^(?:licen[cs]e|copying)(?:$|[._-])", path.name))
                              or (path.is_dir() and path.name.lower() in ("licenses", "licences"))
                              for path in license_directory.iterdir()):
                    if license_directory == source_root:
                        records = registry_licenses(package, directory, destination, checksum)
                        break
                    license_directory = license_directory.parent
            license_path = directory / license_file if license_file else None
            if records is None:
                records = licenses(license_directory, destination, source + "#" + key, source_root) if not license_path else [
                    text_material(destination, license_path.name, source + "#" + key, license_text(license_path, source_root))]
            notice = [path for path in directory.rglob("*") if path.is_file()
                and re.match(r"(?i)^(?:licen[cs]e|copying|copyright|notice)(?:$|[._-])", path.name)]
            assert len(notice) <= 2048
            records += [text_material(destination, path.relative_to(directory).as_posix(), source + "#" + key, license_text(path, source_root))
                        for path in notice if path.parent != directory]
            result.append({"name": package["name"], "version": package["version"], "id": key, "source": source,
                "declared_license": declared or "LicenseRef-" + records[0]["sha256"], "roles": sorted(roles_used),
                "production_roots": sorted(consumers[key]),
                "source_checksum": checksum,
                "licenses": records, "manifest_sha256": sha(Path(package["manifest_path"]))})
        except (AssertionError, OSError, ValueError, KeyError, tarfile.TarError) as error:
            failures.append({"id": key, "name": package["name"], "version": package["version"],
                "source": package["source"], "checksum": checksums.get((package["name"], package["version"], package["source"])),
                "repository": package.get("repository"), "license": package.get("license"),
                "vcs_present": (Path(package["manifest_path"]).parent / ".cargo_vcs_info.json").is_file(),
                "error": type(error).__name__ + ": " + str(error)})
    assert not failures, "Cargo license collection blocked: " + canonical(failures).decode()
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


def ripgrep_source(data, directory, commit):
    assert commit == RIPGREP_SOURCE_COMMIT, "Unreviewed ripgrep source revision"
    prefix = "ripgrep-" + commit
    directory.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        assert 0 < len(members) <= 16384 and sum(row.size for row in members) <= 128 * 1024 * 1024
        assert all(Path(row.name).parts and not Path(row.name).is_absolute() and ".." not in Path(row.name).parts and "\\" not in row.name
            and Path(row.name).parts[0] == prefix for row in members), "Ripgrep source path escapes its pinned root"
        assert all(row.isfile() or row.isdir() or (row.issym() and row.name == prefix + "/HomebrewFormula"
            and row.linkname == "pkg/brew") for row in members), "Unexpected ripgrep source link"
        archive.extractall(directory, filter="data")
    return directory / prefix


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
    source = ripgrep_source(data, Path(os.environ["RUNNER_TEMP"]) / "cm-ripgrep-source", commit)
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
                for common in re.findall(COMMON_LICENSE_PATH, copyright.read_text()):
                    records.append(text_material(destination, common, common, Path(common).read_bytes()))
                source_package = qualification.command("dpkg-query", "-W", "-f=${source:Package}=${source:Version}", owner)
                result.append({"name": owner, "version": version,
                    "source": "https://packages.ubuntu.com/noble/" + owner.split(":")[0], "licenses": records,
                    "declared_license": "LicenseRef-" + records[0]["sha256"],
                    "roles": ["system-runtime-dependency-not-shipped"], "source_package": source_package,
                    "runtime_file": {"path": str(path), "sha256": sha(path)}})
    return result


def cargo_audit():
    import host
    root = Path(os.environ["CM_SOURCE_DIR"])
    if host.load_config(root)["task_id"] not in ("CM-S01", "CM-S02", "CM-S03"):
        return
    assert os.environ["GITHUB_REPOSITORY"] == "DSLZL/CM-build-" + linux_native()["key"]
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host.TARGET],
        cwd=root / host.HOST / "codex-rs", text=True))
    logs = Path(os.environ["CM_CI_LOG_DIR"])
    components = cargo_components(metadata, {"codex-cli", "codex-code-mode-host", "codex-bwrap"},
        logs / "cargo-license-texts", "https://github.com/" + os.environ["CM_SOURCE_REPOSITORY"] + "/tree/" + os.environ["CM_SOURCE_SHA"])
    write(logs / "cargo-license-audit.json", {"status": "pass", "component_count": len(components),
        "source_sha": os.environ["CM_SOURCE_SHA"], "lock_sha256": sha(Path(metadata["workspace_root"]) / "Cargo.lock"),
        "note": "Early license check; packaging still collects and verifies its current materials"})


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
    v8_components = [row for row in components if row["name"] in ("v8", "rusty_v8")]
    assert v8_components, "V8 static archive has no source component"
    for row in v8_components:
        native_licenses += row["licenses"]
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
            "licenseConcluded": "NOASSERTION", "licenseDeclared": re.sub(r"\s*/\s*", " OR ", row["declared_license"]),
            "copyrightText": "NOASSERTION", "comment": json.dumps({"roles": row["roles"], "source_checksum": row.get("source_checksum"),
                "original_license_declaration": row["declared_license"],
                "license_supplements": [item for item in row["licenses"] if item.get("material_kind") == "standard-license-supplement"],
                "published_crate_source": next((item["published_crate_source"] for item in row["licenses"] if "published_crate_source" in item), None)}, sort_keys=True)})
        relationships.append({"spdxElementId": "SPDXRef-Distribution", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier})
        if row["declared_license"].startswith("LicenseRef-"):
            license = next(item for item in row["licenses"] if "LicenseRef-" + item["sha256"] == row["declared_license"])
            path = directory / ("licenses/components" if name == "cm-host" else "") / license["path"]
            extracted[row["declared_license"]] = {"licenseId": row["declared_license"], "extractedText": license_text(path, directory).decode("utf-8")}
    file_rows = []
    for index, row in enumerate(files):
        with (directory / row["path"]).open("rb") as stream:
            sha1 = hashlib.file_digest(stream, "sha1").hexdigest()
        file_rows.append({"fileName": "./" + row["path"], "SPDXID": "SPDXRef-File-" + str(index),
            "checksums": [{"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": row["sha256"]}],
            "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
            "comment": json.dumps({"source": row["source"], "components": row["components"]}, sort_keys=True)})
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
    import runtime_qualification
    output = Path(os.environ["CM_CI_ARTIFACT_DIR"]) / "distribution"
    output.mkdir()
    policy = read(root / POLICY_PATH)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    production = {"created_at": timestamp, "source_sha": os.environ["CM_SOURCE_SHA"],
        "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "job": os.environ["GITHUB_JOB"],
        "host_identity": frozen["host_identity"]["host_build_id"]}
    components = read(inputs / "host/distribution-components.json")
    _, host_files = runtime_qualification.host_manifest(inputs / "host", frozen)
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
                    for row in host_files]
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
            text = license_text(path, directory).decode("utf-8")
            assert text.strip() and len(text.encode()) <= 2 * 1024 * 1024
            texts[record["sha256"]] = text
        notice["license_texts"] = texts
        write(material / "NOTICE.json", notice)
        write(material / "sbom.spdx.json", sbom(directory, name, cargo, rows, production))
        write(material / "assets.json", rows)
        draft = {"schema_version": 1, "domain": "cm.release-receipt.v1", "role": "host" if role == "host" else "mod",
            "name": name, "version": version, "target": linux_native()["target"],
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
        if role != "host":
            # Small data-only archive for the reviewed catalog signer; never executes candidate code.
            shutil.copyfile(archive, material / "transport.cmod")
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
        assert draft["target"] == linux_native()["target"] and 0 < len(draft["version"]) <= 128
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
        assert texts, "Missing actual license texts"
        for key, text in texts.items():
            assert text.strip() and hashlib.sha256(text.encode()).hexdigest() == key, "License text differs: " + name + "/" + key
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
                    expected["name"], expected["version"], location, re.sub(r"\s*/\s*", " OR ", expected["declared_license"]))
                assert json.loads(row["comment"])["original_license_declaration"] == expected["declared_license"]
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
        file_checksums = {}
        for row in bom["files"]:
            checksums = {item["algorithm"]: item["checksumValue"] for item in row["checksums"]}
            assert len(checksums) == len(row["checksums"]) == 2 and set(checksums) == {"SHA1", "SHA256"}
            assert re.fullmatch(r"[0-9a-f]{40}", checksums["SHA1"])
            file_checksums[row["fileName"][2:]] = checksums["SHA256"]
        assert len(file_checksums) == len(bom["files"])
        assert file_checksums == {row["path"]: row["sha256"] for row in assets}
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
    runs = worker.api(path + "/actions/runs?head_sha=" + revision + "&per_page=100")["workflow_runs"]
    for run in runs:
        if (run["status"] != "completed" or run["head_sha"] != revision or run["head_branch"] != "main" or run["conclusion"] != "success"
            or run["event"] not in ("push", "workflow_dispatch") or run["path"] != ".github/workflows/cm-source-check.yml"
            or run["repository"]["id"] != policy["source_repository_id"]
            or run["head_repository"]["id"] != policy["source_repository_id"]):
            continue
        jobs = worker.receipt_jobs(path + "/actions/runs/" + str(run["id"]) + "/attempts/" +
            str(run["run_attempt"]) + "/jobs?per_page=100", ["CI infrastructure / Linux x64 / GitHub hosted"])
        return {"run_id": run["id"], "run_attempt": run["run_attempt"], "source_sha": revision, "jobs": jobs}
    raise RuntimeError("No exact successful first-party source CI for the signing inputs: " + revision)


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
    name = f"cm-{linux_native()['key']}-distribution-materials-" + origin["request_id"] + "-" + str(origin["run_attempt"])
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
    previous_name = f"cm-{linux_native()['key']}-distribution-proofs-" + origin["request_id"] + "-" + str(origin["run_attempt"])
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
    worker.artifact_binding(record, artifact_id, f"cm-{linux_native()['key']}-distribution-proofs-" + os.environ["CM_REQUEST_ID"] +
        "-" + os.environ["GITHUB_RUN_ATTEMPT"], os.environ["CM_DISTRIBUTION_ARTIFACT_DIGEST"].removeprefix("sha256:"), int(os.environ["GITHUB_RUN_ID"]))
    jobs = worker.receipt_jobs("repos/" + policy["builder_repository"] + "/actions/runs/" + os.environ["GITHUB_RUN_ID"] +
        "/attempts/" + os.environ["GITHUB_RUN_ATTEMPT"] + "/jobs?per_page=100", ["attest-distribution"])
    destination = Path(os.environ["CM_CONSUMER_INPUT_DIR"]) / "fixture/s01-proofs"
    artifact_download(policy, record, destination)
    assert read(destination / "authority.json")["production_origin"] == worker.production_origin()
    assert (destination / "bundle.jsonl").is_file()
    prepare_bootstrap(Path(os.environ["CM_CONSUMER_INPUT_DIR"]))
    write(Path(os.environ["CM_CI_LOG_DIR"]) / "distribution-artifact.json", {"artifact": record, "jobs": jobs,
        "signature_gate": "offline consumer must still verify"})


def prepare_bootstrap(inputs):
    policy = read(Path(__file__).resolve().parent / "distribution-policy.json")
    bootstrap = inputs / "fixture/s01-bootstrap"
    bootstrap.mkdir()
    pin = policy["verifier"]
    try:
        archive = fetch(pin["url"], 128 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        if error.code not in (502, 503, 504):
            raise
        error.close()
        # The independent consumer can retry a distinct CDN key without changing producer recipes.
        print("CM bootstrap: retry the pinned verifier through the alternate CDN key", flush=True)
        archive = fetch(pin["url"] + "?download=1", 128 * 1024 * 1024)
    assert hashlib.sha256(archive).hexdigest() == pin["archive_sha256"]
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
        member = stream.getmember(pin["archive"].removesuffix(".tar.gz") + "/bin/gh")
        assert member.isfile() and member.size <= 128 * 1024 * 1024
        (bootstrap / "gh").write_bytes(stream.extractfile(member).read())
    (bootstrap / "gh").chmod(0o755)
    shutil.copyfile(Path(__file__).resolve().parent / "distribution-root.jsonl", bootstrap / "distribution-root.jsonl")
    write(bootstrap / "identity.json", {"archive_sha256": pin["archive_sha256"], "binary_sha256": sha(bootstrap / "gh"),
        "source": "independent reviewed worker pin; no candidate Host execution"})
    # Separate from the immutable producer manifest and from native dependency keys.
    import runtime_consumer as runtime
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
    import tempfile
    import runtime_consumer
    runtime_consumer.check_distribution_verifier_binding(Path(os.environ["CM_SOURCE_DIR"]))
    from types import SimpleNamespace
    from unittest import mock
    bootstrap_policy = read(Path(os.environ["CM_SOURCE_DIR"]) / POLICY_PATH)
    url = bootstrap_policy["verifier"]["url"]
    error = urllib.error.HTTPError(url, 504, "gateway timeout", {}, None)
    with tempfile.TemporaryDirectory() as directory, mock.patch(__name__ + ".read", return_value=bootstrap_policy), \
            mock.patch(__name__ + ".fetch", side_effect=[error, b"wrong archive"]) as request:
        inputs = Path(directory)
        (inputs / "fixture").mkdir()
        try:
            prepare_bootstrap(inputs)
        except AssertionError:
            pass
        else:
            raise AssertionError("Bootstrap fallback accepted a different archive")
        assert request.call_args_list == [mock.call(url, 128 * 1024 * 1024), mock.call(url + "?download=1", 128 * 1024 * 1024)]
    for error in (urllib.error.URLError(ConnectionResetError("reset")), TimeoutError("deadline"),
                  urllib.error.HTTPError("https://example.invalid/pinned", 503, "unavailable", {}, None)):
        with mock.patch("urllib.request.urlopen", side_effect=[error, io.BytesIO(b"pinned")]) as request, mock.patch("time.sleep") as pause:
            assert fetch("https://example.invalid/pinned") == b"pinned"
            assert request.call_count == 2
            pause.assert_called_once_with(5)
        with mock.patch("urllib.request.urlopen", side_effect=error) as request, mock.patch("time.sleep") as pause:
            try:
                fetch("https://example.invalid/pinned")
            except type(error):
                pass
            else:
                raise AssertionError("Persistent material download failure was accepted")
            assert request.call_count == 3 and pause.call_count == 2
    for error in (urllib.error.HTTPError("https://example.invalid/pinned", 404, "missing", {}, None),
                  urllib.error.URLError("certificate rejected")):
        with mock.patch("urllib.request.urlopen", side_effect=error) as request, mock.patch("time.sleep") as pause:
            try:
                fetch("https://example.invalid/pinned")
            except type(error):
                pass
            else:
                raise AssertionError("Permanent material download failure was accepted")
            assert request.call_count == 1 and pause.call_count == 0
    ci_policy = {"source_repository": "DSLZL/CM", "source_repository_id": 1430833890}
    ci_revision = "a" * 40
    ci_run = {"id": 1, "run_attempt": 1, "head_sha": ci_revision, "head_branch": "main",
        "status": "completed", "conclusion": "success", "event": "push",
        "path": ".github/workflows/cm-source-check.yml",
        "repository": {"id": 1430833890}, "head_repository": {"id": 1430833890}}
    ci_candidate = ci_run
    def ci_api(path):
        assert path == "repos/DSLZL/CM/actions/runs?head_sha=" + ci_revision + "&per_page=100"
        return {"workflow_runs": [ci_candidate]}
    ci_worker = SimpleNamespace(api=ci_api, receipt_jobs=lambda *args: [{"id": 2}])
    assert source_check(ci_worker, ci_policy, ci_revision)["run_id"] == 1
    for changed in ({"status": "in_progress"}, {"conclusion": "failure"},
        {"path": ".github/workflows/other.yml"}, {"head_sha": "b" * 40}):
        ci_candidate = ci_run | changed
        try:
            source_check(ci_worker, ci_policy, ci_revision)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Nonmatching source CI accepted")
    assert re.findall(COMMON_LICENSE_PATH, "See /usr/share/common-licenses/GPL. Also /usr/share/common-licenses/LGPL-2.1. "
        "(/usr/share/common-licenses/GPL-3), /usr/share/common-licenses/Apache-2.0; /usr/share/common-licenses/Unknown-1.0.") == [
        "/usr/share/common-licenses/GPL", "/usr/share/common-licenses/LGPL-2.1", "/usr/share/common-licenses/GPL-3",
        "/usr/share/common-licenses/Apache-2.0", "/usr/share/common-licenses/Unknown-1.0"]
    assert canonical({"b": 1, "a": "中"}) == '{"a":"中","b":1}'.encode()
    assert len(REPORTS) == len(set(REPORTS)) == 5
    declarations = ("Apache-2.0/MIT", "MIT OR Apache-2.0", "Apache-2.0 WITH LLVM-exception")
    packages = [{"name": "license-fixture-" + str(index), "version": "1", "source": "https://example.invalid/pinned",
        "roles": ["self-check"], "declared_license": declared, "licenses": [{"path": "LICENSE", "sha256": "0" * 64}]}
        for index, declared in enumerate(declarations)]
    document = sbom(Path("."), "self-check", packages, [], {"created_at": "2026-11-04T00:00:00Z"})
    assert [row["licenseDeclared"] for row in document["packages"][1:]] == ["Apache-2.0 OR MIT", *declarations[1:]]
    assert tuple(json.loads(row["comment"])["original_license_declaration"] for row in document["packages"][1:]) == declarations
    assert go_proxy_source("golang.org/x/sys", "v0.1.0") == "https://proxy.golang.org/golang.org/x/sys/@v/v0.1.0.zip"
    assert go_proxy_source("example.com/Azure/SDK", "v1.0.0-RC1") == "https://proxy.golang.org/example.com/!azure/!s!d!k/@v/v1.0.0-!r!c1.zip"
    import runtime_consumer
    runtime_consumer.check_distribution_verifier_binding(Path(os.environ["CM_SOURCE_DIR"]))
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
    valid = {"status": "completed", "head_sha": "a" * 40, "head_branch": "main", "conclusion": "success", "event": "push",
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
        (root / "sbom-file.txt").write_bytes(b"abc")
        checksum = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        document = sbom(root, "self-check", [], [{"path": "sbom-file.txt", "size": 3,
            "sha256": checksum, "source": "self-check", "components": ["self-check"]}],
            {"created_at": "2026-11-04T00:00:00Z"})
        assert document["files"][0]["fileName"] == "./sbom-file.txt"
        assert document["files"][0]["checksums"] == [
            {"algorithm": "SHA1", "checksumValue": "a9993e364706816aba3e25717850c26c9cd0d89d"},
            {"algorithm": "SHA256", "checksumValue": checksum}]
        materials = Path(temporary) / "materials"
        origin = {"created_at": "2026-11-04T00:00:00Z"}
        asset = {"path": "sbom-file.txt", "size": 3, "sha256": checksum,
            "source": {"repository": "DSLZL/CM", "sha": "a" * 40}, "components": ["SPDXRef-Package-0"]}
        producer = {"artifacts": {}, "production_origin": origin, "policy_sha256": checksum}
        license_data = "Fixture license\r\nUTF-8: 中\r\n".encode("utf-8")
        for name, declaration in zip(("cm-host", "sdk-a", "sdk-b"),
                ("Apache-2.0/MIT", "MIT OR Apache-2.0", "Apache-2.0 WITH LLVM-exception")):
            material = materials / name
            package_root = Path(temporary) / "license-source" / name
            license_directory = package_root / ("licenses/components" if name == "cm-host" else "")
            license_record = text_material(license_directory, "fixture-LICENSE", "https://example.invalid/fixed", license_data)
            (package_root / "sbom-file.txt").write_bytes(b"abc")
            component = {"name": "fixture", "version": "1.0.0", "source": "https://example.invalid/fixed",
                "roles": ["self-check"], "declared_license": declaration, "licenses": [license_record]}
            reference = {**component, "name": "license-ref-fixture", "declared_license": "LicenseRef-" + license_record["sha256"]}
            document = sbom(package_root, name, [component, reference], [asset], origin)
            assert document["hasExtractedLicensingInfos"][0]["extractedText"].encode("utf-8") == license_data
            if name == "sdk-b":
                document["files"][0]["checksums"].reverse()
            write(material / "sbom.spdx.json", document)
            write(material / "NOTICE.json", {"components": [component, reference], "assets": [asset],
                "license_texts": {license_record["sha256"]: license_text(license_directory / license_record["path"], package_root).decode("utf-8")},
                "native_licenses": []})
            write(material / "source.json", {"source": asset["source"]})
            write(material / "assets.json", [asset])
            draft = {"schema_version": 1, "domain": "cm.release-receipt.v1",
                "role": "host" if name == "cm-host" else "mod", "name": name, "version": "1.0.0",
                "target": linux_native()["target"], "source": {**asset["source"], "repository_id": 1430833890},
                "production_origin": origin, "contracts": {"self_check": True}, "policy_sha256": checksum,
                "artifact": {**{key: checksum for key in ("archive_sha256", "manifest_sha256", "payload_sha256")},
                    "archive_size": 3, "object_sha256": hashlib.sha256(canonical({"sbom-file.txt": [3, checksum]})).hexdigest()},
                "materials": {key: sha(material / path) for key, path in
                    (("sbom", "sbom.spdx.json"), ("notice", "NOTICE.json"), ("source", "source.json"))}}
            write(material / "draft.json", draft)
            producer["artifacts"][name] = {"draft_sha256": sha(material / "draft.json")}
        write(materials / "producer.json", producer)
        assert validate_materials(materials, policy) == producer
        material = materials / "sdk-b"
        document["files"][0]["checksums"] = [item for item in document["files"][0]["checksums"] if item["algorithm"] != "SHA1"]
        write(material / "sbom.spdx.json", document)
        draft["materials"]["sbom"] = sha(material / "sbom.spdx.json")
        write(material / "draft.json", draft)
        producer["artifacts"]["sdk-b"]["draft_sha256"] = sha(material / "draft.json")
        write(materials / "producer.json", producer)
        try:
            validate_materials(materials, policy)
        except AssertionError:
            pass
        else:
            raise AssertionError("Rehashed SPDX material without mandatory SHA1 accepted")
        (root / ".git").mkdir()
        (root / "LICENSE").write_text("shared pinned checkout license\n")
        (root / "Cargo.lock").write_text("version = 4\n")
        metadata = {"workspace_root": str(root), "packages": [], "resolve": {"nodes": []}}
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
        from unittest.mock import patch
        with patch("worker_policy.api", return_value={"tree": []}) as github_api:
            assert json.loads(fetch("https://api.github.com/repos/example/pinned/git/trees/" + "a" * 40)) == {"tree": []}
            github_api.assert_called_once_with("repos/example/pinned/git/trees/" + "a" * 40)
            try:
                fetch("https://api.github.com/repos/example/pinned", 1)
            except AssertionError:
                pass
            else:
                raise AssertionError("Unbounded GitHub material accepted")
        reuse_texts = root / "reuse-licenses"
        (reuse_texts / "LICENSES").mkdir(parents=True)
        (reuse_texts / "LICENSES/MIT.txt").write_text("actual source license text\n")
        assert [row["name"] for row in licenses(reuse_texts, root / "texts", "unit-fixture")] == ["LICENSES/MIT.txt"]
        package = next(row for row in metadata["packages"] if row["name"] == "shared")
        package.update(source="registry+https://github.com/rust-lang/crates.io-index", repository="https://github.com/example/pinned.git")
        directory = root / "shared"
        vcs_path = directory / ".cargo_vcs_info.json"
        vcs = {"git": {"sha1": "a" * 40}, "path_in_vcs": "crate"}
        write(vcs_path, vcs)
        crate_data = io.BytesIO()
        with tarfile.open(fileobj=crate_data, mode="w:gz") as archive:
            member = tarfile.TarInfo("shared-1.0.0/.cargo_vcs_info.json")
            member.size = len(canonical(vcs))
            archive.addfile(member, io.BytesIO(canonical(vcs)))
        crate = crate_data.getvalue()
        checksum = hashlib.sha256(crate).hexdigest()
        (root / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "shared"\nversion = "1.0.0"\nsource = '
            + json.dumps(package["source"]) + '\nchecksum = "' + checksum + '"\n')
        data = b"actual pinned license text\n"
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        tree = {"truncated": False, "tree": [
            {"path": "LICENSE.md", "type": "blob", "mode": "100644", "sha": blob},
            {"path": "unrelated/LICENSE", "type": "blob", "mode": "100644", "sha": blob}]}
        tree_url = "https://api.github.com/repos/example/pinned/git/trees/" + "a" * 40 + "?recursive=1"
        license_url = "https://raw.githubusercontent.com/example/pinned/" + "a" * 40 + "/LICENSE.md"
        def pinned_fetch(url, maximum=LIMIT):
            assert url in ("https://static.crates.io/crates/shared/shared-1.0.0.crate", tree_url, license_url), "License source used an unpinned or unrelated path"
            return canonical(tree) if url == tree_url else data if url == license_url else crate
        with patch(__name__ + ".fetch", side_effect=pinned_fetch):
            inherited = {row["name"]: row for row in cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")}
            assert inherited["shared"]["source_checksum"] == checksum
            assert [row["source"] for row in inherited["shared"]["licenses"]] == [license_url]
            assert inherited["shared"]["licenses"][0]["sha256"] == hashlib.sha256(data).hexdigest()
            with patch.dict(package, repository="https://github.com/example/pinned/tree/main/crate"):
                assert [row["source"] for row in registry_licenses(package, directory, root / "texts", checksum)] == [license_url]
            tree["tree"][0]["path"] = "LICENSES/MIT.txt"
            license_url = license_url.removesuffix("LICENSE.md") + "LICENSES/MIT.txt"
            assert [row["name"] for row in registry_licenses(package, directory, root / "texts", checksum)] == ["LICENSES/MIT.txt"]
            tree["tree"][0]["path"] = "LICENSE.md"
            license_url = license_url.removesuffix("LICENSES/MIT.txt") + "LICENSE.md"
            cache_home = root / "cargo-cache-fixture"
            cached_crate = cache_home / "registry/cache" / directory.parent.name / "shared-1.0.0.crate"
            cached_crate.parent.mkdir(parents=True)
            cached_crate.write_bytes(crate)
            def cached_fetch(url, maximum=LIMIT):
                assert not url.endswith(".crate"), "Locked Cargo archive was downloaded again"
                return pinned_fetch(url, maximum)
            with patch.dict(os.environ, CARGO_HOME=str(cache_home)), patch(__name__ + ".fetch", side_effect=cached_fetch):
                assert registry_licenses(package, directory, root / "texts", checksum)
                cached_crate.write_bytes(b"changed cached archive")
                try:
                    registry_licenses(package, directory, root / "rejected", checksum)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Changed Cargo download cache accepted")
            for invalid in ({"git": {"sha1": "main"}}, {"git": {"sha1": "a" * 40, "dirty": True}},
                            {"git": {"sha1": "a" * 40}, "path_in_vcs": "../escape"}):
                write(vcs_path, invalid)
                try:
                    registry_licenses(package, directory, root / "rejected", checksum)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Unpinned Cargo license source accepted")
            write(vcs_path, vcs)
            for invalid_tree in ({**tree, "truncated": True}, {**tree, "tree": [{**tree["tree"][0], "sha": "0" * 40}]},
                                 {**tree, "tree": tree["tree"][1:]}):
                with patch(__name__ + ".fetch", side_effect=lambda url, maximum=LIMIT: canonical(invalid_tree) if url == tree_url else pinned_fetch(url, maximum)):
                    try:
                        registry_licenses(package, directory, root / "rejected", checksum)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("Incomplete or mismatched pinned license accepted")
            write(vcs_path, {"git": {"sha1": "c" * 40}})
            try:
                registry_licenses(package, directory, root / "rejected", checksum)
            except AssertionError:
                pass
            else:
                raise AssertionError("Modified Cargo VCS pin accepted")
            write(vcs_path, vcs)
            declaration = b'[package]\nlicense = "MIT"\n'
            declaration_url = "https://raw.githubusercontent.com/example/pinned/" + "a" * 40 + "/crate/Cargo.toml"
            standard_url = "https://example.invalid/fixed/MIT.txt"
            notice_url = license_url.removesuffix("LICENSE.md") + "NOTICE"
            supplement_tree = {**tree, "tree": [tree["tree"][1], {**tree["tree"][0], "path": "NOTICE"}]}
            def supplement_fetch(url, maximum=LIMIT):
                if url == tree_url:
                    return canonical(supplement_tree)
                if url == declaration_url:
                    return declaration
                return data if url in (standard_url, notice_url) else pinned_fetch(url, maximum)
            supplement_pin = ("example/pinned", "shared", "1.0.0", checksum, "a" * 40)
            with patch.dict(CARGO_LICENSE_SUPPLEMENTS, {supplement_pin: ("MIT", hashlib.sha256(declaration).hexdigest())}), \
                    patch(__name__ + ".SPDX_MIT_PIN", (standard_url, hashlib.sha256(data).hexdigest())), \
                    patch(__name__ + ".fetch", side_effect=supplement_fetch):
                texts = registry_licenses(package, directory, root / "texts", checksum)
                assert [row["name"] for row in texts] == ["NOTICE", "SPDX/MIT.txt"]
                assert texts[-1]["material_kind"] == "standard-license-supplement" and not texts[-1]["upstream_license_file_found"]
                assert texts[-1]["declared_license"] == "MIT" and texts[-1]["locked_source_checksum"] == checksum
                for changed_url in (declaration_url, standard_url, notice_url):
                    with patch(__name__ + ".fetch", side_effect=lambda url, maximum=LIMIT:
                            b"changed material" if url == changed_url else supplement_fetch(url, maximum)):
                        try:
                            registry_licenses(package, directory, root / "rejected", checksum)
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError("Changed supplement declaration, standard text or actual NOTICE accepted")
                with patch.dict(package, license="Apache-2.0"):
                    try:
                        registry_licenses(package, directory, root / "rejected", checksum)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("Changed upstream license declaration accepted")
                with patch.dict(CARGO_LICENSE_SUPPLEMENTS, {}, clear=True):
                    try:
                        registry_licenses(package, directory, root / "rejected", checksum)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("Unreviewed license supplement accepted")
            try:
                registry_licenses(package, directory, root / "rejected", "0" * 64)
            except AssertionError:
                pass
            else:
                raise AssertionError("Mismatched locked Cargo archive accepted")
            source_data = {"Cargo.toml.orig": b"[package]\n", "src/lib.rs": b"pub fn pinned() {}\n"}
            crate_data = io.BytesIO()
            with tarfile.open(fileobj=crate_data, mode="w:gz") as archive:
                for name, contents in source_data.items():
                    member = tarfile.TarInfo("shared-1.0.0/" + name)
                    member.size = len(contents)
                    archive.addfile(member, io.BytesIO(contents))
                    path = "crate/" + ("Cargo.toml" if name == "Cargo.toml.orig" else name)
                    tree["tree"].append({"path": path, "type": "blob", "mode": "100644",
                        "sha": hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()})
            unpinned_crate = crate_data.getvalue()
            vcs_path.unlink()
            with patch.dict(CARGO_LICENSE_PINS, {("example/pinned", "shared", "1.0.0"): ("a" * 40, "crate")}):
                try:
                    registry_licenses(package, directory, root / "rejected", checksum)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("Removed published Cargo VCS pin accepted")
                def reviewed_fetch(url, maximum=LIMIT):
                    return unpinned_crate if url.endswith(".crate") else pinned_fetch(url, maximum)
                with patch(__name__ + ".fetch", side_effect=reviewed_fetch):
                    actual_checksum = hashlib.sha256(unpinned_crate).hexdigest()
                    texts = registry_licenses(package, directory, root / "texts", actual_checksum)
                    assert [row["source"] for row in texts] == [license_url]
                    for dirty, repository, revision in ((False, None, "a" * 40),
                            (True, "https://github.com/example/pinned", "a" * 40),
                            (False, "https://github.com/example/pinned", "b" * 40)):
                        reviewed_vcs = {**vcs, "git": {"sha1": "a" * 40, "dirty": dirty}}
                        write(vcs_path, reviewed_vcs)
                        archive_data = io.BytesIO()
                        archive_sources = {**source_data, ".cargo_vcs_info.json": canonical(reviewed_vcs)}
                        if dirty:
                            archive_sources["native/unused.cc"] = b"separately built native source\n"
                            archive_sources["gen/src_binding_release_x86_64-unknown-linux-gnu.rs"] = b"published generated binding\n"
                            tree["tree"].append({"path": ".github/workflows/ci.yml", "type": "blob", "mode": "100644", "sha": "d" * 40})
                            tree["tree"].append({"path": "crate/native", "type": "commit", "mode": "160000", "sha": "c" * 40})
                        with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
                            for name, contents in archive_sources.items():
                                member = tarfile.TarInfo("shared-1.0.0/" + name)
                                member.size = len(contents)
                                archive.addfile(member, io.BytesIO(contents))
                        reviewed_crate = archive_data.getvalue()
                        reviewed_checksum = hashlib.sha256(reviewed_crate).hexdigest()
                        tree_url = tree_url.replace("a" * 40, revision)
                        license_url = license_url.replace("a" * 40, revision)
                        actual_binding_pin = CARGO_BINDING_SOURCE_PIN
                        with patch.dict(package, repository=repository), patch.dict(CARGO_LICENSE_REPOSITORIES,
                                {("shared", "1.0.0", reviewed_checksum): "https://github.com/example/pinned"}), \
                                patch.dict(CARGO_LICENSE_PINS, {("example/pinned", "shared", "1.0.0"): (revision, "crate")}), \
                                patch(__name__ + ".CARGO_BINDING_SOURCE_PIN", ("example/pinned", "shared", "1.0.0", reviewed_checksum, revision)
                                    if dirty else actual_binding_pin), \
                                patch(__name__ + ".fetch", side_effect=lambda url, maximum=LIMIT:
                                    reviewed_crate if url.endswith(".crate") else pinned_fetch(url, maximum)):
                            reviewed_texts = registry_licenses(package, directory, root / "texts", reviewed_checksum)
                            assert reviewed_texts
                            if dirty:
                                published = reviewed_texts[0]["published_crate_source"]
                                assert published["archive_sha256"] == reviewed_checksum
                                assert published["generated_bindings"] == [{"path": "crate/gen/src_binding_release_x86_64-unknown-linux-gnu.rs",
                                    "sha256": hashlib.sha256(archive_sources["gen/src_binding_release_x86_64-unknown-linux-gnu.rs"]).hexdigest(),
                                    "size": len(archive_sources["gen/src_binding_release_x86_64-unknown-linux-gnu.rs"])}]
                                with patch(__name__ + ".CARGO_BINDING_SOURCE_PIN", actual_binding_pin):
                                    try:
                                        registry_licenses(package, directory, root / "rejected", reviewed_checksum)
                                    except AssertionError:
                                        pass
                                    else:
                                        raise AssertionError("Unreviewed native source boundary accepted")
                            source_row = next(row for row in tree["tree"] if row["path"] == "crate/src/lib.rs")
                            original_blob = source_row["sha"]
                            source_row["sha"] = "0" * 40
                            try:
                                registry_licenses(package, directory, root / "rejected", reviewed_checksum)
                            except AssertionError:
                                pass
                            else:
                                raise AssertionError("Published source mismatch accepted for exceptional Cargo metadata")
                            source_row["sha"] = original_blob
                        if dirty:
                            tree["tree"].pop()
                            tree["tree"].pop()
                        tree_url = tree_url.replace(revision, "a" * 40)
                        license_url = license_url.replace(revision, "a" * 40)
                    vcs_path.unlink()
                    tree["tree"][-1]["sha"] = "0" * 40
                    try:
                        registry_licenses(package, directory, root / "rejected", actual_checksum)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("Published source mismatch accepted for reviewed Cargo pin")
            write(vcs_path, vcs)
        linked_license.write_text("self-check license text\n")
        metadata["packages"][0]["license"] = None
        metadata["packages"][1]["license"] = None
        try:
            cargo_components(metadata, {"a", "b"}, root / "texts", "unit-fixture")
        except AssertionError as error:
            prefix = "Cargo license collection blocked: "
            assert str(error).startswith(prefix)
            failures = json.loads(str(error).removeprefix(prefix))
            assert {row["id"] for row in failures} == {"a", "b"}, "License audit stopped at its first missing component"
        else:
            raise AssertionError("Unknown Cargo license accepted")
        for case in ("safe", "escape", "absolute", "hardlink", "device", "outside", "revision"):
            data = io.BytesIO()
            prefix = "ripgrep-" + RIPGREP_SOURCE_COMMIT
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                member = tarfile.TarInfo(prefix + "/pkg/brew")
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
                member = tarfile.TarInfo(("outside" if case == "outside" else prefix) + "/HomebrewFormula")
                member.type = tarfile.LNKTYPE if case == "hardlink" else tarfile.CHRTYPE if case == "device" else tarfile.SYMTYPE
                member.linkname = "../../escape" if case == "escape" else "/tmp/escape" if case == "absolute" else "pkg/brew"
                archive.addfile(member)
            try:
                source = ripgrep_source(data.getvalue(), root / ("ripgrep-source-" + case),
                    "0" * 40 if case == "revision" else RIPGREP_SOURCE_COMMIT)
            except AssertionError:
                assert case != "safe", "Reviewed internal ripgrep source link was rejected"
            else:
                assert case == "safe", "Unsafe or unreviewed ripgrep source archive accepted"
                assert (source / "HomebrewFormula").resolve() == source / "pkg/brew"
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
    {"attest-prepare": attest_prepare, "consume-proofs": consume_proofs, "cargo-audit": cargo_audit,
        "self-check": self_check}[sys.argv[1]]()
