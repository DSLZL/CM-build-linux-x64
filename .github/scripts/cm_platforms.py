"""Reviewed native targets; configured routing is separate from runtime qualification."""
import json
import os
from pathlib import Path
import re

CONFIG = ".github/cm-platforms.json"
SYSTEMS = {
    "linux": ("Linux", "unknown-linux-gnu", "elf", ".so", ""),
    "macos": ("macOS", "apple-darwin", "macho", ".dylib", ""),
    "windows": ("Windows", "pc-windows-msvc", "pe", ".dll", ".exe"),
}
ARCHES = {"x64": ("X64", "x86_64"), "arm64": ("ARM64", "aarch64")}


def load(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    value = json.loads((root / CONFIG).read_text(encoding="utf-8"))
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "source_repository", "default_platform", "cache_limit_bytes", "platforms"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["source_repository"] != "DSLZL/CM"
            or value["default_platform"] != "linux-x64"
            or type(value["cache_limit_bytes"]) is not int or value["cache_limit_bytes"] != 10_000_000_000):
        raise RuntimeError("Invalid reviewed platform policy")
    entries = value["platforms"]
    if not isinstance(entries, dict) or set(entries) != {system + "-" + arch for system in SYSTEMS for arch in ARCHES}:
        raise RuntimeError("Exactly the six reviewed native platforms are required")
    for key, entry in entries.items():
        system, arch = key.rsplit("-", 1)
        runner_os, suffix, binary_format, library_suffix, exe_suffix = SYSTEMS[system]
        runner_arch, cpu = ARCHES[arch]
        if (not isinstance(entry, dict) or set(entry) != {"repository", "runner", "runner_os", "runner_arch", "target", "format",
                         "library_suffix", "exe_suffix", "recipe", "enabled"}
                or entry["repository"] != "DSLZL/CM-build-" + key
                or (entry["runner_os"], entry["runner_arch"], entry["target"]) != (runner_os, runner_arch, cpu + "-" + suffix)
                or (entry["format"], entry["library_suffix"], entry["exe_suffix"]) != (binary_format, library_suffix, exe_suffix)
                or entry["recipe"] != system + "-recipe.yml"
                or not isinstance(entry["runner"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]+", entry["runner"])
                or type(entry["enabled"]) is not bool):
            raise RuntimeError("Invalid reviewed native platform: " + key)
    return value


def select(key=None, *, root=None, enabled=False):
    table = load(root)
    key = table["default_platform"] if key is None else key
    if not isinstance(key, str) or key not in table["platforms"]:
        raise RuntimeError("Unknown native platform: " + repr(key))
    entry = table["platforms"][key]
    if enabled and not entry["enabled"]:
        raise RuntimeError("Native platform is not enabled until its implementation is reviewed: " + key)
    return {"key": key, **entry}


def worker(*, root=None, enabled=True):
    table = load(root)
    repository = os.environ.get("GITHUB_REPOSITORY")
    matches = [key for key, entry in table["platforms"].items() if entry["repository"] == repository]
    if len(matches) != 1:
        raise RuntimeError("Product work requires its exact independent builder repository")
    entry = select(matches[0], root=root, enabled=enabled)
    if (os.environ.get("CM_PLATFORM", entry["key"]) != entry["key"]
            or os.environ.get("CM_TARGET", entry["target"]) != entry["target"]):
        raise RuntimeError("Requested platform/target differs from the fixed builder repository")
    return entry


def native_inputs(key=None, *, root=None):
    entry = select(key, root=root)
    # Repo, runner labels and enablement control dispatch, not compiler inputs.
    return {name: entry[name] for name in ("target", "format", "library_suffix", "exe_suffix")}


def title(entry):
    return entry["runner_os"] + " " + entry["key"].rsplit("-", 1)[1]


def self_check():
    from copy import deepcopy
    import tempfile
    from unittest.mock import patch

    table = load()
    default = select(enabled=True)
    assert default["key"] == "linux-x64" and title(default) == "Linux x64"
    for key, entry in table["platforms"].items():
        assert select(key)["target"] == entry["target"]
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": entry["repository"],
                "CM_PLATFORM": key, "CM_TARGET": entry["target"]}):
            assert worker(enabled=False)["key"] == key
            if entry["enabled"]:
                assert worker()["key"] == key
            else:
                try:
                    worker()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("An unimplemented native platform was enabled")
    invalid = [lambda: select("linux-arm"), lambda: select(""), lambda: select("../linux-x64"),
        lambda: select(["linux-x64"])]
    for changes in ({"GITHUB_REPOSITORY": "DSLZL/CM"}, {"GITHUB_REPOSITORY": "other/CM-build-linux-x64"},
            {"CM_PLATFORM": "windows-x64"}, {"CM_TARGET": "aarch64-unknown-linux-gnu"}):
        def reject_worker(changes=changes):
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": default["repository"],
                    "CM_PLATFORM": default["key"], "CM_TARGET": default["target"], **changes}):
                worker()
        invalid.append(reject_worker)
    for action in invalid:
        try:
            action()
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid native routing was accepted")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".github").mkdir()
        path = root / CONFIG
        original = native_inputs()
        changed = deepcopy(table)
        changed["platforms"]["macos-arm64"]["runner"] = "macos-27"
        path.write_text(json.dumps(changed), encoding="utf-8")
        assert native_inputs(root=root) == original
        assert native_inputs("linux-arm64", root=root) != original
        for mutate in (lambda value: value.update(cache_limit_bytes=20_000_000_000),
                lambda value: value["platforms"]["linux-x64"].update(repository="other/CM-build-linux-x64"),
                lambda value: value["platforms"]["linux-x64"].update(target="aarch64-unknown-linux-gnu"),
                lambda value: value["platforms"]["linux-x64"].update(enabled="true"),
                lambda value: value["platforms"].pop("windows-arm64")):
            candidate = deepcopy(table)
            mutate(candidate)
            path.write_text(json.dumps(candidate), encoding="utf-8")
            try:
                load(root)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Invalid platform table was accepted")
        for candidate in (None, [], {**table, "platforms": []}, {**table, "platforms": {
                **table["platforms"], "linux-x64": None}}):
            path.write_text(json.dumps(candidate), encoding="utf-8")
            try:
                load(root)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Malformed platform policy was accepted")
    # Administrative routing changes must not discard an otherwise identical Linux Host.
    import retry
    rows = b"100644 blob aaaa\t.github/cm-platforms.json\x00100644 blob bbbb\tci/scripts/cm_platforms.py\x00"
    recipe = "    env:\n      CM_TARGET: x86_64-unknown-linux-gnu\n    steps:\n"
    with patch("retry.git", return_value=rows), patch("retry.source", return_value=recipe):
        current = retry.product_inputs(Path("unused"), "current")
    with patch("retry.git", return_value=b""), patch("retry.source", return_value=recipe):
        assert retry.product_inputs(Path("unused"), "previous") == current
    with patch("retry.git", return_value=b"100644 blob cccc\tcrates/cm/src/lib.rs\x00"), \
            patch("retry.source", return_value=recipe):
        assert retry.product_inputs(Path("unused"), "changed-native") != current
