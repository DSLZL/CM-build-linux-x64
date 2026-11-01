"""Stable runtime transactions and their bounded Python dependency closure."""
import ast
import hashlib
import json
from pathlib import Path

ENTRY_INVALID = ("short-prefix", "short-tail", "future-minor", "stride", "count", "null-array",
    "misaligned-array", "reserved", "descriptor-size", "descriptor-minor", "descriptor-reserved",
    "null-callback", "null-view", "huge-view", "utf8")
CALL_INVALID = ("callback-fail", "status", "cancelled", "increase", "zero", "keep-nonzero", "decision",
    "output-header", "output-reserved", "output-canary", "error-length", "error-null", "error-utf8", "error-canary")
SDK_INVALID = ("short-tail", "null-runtime", "runtime-short", "runtime-minor", "runtime-reserved",
    "null-dispatch", "null-cancel", "null-release", "null-array", "stride", "count", "reserved",
    "undeclared", "reserved-name", "foreign-owner", "duplicate-name", "duplicate-id", "invalid-utf8",
    "duplicate-route", "descriptor-short", "too-many")
MANIFEST_INVALID = ("version-conflict", "missing-dependency", "duplicate-dependency", "self-dependency",
    "bad-range", "capability", "api", "abi", "entry", "cpu", "system", "target", "script", "source-only",
    "state-owner", "digest", "duplicate-id", "conflict", "missing-payload", "ordinary-executable",
    "zip-executable", "directory-link", "directory-hardlink", "directory-special")
ZIP_INVALID = ("traversal", "absolute", "backslash", "depth", "duplicate", "file-directory", "symlink",
    "special", "encrypted", "method", "crc", "truncated", "local-name", "size", "entry-limit",
    "implicit-entry-limit", "entry-byte-limit", "attachment-byte-limit", "total-byte-limit")
CONFIG_INVALID = ("unknown-key", "wrong-type", "unknown-schema", "required", "abi1-config",
    "invalid-selection", "missing-effective-required", *("cli-" + str(index) for index in range(6)))
GROUPS = {
    "p04": ("states", "limits",
        *("startup-" + name for name in ("conflict", "dependency", "abi", "target", "capability", "payload",
            "resource", "backend", "init-fail", *ENTRY_INVALID)),
        *("packages-" + name for name in ("missing-helper", "damaged-package", "missing-inventory")),
        *("callbacks-" + name for name in CALL_INVALID)),
    "m01": ("configured", "order", "exact", "dependencies", "lock", "mixed", "remote",
        *("rejections-" + name for name in MANIFEST_INVALID), *("zip-" + name for name in ZIP_INVALID),
        *("config-" + name for name in CONFIG_INVALID)),
    "m02": ("authoring", "embedded", "stdio", "restart",
            *("rejections-" + name for name in (*SDK_INVALID, "manifest-reserved", "manifest-name-collision")),
            *("cancel-" + mode for mode in ("async", "sync-cancel", "cancel", "late", "noncooperative", "timeout")),
            *("error-" + mode for mode in ("lifecycle-error", "turn-error", "context-error", "tool-error",
                "callback-error", "panic", "stop-error", "release-error", "bounds"))),
    "m03": ("install", "process", "terminal", "live", "rejections", "legacy", "writers", "backends"),
    "m04": ("query", "restart", "rollback", "interruption", "stdio", "terminal", "ownership"),
    "m05": ("update", "failures", "metadata", "commands"),
}
DRIVERS = {"p04": "fixtures/runtime-consumer/driver.py", "m01": "ci/scripts/mod_manifest.py",
           "m02": "fixtures/runtime-sdk/driver.py", "m03": "fixtures/managed-package/driver.py",
           "m04": "fixtures/state/driver.py", "m05": "fixtures/mod-author/driver.py"}
MODULES = {**{name: "ci/scripts/" + name + ".py" for name in
    ("mod_manifest", "runtime_sdk", "managed_package", "runtime_state", "mod_author",
     "turn_budget", "review_before_send", "tool_concurrency", "runtime_cases")},
    "core": "fixtures/native-loader/core_acceptance.py", "core_acceptance": "fixtures/native-loader/core_acceptance.py",
    "tool_barrier": "fixtures/native-loader/tool_barrier.py"}
DYNAMIC = {"sdk": DRIVERS["m02"], "m": DRIVERS["m03"], "packages": "ci/scripts/mod_manifest.py",
           "budget": "fixtures/turn-budget/driver.py", "review": "fixtures/review-before-send/driver.py"}
PROTOCOL = 2


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def labels():
    return {phase + "-" + case: (phase, case) for phase, cases in GROUPS.items() for case in cases}


def function(case):
    prefix = case.split("-", 1)[0]
    return "case_" + (prefix if prefix in {"startup", "packages", "callbacks", "rejections", "zip", "config",
        "cancel", "error"} else case.replace("-", "_"))


def enter(namespace, phase, case):
    assert case in GROUPS[phase]
    originals = namespace.setdefault("_case_roots", {key: namespace[key] for key in
        ("WORK", "PROFILE", "EVIDENCE", "OFFICIAL_PROFILE", "COPY") if key in namespace})
    for key, base in originals.items():
        if key in ("WORK", "PROFILE", "EVIDENCE"):
            namespace[key] = Path({"WORK": "/work", "PROFILE": "/profile", "EVIDENCE": "/evidence"}[key]) / phase / case
        else:
            namespace[key] = Path("/work") / phase / case / base.relative_to(originals["WORK"])
    for key in ("WORK", "PROFILE", "EVIDENCE"):
        namespace[key].parent.mkdir(parents=True, exist_ok=True)


def finish(phase, case, reports, report_names):
    assert case in GROUPS[phase] and len(reports) == len(report_names)
    directory = Path("/evidence") / phase / case
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "reports.json").write_text(json.dumps({"status": "behavior_pass", "reports": dict(zip(report_names, reports))},
        sort_keys=True, indent=2) + "\n")
    (directory / "suite.json").write_text(json.dumps({"status": "pass", "phase": phase, "case": case}) + "\n")


def merge(left, right):
    if isinstance(left, dict) and isinstance(right, dict):
        result = dict(left)
        for key, value in right.items():
            result[key] = merge(result[key], value) if key in result else value
        return result
    if isinstance(left, list) and isinstance(right, list):
        return left + right
    assert left == right, "Conflicting independent report fields"
    return left


def aggregate(evidence, phase, report_names):
    reports = {name: {} for name in report_names}
    for case in GROUPS[phase]:
        directory = evidence / phase / case
        assert json.loads((directory / "suite.json").read_text())["status"] == "pass"
        row = json.loads((directory / "reports.json").read_text())
        assert row["status"] == "behavior_pass" and set(row["reports"]) == set(report_names)
        for name, fields in row["reports"].items():
            reports[name] = merge(reports[name], fields)
    for name, fields in reports.items():
        (evidence / name).write_text(json.dumps({"status": "behavior_pass", **fields}, sort_keys=True, indent=2) + "\n")
    directory = evidence if phase == "p04" else evidence / phase
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "suite.json").write_text(json.dumps({"status": "pass", "reports": list(report_names),
        "cases": list(GROUPS[phase]), "release_ready": False}) + "\n")


class Business(ast.NodeTransformer):
    """Progress output has no business effect; assertions and audit code remain."""
    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call):
            call = node.value.func
            if isinstance(call, ast.Attribute) and isinstance(call.value, ast.Name) and call.value.id == "ci_progress":
                return None
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        node.decorator_list = [item for item in node.decorator_list if not (
            isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
            and isinstance(item.func.value, ast.Name) and item.func.value.id == "ci_progress")]
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


def bindings(module):
    result = {}
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for item in ast.walk(target):
                    if isinstance(item, ast.Name):
                        result[item.id] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for item in node.names:
                result[item.asname or item.name.split(".")[0]] = node
    return result


def closure(texts, entries, dispatch=None):
    dispatch = dispatch or {}
    class Dispatch(ast.NodeTransformer):
        def __init__(self, function):
            self.function = function
        def visit_Call(self, node):
            if (isinstance(node.func, ast.Subscript) and isinstance(node.func.value, ast.Call)
                    and isinstance(node.func.value.func, ast.Name) and node.func.value.func.id == "globals"):
                node.func = ast.Name(id=self.function, ctx=ast.Load())
            return self.generic_visit(node)
    modules = {path: Business().visit(ast.parse(text)) for path, text in texts.items()}
    for path, selected in dispatch.items():
        for node in modules[path].body:
            if isinstance(node, ast.FunctionDef) and node.name == "matrix":
                Dispatch(selected).visit(node)
    tables = {path: bindings(module) for path, module in modules.items()}
    for path, selected in dispatch.items():
        assert isinstance(tables[path].get(selected), (ast.FunctionDef, ast.AsyncFunctionDef)), "Undeclared runtime case"
    dependencies, reasons, pending, visited = {}, [], list(entries), set()

    def fallback(path, reason):
        reasons.append(path + ": " + reason)
        dependencies[path + ":<module-fallback>"] = digest(ast.dump(modules[path], include_attributes=False))

    def inherited(path, cls, method):
        def target(expression):
            if isinstance(expression, ast.Name):
                value = tables[path].get(expression.id)
                if isinstance(value, ast.ClassDef):
                    return path, expression.id
                if isinstance(value, ast.Assign):
                    return target(value.value)
                return MODULES.get(expression.id) or DYNAMIC.get(expression.id)
            if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
                if expression.func.id == "sdk_module":
                    return DRIVERS["m02"]
                if (expression.func.id == "module" and expression.args and
                        isinstance(expression.args[0], ast.Constant) and isinstance(expression.args[0].value, str)):
                    return "fixtures/" + expression.args[0].value
            if isinstance(expression, ast.Attribute):
                parent = target(expression.value)
                if isinstance(parent, str) and isinstance(tables.get(parent, {}).get(expression.attr), ast.ClassDef):
                    return parent, expression.attr
            return None
        for base in cls.bases:
            selected = target(base)
            if isinstance(selected, tuple):
                pending.append((selected[0], selected[1] + "." + method))
            elif not (isinstance(base, ast.Name) and base.id in ("object", "Exception", "RuntimeError")):
                for selected_path in tables:
                    fallback(selected_path, "unresolved class base in " + path + ":" + cls.name)

    while pending:
        path, name = pending.pop()
        if (path, name) in visited:
            continue
        visited.add((path, name))
        table = tables[path]
        owner, dot, method = name.partition(".")
        original = table.get(owner)
        assert original is not None, "Undeclared runtime entry: " + path + ":" + name
        node = original
        if dot:
            assert isinstance(node, ast.ClassDef)
            node = next((item for item in node.body if getattr(item, "name", None) == method), None)
            if node is None:
                inherited(path, original, method)
                continue
        elif isinstance(node, ast.ClassDef):
            pending.append((path, name + ".__init__"))
            node = ast.ClassDef(name=node.name, bases=node.bases, keywords=node.keywords,
                decorator_list=node.decorator_list, body=[item for item in node.body if not isinstance(item,
                    (ast.FunctionDef, ast.AsyncFunctionDef))])
        dependencies[path + ":" + name] = digest(ast.dump(node, include_attributes=False))
        aliases = dict(MODULES)
        aliases.update(DYNAMIC)
        for imported in [*modules[path].body, *ast.walk(node)]:
            if isinstance(imported, ast.Import):
                for item in imported.names:
                    target = MODULES.get(item.name)
                    if target:
                        aliases[item.asname or item.name] = target
            elif isinstance(imported, ast.ImportFrom) and imported.module in MODULES:
                for item in imported.names:
                    if item.name == "*":
                        fallback(path, "wildcard import")
                    else:
                        aliases[item.asname or item.name] = (MODULES[imported.module], item.name)
        classes = {key: (path, key) for key, value in table.items() if isinstance(value, ast.ClassDef)}
        for variable in ("client", "test", "running", "restarted"):
            classes[variable] = (DRIVERS["m02"], "Client")
        for variable in ("provider", "service", "replacement"):
            classes[variable] = (path if "Provider" in table else DRIVERS["m02"], "Provider")
        if dot:
            classes["self"] = (path, owner)

        def resolve(expression):
            if isinstance(expression, ast.Name):
                return classes.get(expression.id) or aliases.get(expression.id)
            if isinstance(expression, ast.Call):
                if isinstance(expression.func, ast.Name):
                    factory = expression.func.id
                    if factory == "module":
                        if expression.args and isinstance(expression.args[0], ast.Constant) and isinstance(expression.args[0].value, str):
                            target = "fixtures/" + expression.args[0].value
                            assert target in tables, "Unknown controlled driver module"
                            return target
                        for target in tables:
                            if target.startswith("fixtures/") and target.endswith("/driver.py"):
                                fallback(target, "dynamic module argument")
                    if factory == "sdk_module":
                        return DRIVERS["m02"]
                    if factory == "driver":
                        return next((DRIVERS[phase] for phase in DRIVERS
                            if path == "ci/scripts/" + {"m02": "runtime_sdk", "m03": "managed_package",
                                "m04": "runtime_state", "m05": "mod_author"}.get(phase, "") + ".py"), None)
                return resolve(expression.func)
            if isinstance(expression, ast.Attribute):
                target = resolve(expression.value)
                if isinstance(target, str) and target in tables:
                    member = tables[target].get(expression.attr)
                    if isinstance(member, (ast.Import, ast.ImportFrom)):
                        for item in member.names:
                            if (item.asname or item.name) == expression.attr:
                                return MODULES.get(item.name)
                    if isinstance(member, ast.ClassDef):
                        return (target, expression.attr)
                if isinstance(target, tuple):
                    return target
            return None

        for item in ast.walk(node):
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                target = resolve(item.value)
                names = item.targets if isinstance(item, ast.Assign) else [item.target]
                for assigned in names:
                    if isinstance(assigned, ast.Name) and target:
                        (aliases if isinstance(target, str) else classes)[assigned.id] = target
        for item in ast.walk(node):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) and item.id in table:
                target = aliases.get(item.id)
                pending.append((path, item.id))
                if isinstance(target, tuple):
                    pending.append(target)
            if isinstance(item, ast.Attribute):
                if (dot and isinstance(item.value, ast.Call) and isinstance(item.value.func, ast.Name)
                        and item.value.func.id == "super"):
                    inherited(path, original, item.attr)
                target = resolve(item.value)
                if isinstance(target, str) and target in tables and item.attr in tables[target]:
                    pending.append((target, item.attr))
                elif isinstance(target, tuple):
                    target_path, class_name = target
                    if isinstance(tables.get(target_path, {}).get(class_name), ast.ClassDef):
                        pending.append((target_path, class_name + "." + item.attr))
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id in ("eval", "exec", "getattr", "__import__"):
                for target in tables:
                    fallback(target, "dynamic namespace/member lookup in " + path + ":" + name)
    return {"dependencies": dict(sorted(dependencies.items())), "conservative_reasons": sorted(set(reasons))}

def self_check():
    texts = {"a.py": "UNUSED=1\nUSED=2\ndef other():return UNUSED\ndef entry():return USED\n"}
    original = closure(texts, [("a.py", "entry")])
    assert original == closure({"a.py": texts["a.py"].replace("UNUSED=1", "UNUSED=9")}, [("a.py", "entry")])
    assert original != closure({"a.py": texts["a.py"].replace("USED=2", "USED=9")}, [("a.py", "entry")])
    assert original == closure({"a.py": texts["a.py"].replace("return USED", 'ci_progress.emit("heartbeat", "running")\n return USED')},
                               [("a.py", "entry")])
    protocol_output = {"a.py": 'def entry():print("protocol-reply")\n'}
    assert closure(protocol_output, [("a.py", "entry")]) != closure({
        "a.py": protocol_output["a.py"].replace("protocol-reply", "different-reply")}, [("a.py", "entry")])
    texts = {"ci/scripts/mod_manifest.py": "VALUE=1\ndef helper():return VALUE\ndef unused():return 0\n",
             "b.py": "import mod_manifest as mm\ndef entry():return mm.helper()\n"}
    original = closure(texts, [("b.py", "entry")])
    changed = dict(texts)
    changed["ci/scripts/mod_manifest.py"] = changed["ci/scripts/mod_manifest.py"].replace("VALUE=1", "VALUE=2")
    assert original != closure(changed, [("b.py", "entry")])
    changed["ci/scripts/mod_manifest.py"] = texts["ci/scripts/mod_manifest.py"].replace("return 0", "return 1")
    assert original == closure(changed, [("b.py", "entry")])
    imported = {"a.py": "from math import ceil as operation\ndef entry():return operation(1.2)\n"}
    assert closure(imported, [("a.py", "entry")]) != closure({
        "a.py": imported["a.py"].replace("import ceil", "import floor")}, [("a.py", "entry")])
    assert merge({"rows": [1]}, {"rows": [2], "pass": True}) == {"rows": [1, 2], "pass": True}
    assert len(labels()) == sum(map(len, GROUPS.values()))
    classes = {"c.py": "class C:\n def __init__(self):pass\n def used(self):return 1\n def unused(self):return 0\ndef entry():\n c=C()\n return c.used()\n"}
    selected = closure(classes, [("c.py", "entry")])
    assert selected == closure({"c.py": classes["c.py"].replace("return 0", "return 9")}, [("c.py", "entry")])
    assert selected != closure({"c.py": classes["c.py"].replace("return 1", "return 9")}, [("c.py", "entry")])
    inherited_text = {"base.py": "class Parent:\n def used(self):return 1\n def unused(self):return 0\nclass Child(Parent):pass\ndef entry():\n c=Child()\n return c.used()\n"}
    selected = closure(inherited_text, [("base.py", "entry")])
    assert selected != closure({"base.py": inherited_text["base.py"].replace("return 1", "return 9")},
        [("base.py", "entry")])
    assert selected == closure({"base.py": inherited_text["base.py"].replace("return 0", "return 9")},
        [("base.py", "entry")])
    unknown = {"a.py": "def entry():return eval('1')\n"}
    assert closure(unknown, [("a.py", "entry")])["conservative_reasons"]