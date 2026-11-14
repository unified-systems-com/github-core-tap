"""Every dimension key this plugin declares has a Dimension node with a fixed id (unified-systems-com/tap#711).

Dimension nodes are declared, never minted on the fly: once the dimension map keys by node id, a key
with no node is refused. The declared keys are read from the plugin's own source (every
``DEFAULT_DIMENSIONS`` assignment, resolving a module-level dict it names, and every edge's
``default_dimensions``), so a new key without a node fails here. The ids are pinned, because the
map stores them and a regenerated id would orphan every row that carries the old one.
"""

import ast
import json
import uuid
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent
SEED = PACKAGE / "grift" / "dimension.grift.json"
# Keys this plugin writes but does not own: their Dimension node ships with the owning plugin.
# git.host is git_core's (req-git-core-dimensions; domain/dimensions/git.host.md says so).
FOREIGN = {"git.host": ("git_core", "01a1d10a-eb22-7742-a0c1-5988c9d08db4")}  # git-core-tap#36
PINNED = {
    "github.observation": "01a1d10a-e9e7-71e3-bda0-59f5841ece12",
    "github.surface": "01a1d10a-e9e7-71e3-bda0-59f6cc777266",
}


def _dimension_nodes() -> list[dict]:
    doc = json.loads(SEED.read_text(encoding="utf-8"))
    return [n for batch in doc["batches"] for n in batch["nodes"] if n["entity"]["entity_type"] == "dimension"]


class UnresolvedDeclaration(AssertionError):
    """A DEFAULT_DIMENSIONS value this test cannot read exactly: fail closed, never guess empty."""


def _dict_keys(node: ast.AST, named: dict[str, list[ast.AST]], where: str) -> set[str]:
    if isinstance(node, ast.Dict):
        keys: set[str] = set()
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:  # {**OTHER, ...}
                keys |= _dict_keys(value, named, where)
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
            else:
                raise UnresolvedDeclaration(f"{where}: a non-literal dimension key")
        return keys
    if isinstance(node, ast.Name):
        bound = named.get(node.id, [])
        if len(bound) != 1:
            raise UnresolvedDeclaration(f"{where}: {node.id} has {len(bound)} module-level bindings in the package")
        return _dict_keys(bound[0], named, where)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        keys = set()
        for arg in node.args:
            keys |= _dict_keys(arg, named, where)
        for kw in node.keywords:
            if kw.arg is None:
                keys |= _dict_keys(kw.value, named, where)
            else:
                keys.add(kw.arg)
        return keys
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _dict_keys(node.left, named, where) | _dict_keys(node.right, named, where)
    raise UnresolvedDeclaration(f"{where}: unsupported DEFAULT_DIMENSIONS form {ast.dump(node)[:80]}")


def _refuse_mutation(node: ast.AST, where: str) -> None:
    """Only a bare ``DEFAULT_DIMENSIONS = ...`` is read. A mutation (a subscript, an attribute, an
    augmented assignment) could add a key unseen, so it fails instead."""
    if isinstance(node, ast.AugAssign):
        targets = [node.target]
    elif isinstance(node, ast.Assign):
        targets = node.targets
    else:
        return
    for target in targets:
        inner = target.value if isinstance(target, ast.Subscript) else target
        name = inner.attr if isinstance(inner, ast.Attribute) else getattr(inner, "id", None)
        if name == "DEFAULT_DIMENSIONS" and (isinstance(node, ast.AugAssign) or inner is not target or isinstance(inner, ast.Attribute)):
            raise UnresolvedDeclaration(f"{where}: DEFAULT_DIMENSIONS is mutated, not declared")


def _declared_keys() -> set[str]:
    sources = [p for p in PACKAGE.rglob("*.py") if "tests" not in p.parts and "migrations" not in p.parts]
    trees = {p: ast.parse(p.read_text(encoding="utf-8")) for p in sources}
    named: dict[str, list[ast.AST]] = {}
    for tree in trees.values():
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign | ast.AnnAssign) and stmt.value is not None:
                for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                    if isinstance(target, ast.Name) and target.id != "DEFAULT_DIMENSIONS":
                        named.setdefault(target.id, []).append(stmt.value)
    keys: set[str] = set()
    for path, tree in trees.items():
        for node in ast.walk(tree):
            _refuse_mutation(node, f"{path.relative_to(PACKAGE)}:{getattr(node, 'lineno', 0)}")
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == "DEFAULT_DIMENSIONS" for t in targets):
                    keys |= _dict_keys(node.value, named, f"{path.relative_to(PACKAGE)}:{node.lineno}")
    for edge in PACKAGE.rglob("*.edge.json"):
        keys |= set(json.loads(edge.read_text(encoding="utf-8")).get("default_dimensions") or {})
    return keys


def test_every_declared_key_has_a_dimension_node() -> None:
    names = {n["node"]["name"] for n in _dimension_nodes()}
    missing = _declared_keys() - names - set(FOREIGN)
    assert not missing, f"declared dimension keys with no Dimension node in {SEED.name}: {sorted(missing)}"


def test_the_seed_ids_are_pinned_uuid7s() -> None:
    nodes = _dimension_nodes()
    assert {n["node"]["name"]: n["entity"]["entity_id"] for n in nodes} == PINNED
    for node in nodes:
        assert uuid.UUID(node["entity"]["entity_id"]).version == 7, node["entity"]["entity_id"]
        assert node["entity"]["name"] == node["node"]["name"]
        assert node["node"]["description"].strip(), node


def test_an_unreadable_declaration_fails_closed() -> None:
    import pytest

    for source in ("make_dimensions()", "UNBOUND_NAME", "{**make_dimensions()}"):
        with pytest.raises(UnresolvedDeclaration):
            _dict_keys(ast.parse(source, mode="eval").body, {}, "probe")
    named = {"BASE": [ast.parse('{"a.b": "x"}', mode="eval").body]}
    assert _dict_keys(ast.parse('{**BASE, "c.d": "y"}', mode="eval").body, named, "probe") == {"a.b", "c.d"}


def test_a_foreign_key_is_declared_by_its_owner() -> None:
    """A key this plugin writes but does not own must have its node in the owning plugin's seed,
    under the id pinned here. The owner is a dependency, so its seed is read from the installed
    package; a release of the owner that predates its seed skips with the release it needs."""
    import importlib.util

    import pytest

    for key, (owner, node_id) in FOREIGN.items():
        spec = importlib.util.find_spec(f"tap_plugin.{owner}")
        assert spec is not None and spec.origin, f"{key}: owning plugin {owner} is not installed"
        seed = Path(spec.origin).parent / "grift" / "dimension.grift.json"
        if not seed.exists():
            pytest.skip(f"{owner} as installed ships no dimension seed yet; needs a release carrying git-core-tap#36")
        doc = json.loads(seed.read_text(encoding="utf-8"))
        owned = {n["node"]["name"]: n["entity"]["entity_id"] for b in doc["batches"] for n in b["nodes"]}
        assert owned.get(key) == node_id, f"{key}: {owner}'s seed has {owned.get(key)!r}, pinned {node_id}"


def test_a_mutated_declaration_fails_closed() -> None:
    import pytest

    for source in ('DEFAULT_DIMENSIONS["x.y"] = "z"', "DEFAULT_DIMENSIONS |= {}", 'Model.DEFAULT_DIMENSIONS = {"x.y": "z"}'):
        with pytest.raises(UnresolvedDeclaration):
            _refuse_mutation(ast.parse(source).body[0], "probe")
    _refuse_mutation(ast.parse('DEFAULT_DIMENSIONS = {"x.y": "z"}').body[0], "probe")
