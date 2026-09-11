#!/usr/bin/env python3
"""
specgraph — deterministic requirements graph generator + validator for the Opslifyd spec.

Parses every feature file (spec/phases/*/features/F*.md) and every inline feature
(### F*. headings inside spec/phases/*/README.md), extracts the dependency data that
already lives in the specs (id, phase, status, owner, Depends on, Blocks), and emits:

  - spec/graph.json   machine-readable graph the orchestrator reads (single source of truth)
  - spec/graph.mmd    Mermaid dependency diagram for humans

It then VALIDATES and exits non-zero on any of:
  - dependency cycle
  - a `Depends on:` pointing at a feature id that does not exist (dangling)
  - a `Blocks:` pointing at a feature id that does not exist
  - a blocks/depends asymmetry (A blocks B but B does not depend on A) -> warning, not fatal

Nothing is remembered by a model. The graph is regenerated from the files every run,
so agents ground on exact, current requirements instead of recall.

Usage:
    python3 spec/tools/specgraph.py            # generate + validate (run from repo root)
    python3 spec/tools/specgraph.py --check    # validate only, no file writes (CI mode)
"""

from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # .../opslifyd
SPEC = REPO / "spec"
PHASES = SPEC / "phases"

FEATURE_ID = re.compile(r"\bF\d+\.\d+\b")
PHASE_TOKEN = re.compile(r"\bP\d+\b")
H1 = re.compile(r"^#\s+(F\d+\.\d+)\s*[—-]\s*(.+?)\s*$")
H3 = re.compile(r"^###\s+(F\d+\.\d+)\s*[—-]\s*(.+?)\s*$")
FOLDER = re.compile(r"^p(\d+)-")


def field(text: str, name: str) -> str | None:
    """Extract `**Name:** value` up to the next ` · ` separator or end of line."""
    m = re.search(rf"\*\*{re.escape(name)}:\*\*\s*(.+?)(?:\s+·\s+|\n|$)", text)
    return m.group(1).strip() if m else None


def tokens(value: str | None) -> tuple[list[str], list[str]]:
    """Return (feature_ids, phase_ids) found in a Depends/Blocks value. 'none' -> empty."""
    if not value or value.strip().lower() == "none":
        return [], []
    return FEATURE_ID.findall(value), PHASE_TOKEN.findall(value)


def phase_of_folder(p: Path) -> str | None:
    m = FOLDER.match(p.name)
    return f"P{int(m.group(1))}" if m else None


def parse_feature_file(path: Path, phase: str) -> dict:
    text = path.read_text(encoding="utf-8")
    first_lines = text.splitlines()
    fid = title = None
    for ln in first_lines[:5]:
        m = H1.match(ln)
        if m:
            fid, title = m.group(1), m.group(2)
            break
    if not fid:
        raise ValueError(f"{path}: no `# Fx.y — title` H1 found")
    header = "\n".join(first_lines[:12])  # metadata line lives near the top
    dep_f, dep_p = tokens(field(header, "Depends on"))
    blk_f, blk_p = tokens(field(header, "Blocks"))
    return {
        "id": fid,
        "phase": field(header, "Phase") or phase,
        "title": title,
        "status": (field(header, "Status") or "todo").lower(),
        "owner": field(header, "Owner") or "",
        "depends_on": dep_f,
        "depends_on_phases": dep_p,
        "blocks": blk_f,
        "blocks_phases": blk_p,
        "source": str(path.relative_to(REPO)),
        "detailed": True,
    }


def parse_phase_readme(path: Path, phase: str) -> tuple[dict, list[dict]]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    header = "\n".join(lines[:6])
    pdep_f, pdep_p = tokens(field(header, "Depends on"))
    phase_meta = {
        "phase": phase,
        "depends_on": pdep_f,
        "depends_on_phases": pdep_p,
        "source": str(path.relative_to(REPO)),
    }
    inline: list[dict] = []
    for ln in lines:
        m = H3.match(ln)
        if m:
            fid, title = m.group(1), m.group(2)
            inline.append({
                "id": fid,
                "phase": phase,
                "title": title,
                "status": "spec-level",       # not yet split into a detailed feature file
                "owner": "",
                "depends_on": list(pdep_f),   # inline features inherit the phase dependency
                "depends_on_phases": list(pdep_p),
                "blocks": [],
                "blocks_phases": [],
                "source": str(path.relative_to(REPO)),
                "detailed": False,
            })
    return phase_meta, inline


def build() -> tuple[list[dict], list[dict], dict]:
    nodes: dict[str, dict] = {}
    phase_meta: dict[str, dict] = {}

    for phase_dir in sorted(PHASES.iterdir()):
        if not phase_dir.is_dir():
            continue
        phase = phase_of_folder(phase_dir)
        if not phase:
            continue
        readme = phase_dir / "README.md"
        detailed_ids: set[str] = set()
        feat_dir = phase_dir / "features"
        if feat_dir.is_dir():
            for f in sorted(feat_dir.glob("F*.md")):
                node = parse_feature_file(f, phase)
                nodes[node["id"]] = node
                detailed_ids.add(node["id"])
        if readme.is_file():
            meta, inline = parse_phase_readme(readme, phase)
            phase_meta[phase] = meta
            for node in inline:
                # a detailed feature file overrides its inline stub
                if node["id"] not in detailed_ids and node["id"] not in nodes:
                    nodes[node["id"]] = node

    # expand phase-level dependencies into concrete feature edges
    by_phase: dict[str, list[str]] = {}
    for nid, n in nodes.items():
        by_phase.setdefault(n["phase"], []).append(nid)

    for n in nodes.values():
        expanded = set(n["depends_on"])
        for pth in n["depends_on_phases"]:
            expanded.update(by_phase.get(pth, []))
        expanded.discard(n["id"])
        n["depends_on_resolved"] = sorted(expanded)

    edges = [{"from": d, "to": n["id"]}                    # dependency -> dependent
             for n in nodes.values() for d in n["depends_on_resolved"]]
    return list(nodes.values()), edges, phase_meta


def validate(nodes: list[dict], edges: list[dict]) -> tuple[list[str], list[str]]:
    ids = {n["id"] for n in nodes}
    errors: list[str] = []
    warnings: list[str] = []

    for n in nodes:
        for d in n["depends_on"]:
            if d not in ids:
                errors.append(f"{n['id']} ({n['source']}): depends on unknown feature {d}")
        for b in n["blocks"]:
            if b not in ids:
                errors.append(f"{n['id']} ({n['source']}): blocks unknown feature {b}")

    # blocks/depends symmetry (advisory) — checked against RESOLVED deps so a
    # dependent that depends on the whole phase (e.g. "P0") is not flagged.
    dep = {n["id"]: set(n.get("depends_on_resolved", n["depends_on"])) for n in nodes}
    for n in nodes:
        for b in n["blocks"]:
            if b in ids and n["id"] not in dep.get(b, set()):
                warnings.append(f"{n['id']} blocks {b}, but {b} does not depend on {n['id']}")

    # cycle detection over resolved edges
    adj: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    for e in edges:
        if e["from"] in adj:
            adj[e["from"]].append(e["to"])
    WHITE, GREY, BLACK = 0, 1, 2
    color = {i: WHITE for i in adj}
    stack: list[str] = []

    def dfs(u: str) -> bool:
        color[u] = GREY
        stack.append(u)
        for v in adj[u]:
            if color[v] == GREY:
                i = stack.index(v)
                errors.append("dependency cycle: " + " -> ".join(stack[i:] + [v]))
                return True
            if color[v] == WHITE and dfs(v):
                return True
        stack.pop()
        color[u] = BLACK
        return False

    for i in adj:
        if color[i] == WHITE:
            if dfs(i):
                break
    return errors, warnings


def topo_order(nodes: list[dict], edges: list[dict]) -> list[str]:
    from collections import deque
    indeg = {n["id"]: 0 for n in nodes}
    adj: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    for e in edges:
        if e["from"] in adj and e["to"] in indeg:
            adj[e["from"]].append(e["to"])
            indeg[e["to"]] += 1
    q = deque(sorted(i for i, d in indeg.items() if d == 0))
    order: list[str] = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in sorted(adj[u]):
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    return order  # may be shorter than nodes if a cycle exists


def to_mermaid(nodes: list[dict], edges: list[dict]) -> str:
    by_phase: dict[str, list[dict]] = {}
    for n in nodes:
        by_phase.setdefault(n["phase"], []).append(n)
    out = ["flowchart LR"]
    for phase in sorted(by_phase):
        out.append(f'    subgraph {phase}')
        for n in sorted(by_phase[phase], key=lambda x: x["id"]):
            tag = "" if n["detailed"] else " ~"
            out.append(f'        {n["id"].replace(".", "_")}["{n["id"]}{tag}<br/>{n["title"]}"]')
        out.append("    end")
    for e in edges:
        out.append(f'    {e["from"].replace(".", "_")} --> {e["to"].replace(".", "_")}')
    out.append("")
    out.append("%% ~ marks a spec-level (inline) feature not yet split into a detailed file")
    return "\n".join(out)


def main() -> int:
    check_only = "--check" in sys.argv
    nodes, edges, phase_meta = build()
    errors, warnings = validate(nodes, edges)
    order = topo_order(nodes, edges)

    graph = {
        "generated_by": "spec/tools/specgraph.py",
        "note": "Deterministic — regenerated from spec files. Do not hand-edit.",
        "phases": phase_meta,
        "nodes": sorted(nodes, key=lambda n: n["id"]),
        "edges": edges,
        "topological_order": order,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
    }

    if not check_only:
        (SPEC / "graph.json").write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
        (SPEC / "graph.mmd").write_text(to_mermaid(nodes, edges) + "\n", encoding="utf-8")

    print(f"features: {len(nodes)}  edges: {len(edges)}")
    for w in warnings:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}")
    if errors:
        print("VALIDATION FAILED")
        return 1
    print("VALIDATION OK" + ("" if check_only else "  ->  wrote spec/graph.json, spec/graph.mmd"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
