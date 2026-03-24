"""Graphviz DOT report generator."""
from __future__ import annotations

from pathlib import Path

from ..db import FactStore
from ..models import BoundaryType, Side, WiringStatus


def generate_dot(store: FactStore, output_path: Path,
                 boundary_type: str = "") -> str:
    """Generate a Graphviz DOT file of boundary surfaces."""
    surfaces = store.get_surfaces(boundary_type=boundary_type)

    lines = [
        'digraph boundary_map {',
        '    rankdir=LR;',
        '    node [shape=box, fontname="Courier", fontsize=10];',
        '    edge [fontname="Courier", fontsize=8];',
        '',
        '    subgraph cluster_userspace {',
        '        label="Userspace";',
        '        style=dashed;',
        '        color=blue;',
    ]

    us_nodes = set()
    k_nodes = set()

    for s in surfaces:
        if s.userspace_producer:
            node_id = _safe_id(f"us_{s.userspace_producer}")
            if node_id not in us_nodes:
                lines.append(
                    f'        {node_id} [label="{_truncate(s.userspace_producer, 30)}"];'
                )
                us_nodes.add(node_id)

    lines.extend([
        '    }',
        '',
        '    subgraph cluster_boundary {',
        '        label="Boundary Surface";',
        '        style=filled;',
        '        color=lightyellow;',
    ])

    for s in surfaces:
        node_id = _safe_id(f"surf_{s.name}")
        color = _status_color(s.status)
        lines.append(
            f'        {node_id} [label="{s.name}\\n[{s.status.value}]", '
            f'style=filled, fillcolor="{color}"];'
        )

    lines.extend([
        '    }',
        '',
        '    subgraph cluster_kernel {',
        '        label="Kernel";',
        '        style=dashed;',
        '        color=red;',
    ])

    for s in surfaces:
        if s.handler:
            node_id = _safe_id(f"k_{s.handler}")
            if node_id not in k_nodes:
                lines.append(
                    f'        {node_id} [label="{s.handler}"];'
                )
                k_nodes.add(node_id)

    lines.extend([
        '    }',
        '',
    ])

    # Edges
    for s in surfaces:
        surf_id = _safe_id(f"surf_{s.name}")
        if s.userspace_producer:
            us_id = _safe_id(f"us_{s.userspace_producer}")
            lines.append(f'    {us_id} -> {surf_id} [label="produces"];')
        if s.handler:
            k_id = _safe_id(f"k_{s.handler}")
            lines.append(f'    {surf_id} -> {k_id} [label="dispatches"];')

    lines.append('}')

    content = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(content)
    return content


def _safe_id(s: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in s)


def _truncate(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s


def _status_color(status: WiringStatus) -> str:
    colors = {
        WiringStatus.DECLARED: "white",
        WiringStatus.DEFINED: "lightyellow",
        WiringStatus.REGISTERED: "lightgreen",
        WiringStatus.STATICALLY_REACHABLE: "green",
        WiringStatus.DISPATCH_LINKED: "lightblue",
        WiringStatus.PARTIALLY_WIRED: "orange",
        WiringStatus.DEAD: "red",
        WiringStatus.MISMATCHED: "hotpink",
    }
    return colors.get(status, "white")
