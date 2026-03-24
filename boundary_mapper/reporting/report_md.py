"""Markdown report generator.

Enhanced with executive summary, top-N priority lists, action recommendations,
surface family summaries, and noise separation.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..db import FactStore
from ..models import (
    BoundarySurface, BoundaryType, Finding, FindingSeverity, WiringStatus,
)

SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def generate_report(store: FactStore, output_path: Path,
                    profile_name: str = "") -> str:
    """Generate a full boundary mapping report in markdown."""
    stats = store.stats()
    surfaces = store.get_surfaces()
    # Fetch ALL findings — the old limit=1000 silently dropped HIGH
    # severity findings when INFO findings filled the limit first.
    findings = store.get_findings(limit=50000)

    lines = []
    _h = lines.append

    _h(f"# Boundary Mapping Report — {profile_name or 'unknown'}")
    _h("")
    _h(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _h("")

    # ── A. Executive Summary ──
    _render_executive_summary(_h, stats, surfaces, findings)

    # ── B. Highest-Value Gaps ──
    _render_highest_value_gaps(_h, surfaces, findings)

    # ── C. Dead Public Surface Cleanup ──
    _render_dead_surface_cleanup(_h, surfaces, findings)

    # ── D. Intentional Kernel-Only Surfaces ──
    _render_kernel_only_surfaces(_h, surfaces)

    # ── E. Action Recommendation Summary ──
    _render_action_summary(_h, surfaces, findings)

    # ── F. Surface Family Summaries ──
    _render_family_summaries(_h, surfaces)

    # ── G. Internal Wiring Audit ──
    _render_internal_wiring(_h, findings)

    # ── G2. Consistency Problems ──
    _render_consistency(_h, findings)

    # ── H. All Boundary Surfaces (detail) ──
    _render_all_surfaces(_h, surfaces)

    # ── I. Findings by Severity ──
    _render_findings(_h, findings)

    # ── I. Noisy Low-Value Items ──
    _render_noisy_items(_h, findings)

    # ── J. Wiring Status Distribution ──
    _render_status_distribution(_h, surfaces)

    # ── Legend ──
    _h("## Evidence Legend")
    _h("")
    _h("- **Extraction methods:** `clang_ast` (AST-backed), "
       "`pattern_match` (regex), `heuristic` (inference), "
       "`build_system` (Kbuild), `runtime_trace` (observed)")
    _h("- **Confidence levels:** `high` (exact match), "
       "`medium` (strong pattern), `low` (heuristic), "
       "`speculative` (guess)")
    _h("")

    content = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(content)
    return content


# ─── Section renderers ───


def _render_executive_summary(_h, stats, surfaces, findings):
    _h("## Executive Summary")
    _h("")

    # Count substatus categories
    healthy = 0
    incomplete = 0
    kernel_only = 0
    dead_uapi = 0
    future_reserved = 0
    diagnostic = 0

    for s in surfaces:
        sub = s.properties.get("substatus", s.status.value)
        if sub.startswith("statically_reachable"):
            healthy += 1
        elif "kernel_only" in sub or "diagnostic" in sub:
            kernel_only += 1
        elif "future_reserved" in sub:
            future_reserved += 1
        elif "dead_uapi" in sub:
            dead_uapi += 1
        elif sub.startswith("dispatch_linked"):
            incomplete += 1
        elif sub == "declared":
            dead_uapi += 1
        else:
            incomplete += 1

    # Count finding severity distribution
    sev_counts = Counter(f.severity.value for f in findings)
    # Count noise (INFO + reserved/future categories)
    noise_count = sum(1 for f in findings if f.severity == FindingSeverity.INFO)
    actionable_count = sum(1 for f in findings
                          if f.severity in (FindingSeverity.HIGH,
                                            FindingSeverity.MEDIUM))

    _h(f"| Category | Count |")
    _h(f"|----------|-------|")
    _h(f"| Healthy (fully wired) | {healthy} |")
    _h(f"| Incomplete (dispatch-linked, missing userspace) | {incomplete} |")
    _h(f"| Intentional kernel-only / diagnostic | {kernel_only} |")
    _h(f"| Dead public UAPI (no dispatch) | {dead_uapi} |")
    _h(f"| Future reserved / planned | {future_reserved} |")
    _h(f"| Diagnostic-only stats | {diagnostic} |")
    _h(f"| **Total surfaces** | **{len(surfaces)}** |")
    _h("")
    _h(f"| Finding severity | Count |")
    _h(f"|-----------------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        _h(f"| {sev.upper()} | {sev_counts.get(sev, 0)} |")
    _h(f"| **Total findings** | **{len(findings)}** |")
    _h(f"| Actionable (HIGH+MEDIUM) | {actionable_count} |")
    _h(f"| Low-value noise (INFO) | {noise_count} |")
    _h("")


def _render_internal_wiring(_h, findings):
    _h("## Internal Wiring Audit")
    _h("")
    _h("Checks that code inside the module is properly connected: "
       "init chains, ops tables, registrations, exports, dead functions.")
    _h("")

    internal_cats = {
        "orphan_init": "Init functions not in init chain",
        "unregistered_ops_table": "Ops tables defined but not registered",
        "missing_ops_handler": "Ops table slots pointing to missing functions",
        "unbalanced_registration": "Register without matching unregister",
        "dead_function": "Functions with no detected callers",
        "export_without_def": "EXPORT_SYMBOL for non-existent functions",
    }

    internal_findings = [f for f in findings if f.category in internal_cats]

    if not internal_findings:
        _h("No internal wiring issues detected.")
        _h("")
        return

    # Summary table
    by_cat = defaultdict(list)
    for f in internal_findings:
        by_cat[f.category].append(f)

    _h("| Check | Findings | Severity |")
    _h("|-------|----------|----------|")
    for cat, label in internal_cats.items():
        fs = by_cat.get(cat, [])
        if not fs:
            _h(f"| {label} | 0 | — |")
        else:
            sevs = set(f.severity.value for f in fs)
            _h(f"| {label} | {len(fs)} | {', '.join(sorted(sevs))} |")
    _h("")

    # Detail for HIGH and MEDIUM internal findings
    important = [f for f in internal_findings
                 if f.severity in (FindingSeverity.HIGH, FindingSeverity.MEDIUM)]
    if important:
        _h("### Issues Requiring Attention")
        _h("")
        for f in important:
            icon = {"high": "🟠", "medium": "🟡"}.get(f.severity.value, "")
            _h(f"- {icon} **{f.title}** — `{f.recommendation}`")
            _h(f"  {f.description}")
            if f.evidence:
                ev = f.evidence[0]
                _h(f"  `{ev.file_path}:{ev.line_start}`")
            _h("")

    # Count dead functions separately (can be long)
    dead = by_cat.get("dead_function", [])
    if dead:
        _h(f"### Dead Functions ({len(dead)})")
        _h("")
        if len(dead) <= 20:
            _h("| Function | File | Line | Action |")
            _h("|----------|------|------|--------|")
            for f in dead:
                ev = f.evidence[0] if f.evidence else None
                fp = ev.file_path if ev else "?"
                ln = ev.line_start if ev else 0
                name = f.title.replace("Unreferenced function: ", "")
                _h(f"| `{name}` | {fp} | {ln} | `{f.recommendation}` |")
        else:
            _h(f"Found {len(dead)} unreferenced functions. "
               f"Top 20 shown, see findings for full list.")
            _h("")
            _h("| Function | File |")
            _h("|----------|------|")
            for f in dead[:20]:
                ev = f.evidence[0] if f.evidence else None
                name = f.title.replace("Unreferenced function: ", "")
                _h(f"| `{name}` | {ev.file_path if ev else '?'} |")
            _h(f"| ... +{len(dead) - 20} more | |")
        _h("")


def _render_consistency(_h, findings):
    _h("## Consistency Problems")
    _h("")
    _h("Issues that cause build failures, linker errors, or silent "
       "runtime bugs due to conflicting definitions across files.")
    _h("")

    consistency_cats = {
        "signature_mismatch": "Function signature mismatches across files",
        "duplicate_definition": "Same function defined in multiple .c files",
        "constant_redefinition": "#define with different values in different files",
        "struct_drift": "Struct/enum defined in multiple directories",
    }

    consistency_findings = [f for f in findings if f.category in consistency_cats]

    if not consistency_findings:
        _h("No consistency problems detected.")
        _h("")
        return

    by_cat = defaultdict(list)
    for f in consistency_findings:
        by_cat[f.category].append(f)

    _h("| Check | Findings | Severity |")
    _h("|-------|----------|----------|")
    for cat, label in consistency_cats.items():
        fs = by_cat.get(cat, [])
        if fs:
            sevs = set(f.severity.value for f in fs)
            _h(f"| {label} | {len(fs)} | {', '.join(sorted(sevs))} |")
        else:
            _h(f"| {label} | 0 | — |")
    _h("")

    # Show HIGH severity consistency issues in detail
    high = [f for f in consistency_findings
            if f.severity in (FindingSeverity.HIGH, FindingSeverity.MEDIUM)]
    if high:
        _h("### Conflicts Requiring Attention")
        _h("")
        for f in high[:30]:
            icon = {"high": "🔴", "medium": "🟡"}.get(f.severity.value, "")
            _h(f"- {icon} **{f.title}** — `{f.recommendation}`")
            _h(f"  {f.description}")
            if f.evidence:
                for ev in f.evidence[:3]:
                    _h(f"  `{ev.file_path}:{ev.line_start}`")
            _h("")
        if len(high) > 30:
            _h(f"... +{len(high) - 30} more")
            _h("")


def _render_highest_value_gaps(_h, surfaces, findings):
    _h("## Highest-Value Gaps")
    _h("")
    _h("Surfaces with the highest importance scores that are incomplete.")
    _h("")

    # Sort incomplete surfaces by importance_score descending
    incomplete = []
    for s in surfaces:
        sub = s.properties.get("substatus", "")
        score = s.properties.get("importance_score", 0)
        if sub in ("dispatch_linked_missing_userspace", "declared_only_dead_uapi"):
            incomplete.append(s)
    incomplete.sort(key=lambda s: s.properties.get("importance_score", 0),
                    reverse=True)

    if not incomplete:
        _h("No incomplete high-value surfaces found.")
        _h("")
        return

    _h("| # | Surface | Substatus | Family | Importance | Action |")
    _h("|---|---------|-----------|--------|------------|--------|")
    for i, s in enumerate(incomplete[:15], 1):
        p = s.properties
        _h(f"| {i} | {s.name} | {p.get('substatus', '?')} | "
           f"{p.get('family', '?')} | {p.get('importance_score', '?')}/10 | "
           f"`{p.get('recommended_action', '?')}` |")
    _h("")


def _render_dead_surface_cleanup(_h, surfaces, findings):
    _h("## Dead Public Surface Cleanup Candidates")
    _h("")
    _h("UAPI constants with no kernel dispatch — candidates for removal or gating.")
    _h("")

    dead = [s for s in surfaces
            if s.properties.get("substatus", "").startswith("declared_only")]
    dead.sort(key=lambda s: s.properties.get("importance_score", 0), reverse=True)

    if not dead:
        _h("No dead public surfaces found.")
        _h("")
        return

    # Group by bucket
    by_bucket = defaultdict(list)
    for s in dead:
        bucket = s.properties.get("bucket", "unknown")
        by_bucket[bucket].append(s)

    for bucket, surfs in sorted(by_bucket.items()):
        _h(f"### {bucket} ({len(surfs)})")
        _h("")
        _h("| Surface | Family | Importance | Action |")
        _h("|---------|--------|------------|--------|")
        for s in surfs:
            p = s.properties
            _h(f"| {s.name} | {p.get('family', '?')} | "
               f"{p.get('importance_score', '?')}/10 | "
               f"`{p.get('recommended_action', '?')}` |")
        _h("")


def _render_kernel_only_surfaces(_h, surfaces):
    _h("## Intentional Kernel-Only Surfaces")
    _h("")
    _h("Surfaces that are dispatch-linked but intentionally not exposed to "
       "userspace. These should not be treated as urgent gaps.")
    _h("")

    kernel_only = [s for s in surfaces
                   if s.properties.get("substatus", "") in (
                       "dispatch_linked_kernel_only",
                       "dispatch_linked_diagnostic",
                   )]

    if not kernel_only:
        _h("No kernel-only surfaces detected.")
        _h("")
        return

    _h("| Surface | Type | Family | Substatus |")
    _h("|---------|------|--------|-----------|")
    for s in kernel_only:
        p = s.properties
        _h(f"| {s.name} | {s.boundary_type.value} | "
           f"{p.get('family', '?')} | {p.get('substatus', '?')} |")
    _h("")


def _render_action_summary(_h, surfaces, findings):
    _h("## Action Recommendation Summary")
    _h("")

    # Count actions from surfaces
    action_counts = Counter()
    for s in surfaces:
        action = s.properties.get("recommended_action")
        if action:
            action_counts[action] += 1

    # Count actions from findings
    finding_action_counts = Counter()
    for f in findings:
        if f.recommendation:
            finding_action_counts[f.recommendation] += 1

    if not action_counts and not finding_action_counts:
        _h("No recommendations generated.")
        _h("")
        return

    _h("### Surface Actions")
    _h("")
    _h("| Action | Count |")
    _h("|--------|-------|")
    for action, count in action_counts.most_common():
        _h(f"| `{action}` | {count} |")
    _h("")

    _h("### Finding Recommendations")
    _h("")
    _h("| Recommendation | Count |")
    _h("|----------------|-------|")
    for action, count in finding_action_counts.most_common():
        _h(f"| `{action}` | {count} |")
    _h("")


def _render_family_summaries(_h, surfaces):
    _h("## Surface Family Summaries")
    _h("")

    # Group by boundary type
    by_type = defaultdict(list)
    for s in surfaces:
        by_type[s.boundary_type.value].append(s)

    for btype in ("genetlink", "setsockopt", "ioctl", "sysctl", "procfs"):
        surfs = by_type.get(btype, [])
        if not surfs:
            continue
        _h(f"### {btype.upper()} ({len(surfs)} surfaces)")
        _h("")

        # Sub-group by substatus
        by_sub = Counter()
        for s in surfs:
            by_sub[s.properties.get("substatus", s.status.value)] += 1

        _h("| Substatus | Count |")
        _h("|-----------|-------|")
        for sub, count in by_sub.most_common():
            _h(f"| {sub} | {count} |")
        _h("")

        # For sockopts, also show by family
        if btype == "setsockopt":
            by_fam = Counter()
            for s in surfs:
                by_fam[s.properties.get("family", "unknown")] += 1
            _h("| Sockopt Family | Count |")
            _h("|---------------|-------|")
            for fam, count in by_fam.most_common():
                _h(f"| {fam} | {count} |")
            _h("")


def _render_all_surfaces(_h, surfaces):
    _h("## All Boundary Surfaces")
    _h("")

    by_type = defaultdict(list)
    for s in surfaces:
        by_type[s.boundary_type.value].append(s)

    for btype, surfs in sorted(by_type.items()):
        _h(f"### {btype.upper()} ({len(surfs)} surfaces)")
        _h("")
        _h("| Surface | Status | Substatus | Handler | "
           "Importance | Action |")
        _h("|---------|--------|-----------|---------|"
           "-----------|--------|")
        for s in sorted(surfs, key=lambda x: (
                -x.properties.get("importance_score", 0), x.name)):
            icon = _status_icon(s.status)
            p = s.properties
            _h(f"| {s.name} | {icon} {s.status.value} | "
               f"{p.get('substatus', '—')} | "
               f"`{s.handler or '—'}` | "
               f"{p.get('importance_score', '—')} | "
               f"`{p.get('recommended_action', '—')}` |")
        _h("")


def _render_findings(_h, findings):
    _h("## Findings")
    _h("")

    findings_sorted = sorted(findings,
                             key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # Only show HIGH + MEDIUM + LOW in the main findings section
    by_severity = defaultdict(list)
    for f in findings_sorted:
        by_severity[f.severity.value].append(f)

    for sev in ("critical", "high", "medium", "low"):
        fs = by_severity.get(sev, [])
        if not fs:
            continue
        _h(f"### {sev.upper()} ({len(fs)})")
        _h("")
        for f in fs:
            _h(f"#### {f.id}: {f.title}")
            _h("")
            _h(f"**Category:** {f.category}  ")
            _h(f"**Status:** {f.status.value}  ")
            if f.recommendation:
                _h(f"**Recommendation:** `{f.recommendation}`  ")
            _h("")
            _h(f"{f.description}")
            _h("")
            if f.evidence:
                _h("**Evidence:**")
                for ev in f.evidence[:3]:
                    conf = f"[{ev.confidence.value}]"
                    _h(f"- `{ev.file_path}:{ev.line_start}` "
                       f"{ev.symbol} {conf}")
                    if ev.note:
                        _h(f"  {ev.note}")
                _h("")


def _render_noisy_items(_h, findings):
    _h("## Low-Value / Informational Items")
    _h("")
    _h("These findings exist but should not distract from engineering priorities.")
    _h("")

    info = [f for f in findings if f.severity == FindingSeverity.INFO]
    if not info:
        _h("None.")
        _h("")
        return

    # Group by category
    by_cat = defaultdict(list)
    for f in info:
        by_cat[f.category].append(f)

    for cat, fs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        _h(f"### {cat} ({len(fs)})")
        _h("")
        # Show as compact table, not full detail
        if len(fs) <= 5:
            for f in fs:
                _h(f"- {f.title} — `{f.recommendation}`")
        else:
            _h(f"| Finding | Recommendation |")
            _h(f"|---------|----------------|")
            for f in fs[:20]:
                _h(f"| {f.title} | `{f.recommendation}` |")
            if len(fs) > 20:
                _h(f"| ... and {len(fs) - 20} more | |")
        _h("")


def _render_status_distribution(_h, surfaces):
    _h("## Wiring Status Distribution")
    _h("")
    status_counts = Counter(s.status.value for s in surfaces)
    substatus_counts = Counter(
        s.properties.get("substatus", s.status.value) for s in surfaces)

    _h("### Top-Level Status")
    _h("")
    _h("| Status | Count |")
    _h("|--------|-------|")
    for status, count in status_counts.most_common():
        _h(f"| {_status_icon(WiringStatus(status))} {status} | {count} |")
    _h("")

    _h("### Substatus (enriched)")
    _h("")
    _h("| Substatus | Count |")
    _h("|-----------|-------|")
    for sub, count in substatus_counts.most_common():
        _h(f"| {sub} | {count} |")
    _h("")


def _status_icon(status: WiringStatus) -> str:
    icons = {
        WiringStatus.DECLARED: "⬜",
        WiringStatus.DEFINED: "🟨",
        WiringStatus.REGISTERED: "🟩",
        WiringStatus.STATICALLY_REACHABLE: "✅",
        WiringStatus.DISPATCH_LINKED: "🔗",
        WiringStatus.DATA_LINKED: "📎",
        WiringStatus.RUNTIME_OBSERVED: "🔬",
        WiringStatus.PARTIALLY_WIRED: "⚠️",
        WiringStatus.DEAD: "💀",
        WiringStatus.MISMATCHED: "❌",
    }
    return icons.get(status, "❓")


def generate_surface_detail(store: FactStore, surface_name: str) -> str:
    """Generate detailed view of a single boundary surface."""
    surfaces = store.get_surfaces()
    target = None
    for s in surfaces:
        if surface_name in s.name:
            target = s
            break

    if not target:
        return f"Surface '{surface_name}' not found."

    p = target.properties or {}
    lines = [
        f"# Surface Detail: {target.name}",
        f"",
        f"**Type:** {target.boundary_type.value}",
        f"**Status:** {target.status.value}",
        f"**Substatus:** {p.get('substatus', '—')}",
        f"**Family:** {p.get('family', '—')}",
        f"**Importance:** {p.get('importance_score', '—')}/10",
        f"**Bucket:** {p.get('bucket', '—')}",
        f"**Recommended Action:** `{p.get('recommended_action', '—')}`",
        f"**Description:** {target.description}",
        f"",
        f"## Path",
        f"",
        f"1. **Userspace Producer:** `{target.userspace_producer or 'NONE'}`",
        f"2. **Shared Contract:** `{target.shared_contract or 'NONE'}`",
        f"3. **Dispatch Key:** `{target.dispatch_key or 'NONE'}`",
        f"4. **Kernel Entrypoint:** `{target.kernel_entrypoint or 'NONE'}`",
        f"5. **Handler:** `{target.handler or 'NONE'}`",
        f"6. **Response Path:** `{target.response_path or 'NONE'}`",
        f"",
        f"## Evidence",
        f"",
    ]
    for ev in target.evidence:
        lines.append(
            f"- `{ev.file_path}:{ev.line_start}` [{ev.confidence.value}] "
            f"({ev.method.value}) {ev.note}"
        )
    return "\n".join(lines)
