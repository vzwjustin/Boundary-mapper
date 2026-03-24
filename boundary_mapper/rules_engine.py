"""Rules engine — detects wiring issues, dead code, contract drift, etc.

Generic rule framework for boundary and internal wiring analysis.
Each rule produces Finding objects with evidence.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Optional

from .db import FactStore
from .models import (
    BoundarySurface, BoundaryType, Confidence, Evidence, ExtractionMethod,
    Finding, FindingSeverity, Side, SymbolKind, WiringStatus,
)

log = logging.getLogger(__name__)


class Rule(ABC):
    """Base rule interface."""
    name: str = ""
    description: str = ""
    category: str = ""

    @abstractmethod
    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        """Run the rule and return findings."""
        ...


class DeadSurfaceRule(Rule):
    """Detect boundary surfaces with no handler or no producer.

    Enhanced: uses profile knowledge to distinguish intentionally kernel-only
    and future-reserved surfaces from truly dead ones.
    """
    name = "dead_surface"
    description = "Boundary surface declared but not connected on both sides"
    category = "dead_code"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        surfaces = store.get_surfaces()
        for surf in surfaces:
            if surf.status not in (WiringStatus.DEAD, WiringStatus.DECLARED):
                continue

            if not surf.kernel_entrypoint and not surf.handler:
                # Determine severity and recommendation using profile
                opt_name = surf.shared_contract or surf.name.split(":")[-1]
                severity = FindingSeverity.HIGH
                category = "dead_surface"
                recommendation = "Implement handler or remove dead declaration"

                if hasattr(profile, "is_future_reserved") and profile.is_future_reserved(opt_name):
                    severity = FindingSeverity.LOW
                    category = "future_reserved_surface"
                    recommendation = "keep_as_future_reserved"
                elif hasattr(profile, "is_diagnostic") and profile.is_diagnostic(opt_name):
                    severity = FindingSeverity.LOW
                    category = "diagnostic_surface"
                    recommendation = "implement_with_feature"

                findings.append(Finding(
                    title=f"Dead surface: {surf.name}",
                    description=(
                        f"Boundary surface '{surf.name}' ({surf.boundary_type.value}) "
                        f"is declared but has no kernel handler."
                    ),
                    severity=severity,
                    category=category,
                    status=WiringStatus.DEAD,
                    evidence=surf.evidence,
                    recommendation=recommendation,
                ))
            elif not surf.userspace_producer:
                # Kernel-only surface — check if intentional
                opt_name = surf.shared_contract or surf.name.split(":")[-1]
                family_name = surf.name.split(":")[0] if ":" in surf.name else ""

                severity = FindingSeverity.MEDIUM
                category = "missing_producer"
                recommendation = "Verify userspace code exercises this path"

                if hasattr(profile, "is_kernel_only_genl") and profile.is_kernel_only_genl(family_name):
                    severity = FindingSeverity.INFO
                    category = "intentional_kernel_only"
                    recommendation = "leave_kernel_only"
                elif hasattr(profile, "is_future_reserved") and profile.is_future_reserved(opt_name):
                    severity = FindingSeverity.INFO
                    category = "future_reserved_surface"
                    recommendation = "keep_as_future_reserved"

                findings.append(Finding(
                    title=f"No userspace producer: {surf.name}",
                    description=(
                        f"Boundary surface '{surf.name}' has a kernel handler "
                        f"({surf.handler}) but no detected userspace producer."
                    ),
                    severity=severity,
                    category=category,
                    status=WiringStatus.PARTIALLY_WIRED,
                    evidence=surf.evidence,
                    recommendation=recommendation,
                ))
        return findings


class MissingHandlerRule(Rule):
    """Detect userspace producers without matching kernel handlers."""
    name = "missing_handler"
    description = "Userspace sends commands that no kernel handler processes"
    category = "missing_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        us_syms = store.find_symbols(side="userspace", limit=500)
        kernel_funcs = {s.name for s in store.find_symbols(
            kind="function_def", side="kernel", limit=5000)}

        for sym in us_syms:
            if sym.kind == SymbolKind.GO_CONST:
                for prefix in profile.get_command_prefixes():
                    if sym.name.startswith(prefix):
                        cmd_lower = sym.name.replace(prefix, "").lower()
                        found = any(cmd_lower in fn.lower() for fn in kernel_funcs)
                        if not found:
                            findings.append(Finding(
                                title=f"Userspace command without handler: {sym.name}",
                                description=(
                                    f"Userspace references {sym.name} in "
                                    f"{sym.file_path}:{sym.line_start} but no "
                                    f"kernel handler containing '{cmd_lower}' found."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                category="missing_handler",
                                status=WiringStatus.PARTIALLY_WIRED,
                                evidence=sym.evidence,
                                recommendation="implement_kernel_handler",
                            ))
        return findings


class ContractDriftRule(Rule):
    """Detect mismatches between UAPI constants and their usage.

    Enhanced: classifies drift as reserved_contract, future_surface, or
    genuine unused_uapi, with appropriate severity downgrade.
    """
    name = "contract_drift"
    description = "UAPI enum/constant defined but unused, or used but undefined"
    category = "contract_drift"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        shared_consts = store.find_symbols(side="shared", kind="constant",
                                           limit=500)
        shared_enums = store.find_symbols(side="shared", kind="enum_value",
                                           limit=500)

        kernel_dispatch = {s.name for s in store.find_symbols(
            kind="enum_value", side="kernel", limit=2000)
            if s.properties.get("dispatch")}

        has_reserved_check = hasattr(profile, "is_reserved_attr")
        has_future_check = hasattr(profile, "is_future_reserved")

        for sym in shared_consts + shared_enums:
            relevant = False
            for prefix in (profile.get_command_prefixes() +
                           profile.get_option_prefixes()):
                if sym.name.startswith(prefix):
                    relevant = True
                    break
            if not relevant:
                continue

            if sym.name in kernel_dispatch:
                continue

            kernel_refs = store.find_symbols(
                name=sym.name, side="kernel", limit=5)
            if kernel_refs:
                continue

            # Classify the drift
            severity = FindingSeverity.LOW
            category = "unused_uapi"
            recommendation = "remove_or_deprecate_uapi"

            if has_reserved_check and profile.is_reserved_attr(sym.name):
                severity = FindingSeverity.INFO
                category = "reserved_contract"
                recommendation = "ignore_for_now_low_value"
            elif has_future_check and profile.is_future_reserved(sym.name):
                severity = FindingSeverity.INFO
                category = "future_surface"
                recommendation = "keep_as_future_reserved"
            elif sym.name.endswith("_STATS") or sym.name.endswith("_INFO"):
                # Heuristic: stats/info constants often come with features
                severity = FindingSeverity.INFO
                category = "future_surface"
                recommendation = "implement_with_feature"

            findings.append(Finding(
                title=f"UAPI constant unused in kernel: {sym.name}",
                description=(
                    f"{sym.name} defined in {sym.file_path}:{sym.line_start} "
                    f"but not found in kernel dispatch or usage."
                ),
                severity=severity,
                category=category,
                status=WiringStatus.DECLARED,
                evidence=sym.evidence,
                recommendation=recommendation,
            ))

        return findings


class AttributeSymmetryRule(Rule):
    """Check netlink attribute read/write symmetry.

    Enhanced: classifies asymmetry as expected (command attrs are write-only
    from kernel perspective, response attrs are read-only) vs suspicious.
    """
    name = "attr_symmetry"
    description = "Netlink attribute read/write asymmetry"
    category = "contract_drift"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        attr_reads = defaultdict(list)
        attr_writes = defaultdict(list)

        for sym in store.find_symbols(kind="constant", limit=5000):
            direction = sym.properties.get("attr_direction")
            if direction == "read":
                attr_reads[sym.name].append(sym)
            elif direction == "write":
                attr_writes[sym.name].append(sym)

        has_reserved_check = hasattr(profile, "is_reserved_attr")

        for prefix in profile.get_attribute_prefixes():
            uapi_attrs = store.find_symbols(
                name=prefix, side="shared", kind="enum_value", limit=200)
            for sym in uapi_attrs:
                if sym.name in attr_reads or sym.name in attr_writes:
                    continue

                # Classify the unused attribute
                severity = FindingSeverity.LOW
                category = "unused_attribute"
                recommendation = "verify_runtime"

                if has_reserved_check and profile.is_reserved_attr(sym.name):
                    severity = FindingSeverity.INFO
                    category = "reserved_contract"
                    recommendation = "ignore_for_now_low_value"
                elif sym.name.endswith("_UNSPEC") or sym.name.endswith("_PAD"):
                    severity = FindingSeverity.INFO
                    category = "reserved_contract"
                    recommendation = "ignore_for_now_low_value"

                findings.append(Finding(
                    title=f"UAPI attribute never accessed: {sym.name}",
                    description=(
                        f"{sym.name} defined in UAPI but never "
                        f"nla_get/nla_put'd in kernel code."
                    ),
                    severity=severity,
                    category=category,
                    status=WiringStatus.DECLARED,
                    evidence=sym.evidence,
                    recommendation=recommendation,
                ))

        return findings


class SockoptCompleteness(Rule):
    """Check that every UAPI sockopt has a dispatch handler.

    Enhanced: classifies each missing sockopt into a bucket with a specific
    recommended action and adjusts severity based on profile knowledge.
    """
    name = "sockopt_completeness"
    description = "Socket option defined but missing set or get handler"
    category = "incomplete_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        if not hasattr(profile, "SOCKOPT_MAP"):
            return findings

        set_cases = set()
        all_dispatch = store.find_symbols(kind="enum_value", limit=5000)
        for sym in all_dispatch:
            if sym.properties.get("dispatch"):
                set_cases.add(sym.name)

        has_classify = hasattr(profile, "classify_sockopt_bucket")
        has_importance = hasattr(profile, "get_importance_score")
        has_action = hasattr(profile, "get_recommended_action")

        for opt_num, opt_name in profile.SOCKOPT_MAP.items():
            if opt_name in set_cases:
                continue

            # Use profile classification if available
            bucket = "dead_uapi"
            recommendation = "add_kernel_dispatch"
            importance = 5
            severity = FindingSeverity.HIGH

            if has_classify:
                bucket = profile.classify_sockopt_bucket(
                    opt_name, has_dispatch=False, has_userspace=False)
            if has_action:
                recommendation = profile.get_recommended_action(
                    opt_name, has_dispatch=False, has_userspace=False)
            if has_importance:
                importance = profile.get_importance_score(opt_name)

            # Adjust severity based on bucket
            if bucket == "likely_future":
                severity = FindingSeverity.LOW
            elif bucket == "diagnostic_only":
                severity = FindingSeverity.LOW
            elif bucket == "dead_uapi":
                if importance >= 7:
                    severity = FindingSeverity.HIGH
                elif importance >= 4:
                    severity = FindingSeverity.MEDIUM
                else:
                    severity = FindingSeverity.LOW

            family = ""
            if hasattr(profile, "get_sockopt_family"):
                family = profile.get_sockopt_family(opt_name)

            desc_parts = [
                f"Socket option {opt_name} (={opt_num}) defined in UAPI "
                f"but no case statement found in any sockopt handler.",
            ]
            if bucket != "dead_uapi":
                desc_parts.append(f"Classification: {bucket}.")
            if family:
                desc_parts.append(f"Family: {family}.")
            desc_parts.append(f"Importance: {importance}/10.")

            findings.append(Finding(
                title=f"Sockopt {opt_name} has no dispatch case",
                description=" ".join(desc_parts),
                severity=severity,
                category=f"missing_dispatch:{bucket}",
                status=WiringStatus.DECLARED,
                evidence=[Evidence(
                    file_path="<uapi>",
                    line_start=0,
                    symbol=opt_name,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.MEDIUM,
                    note=f"bucket={bucket} importance={importance} action={recommendation}",
                )],
                recommendation=recommendation,
            ))
        return findings


class OrphanHandlerRule(Rule):
    """Detect kernel handler functions not referenced by any ops table."""
    name = "orphan_handler"
    description = "Handler function exists but not registered in ops table"
    category = "dead_code"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        handler_patterns = []
        for bp in profile.get_boundary_patterns():
            handler_patterns.extend(bp.handler_patterns)

        all_funcs = store.find_symbols(kind="function_def", side="kernel",
                                       limit=5000)
        all_edges = store.get_edges(kind="implements", limit=5000)
        registered_handlers = set()
        for edge in all_edges:
            registered_handlers.add(edge.properties.get("handler", ""))

        import re
        for func in all_funcs:
            for pat in handler_patterns:
                try:
                    cleaned = pat.replace(r"\(", "").replace("(", "")
                    cleaned = cleaned.replace(r"\)", "").replace(")", "")
                    if re.search(cleaned, func.name):
                        if func.name not in registered_handlers:
                            findings.append(Finding(
                                title=f"Orphan handler: {func.name}",
                                description=(
                                    f"Function {func.name} in "
                                    f"{func.file_path}:{func.line_start} "
                                    f"matches handler pattern but is not "
                                    f"registered in any ops table."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                category="orphan_handler",
                                status=WiringStatus.DEFINED,
                                evidence=func.evidence,
                                recommendation="investigate_manually",
                            ))
                        break
                except re.error:
                    continue

        return findings


class SurfaceEnrichmentRule(Rule):
    """Post-processing rule that enriches all surfaces with classification metadata.

    Runs after other rules have populated the database. Adds:
    - substatus (more granular than top-level status)
    - importance_score
    - family classification
    - recommended_action
    - bucket classification
    """
    name = "surface_enrichment"
    description = "Enrich surfaces with substatus, importance, and recommendations"
    category = "enrichment"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []
        surfaces = store.get_surfaces()
        has_classify = hasattr(profile, "classify_sockopt_bucket")
        has_importance = hasattr(profile, "get_importance_score")
        has_action = hasattr(profile, "get_recommended_action")
        has_family = hasattr(profile, "get_sockopt_family")

        for surf in surfaces:
            props = dict(surf.properties) if surf.properties else {}
            opt_name = surf.shared_contract or surf.name.split(":")[-1]

            # Determine substatus
            substatus = surf.status.value
            if surf.boundary_type == BoundaryType.SETSOCKOPT:
                has_dispatch = surf.status == WiringStatus.DISPATCH_LINKED
                has_us = bool(surf.userspace_producer)

                if has_classify:
                    props["bucket"] = profile.classify_sockopt_bucket(
                        opt_name, has_dispatch, has_us)
                if has_family:
                    props["family"] = profile.get_sockopt_family(opt_name)
                if has_importance:
                    props["importance_score"] = profile.get_importance_score(opt_name)
                if has_action:
                    props["recommended_action"] = profile.get_recommended_action(
                        opt_name, has_dispatch, has_us)

                # Compute substatus
                if has_dispatch and has_us:
                    substatus = "statically_reachable_active"
                elif has_dispatch and not has_us:
                    if hasattr(profile, "is_diagnostic") and profile.is_diagnostic(opt_name):
                        substatus = "dispatch_linked_diagnostic"
                    else:
                        substatus = "dispatch_linked_missing_userspace"
                elif not has_dispatch:
                    if hasattr(profile, "is_future_reserved") and profile.is_future_reserved(opt_name):
                        substatus = "declared_only_future_reserved"
                    elif hasattr(profile, "is_diagnostic") and profile.is_diagnostic(opt_name):
                        substatus = "declared_only_diagnostic"
                    else:
                        substatus = "declared_only_dead_uapi"

            elif surf.boundary_type == BoundaryType.GENETLINK:
                family_name = surf.name.split(":")[0] if ":" in surf.name else ""
                props["family"] = family_name
                if surf.status == WiringStatus.STATICALLY_REACHABLE:
                    substatus = "statically_reachable_active"
                elif surf.status == WiringStatus.DISPATCH_LINKED:
                    if hasattr(profile, "is_kernel_only_genl") and \
                            profile.is_kernel_only_genl(family_name):
                        substatus = "dispatch_linked_kernel_only"
                        props["recommended_action"] = "leave_kernel_only"
                    else:
                        substatus = "dispatch_linked_missing_userspace"
                        props["recommended_action"] = "implement_userspace_caller"
                props["importance_score"] = 10 if substatus.startswith("statically") else 5

            elif surf.boundary_type == BoundaryType.IOCTL:
                props["family"] = "ioctl"
                props["importance_score"] = 6
                props["recommended_action"] = "implement_userspace_caller"

            props["substatus"] = substatus

            # Write enrichment back to DB
            surf.properties = props
            store.upsert_surface(surf)

        return findings


# ─── Internal wiring rules ───


def _build_call_graph(store: FactStore) -> dict[str, set[str]]:
    """Build caller→{callees} adjacency map from CALLS edges in the DB."""
    graph: dict[str, set[str]] = defaultdict(set)
    call_edges = store.get_edges(kind="calls", limit=100000)
    for edge in call_edges:
        caller = edge.properties.get("caller", "")
        callee = edge.properties.get("callee", "")
        if caller and callee:
            graph[caller].add(callee)
    return graph


def _transitive_reachable(graph: dict[str, set[str]], roots: set[str]) -> set[str]:
    """BFS/DFS: return all functions transitively reachable from roots."""
    visited = set()
    stack = list(roots)
    while stack:
        fn = stack.pop()
        if fn in visited:
            continue
        visited.add(fn)
        for callee in graph.get(fn, ()):
            if callee not in visited:
                stack.append(callee)
    return visited


def _reverse_call_graph(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    """Build callee→{callers} reverse map."""
    rev: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            rev[callee].add(caller)
    return rev


class InitChainRule(Rule):
    """Detect __init functions not wired into the module init chain.

    Uses the full call graph to walk transitively from module_init roots
    and find __init functions that are never reached.
    """
    name = "init_chain"
    description = "Init functions not wired into module_init chain"
    category = "internal_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        # Build call graph
        graph = _build_call_graph(store)

        # Find all module_init entry points
        init_regs = store.find_symbols(name="__module_init__",
                                       kind="registration", limit=50)
        init_targets = {s.properties.get("target", "") for s in init_regs}

        if not init_targets:
            return findings

        # Seed the reachability with init targets + ops table handlers +
        # registration targets (these are all "wired in")
        roots = set(init_targets)
        all_impl_edges = store.get_edges(kind="implements", limit=10000)
        for edge in all_impl_edges:
            handler = edge.properties.get("handler", "")
            if handler:
                roots.add(handler)
        reg_syms = store.find_symbols(name="__reg__", kind="registration",
                                      limit=500)
        for sym in reg_syms:
            target = sym.properties.get("target", "")
            if target:
                roots.add(target)

        # Walk the call graph transitively from all roots
        reachable = _transitive_reachable(graph, roots)

        # Find all __init-annotated function definitions
        all_funcs = store.find_symbols(kind="function_def", side="kernel",
                                       limit=20000)
        for fn in all_funcs:
            is_init = False
            for ev in fn.evidence:
                if "__init" in ev.snippet:
                    is_init = True
                    break
            if not is_init:
                continue

            if fn.name in reachable:
                continue
            # Check if it's exported
            exports = store.find_symbols(name=f"__export__{fn.name}",
                                         kind="registration", limit=1)
            if exports:
                continue

            findings.append(Finding(
                title=f"Init function not in init chain: {fn.name}",
                description=(
                    f"Function {fn.name} in {fn.file_path}:{fn.line_start} "
                    f"has __init annotation but is not reachable from "
                    f"module_init via any call path."
                ),
                severity=FindingSeverity.MEDIUM,
                category="orphan_init",
                status=WiringStatus.DEFINED,
                evidence=fn.evidence,
                recommendation="wire_into_init_chain",
            ))

        return findings


class OpsTableWiringRule(Rule):
    """Detect ops tables that are defined but never registered.

    Also detects ops table slots that point to non-existent handlers.
    """
    name = "ops_table_wiring"
    description = "Ops tables not registered or with missing handler targets"
    category = "internal_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        # Find all ops table symbols
        ops_tables = store.find_symbols(kind="ops_table", side="kernel",
                                        limit=500)
        # Find all registration symbols
        reg_syms = store.find_symbols(name="__reg__", kind="registration",
                                      limit=500)
        registered_targets = set()
        for sym in reg_syms:
            registered_targets.add(sym.properties.get("target", ""))

        # Also check genl_register targets
        genl_regs = store.find_symbols(name="register_", kind="registration",
                                       limit=100)
        for sym in genl_regs:
            family = sym.properties.get("family", "")
            if family:
                registered_targets.add(family)

        # Check each ops table
        for ops in ops_tables:
            struct_type = ops.properties.get("struct_type", "")
            # Skip non-ops structs (simple variable initializers)
            if not any(kw in struct_type for kw in (
                "ops", "proto", "family", "ctl_table", "nf_hook",
            )):
                continue

            if ops.name not in registered_targets:
                # Check if it's referenced in any edge
                edges = store.get_edges(kind="implements", limit=10000)
                is_referenced = any(
                    e.properties.get("ops_table") == ops.name for e in edges)
                if not is_referenced:
                    continue  # Not an ops table with handlers

                findings.append(Finding(
                    title=f"Ops table not registered: {ops.name}",
                    description=(
                        f"Ops table {ops.name} ({struct_type}) in "
                        f"{ops.file_path}:{ops.line_start} has handler "
                        f"assignments but no detected registration call."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="unregistered_ops_table",
                    status=WiringStatus.DEFINED,
                    evidence=ops.evidence,
                    recommendation="add_registration_call",
                ))

        # Check for ops table edges pointing to non-existent handlers
        all_edges = store.get_edges(kind="implements", limit=10000)
        all_func_names = {s.name for s in store.find_symbols(
            kind="function_def", limit=20000)}

        # Fields that are clearly not function pointers (struct metadata)
        non_handler_fields = {
            "name", "version", "maxattr", "hdrsize", "module", "owner",
            "type", "protocol", "flags", "family", "policy", "netnsok",
            "parallel_ops", "pre_doit", "post_doit", "mcgrps", "n_mcgrps",
            "ops", "n_ops", "sock_type", "pf", "idiag_type",
            # Config/parameter fields (assigned constants, not function ptrs)
            "enabled", "max_connections_per_second", "max_connections_burst",
            "per_ip_rate_limit", "key_len", "max_conn_rate",
            "rate_limit_window_ms", "burst_limit", "attack_threshold",
            "cookie_lifetime_ms", "gc_interval_ms", "entry_timeout_ms",
            "next_port", "min_port", "max_port",
        }

        for edge in all_edges:
            handler = edge.properties.get("handler", "")
            ops_table = edge.properties.get("ops_table", "")
            field = edge.properties.get("field", "")
            if handler and handler not in all_func_names:
                # Skip common non-function values
                if handler in ("NULL", "true", "false", "0", "1"):
                    continue
                if handler.startswith("THIS_MODULE"):
                    continue
                # Skip fields that are struct metadata, not function pointers
                if field in non_handler_fields:
                    continue
                # Skip if value looks like a constant (ALL_CAPS)
                if handler.isupper() or handler[0].isupper():
                    continue
                # Skip numeric-looking or string-looking values
                if handler.isdigit():
                    continue

                findings.append(Finding(
                    title=f"Ops handler missing: {ops_table}.{field} = {handler}",
                    description=(
                        f"Ops table {ops_table} assigns .{field} = {handler}, "
                        f"but no function definition for {handler} was found."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="missing_ops_handler",
                    status=WiringStatus.PARTIALLY_WIRED,
                    evidence=edge.evidence,
                    recommendation="implement_handler_or_fix_assignment",
                ))

        return findings


class RegistrationBalanceRule(Rule):
    """Detect register calls without matching unregister calls.

    If module registers something in init, it should unregister in exit.
    """
    name = "registration_balance"
    description = "Register calls without matching unregister"
    category = "internal_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        reg_syms = store.find_symbols(name="__reg__", kind="registration",
                                      limit=500)
        unreg_syms = store.find_symbols(name="__unreg__", kind="registration",
                                        limit=500)

        # Build sets of (target) for registers and unregisters
        registered = {}  # target → registration symbol
        for sym in reg_syms:
            target = sym.properties.get("target", "")
            if target:
                registered[target] = sym

        unregistered = set()
        for sym in unreg_syms:
            target = sym.properties.get("target", "")
            if target:
                unregistered.add(target)

        # Find registers without matching unregisters
        for target, sym in registered.items():
            if target not in unregistered:
                reg_fn = sym.properties.get("register_fn", "?")
                findings.append(Finding(
                    title=f"No unregister for: {target}",
                    description=(
                        f"{reg_fn}(&{target}) in {sym.file_path}:{sym.line_start} "
                        f"but no matching unregister call found. "
                        f"This may leak resources on module unload."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="unbalanced_registration",
                    status=WiringStatus.PARTIALLY_WIRED,
                    evidence=sym.evidence,
                    recommendation="add_unregister_in_exit",
                ))

        return findings


class DeadFunctionRule(Rule):
    """Detect functions with zero callers in the full call graph.

    Now uses the resolved call graph (CALLS edges) to check whether
    any other function in the module calls this one. A function is
    dead if it has:
    - No callers in the call graph
    - Not in any ops table
    - Not exported (EXPORT_SYMBOL)
    - Not a module_init/exit target
    - Not a registration target

    Only checks functions in profile-relevant paths.
    """
    name = "dead_function"
    description = "Functions with zero callers in full call graph"
    category = "internal_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        # Build reverse call graph (callee → callers)
        graph = _build_call_graph(store)
        rev = _reverse_call_graph(graph)

        # Collect all structurally referenced functions
        # (ops tables, exports, init/exit, registrations)
        structurally_referenced = set()

        all_impl_edges = store.get_edges(kind="implements", limit=20000)
        for edge in all_impl_edges:
            handler = edge.properties.get("handler", "")
            if handler:
                structurally_referenced.add(handler)

        for sym in store.find_symbols(name="__export__", kind="registration",
                                      limit=1000):
            structurally_referenced.add(sym.properties.get("target", ""))
        for sym in store.find_symbols(name="__module_init__",
                                      kind="registration", limit=50):
            structurally_referenced.add(sym.properties.get("target", ""))
        for sym in store.find_symbols(name="__module_exit__",
                                      kind="registration", limit=50):
            structurally_referenced.add(sym.properties.get("target", ""))
        for sym in store.find_symbols(name="__reg__", kind="registration",
                                      limit=500):
            structurally_referenced.add(sym.properties.get("target", ""))
            structurally_referenced.add(sym.properties.get("register_fn", ""))

        # Profile-relevant paths
        relevant_dirs = set()
        for pat in (profile.get_kernel_file_patterns() +
                    profile.get_userspace_file_patterns()):
            prefix = pat.split("*")[0].rstrip("/")
            if prefix:
                relevant_dirs.add(prefix)

        all_funcs = store.find_symbols(kind="function_def", side="kernel",
                                       limit=20000)
        for fn in all_funcs:
            # Skip if structurally referenced
            if fn.name in structurally_referenced:
                continue
            # Skip if has callers in call graph
            if fn.name in rev and rev[fn.name]:
                continue
            # Only check profile-relevant paths
            if relevant_dirs and not any(fn.file_path.startswith(d)
                                         for d in relevant_dirs):
                continue
            # Skip headers and __ prefixed
            if fn.file_path.endswith(".h"):
                continue
            if fn.name.startswith("__"):
                continue

            findings.append(Finding(
                title=f"Dead function: {fn.name}",
                description=(
                    f"Function {fn.name} in {fn.file_path}:{fn.line_start} "
                    f"has no callers in the call graph, is not in any ops "
                    f"table, not exported, and not a registration target."
                ),
                severity=FindingSeverity.LOW,
                category="dead_function",
                status=WiringStatus.DEFINED,
                evidence=fn.evidence,
                recommendation="remove_or_wire_function",
            ))

        return findings


class ExportWithoutDefRule(Rule):
    """Detect EXPORT_SYMBOL for functions that don't exist."""
    name = "export_without_def"
    description = "EXPORT_SYMBOL for non-existent function"
    category = "internal_wiring"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        exports = store.find_symbols(name="__export__", kind="registration",
                                     limit=1000)
        all_func_names = {s.name for s in store.find_symbols(
            kind="function_def", limit=20000)}

        for exp in exports:
            target = exp.properties.get("target", "")
            if target and target not in all_func_names:
                findings.append(Finding(
                    title=f"Export without definition: {target}",
                    description=(
                        f"EXPORT_SYMBOL({target}) in "
                        f"{exp.file_path}:{exp.line_start} "
                        f"but no function definition for {target} found."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="export_without_def",
                    status=WiringStatus.PARTIALLY_WIRED,
                    evidence=exp.evidence,
                    recommendation="implement_or_remove_export",
                ))

        return findings


# ─── Consistency rules (things that break builds / cause subtle bugs) ───


class SignatureMismatchRule(Rule):
    """Detect functions declared with different signatures in different files.

    This catches the exact class of bug where a header declares
    foo(struct bar *) but another header or the definition has foo(void).
    These cause linker errors, implicit casts, or silent corruption.
    """
    name = "signature_mismatch"
    description = "Function declared/defined with conflicting signatures across files"
    category = "consistency"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        # Gather all function defs and decls with signatures
        all_funcs = store.find_symbols(kind="function_def", limit=30000)
        all_decls = store.find_symbols(kind="function_decl", limit=30000)

        # Group by name → [(file, line, signature, kind)]
        by_name: dict[str, list[tuple]] = defaultdict(list)
        for sym in all_funcs + all_decls:
            sig = sym.properties.get("signature", "")
            if not sig:
                continue
            by_name[sym.name].append((
                sym.file_path, sym.line_start, sig,
                sym.kind.value, sym.evidence,
            ))

        for name, entries in by_name.items():
            if len(entries) < 2:
                continue

            # Collect unique signatures
            sigs = {}  # sig → [(file, line, kind)]
            for fpath, line, sig, kind, ev in entries:
                sigs.setdefault(sig, []).append((fpath, line, kind, ev))

            if len(sigs) <= 1:
                continue  # all consistent

            # MISMATCH: multiple different signatures for the same function
            sig_list = list(sigs.items())
            desc_parts = [f"Function {name} has {len(sigs)} different signatures:"]
            all_evidence = []
            for sig, locations in sig_list:
                for fpath, line, kind, ev in locations:
                    desc_parts.append(
                        f"  {kind}: {sig} in {fpath}:{line}")
                    all_evidence.extend(ev)

            findings.append(Finding(
                title=f"Signature mismatch: {name}",
                description=" ".join(desc_parts),
                severity=FindingSeverity.HIGH,
                category="signature_mismatch",
                status=WiringStatus.MISMATCHED,
                evidence=all_evidence[:5],
                recommendation="fix_signature_to_match",
            ))

        return findings


class DuplicateDefinitionRule(Rule):
    """Detect the same function defined in multiple .c files.

    Multiple definitions of the same non-static function will cause
    linker errors (multiple definition of `foo`). Static functions
    with the same name in different files are fine.
    """
    name = "duplicate_definition"
    description = "Same function defined in multiple .c files"
    category = "consistency"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        all_funcs = store.find_symbols(kind="function_def", limit=30000)

        # Group by name → [file_paths]
        by_name: dict[str, list] = defaultdict(list)
        for sym in all_funcs:
            # Skip header files (inline defs are expected in multiple TUs)
            if sym.file_path.endswith(".h"):
                continue
            by_name[sym.name].append(sym)

        for name, syms in by_name.items():
            if len(syms) < 2:
                continue
            # Multiple .c files define the same function
            files = [f"{s.file_path}:{s.line_start}" for s in syms]
            # Check if any evidence suggests "static" — if so, skip
            all_static = all(
                "static" in (e.snippet or "")
                for s in syms for e in s.evidence
            )
            if all_static:
                continue

            findings.append(Finding(
                title=f"Duplicate definition: {name}",
                description=(
                    f"Function {name} defined in {len(syms)} files: "
                    f"{', '.join(files)}. "
                    f"This will cause linker errors if both are compiled."
                ),
                severity=FindingSeverity.HIGH,
                category="duplicate_definition",
                status=WiringStatus.MISMATCHED,
                evidence=[e for s in syms for e in s.evidence][:5],
                recommendation="remove_duplicate_or_make_static",
            ))

        return findings


class ConstantRedefinitionRule(Rule):
    """Detect #define constants with different values in different files.

    If FOO is #defined as 10 in one header and 20 in another,
    which one wins depends on include order — a nasty silent bug.
    """
    name = "constant_redefinition"
    description = "#define constant with different values across files"
    category = "consistency"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        all_consts = store.find_symbols(kind="constant", limit=10000)

        by_name: dict[str, list] = defaultdict(list)
        for sym in all_consts:
            val = sym.properties.get("value", "")
            if val:
                by_name[sym.name].append((sym, val))

        for name, entries in by_name.items():
            if len(entries) < 2:
                continue
            # Check if values differ
            values = set(val for _, val in entries)
            if len(values) <= 1:
                continue

            desc_parts = [f"#define {name} has {len(values)} different values:"]
            all_evidence = []
            for sym, val in entries:
                desc_parts.append(f"  {val} in {sym.file_path}:{sym.line_start}")
                all_evidence.extend(sym.evidence)

            findings.append(Finding(
                title=f"Constant redefined: {name}",
                description=" ".join(desc_parts),
                severity=FindingSeverity.HIGH,
                category="constant_redefinition",
                status=WiringStatus.MISMATCHED,
                evidence=all_evidence[:5],
                recommendation="resolve_conflicting_definitions",
            ))

        return findings


class StructSizeDriftRule(Rule):
    """Detect struct defined in multiple places (potential ABI drift).

    If the same struct name appears in different files, the definitions
    might have drifted apart — different field counts, different sizes.
    This is especially dangerous for structs shared across UAPI boundaries.
    """
    name = "struct_drift"
    description = "Same struct defined in multiple files (potential ABI drift)"
    category = "consistency"

    def evaluate(self, store: FactStore, profile) -> list[Finding]:
        findings = []

        all_structs = store.find_symbols(kind="struct", limit=5000)
        # Also check ops_table symbols since they're struct vars
        all_enums = store.find_symbols(kind="enum", limit=5000)

        for symbols, kind_name in [(all_structs, "struct"), (all_enums, "enum")]:
            by_name: dict[str, list] = defaultdict(list)
            for sym in symbols:
                by_name[sym.name].append(sym)

            for name, syms in by_name.items():
                if len(syms) < 2:
                    continue
                # Multiple definitions — check if they're in different directories
                dirs = set()
                for s in syms:
                    d = "/".join(s.file_path.split("/")[:-1])
                    dirs.add(d)
                if len(dirs) < 2:
                    continue  # same directory = likely same definition

                files = [f"{s.file_path}:{s.line_start}" for s in syms]
                findings.append(Finding(
                    title=f"{kind_name} defined in multiple locations: {name}",
                    description=(
                        f"{kind_name} {name} found in {len(syms)} files across "
                        f"{len(dirs)} directories: {', '.join(files)}. "
                        f"If these have drifted apart, ABI mismatches will occur."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="struct_drift",
                    status=WiringStatus.MISMATCHED,
                    evidence=[e for s in syms for e in s.evidence][:5],
                    recommendation="verify_definitions_match",
                ))

        return findings


# ─── Rule registry ───

ALL_RULES: list[type[Rule]] = [
    # Boundary rules (UAPI ↔ kernel)
    DeadSurfaceRule,
    MissingHandlerRule,
    ContractDriftRule,
    AttributeSymmetryRule,
    SockoptCompleteness,
    OrphanHandlerRule,
    # Internal wiring rules
    InitChainRule,
    OpsTableWiringRule,
    RegistrationBalanceRule,
    DeadFunctionRule,
    ExportWithoutDefRule,
    # Consistency rules (things that break builds / cause subtle bugs)
    SignatureMismatchRule,
    DuplicateDefinitionRule,
    ConstantRedefinitionRule,
    StructSizeDriftRule,
    # Post-processing (must be last)
    SurfaceEnrichmentRule,
]


class RulesEngine:
    """Execute rules against the fact store."""

    def __init__(self, store: FactStore, profile, rules: list[type[Rule]] = None):
        self.store = store
        self.profile = profile
        self.rules = [r() for r in (rules or ALL_RULES)]

    def run_all(self) -> list[Finding]:
        """Run all rules and return deduplicated findings."""
        all_findings = []
        for rule in self.rules:
            log.info("Running rule: %s", rule.name)
            try:
                findings = rule.evaluate(self.store, self.profile)
                for f in findings:
                    f.id = self.store.upsert_finding(f)
                all_findings.extend(findings)
                log.info("  → %d findings", len(findings))
            except Exception as e:
                log.error("Rule %s failed: %s", rule.name, e)
        return all_findings
