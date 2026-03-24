"""Graph builder — assembles extracted facts into a boundary graph.

Takes extracted symbols, edges, registrations, and dispatch entries
and resolves them into a connected graph stored in the FactStore.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from .db import FactStore
from .models import (
    BoundaryFlow, BoundarySurface, BoundaryType, Confidence, EdgeKind,
    Evidence, ExtractionMethod, FlowStep, GraphEdge, Side, SymbolKind,
    SymbolNode, WiringStatus,
)
from .pattern_extract import ExtractedFile
from .repo_scan import RepoLayout

log = logging.getLogger(__name__)


class GraphBuilder:
    """Build the boundary graph from extracted facts."""

    def __init__(self, store: FactStore, profile):
        self.store = store
        self.profile = profile
        # Index: name → list of symbol IDs for resolution
        self._name_index: dict[str, list[str]] = defaultdict(list)
        # Track ops table entries for dispatch linking
        self._ops_entries: list[dict] = []
        # Raw call graph refs (resolved after all files ingested)
        self._call_refs: list[dict] = []

    def ingest(self, extracted: ExtractedFile):
        """Ingest all facts from one extracted file."""
        for sym in extracted.symbols:
            sym_id = self.store.upsert_symbol(sym)
            self._name_index[sym.name].append(sym_id)

        # Store raw edges (unresolved)
        for edge in extracted.edges:
            self._ops_entries.append({
                "edge": edge,
                "file": extracted.rel_path,
            })

        # Store registrations as symbols + edges
        for reg in extracted.registrations:
            self._ingest_registration(reg)

        # Store dispatch entries
        for disp in extracted.dispatch_entries:
            self._ingest_dispatch(disp)

        # Store attribute reads/writes as evidence
        for ar in extracted.attr_reads:
            self._ingest_attr_access(ar, "read")
        for aw in extracted.attr_writes:
            self._ingest_attr_access(aw, "write")

        # Store internal wiring references
        for ref in extracted.internal_refs:
            self._ingest_internal_ref(ref)

        # Accumulate call graph refs (resolved later)
        self._call_refs.extend(extracted.call_refs)

        # Store lint hits as findings
        for hit in extracted.lint_hits:
            self._store_lint_finding(hit)

    def _ingest_registration(self, reg: dict):
        """Create a registration node and edge."""
        reg_sym = SymbolNode(
            name=f"register_{reg.get('family', reg.get('path', 'unknown'))}",
            kind=SymbolKind.REGISTRATION,
            side=Side.KERNEL,
            file_path=reg["file"],
            line_start=reg["line"],
            properties=reg,
            evidence=[Evidence(
                file_path=reg["file"],
                line_start=reg["line"],
                symbol=reg.get("family", reg.get("path", "")),
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.HIGH,
                note=f"Registration type: {reg['type']}",
            )],
        )
        sym_id = self.store.upsert_symbol(reg_sym)
        self._name_index[reg_sym.name].append(sym_id)

    def _ingest_dispatch(self, disp: dict):
        """Create a dispatch entry node."""
        case_name = disp["case"]
        disp_sym = SymbolNode(
            name=case_name,
            kind=SymbolKind.ENUM_VALUE,
            side=Side.KERNEL,
            file_path=disp["file"],
            line_start=disp["line"],
            properties={"dispatch": True},
            evidence=[Evidence(
                file_path=disp["file"],
                line_start=disp["line"],
                symbol=case_name,
                snippet=f"case {case_name}:",
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.HIGH,
                note="Switch dispatch case",
            )],
        )
        self.store.upsert_symbol(disp_sym)

    def _ingest_attr_access(self, access: dict, direction: str):
        """Track attribute reads and writes for contract correlation."""
        attr = access["attr"]
        sym = SymbolNode(
            name=attr,
            kind=SymbolKind.CONSTANT,
            side=Side.KERNEL,
            file_path=access["file"],
            line_start=access["line"],
            properties={
                "attr_direction": direction,
                "nla_type": access["type"],
            },
            evidence=[Evidence(
                file_path=access["file"],
                line_start=access["line"],
                symbol=attr,
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.HIGH,
                note=f"nla_{direction}: {attr} ({access['type']})",
            )],
        )
        self.store.upsert_symbol(sym)

    def _ingest_internal_ref(self, ref: dict):
        """Store an internal wiring reference (init, exit, export, register)."""
        pattern = ref.get("pattern", "unknown")
        file_path = ref["file"]
        line = ref["line"]

        if pattern == "module_init":
            fn = ref.get("function", "")
            sym = SymbolNode(
                name=f"__module_init__{fn}",
                kind=SymbolKind.REGISTRATION,
                side=Side.KERNEL,
                file_path=file_path,
                line_start=line,
                properties={"internal_type": "module_init", "target": fn},
                evidence=[Evidence(
                    file_path=file_path, line_start=line, symbol=fn,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"module_init({fn})",
                )],
            )
            self.store.upsert_symbol(sym)

        elif pattern == "module_exit":
            fn = ref.get("function", "")
            sym = SymbolNode(
                name=f"__module_exit__{fn}",
                kind=SymbolKind.REGISTRATION,
                side=Side.KERNEL,
                file_path=file_path,
                line_start=line,
                properties={"internal_type": "module_exit", "target": fn},
                evidence=[Evidence(
                    file_path=file_path, line_start=line, symbol=fn,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"module_exit({fn})",
                )],
            )
            self.store.upsert_symbol(sym)

        elif pattern == "export_symbol":
            fn = ref.get("function", "")
            sym = SymbolNode(
                name=f"__export__{fn}",
                kind=SymbolKind.REGISTRATION,
                side=Side.KERNEL,
                file_path=file_path,
                line_start=line,
                properties={"internal_type": "export", "target": fn},
                evidence=[Evidence(
                    file_path=file_path, line_start=line, symbol=fn,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"EXPORT_SYMBOL({fn})",
                )],
            )
            self.store.upsert_symbol(sym)

        elif pattern == "register_call":
            reg_fn = ref.get("register_fn", "")
            target = ref.get("target", "")
            sym = SymbolNode(
                name=f"__reg__{reg_fn}__{target}",
                kind=SymbolKind.REGISTRATION,
                side=Side.KERNEL,
                file_path=file_path,
                line_start=line,
                properties={"internal_type": "register", "register_fn": reg_fn,
                             "target": target},
                evidence=[Evidence(
                    file_path=file_path, line_start=line, symbol=target,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"{reg_fn}(&{target})",
                )],
            )
            self.store.upsert_symbol(sym)

        elif pattern == "unregister_call":
            unreg_fn = ref.get("unregister_fn", "")
            target = ref.get("target", "")
            sym = SymbolNode(
                name=f"__unreg__{unreg_fn}__{target}",
                kind=SymbolKind.REGISTRATION,
                side=Side.KERNEL,
                file_path=file_path,
                line_start=line,
                properties={"internal_type": "unregister", "unregister_fn": unreg_fn,
                             "target": target},
                evidence=[Evidence(
                    file_path=file_path, line_start=line, symbol=target,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"{unreg_fn}(&{target})",
                )],
            )
            self.store.upsert_symbol(sym)

    def _store_lint_finding(self, hit: dict):
        """Store a lint pattern hit as a finding in the DB."""
        from .models import Finding, FindingSeverity
        sev_map = {
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        finding = Finding(
            title=f"{hit['name']}: {hit['snippet'][:60]}",
            description=f"{hit['message']} — {hit['file']}:{hit['line']}",
            severity=sev_map.get(hit["severity"], FindingSeverity.LOW),
            category=hit["category"],
            status=WiringStatus.DEFINED,
            evidence=[Evidence(
                file_path=hit["file"],
                line_start=hit["line"],
                symbol=hit["name"],
                snippet=hit["snippet"],
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.MEDIUM,
                note=hit["message"],
            )],
            recommendation=hit["recommendation"],
        )
        self.store.upsert_finding(finding)

    def resolve_edges(self):
        """Resolve symbolic references in edges to actual symbol IDs."""
        resolved = 0
        for entry in self._ops_entries:
            edge = entry["edge"]
            props = edge.properties

            if "ops_table" in props and "handler" in props:
                # Find the ops table symbol
                ops_name = props["ops_table"]
                handler_name = props["handler"]

                source_ids = self._name_index.get(ops_name, [])
                target_ids = self._name_index.get(handler_name, [])

                if source_ids and target_ids:
                    edge.source_id = source_ids[0]
                    edge.target_id = target_ids[0]
                    self.store.add_edge(edge)
                    resolved += 1
                elif source_ids and not target_ids:
                    # Handler not found — create a placeholder symbol
                    placeholder = SymbolNode(
                        name=handler_name,
                        kind=SymbolKind.FUNCTION_DEF,
                        side=Side.KERNEL,
                        file_path="<unresolved>",
                        properties={"unresolved": True},
                    )
                    pid = self.store.upsert_symbol(placeholder)
                    edge.source_id = source_ids[0]
                    edge.target_id = pid
                    edge.confidence = Confidence.LOW
                    self.store.add_edge(edge)

        log.info("Resolved %d / %d ops table edges", resolved,
                 len(self._ops_entries))

        # Resolve call graph
        self._resolve_call_graph()

    def _resolve_call_graph(self):
        """Resolve raw call refs into CALLS edges.

        Only creates edges where BOTH caller and callee exist as known
        function definitions in the symbol table. This gives us the
        intra-module call graph without noise from external API calls.
        """
        if not self._call_refs:
            return

        # Build set of known function names for fast lookup
        known_funcs = set(self._name_index.keys())

        resolved = 0
        # Deduplicate: only store one edge per (caller, callee) pair
        seen = set()

        for ref in self._call_refs:
            caller = ref["caller"]
            callee = ref["callee"]

            if caller == callee:
                continue  # skip self-recursion
            pair = (caller, callee)
            if pair in seen:
                continue

            # Both must be known symbols
            if caller not in known_funcs or callee not in known_funcs:
                continue

            caller_ids = self._name_index[caller]
            callee_ids = self._name_index[callee]
            if not caller_ids or not callee_ids:
                continue

            seen.add(pair)

            edge = GraphEdge(
                source_id=caller_ids[0],
                target_id=callee_ids[0],
                kind=EdgeKind.CALLS,
                confidence=Confidence.MEDIUM,
                properties={
                    "caller": caller,
                    "callee": callee,
                },
                evidence=[Evidence(
                    file_path=ref["file"],
                    line_start=ref["line"],
                    symbol=callee,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.MEDIUM,
                    note=f"{caller}() calls {callee}()",
                )],
            )
            self.store.add_edge(edge)
            resolved += 1

        log.info("Resolved %d call graph edges from %d raw refs "
                 "(%d unique pairs)",
                 resolved, len(self._call_refs), len(seen))

    def build_boundary_surfaces(self, layout: RepoLayout):
        """Identify and store boundary surfaces."""
        self._build_genetlink_surfaces()
        self._build_sockopt_surfaces()
        self._build_sysctl_surfaces()
        self._build_ioctl_surfaces()

    def _build_genetlink_surfaces(self):
        """Build boundary surfaces for genetlink families."""
        if not hasattr(self.profile, "GENL_FAMILIES"):
            return

        for family_name, info in self.profile.GENL_FAMILIES.items():
            for cmd_num, cmd_name in info.get("commands", {}).items():
                # Find the handler for this command
                handler = self._find_genl_handler(cmd_name, info)

                status = WiringStatus.DECLARED
                if handler:
                    status = WiringStatus.DISPATCH_LINKED

                # Check if userspace produces this command
                us_producer = self._find_userspace_producer(cmd_name)
                if us_producer and handler:
                    status = WiringStatus.STATICALLY_REACHABLE

                surf = BoundarySurface(
                    boundary_type=BoundaryType.GENETLINK,
                    name=f"{family_name}:{cmd_name}",
                    description=f"genetlink command {cmd_name} "
                                f"(family={family_name}, cmd={cmd_num})",
                    kernel_entrypoint=handler or "",
                    userspace_producer=us_producer or "",
                    shared_contract=cmd_name,
                    dispatch_key=str(cmd_num),
                    handler=handler or "",
                    status=status,
                    evidence=[Evidence(
                        file_path=info["source_file"],
                        line_start=0,
                        symbol=cmd_name,
                        method=ExtractionMethod.PATTERN_MATCH,
                        confidence=Confidence.HIGH,
                        note=f"Command {cmd_num} in {family_name} ops table",
                    )],
                )
                self.store.upsert_surface(surf)

    def _find_genl_handler(self, cmd_name: str, family_info: dict) -> Optional[str]:
        """Find the kernel handler for a genetlink command."""
        # Look for genl_ops entries that reference this command
        edges = self.store.get_edges(kind="implements")
        for edge in edges:
            props = edge.properties
            if props.get("ops_table") in (
                family_info.get("ops_var", ""),
            ):
                # Check if this entry handles our command
                for ev in edge.evidence:
                    if cmd_name in ev.note or cmd_name in ev.snippet:
                        return props.get("handler", "")

        # Generate search patterns from command name
        # Strip known command prefixes to get the base command word
        cmd_lower = cmd_name.lower()
        for prefix in self.profile.get_command_prefixes():
            stripped = cmd_lower.replace(prefix.lower(), "")
            if stripped != cmd_lower:
                cmd_lower = stripped
                break

        # Try handler patterns based on common naming conventions
        search_patterns = []
        # Get module prefix from profile name or first command prefix
        mod_prefixes = []
        for p in self.profile.get_command_prefixes():
            # "MYMOD_CMD_" → "mymod"
            parts = p.lower().rstrip("_").split("_")
            if parts:
                mod_prefixes.append(parts[0])
        if not mod_prefixes:
            mod_prefixes = [""]

        for mp in mod_prefixes:
            if mp:
                search_patterns.append(f"{mp}_nl_cmd_{cmd_lower}")
                search_patterns.append(f"{mp}_nl_{cmd_lower}")
                search_patterns.append(f"{mp}_nl_cmd_{cmd_lower}_dump")
            else:
                search_patterns.append(f"nl_cmd_{cmd_lower}")

        # Also try splitting the command name for dump patterns
        parts = cmd_lower.split("_")
        if len(parts) >= 2:
            for mp in mod_prefixes:
                if mp:
                    search_patterns.append(f"{mp}_nl_cmd_{parts[0]}_dump")

        for pattern in search_patterns:
            candidates = self.store.find_symbols(
                name=pattern, kind="function_def",
            )
            if candidates:
                return candidates[0].name
        return None

    def _find_userspace_producer(self, cmd_name: str) -> Optional[str]:
        """Find userspace code that produces this command."""
        # Search for Go constants referencing this command
        candidates = self.store.find_symbols(
            name=cmd_name, side="userspace",
        )
        if candidates:
            return f"{candidates[0].file_path}:{candidates[0].line_start}"
        return None

    def _build_sockopt_surfaces(self):
        """Build boundary surfaces for socket options."""
        if not hasattr(self.profile, "SOCKOPT_MAP"):
            return

        for opt_num, opt_name in self.profile.SOCKOPT_MAP.items():
            # Check if case handler exists
            handler_syms = self.store.find_symbols(
                name=opt_name, kind="enum_value",
            )
            # Find dispatch case
            has_set_handler = bool(handler_syms)

            # Check getsockopt too
            status = WiringStatus.DECLARED
            if has_set_handler:
                status = WiringStatus.DISPATCH_LINKED

            surf = BoundarySurface(
                boundary_type=BoundaryType.SETSOCKOPT,
                name=f"sockopt:{opt_name}",
                description=f"Socket option {opt_name} (opt={opt_num})",
                kernel_entrypoint="",
                shared_contract=opt_name,
                dispatch_key=str(opt_num),
                status=status,
                evidence=[Evidence(
                    file_path="<uapi>",
                    line_start=0,
                    symbol=opt_name,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"#define {opt_name} {opt_num}",
                )],
            )
            self.store.upsert_surface(surf)

    def _build_sysctl_surfaces(self):
        """Build surfaces for sysctl entries."""
        regs = self.store.find_symbols(kind="registration")
        for sym in regs:
            if sym.properties.get("type") == "sysctl":
                path = sym.properties.get("path", "unknown")
                surf = BoundarySurface(
                    boundary_type=BoundaryType.SYSCTL,
                    name=f"sysctl:{path}",
                    description=f"sysctl at {path}",
                    kernel_entrypoint=sym.name,
                    status=WiringStatus.REGISTERED,
                    evidence=sym.evidence,
                )
                self.store.upsert_surface(surf)

    def _build_ioctl_surfaces(self):
        """Build surfaces for ioctl commands."""
        if not hasattr(self.profile, "IOCTL_MAP"):
            return

        for cmd_num, cmd_name in self.profile.IOCTL_MAP.items():
            # Check for case dispatch
            dispatch = self.store.find_symbols(name=cmd_name, kind="enum_value")
            has_dispatch = bool(dispatch)

            status = WiringStatus.DECLARED
            if has_dispatch:
                status = WiringStatus.DISPATCH_LINKED

            surf = BoundarySurface(
                boundary_type=BoundaryType.IOCTL,
                name=f"ioctl:{cmd_name}",
                description=f"ioctl command {cmd_name} (magic='Q', nr={cmd_num})",
                kernel_entrypoint="",
                shared_contract=cmd_name,
                dispatch_key=str(cmd_num),
                status=status,
                evidence=[Evidence(
                    file_path="<uapi>",
                    line_start=0,
                    symbol=cmd_name,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"ioctl _IOWR('Q', {cmd_num}, ...)",
                )],
            )
            self.store.upsert_surface(surf)
