"""Pattern-based symbol and boundary extraction.

Uses LanguageDef definitions from languages.py for all regex patterns.
Each language ships its own symbol + boundary patterns. Users can add
new languages or override builtins via JSON config.

Every extracted fact is tagged with ExtractionMethod.PATTERN_MATCH.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from .languages import LanguageDef, LintPattern, SymbolPattern, BoundaryPattern, detect_language
from .models import (
    BoundarySurface, BoundaryType, Confidence, EdgeKind, Evidence,
    ExtractionMethod, GraphEdge, Side, SymbolKind, SymbolNode,
    WiringStatus,
)
from .repo_scan import ScannedFile

log = logging.getLogger(__name__)


class PatternExtractor:
    """Extract symbols and relationships from source files using language definitions."""

    def __init__(self, profile):
        self.profile = profile
        # Cache compiled regexes per language
        self._compiled: dict[str, dict[str, re.Pattern]] = {}

    def _compile(self, lang: LanguageDef) -> dict[str, re.Pattern]:
        """Compile all regexes for a language (cached)."""
        if lang.name in self._compiled:
            return self._compiled[lang.name]

        compiled = {}
        for sp in lang.symbol_patterns:
            try:
                compiled[f"sym:{sp.name}"] = re.compile(sp.regex, re.MULTILINE)
            except re.error as e:
                log.warning("Bad regex in %s/%s: %s", lang.name, sp.name, e)
        for bp in lang.boundary_patterns:
            try:
                compiled[f"bnd:{bp.name}"] = re.compile(bp.regex, re.MULTILINE)
            except re.error as e:
                log.warning("Bad regex in %s/%s: %s", lang.name, bp.name, e)
        self._compiled[lang.name] = compiled
        return compiled

    def extract_file(self, sf: ScannedFile) -> ExtractedFile:
        """Extract all facts from a single file."""
        try:
            with open(sf.abs_path, "r", errors="replace") as f:
                content = f.read()
        except (OSError, IOError) as e:
            log.warning("Cannot read %s: %s", sf.abs_path, e)
            return ExtractedFile(sf.rel_path)

        result = ExtractedFile(sf.rel_path)
        _, lang = detect_language(sf.rel_path)

        if lang is None:
            return result

        compiled = self._compile(lang)
        ext = Path(sf.rel_path).suffix.lstrip(".")

        # ── Extract symbols ──
        for sp in lang.symbol_patterns:
            if sp.only_in and ext != sp.only_in:
                continue
            pat = compiled.get(f"sym:{sp.name}")
            if not pat:
                continue

            for m in pat.finditer(content):
                name = m.group(sp.group)
                line = content[:m.start()].count("\n") + 1

                # For struct_var in C, detect ops tables
                kind = sp.kind
                if sp.name == "struct_var":
                    struct_type = m.group(1)
                    if any(kw in struct_type for kw in (
                        "ops", "proto", "family", "ctl_table", "nf_hook",
                    )):
                        kind = SymbolKind.OPS_TABLE

                    # Also extract ops table field assignments
                    self._extract_ops_fields(
                        content, m, name, line, sf, result, compiled, lang)

                # For enum_def, also extract inner values
                if sp.name == "enum_def":
                    self._extract_enum_values(
                        content, m, name, line, sf, result)

                # For #define, filter to profile-relevant prefixes
                if sp.kind == SymbolKind.CONSTANT:
                    prefixes = (self.profile.get_command_prefixes() +
                                self.profile.get_option_prefixes() +
                                self.profile.get_attribute_prefixes())
                    if prefixes and not any(name.startswith(p) for p in prefixes):
                        if not name.startswith("SOL_"):
                            continue

                sym = SymbolNode(
                    name=name,
                    kind=kind,
                    side=sf.side,
                    file_path=sf.rel_path,
                    line_start=line,
                    properties={},
                    evidence=[Evidence(
                        file_path=sf.rel_path,
                        line_start=line,
                        symbol=name,
                        snippet=m.group(0)[:120],
                        method=ExtractionMethod.PATTERN_MATCH,
                        confidence=sp.confidence,
                    )],
                )

                # Add extra properties for defines
                if sp.kind == SymbolKind.CONSTANT and m.lastindex and m.lastindex >= 2:
                    sym.properties["value"] = m.group(2).strip()

                # Add struct_type for struct_var
                if sp.name == "struct_var":
                    sym.qualified_name = f"{m.group(1)}.{name}"
                    sym.properties["struct_type"] = m.group(1)

                # Extract function signatures for mismatch detection
                if sp.name in ("function_def", "function_decl",
                               "init_function", "exit_function"):
                    sig = self._extract_c_signature(content, m, name)
                    if sig:
                        sym.properties["signature"] = sig
                        sym.properties["sig_kind"] = sp.name

                # For function definitions, capture body metrics
                if sp.name in ("function_def", "init_function",
                               "exit_function"):
                    body_info = self._analyze_function_body(content, m)
                    if body_info:
                        sym.properties.update(body_info)

                result.symbols.append(sym)

        # ── Extract boundary artifacts ──
        for bp in lang.boundary_patterns:
            pat = compiled.get(f"bnd:{bp.name}")
            if not pat:
                continue

            for m in pat.finditer(content):
                line = content[:m.start()].count("\n") + 1

                if bp.extract_type == "dispatch":
                    case_grp = bp.groups.get("case", 1)
                    case_name = m.group(case_grp)
                    # Filter to profile-relevant cases
                    prefixes = (self.profile.get_command_prefixes() +
                                self.profile.get_option_prefixes())
                    if prefixes and not any(case_name.startswith(p)
                                            for p in prefixes):
                        continue
                    result.dispatch_entries.append({
                        "case": case_name,
                        "file": sf.rel_path,
                        "line": line,
                    })

                elif bp.extract_type == "registration":
                    reg_data = {"type": bp.name, "file": sf.rel_path, "line": line}
                    for field_name, grp in bp.groups.items():
                        reg_data[field_name] = m.group(grp)
                    result.registrations.append(reg_data)

                elif bp.extract_type == "attr_read":
                    result.attr_reads.append({
                        "attr": m.group(bp.groups.get("attr", 2)),
                        "type": m.group(bp.groups.get("type", 1)),
                        "file": sf.rel_path,
                        "line": line,
                    })

                elif bp.extract_type == "attr_write":
                    result.attr_writes.append({
                        "attr": m.group(bp.groups.get("attr", 2)),
                        "type": m.group(bp.groups.get("type", 1)),
                        "file": sf.rel_path,
                        "line": line,
                    })

                elif bp.extract_type == "ops_field":
                    # Handled inline in struct_var extraction
                    pass

                elif bp.extract_type == "internal":
                    # Skip overly broad patterns like function_call in extraction
                    # (these are used by rules engine via direct regex, not stored)
                    if bp.name == "function_call":
                        continue
                    ref = {"file": sf.rel_path, "line": line, "pattern": bp.name}
                    for field_name, grp in bp.groups.items():
                        if isinstance(grp, int):
                            ref[field_name] = m.group(grp)
                        else:
                            ref[field_name] = grp  # static value like "module_init"
                    result.internal_refs.append(ref)

        # ── Go-specific: extract constant references to profile commands ──
        if lang.name == "go":
            self._extract_go_const_refs(content, sf, result)

        # ── Call graph extraction ──
        if lang.name in ("c", "go", "rust"):
            self._extract_call_graph(content, sf, result, lang, compiled)

        # ── Lint pattern extraction ──
        if lang.lint_patterns:
            self._extract_lint(content, sf, result, lang, ext)

        return result

    # ── Function body analysis ──

    _STUB_MARKERS = re.compile(
        r'\b(?:TODO|FIXME|HACK|XXX|STUB|NOT\s+IMPLEMENTED|UNIMPLEMENTED)\b',
        re.IGNORECASE,
    )

    def _analyze_function_body(self, content: str, match) -> dict:
        """Analyze a function body to determine if it's live, stub, or empty."""
        body_start = match.end()
        brace_depth = 1
        pos = body_start
        max_pos = min(body_start + 50000, len(content))
        while pos < max_pos and brace_depth > 0:
            ch = content[pos]
            if ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
            pos += 1

        if brace_depth != 0:
            return {}

        body = content[body_start:pos - 1]
        body_lines = body.count("\n") + 1

        # Strip comments and whitespace for real content analysis
        stripped = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
        stripped = re.sub(r'//.*$', '', stripped, flags=re.MULTILINE)
        stripped = stripped.strip()

        # Classify the body
        has_todo = bool(self._STUB_MARKERS.search(body))
        is_empty = not stripped or stripped in ("{", "}", "")

        # Check for return-only stubs: just "return 0;" or "return -ENOTSUPP;"
        is_return_only = False
        non_empty_lines = [l.strip() for l in stripped.split("\n")
                          if l.strip() and not l.strip().startswith("//")]
        if len(non_empty_lines) <= 2:
            if all(l.startswith("return") or l == "" for l in non_empty_lines):
                is_return_only = True

        status = "live"
        if is_empty:
            status = "empty"
        elif has_todo and body_lines <= 10:
            status = "stub_todo"
        elif is_return_only:
            status = "stub_return"
        elif has_todo:
            status = "live_todo"

        return {
            "body_lines": body_lines,
            "body_status": status,
            "has_todo": has_todo,
        }

    # ── Signature extraction ──

    _RE_C_SIG = re.compile(
        r'(\w[\w\s\*]+?)\s*'   # return type
        r'(\w+)\s*'             # function name
        r'\(([^)]*)\)',          # parameter list
    )

    def _extract_c_signature(self, content: str, match, func_name: str) -> str:
        """Extract a normalized function signature from around a regex match.

        Returns a canonical form like "int(struct foo *, int)" that can
        be compared across declarations and definitions.
        """
        start = max(0, match.start() - 20)
        end = min(len(content), match.end() + 200)
        snippet = content[start:end]

        for m in self._RE_C_SIG.finditer(snippet):
            if m.group(2) == func_name:
                ret_type = self._normalize_type(m.group(1))
                params = m.group(3).strip()
                param_types = self._normalize_params(params)
                return f"{ret_type}({param_types})"
        return ""

    @staticmethod
    def _normalize_type(t: str) -> str:
        """Normalize a C type string for comparison."""
        t = re.sub(r'\b(static|inline|extern|__init|__exit|const)\b', '', t)
        t = re.sub(r'\s+', ' ', t).strip()
        return t or "void"

    @staticmethod
    def _normalize_params(params: str) -> str:
        """Normalize parameter list: keep types, drop names."""
        if not params or params.strip() == "void":
            return "void"
        parts = []
        for param in params.split(","):
            param = param.strip()
            if not param:
                continue
            param = re.sub(r'\b(static|inline|const)\b', '', param).strip()
            tokens = param.split()
            if len(tokens) >= 2:
                last = tokens[-1].rstrip("*")
                if last and last[0].islower() and last not in (
                    "int", "long", "short", "char", "void", "bool",
                    "size_t", "ssize_t",
                ):
                    type_part = " ".join(tokens[:-1])
                    stars = len(tokens[-1]) - len(last)
                    if stars:
                        type_part += " " + "*" * stars
                    parts.append(type_part.strip())
                else:
                    parts.append(param)
            else:
                parts.append(param)
        return ", ".join(parts) if parts else "void"

    def _extract_ops_fields(self, content, struct_match, var_name, start_line,
                            sf, result, compiled, lang):
        """Extract .field = handler entries from a struct initializer."""
        brace_start = struct_match.end()
        brace_depth = 1
        pos = brace_start
        while pos < len(content) and brace_depth > 0:
            if content[pos] == "{":
                brace_depth += 1
            elif content[pos] == "}":
                brace_depth -= 1
            pos += 1
        block = content[brace_start:pos]

        ops_pat = compiled.get("bnd:ops_field")
        if not ops_pat:
            # Fallback: use a simple pattern
            ops_pat = re.compile(r'^\s*\.(\w+)\s*=\s*(\w+)\s*,', re.MULTILINE)

        for fm in ops_pat.finditer(block):
            field_name = fm.group(1)
            handler_name = fm.group(2)
            fline = start_line + block[:fm.start()].count("\n")

            result.edges.append(GraphEdge(
                source_id="",
                target_id="",
                kind=EdgeKind.IMPLEMENTS,
                confidence=Confidence.HIGH,
                properties={
                    "ops_table": var_name,
                    "field": field_name,
                    "handler": handler_name,
                },
                evidence=[Evidence(
                    file_path=sf.rel_path,
                    line_start=fline,
                    symbol=handler_name,
                    snippet=fm.group(0).strip(),
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                    note=f"{var_name}.{field_name} = {handler_name}",
                )],
            ))

    def _extract_enum_values(self, content, enum_match, enum_name,
                             start_line, sf, result):
        """Extract enum member values from an enum block."""
        brace_start = enum_match.end()
        brace_end = content.find("}", brace_start)
        if brace_end <= 0:
            return
        block = content[brace_start:brace_end]
        val_re = re.compile(r'^\s+(\w+)\s*(?:=\s*[^,]+)?\s*,', re.MULTILINE)
        for vm in val_re.finditer(block):
            val_name = vm.group(1)
            if val_name.startswith("__"):
                continue
            vline = start_line + block[:vm.start()].count("\n")
            result.symbols.append(SymbolNode(
                name=val_name,
                qualified_name=f"{enum_name}.{val_name}",
                kind=SymbolKind.ENUM_VALUE,
                side=sf.side,
                file_path=sf.rel_path,
                line_start=vline,
                evidence=[Evidence(
                    file_path=sf.rel_path,
                    line_start=vline,
                    symbol=val_name,
                    method=ExtractionMethod.PATTERN_MATCH,
                    confidence=Confidence.HIGH,
                )],
            ))

    def _extract_go_const_refs(self, content, sf, result):
        """Extract Go constant references to profile commands/attrs."""
        prefixes = (self.profile.get_command_prefixes() +
                    self.profile.get_attribute_prefixes())
        for prefix in prefixes:
            pat = re.compile(rf'\b({re.escape(prefix)}\w+)\b')
            for m in pat.finditer(content):
                name = m.group(1)
                line = content[:m.start()].count("\n") + 1
                lines = content.split("\n")
                snippet = lines[line - 1].strip()[:100] if line <= len(lines) else ""
                result.symbols.append(SymbolNode(
                    name=name,
                    kind=SymbolKind.GO_CONST,
                    side=Side.USERSPACE,
                    file_path=sf.rel_path,
                    line_start=line,
                    evidence=[Evidence(
                        file_path=sf.rel_path,
                        line_start=line,
                        symbol=name,
                        snippet=snippet,
                        method=ExtractionMethod.PATTERN_MATCH,
                        confidence=Confidence.MEDIUM,
                        note="Go constant reference",
                    )],
                ))


    # ── Call graph extraction ──

    # C/Go/Rust keywords and macros that look like function calls but aren't
    _CALL_SKIP = frozenset({
        # C keywords
        "if", "else", "while", "for", "do", "switch", "case", "return",
        "goto", "sizeof", "typeof", "__typeof__", "alignof", "_Alignof",
        "offsetof", "defined",
        # C macros that aren't calls
        "likely", "unlikely", "WARN", "BUG", "WARN_ON", "BUG_ON",
        "WARN_ON_ONCE", "BUILD_BUG_ON", "IS_ERR", "PTR_ERR", "ERR_PTR",
        "ERR_CAST", "IS_ENABLED", "IS_BUILTIN", "IS_MODULE",
        "pr_err", "pr_info", "pr_warn", "pr_debug", "pr_notice",
        "pr_info_ratelimited", "pr_warn_ratelimited",
        "printk", "dev_err", "dev_warn", "dev_info", "dev_dbg",
        "ARRAY_SIZE", "container_of", "list_for_each_entry",
        "list_for_each_entry_safe", "list_for_each", "hlist_for_each_entry",
        "rcu_read_lock", "rcu_read_unlock", "rcu_dereference",
        "rcu_assign_pointer", "rcu_access_pointer",
        "spin_lock", "spin_unlock", "spin_lock_bh", "spin_unlock_bh",
        "spin_lock_irqsave", "spin_unlock_irqrestore", "spin_lock_init",
        "mutex_lock", "mutex_unlock", "mutex_init",
        "READ_ONCE", "WRITE_ONCE", "smp_store_release", "smp_load_acquire",
        "smp_rmb", "smp_wmb", "smp_mb",
        "EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL",
        "module_init", "module_exit", "MODULE_LICENSE", "MODULE_AUTHOR",
        "MODULE_DESCRIPTION", "MODULE_VERSION",
        "GFP_KERNEL", "GFP_ATOMIC", "NULL",
        "min", "max", "min_t", "max_t", "clamp",
        "atomic_read", "atomic_set", "atomic_inc", "atomic_dec",
        "refcount_read", "refcount_set", "refcount_inc", "refcount_dec",
        "INIT_LIST_HEAD", "INIT_HLIST_NODE",
        # Go keywords
        "func", "range", "select", "defer", "go", "make", "len", "cap",
        "append", "copy", "delete", "close", "panic", "recover", "new",
        # Rust keywords
        "match", "loop", "impl", "unsafe", "async", "await", "move",
        "Box", "Vec", "String", "Some", "None", "Ok", "Err",
    })

    # Regex to find function calls: identifier followed by (
    _RE_CALL = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')

    def _extract_call_graph(self, content: str, sf, result, lang, compiled):
        """Extract function-to-function call edges.

        For each function body, find all identifier( patterns and record
        caller→callee relationships. These are resolved against the symbol
        table in graph_build to produce actual CALLS edges.
        """
        # Find all function definitions with their body ranges
        func_pat = compiled.get("sym:function_def")
        if not func_pat:
            return

        # Also check init/exit function patterns
        init_pat = compiled.get("sym:init_function")
        exit_pat = compiled.get("sym:exit_function")

        # Collect all function definition matches
        func_matches = []
        if func_pat:
            for m in func_pat.finditer(content):
                func_matches.append(m)
        if init_pat:
            for m in init_pat.finditer(content):
                func_matches.append(m)
        if exit_pat:
            for m in exit_pat.finditer(content):
                func_matches.append(m)

        # Sort by position to process in order
        func_matches.sort(key=lambda m: m.start())

        for m in func_matches:
            # Determine the function name (group 1 for most patterns)
            try:
                caller = m.group(1)
            except IndexError:
                continue

            # Find the function body by matching braces
            # The match ends just after the opening {
            body_start = m.end()
            brace_depth = 1
            pos = body_start
            max_pos = min(body_start + 50000, len(content))  # cap at 50KB per function
            while pos < max_pos and brace_depth > 0:
                ch = content[pos]
                if ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                pos += 1

            if brace_depth != 0:
                continue  # couldn't find matching brace

            body = content[body_start:pos - 1]

            # Find all calls within this function body
            for cm in self._RE_CALL.finditer(body):
                callee = cm.group(1)
                # Skip keywords and macros
                if callee in self._CALL_SKIP:
                    continue
                # Skip very short names (likely macros/vars) and ALL_CAPS (macros)
                if len(callee) < 3:
                    continue
                if callee.isupper():
                    continue

                call_line = (content[:body_start].count("\n") +
                             body[:cm.start()].count("\n") + 1)

                result.call_refs.append({
                    "caller": caller,
                    "callee": callee,
                    "file": sf.rel_path,
                    "line": call_line,
                })


    # ── Lint pattern extraction ──

    def _extract_lint(self, content: str, sf, result, lang, ext: str):
        """Run lint patterns against file content and collect hits."""
        for lp in lang.lint_patterns:
            if lp.only_in and ext != lp.only_in:
                continue
            try:
                flags = re.MULTILINE
                if lp.multiline:
                    flags |= re.DOTALL
                pat = re.compile(lp.regex, flags)
            except re.error:
                continue

            for m in pat.finditer(content):
                line = content[:m.start()].count("\n") + 1
                snippet = m.group(0)[:120].strip()
                result.lint_hits.append({
                    "name": lp.name,
                    "severity": lp.severity,
                    "category": lp.category,
                    "message": lp.message,
                    "recommendation": lp.recommendation,
                    "file": sf.rel_path,
                    "line": line,
                    "snippet": snippet,
                })


class ExtractedFile:
    """Results of extracting facts from a single file."""

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.symbols: list[SymbolNode] = []
        self.edges: list[GraphEdge] = []
        self.registrations: list[dict] = []
        self.dispatch_entries: list[dict] = []
        self.attr_reads: list[dict] = []
        self.attr_writes: list[dict] = []
        self.internal_refs: list[dict] = []
        self.call_refs: list[dict] = []    # {caller, callee, file, line}
        self.lint_hits: list[dict] = []    # {name, severity, category, message, ...}
