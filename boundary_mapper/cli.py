"""CLI entry point for boundary mapper.

Designed for zero-config use when .boundary-mapper.json exists in the repo.

Examples:
    # First time — scaffold a config for your module
    boundary-mapper init mymod

    # Scan your repo (auto-detects config)
    boundary-mapper scan

    # Fresh scan (wipe old data)
    boundary-mapper scan --fresh

    # Quick queries
    boundary-mapper surfaces
    boundary-mapper findings --high
    boundary-mapper show MY_OPT_FOO

    # Use a bundled profile on any repo
    boundary-mapper scan --repo /path/to/repo --profile custom

    # List available profiles
    boundary-mapper profiles
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from . import __version__


# ─── Terminal colors ───

def _use_color():
    """Check if stdout supports color."""
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()

_COLOR = _use_color()

def _c(code: str, text: str) -> str:
    """Apply ANSI color if terminal supports it."""
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def RED(t):     return _c("91", t)
def GREEN(t):   return _c("92", t)
def YELLOW(t):  return _c("93", t)
def BLUE(t):    return _c("94", t)
def CYAN(t):    return _c("96", t)
def DIM(t):     return _c("2", t)
def BOLD(t):    return _c("1", t)
def BRED(t):    return _c("1;91", t)
def BGREEN(t):  return _c("1;92", t)
def BYELLOW(t): return _c("1;93", t)
from .config import (
    AnalysisConfig, CONFIG_FILENAME, generate_config_template,
    generate_claude_skill,
)
from .db import FactStore
from .graph_build import GraphBuilder
from .languages import (
    BUILTIN_LANGUAGES, language_from_json, register_language, get_language,
)
from .pattern_extract import PatternExtractor
from .profiles.base import BaseProfile
from .profiles.custom import CustomProfile
from .repo_scan import scan_repo
from .reporting.report_md import generate_report, generate_surface_detail
from .reporting.report_json import generate_json_report
from .reporting.report_dot import generate_dot
from .rules_engine import RulesEngine

log = logging.getLogger("boundary_mapper")

# ─── Profile registry ───

BUILTIN_PROFILES = {
    "base": (BaseProfile, "Generic Linux kernel module (no sockopt/genl maps)"),
}


def resolve_profile(name: str, custom_data: dict = None):
    """Resolve a profile by name. Supports builtins and JSON-defined custom."""
    if name == "custom" and custom_data:
        return CustomProfile(custom_data)
    entry = BUILTIN_PROFILES.get(name)
    if entry:
        return entry[0]()
    print(f"Unknown profile: {name}")
    print(f"Available: {', '.join(BUILTIN_PROFILES.keys())}, custom")
    print(f"Run 'boundary-mapper init' to create a custom profile.")
    sys.exit(1)


# ─── Config resolution ───

def _load_custom_languages(config_data: dict):
    """Register any custom languages defined in the config file."""
    for lang_data in config_data.get("languages", []):
        try:
            lang = language_from_json(lang_data)
            register_language(lang)
            log.info("Registered custom language: %s (%s)",
                     lang.name, ", ".join(lang.extensions))
        except Exception as e:
            log.warning("Failed to load custom language %s: %s",
                        lang_data.get("name", "?"), e)


def load_config(args) -> tuple:
    """Load config from args + auto-detected config file. Returns (config, profile)."""
    repo_path = Path(args.repo).resolve()

    # Try auto-detect config file
    auto = AnalysisConfig.auto_detect(repo_path)

    # Load custom languages from config
    cfg_path = repo_path / CONFIG_FILENAME
    if cfg_path.is_file():
        with open(cfg_path) as f:
            raw = json.load(f)
        _load_custom_languages(raw)

    # CLI args override auto-detected values
    if auto:
        config = auto
        if args.profile != "_auto_":
            config.profile_name = args.profile
        if args.db != ".boundary_mapper.db":
            config.db_path = Path(args.db)
        config.verbose = args.verbose
    else:
        profile_name = args.profile if args.profile != "_auto_" else "base"
        config = AnalysisConfig(
            repo_root=repo_path,
            profile_name=profile_name,
            db_path=Path(args.db),
            verbose=args.verbose,
        )

    config.resolve()
    profile = resolve_profile(config.profile_name, config.custom_profile_data)
    return config, profile


def load_store(args) -> FactStore:
    """Quick helper: resolve config and open the DB."""
    repo_path = Path(args.repo).resolve()
    auto = AnalysisConfig.auto_detect(repo_path)
    db_path = Path(args.db)
    if auto and args.db == ".boundary_mapper.db":
        db_path = auto.db_path or db_path
    if not db_path.is_absolute():
        db_path = repo_path / db_path
    return FactStore(db_path)


# ─── Commands ───

def cmd_init(args):
    """Scan the repo and generate .boundary-mapper.json automatically."""
    module_name = args.module or Path(args.repo).resolve().name
    profile = args.profile if args.profile != "_auto_" else "custom"
    repo = Path(args.repo).resolve()
    cfg_path = repo / CONFIG_FILENAME

    if cfg_path.exists() and not args.force:
        print(f"Config already exists: {cfg_path}")
        print(f"Use --force to overwrite.")
        return

    if profile in BUILTIN_PROFILES and profile != "base":
        data = {"profile": profile}
    else:
        print(f"Scanning {repo} ...")
        data = generate_config_template(profile, module_name, repo_root=repo)
        custom = data.get("custom", {})
        n_dirs = len(custom.get("directories", []))
        n_sock = len(custom.get("sockopt_map", {}))
        n_genl = len(custom.get("genl_families", {}))
        n_kp = len(custom.get("kernel_paths", []))
        n_up = len(custom.get("userspace_paths", []))
        print(f"Discovered: {n_dirs} directories, {n_kp} kernel paths, "
              f"{n_up} userspace paths, {n_sock} sockopts, {n_genl} genl families")

    with open(cfg_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Created {cfg_path}")

    # Generate Claude skill if requested or by default
    if args.skill:
        _generate_skill(repo, module_name)

    print()
    if profile == "custom":
        print(f"Ready to scan. Run:")
        print(f"  boundary-mapper scan --fresh")
        print()
        print(f"Review {CONFIG_FILENAME} if you want to adjust paths or prefixes.")
        if not args.skill:
            print(f"Add --skill to generate a Claude Code skill for AI assistants.")
    else:
        print(f"Using builtin profile: {profile}")
        print(f"Run: boundary-mapper scan")


def _generate_skill(repo: Path, module_name: str):
    """Generate a Claude Code skill for this project."""
    # Try ~/.claude/skills/ first, fall back to repo-local
    home_skills = Path.home() / ".claude" / "skills" / f"{module_name}-boundary-mapper"
    repo_skills = repo / ".claude" / "skills" / f"{module_name}-boundary-mapper"

    # Determine tool path relative to repo
    tool_rel = "."
    bm_dir = repo / "tools" / "boundary_mapper"
    if bm_dir.is_dir():
        tool_rel = "tools/boundary_mapper"

    skill_content = generate_claude_skill(module_name, tool_rel)

    # Write to home dir if .claude/skills exists, otherwise repo-local
    if home_skills.parent.parent.exists():
        target = home_skills
    else:
        target = repo_skills

    target.mkdir(parents=True, exist_ok=True)
    skill_path = target / "skill.md"
    with open(skill_path, "w") as f:
        f.write(skill_content)
    print(f"Created Claude skill: {skill_path}")


def cmd_scan(args):
    """Full scan: walk repo, extract, build graph, run rules, report."""
    config, profile = load_config(args)
    store = FactStore(config.db_path)

    if args.fresh:
        log.info("Clearing existing data")
        store.clear_all()

    t0 = time.time()

    # Phase 1: Scan repo
    log.info("Phase 1: Scanning repository at %s", config.repo_root)
    layout = scan_repo(config, profile)

    # Phase 2: Extract symbols and boundaries
    log.info("Phase 2: Extracting symbols from %d files", len(layout.files))
    extractor = PatternExtractor(profile)
    builder = GraphBuilder(store, profile)

    # Use profile to determine relevant paths
    # Accept all language tags that have a LanguageDef registered
    relevant_langs = set()
    for lang in BUILTIN_LANGUAGES.values():
        for ext in lang.extensions:
            relevant_langs.add(ext.lstrip("."))  # "c", "h", "go", "rs", etc.
    relevant_paths = set()
    for pat in (profile.get_kernel_file_patterns() +
                profile.get_userspace_file_patterns() +
                profile.get_shared_header_patterns() +
                profile.get_test_file_patterns()):
        parts = pat.split("*")[0].rstrip("/")
        if parts:
            relevant_paths.add(parts)

    relevant_files = []
    for f in layout.files:
        if f.language not in relevant_langs:
            continue
        if not relevant_paths or any(f.rel_path.startswith(p)
                                     for p in relevant_paths):
            relevant_files.append(f)

    log.info("Filtered to %d relevant files", len(relevant_files))

    for sf in relevant_files:
        extracted = extractor.extract_file(sf)
        builder.ingest(extracted)

    # Phase 3-5
    log.info("Phase 3: Resolving cross-references")
    builder.resolve_edges()

    log.info("Phase 4: Building boundary surfaces")
    builder.build_boundary_surfaces(layout)

    log.info("Phase 5: Running rules engine")
    engine = RulesEngine(store, profile)
    findings = engine.run_all()

    elapsed = time.time() - t0
    stats = store.stats()

    # Always generate markdown report
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    md_path = output_dir / "boundary_report.md"
    generate_report(store, md_path, profile.name)

    # Optional extra formats
    if not args.no_extras:
        generate_json_report(store, output_dir / "boundary_report.json",
                             profile.name)
        generate_dot(store, output_dir / "boundary_graph.dot")

    # Print summary
    print(f"\n{'='*60}")
    print(f"Boundary Mapper v{__version__} — {profile.name}")
    print(f"{'='*60}")
    print(f"Scanned: {len(layout.files)} files "
          f"({layout.total_c_files} C, {layout.total_h_files} H, "
          f"{layout.total_go_files} Go)")
    # Count call graph edges specifically
    call_edges = len(store.get_edges(kind="calls", limit=1))
    total_calls = stats['edges'] - call_edges  # approximate ops edges
    print(f"Symbols: {stats['symbols']}")
    print(f"Edges:   {stats['edges']} ({call_edges and 'incl. call graph' or 'ops only'})")
    print(f"Surfaces:{stats['surfaces']:>5}")
    print(f"Findings:{stats['findings']:>5}")
    print(f"Time:    {elapsed:.1f}s")
    print(f"\nReport: {md_path}")

    store.close()


def cmd_surfaces(args):
    """List boundary surfaces."""
    store = load_store(args)
    surfaces = store.get_surfaces(boundary_type=args.type or "")
    for s in sorted(surfaces, key=lambda x: (
            x.boundary_type.value,
            -x.properties.get("importance_score", 0),
            x.name)):
        icon = {
            "declared": "⬜", "dispatch_linked": "🔗",
            "statically_reachable": "✅", "registered": "🟩",
            "dead": "💀", "partially_wired": "⚠️",
        }.get(s.status.value, "❓")
        p = s.properties
        sub = p.get("substatus", "")
        sub_tag = f" [{sub}]" if sub else ""
        imp = p.get("importance_score")
        imp_tag = f" imp={imp}" if imp is not None else ""
        print(f"{icon} [{s.boundary_type.value:>10}] "
              f"{s.name} → {s.handler or 'NO HANDLER'}"
              f"{sub_tag}{imp_tag}")
    print(f"\nTotal: {len(surfaces)} surfaces")
    store.close()


def cmd_findings(args):
    """List findings."""
    store = load_store(args)

    # Resolve severity filter from --high/--medium/--low/--severity
    severity = ""
    if getattr(args, "high", False):
        severity = "high"
    elif getattr(args, "medium", False):
        severity = "medium"
    elif getattr(args, "low", False):
        severity = "low"
    elif getattr(args, "info", False):
        severity = "info"
    elif args.severity:
        severity = args.severity

    findings = store.get_findings(severity=severity, limit=args.limit)
    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🔵", "info": "⚪"}.get(f.severity.value, "❓")
        rec = f" → {f.recommendation}" if f.recommendation else ""
        print(f"{icon} [{f.severity.value:>8}] {f.id}: {f.title}{rec}")
        if args.verbose:
            print(f"  {f.description}")
            for ev in f.evidence[:3]:
                print(f"  └ {ev.file_path}:{ev.line_start} "
                      f"[{ev.confidence.value}]")
    print(f"\nTotal: {len(findings)} findings")
    store.close()


def cmd_trace(args):
    """Trace call paths line by line, showing status at every hop."""
    from collections import defaultdict, deque

    store = load_store(args)

    # Build function info index: name → {file, line, body_lines, body_status, signature}
    func_info = {}
    for sym in store.find_symbols(kind="function_def", limit=50000):
        func_info[sym.name] = {
            "file": sym.file_path,
            "line": sym.line_start,
            "body_lines": sym.properties.get("body_lines", 0),
            "body_status": sym.properties.get("body_status", "unknown"),
            "has_todo": sym.properties.get("has_todo", False),
            "signature": sym.properties.get("signature", ""),
        }
    # Also index declarations
    func_decls = {}
    for sym in store.find_symbols(kind="function_decl", limit=20000):
        sig = sym.properties.get("signature", "")
        if sig:
            func_decls.setdefault(sym.name, []).append({
                "file": sym.file_path, "line": sym.line_start, "sig": sig,
            })

    # Build call graph with evidence
    call_edges = store.get_edges(kind="calls", limit=200000)
    fwd = defaultdict(list)
    rev = defaultdict(list)
    for edge in call_edges:
        caller = edge.properties.get("caller", "")
        callee = edge.properties.get("callee", "")
        if not caller or not callee:
            continue
        ev = edge.evidence[0] if edge.evidence else None
        file_path = ev.file_path if ev else "?"
        line = ev.line_start if ev else 0
        fwd[caller].append((callee, file_path, line))
        rev[callee].append((caller, file_path, line))

    func = args.function
    depth = args.depth

    # Fuzzy match
    all_names = set(fwd.keys()) | set(rev.keys()) | set(func_info.keys())
    if func not in all_names:
        matches = [n for n in all_names if func.lower() in n.lower()]
        if not matches:
            print(f"Function '{func}' not found in call graph.")
            print(f"Call graph has {len(all_names)} functions.")
            store.close()
            return
        if len(matches) == 1:
            func = matches[0]
            print(f"(matched: {func})")
        else:
            matches.sort()
            print(f"Multiple matches for '{args.function}':")
            for m in matches[:20]:
                tag = _status_tag(func_info.get(m, {}))
                callers = len(rev.get(m, []))
                callees = len(fwd.get(m, []))
                print(f"  {m}  ({callers} callers, {callees} callees) {tag}")
            if len(matches) > 20:
                print(f"  ... +{len(matches) - 20} more")
            store.close()
            return
    print()

    if args.to:
        _trace_path_full(fwd, func, args.to, all_names, func_info)
    elif args.from_init:
        init_regs = store.find_symbols(name="__module_init__",
                                       kind="registration", limit=50)
        init_targets = [s.properties.get("target", "") for s in init_regs]
        if not init_targets:
            print("No module_init found.")
        else:
            found = False
            for root in init_targets:
                if root in all_names:
                    path = _find_path(fwd, root, func)
                    if path:
                        print(f"Call path: module_init({root}) → {func}")
                        print()
                        _render_path_full(path, fwd, func_info)
                        found = True
                        break
            if not found:
                print(f"{func} is NOT reachable from module_init.")
                print()
                _show_callers_full(rev, func, func_info, depth=2)
    else:
        _show_full_context(fwd, rev, func, func_info, func_decls, depth)

    store.close()


# ─── Status helpers ───

_STATUS_ICONS = {
    "live": "✅", "live_todo": "⚠️", "stub_todo": "🔨",
    "stub_return": "📌", "empty": "💀", "unknown": "❓", "missing": "❌",
}

def _status_tag(info: dict) -> str:
    """Generate a colored status tag."""
    if not info:
        return RED("[❌ MISSING]")
    status = info.get("body_status", "unknown")
    lines = info.get("body_lines", 0)
    icon = _STATUS_ICONS.get(status, "❓")
    label = status.upper().replace("_", " ")
    tag = f"[{icon} {label} {lines}L]" if lines else f"[{icon} {label}]"
    if status in ("live",):
        return GREEN(tag)
    if status in ("live_todo",):
        return YELLOW(tag)
    if status in ("stub_todo", "stub_return"):
        return YELLOW(tag)
    if status in ("empty", "missing", "unknown"):
        return RED(tag)
    return tag


def _func_location(info: dict) -> str:
    """Format file:line for a function."""
    if not info:
        return ""
    return f"{info.get('file', '?')}:{info.get('line', 0)}"


# ─── Path finding ───

def _find_path(fwd, start, end):
    from collections import deque
    if start == end:
        return [start]
    visited = {start}
    queue = deque([(start, [start])])
    while queue:
        current, path = queue.popleft()
        for callee, _, _ in fwd.get(current, []):
            if callee == end:
                return path + [callee]
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))
    return None


# ─── Rendering ───

def _render_path_full(path, fwd, func_info):
    """Render a call path with file:line AND status at every hop."""
    verdicts = {"live": 0, "stub": 0, "broken": 0}
    for i, name in enumerate(path):
        info = func_info.get(name, {})
        tag = _status_tag(info)
        loc = _func_location(info)
        indent = "  " * i

        if i == 0:
            print(f"{indent}{name}()  {loc}  {tag}")
        else:
            # Find the call site
            prev = path[i - 1]
            call_loc = ""
            for c, f, l in fwd.get(prev, []):
                if c == name:
                    call_loc = f"{f}:{l}"
                    break
            print(f"{indent}└─ {name}()  {loc}  {tag}")
            if call_loc and call_loc != loc:
                print(f"{indent}   call at {call_loc}")

        # Tally verdict
        status = info.get("body_status", "missing")
        if status in ("live", "live_todo"):
            verdicts["live"] += 1
        elif status in ("stub_todo", "stub_return", "empty"):
            verdicts["stub"] += 1
        else:
            verdicts["broken"] += 1

    # Print verdict
    print()
    total = len(path)
    if verdicts["broken"] > 0:
        print(f"  VERDICT: ❌ BROKEN — {verdicts['broken']}/{total} missing or undefined")
    elif verdicts["stub"] > 0:
        print(f"  VERDICT: 🔨 NEEDS WORK — {verdicts['stub']}/{total} stubbed, "
              f"{verdicts['live']}/{total} live")
    else:
        print(f"  VERDICT: ✅ FULLY WIRED — all {total} functions are live")


def _trace_path_full(fwd, start, end, all_names, func_info):
    if end not in all_names:
        matches = [n for n in all_names if end.lower() in n.lower()]
        if len(matches) == 1:
            end = matches[0]
            print(f"(target matched: {end})")
        elif matches:
            print(f"Multiple matches for '{end}':")
            for m in matches[:10]:
                print(f"  {m} {_status_tag(func_info.get(m, {}))}")
            return
        else:
            print(f"Target '{end}' not found.")
            return

    path = _find_path(fwd, start, end)
    if path:
        print(f"Call path ({len(path) - 1} hops):")
        print()
        _render_path_full(path, fwd, func_info)
    else:
        print(f"No call path from {start} to {end}.")


def _show_callers_full(rev, func, func_info, depth=3):
    print(f"  Callers of {func}():")
    seen = set()
    _callers_recursive(rev, func, func_info, depth, 2, seen)


def _callers_recursive(rev, func, func_info, max_depth, indent, seen):
    if func in seen:
        return
    seen.add(func)
    callers = rev.get(func, [])
    for caller, file_path, line in callers[:10]:
        info = func_info.get(caller, {})
        tag = _status_tag(info)
        prefix = " " * indent
        print(f"{prefix}← {caller}()  {file_path}:{line}  {tag}")
        if max_depth > 1:
            _callers_recursive(rev, caller, func_info, max_depth - 1,
                               indent + 2, seen)
    if len(callers) > 10:
        print(f"{' ' * indent}  ... +{len(callers) - 10} more callers")


def _show_full_context(fwd, rev, func, func_info, func_decls, depth):
    """Show full function context: status, callers, callees, signatures, verdict."""
    info = func_info.get(func, {})
    tag = _status_tag(info)
    loc = _func_location(info)
    callers = rev.get(func, [])
    callees = fwd.get(func, [])

    print(f"{'='*60}")
    print(f"  {func}()  {tag}")
    print(f"  {loc}")
    if info.get("signature"):
        print(f"  signature: {info['signature']}")
    print(f"{'='*60}")
    print(f"  {len(callers)} callers, {len(callees)} callees")

    # Check for signature mismatches
    decls = func_decls.get(func, [])
    if decls and info.get("signature"):
        for d in decls:
            if d["sig"] != info["signature"]:
                print(f"\n  ❌ SIGNATURE MISMATCH:")
                print(f"    def: {info['signature']}  ({info.get('file')})")
                print(f"    decl: {d['sig']}  ({d['file']}:{d['line']})")
    print()

    if callers:
        print(f"  CALLED BY ({len(callers)}):")
        for caller, file_path, line in sorted(callers,
                                              key=lambda x: x[0])[:20]:
            ci = func_info.get(caller, {})
            ctag = _status_tag(ci)
            print(f"    ← {caller}()  {file_path}:{line}  {ctag}")
        if len(callers) > 20:
            print(f"    ... +{len(callers) - 20} more")
        print()

    if callees:
        print(f"  CALLS ({len(callees)}):")
        live = stub = broken = 0
        for callee, file_path, line in sorted(callees,
                                              key=lambda x: x[0])[:30]:
            ci = func_info.get(callee, {})
            ctag = _status_tag(ci)
            print(f"    → {callee}()  {file_path}:{line}  {ctag}")
            s = ci.get("body_status", "missing")
            if s in ("live", "live_todo"):
                live += 1
            elif s in ("stub_todo", "stub_return", "empty"):
                stub += 1
            else:
                broken += 1
        if len(callees) > 30:
            print(f"    ... +{len(callees) - 30} more")
        print()
        print(f"  CALLEES: {live} live, {stub} stubbed, {broken} missing")

    # Transitive reach
    if depth > 1:
        visited = set()
        stack = [func]
        stubs_found = []
        broken_found = []
        while stack and len(visited) < 500:
            fn = stack.pop()
            if fn in visited:
                continue
            visited.add(fn)
            fi = func_info.get(fn, {})
            s = fi.get("body_status", "missing")
            if s in ("stub_todo", "stub_return", "empty") and fn != func:
                stubs_found.append(fn)
            elif s == "missing" and fn != func and fn not in func_info:
                broken_found.append(fn)
            for callee, _, _ in fwd.get(fn, []):
                if callee not in visited:
                    stack.append(callee)

        print(f"  TRANSITIVE REACH: {len(visited) - 1} functions")
        if stubs_found:
            print(f"  🔨 STUBS DOWNSTREAM ({len(stubs_found)}):")
            for s in stubs_found[:10]:
                si = func_info.get(s, {})
                print(f"    {s}  {_func_location(si)}  {_status_tag(si)}")
            if len(stubs_found) > 10:
                print(f"    ... +{len(stubs_found) - 10} more")
        if broken_found:
            print(f"  ❌ BROKEN DOWNSTREAM ({len(broken_found)}):")
            for b in broken_found[:10]:
                print(f"    {b}  [MISSING]")
        print()


def cmd_diagnose(args):
    """Full health check — one function or the whole repo."""
    from collections import defaultdict
    import re as _re
    store = load_store(args)
    repo_root = Path(args.repo).resolve()

    # If --all, run repo-wide audit instead of single function
    if getattr(args, "all", False):
        _diagnose_all(store, repo_root, args)
        store.close()
        return

    func = args.function
    if not func:
        print("Specify a function name, or use --all for repo-wide audit.")
        store.close()
        return

    # ── Build indexes ──
    func_info = {}
    for sym in store.find_symbols(kind="function_def", limit=50000):
        func_info[sym.name] = {
            "file": sym.file_path, "line": sym.line_start,
            "body_lines": sym.properties.get("body_lines", 0),
            "body_status": sym.properties.get("body_status", "unknown"),
            "has_todo": sym.properties.get("has_todo", False),
            "signature": sym.properties.get("signature", ""),
        }
    func_decls = defaultdict(list)
    for sym in store.find_symbols(kind="function_decl", limit=20000):
        sig = sym.properties.get("signature", "")
        if sig:
            func_decls[sym.name].append({
                "file": sym.file_path, "line": sym.line_start, "sig": sig,
            })

    call_edges = store.get_edges(kind="calls", limit=200000)
    fwd = defaultdict(list)
    rev = defaultdict(list)
    for edge in call_edges:
        caller = edge.properties.get("caller", "")
        callee = edge.properties.get("callee", "")
        if caller and callee:
            ev = edge.evidence[0] if edge.evidence else None
            fp = ev.file_path if ev else "?"
            ln = ev.line_start if ev else 0
            fwd[caller].append((callee, fp, ln))
            rev[callee].append((caller, fp, ln))

    # Fuzzy match
    all_names = set(func_info.keys()) | set(fwd.keys()) | set(rev.keys())
    if func not in all_names:
        matches = [n for n in all_names if func.lower() in n.lower()]
        if len(matches) == 1:
            func = matches[0]
        elif matches:
            print(f"Multiple matches for '{func}':")
            for m in sorted(matches)[:15]:
                print(f"  {m}  {_status_tag(func_info.get(m, {}))}")
            store.close()
            return
        else:
            print(f"'{func}' not found.")
            store.close()
            return

    info = func_info.get(func, {})
    tag = _status_tag(info)
    loc = _func_location(info)
    callers = rev.get(func, [])
    callees = fwd.get(func, [])

    # ══════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  DIAGNOSE: {func}()")
    print(f"{'═'*60}")
    print(f"  {loc}  {tag}")
    if info.get("signature"):
        print(f"  signature: {info['signature']}")
    print()

    issues = []
    warnings = []
    good = []

    # ── 1. Does it exist? ──
    if not info:
        issues.append("MISSING — no function definition found")
        print(f"  ❌ MISSING: no definition found in the scanned codebase")
        print()
        store.close()
        return
    elif info["body_status"] == "empty":
        issues.append(f"EMPTY body — needs implementation")
    elif info["body_status"] == "stub_todo":
        issues.append(f"STUB with TODO — needs implementation ({info['body_lines']}L)")
    elif info["body_status"] == "stub_return":
        warnings.append(f"Return-only stub — may need real implementation")
    elif info["body_status"] == "live_todo":
        warnings.append(f"Has TODO/FIXME markers")
    else:
        good.append(f"Live implementation ({info['body_lines']} lines)")

    # ── 2. Signature mismatches ──
    decls = func_decls.get(func, [])
    if decls and info.get("signature"):
        for d in decls:
            if d["sig"] != info["signature"]:
                issues.append(
                    f"SIGNATURE MISMATCH: def has {info['signature']} "
                    f"but {d['file']}:{d['line']} declares {d['sig']}")
    if decls and info.get("signature"):
        matching = [d for d in decls if d["sig"] == info["signature"]]
        if matching:
            good.append(f"Signature consistent across {len(matching) + 1} files")

    # ── 3. Is it reachable? ──
    init_regs = store.find_symbols(name="__module_init__",
                                   kind="registration", limit=50)
    init_targets = {s.properties.get("target", "") for s in init_regs}
    if init_targets:
        # BFS from init
        reachable_from_init = set()
        stack = list(init_targets)
        while stack and len(reachable_from_init) < 5000:
            fn = stack.pop()
            if fn in reachable_from_init:
                continue
            reachable_from_init.add(fn)
            for callee, _, _ in fwd.get(fn, []):
                if callee not in reachable_from_init:
                    stack.append(callee)

        if func in reachable_from_init:
            good.append("Reachable from module_init")
        else:
            if callers:
                warnings.append("NOT reachable from module_init (runtime-only path)")
            else:
                issues.append("NOT reachable from module_init AND has no callers")

    # ── 4. Callers ──
    if not callers:
        # Check if it's in an ops table or exported
        in_ops = False
        all_impl = store.get_edges(kind="implements", limit=20000)
        for edge in all_impl:
            if edge.properties.get("handler") == func:
                in_ops = True
                break
        exports = store.find_symbols(name=f"__export__{func}",
                                     kind="registration", limit=1)
        if in_ops:
            good.append("Wired via ops table (indirect callers)")
        elif exports:
            good.append("Exported symbol (called externally)")
        else:
            issues.append("ZERO callers — no function calls this, not in ops table, not exported")
    else:
        good.append(f"{len(callers)} callers")

    # ── 5. Callees health ──
    stub_callees = []
    missing_callees = []
    for callee, fp, ln in callees:
        ci = func_info.get(callee, {})
        s = ci.get("body_status", "missing")
        if s in ("stub_todo", "stub_return", "empty"):
            stub_callees.append(callee)
        elif not ci:
            missing_callees.append(callee)
    if stub_callees:
        warnings.append(f"{len(stub_callees)} callees are stubs: {', '.join(stub_callees[:5])}")
    if missing_callees:
        # Filter out likely kernel builtins
        real_missing = [m for m in missing_callees
                       if not m[0].islower() or len(m) > 15]
        if real_missing:
            warnings.append(f"{len(real_missing)} callees not found: {', '.join(real_missing[:5])}")
    if callees and not stub_callees and not missing_callees:
        good.append(f"All {len(callees)} callees are live")

    # ── 6. Lint findings on this file ──
    findings = store.get_findings(limit=50000)
    file_path = info.get("file", "")
    lint_here = [f for f in findings
                 if f.evidence and f.evidence[0].file_path == file_path
                 and abs(f.evidence[0].line_start - info.get("line", 0)) < info.get("body_lines", 50) + 5
                 and f.category in (
                     "unchecked_alloc", "use_after_free", "deadlock",
                     "unsafe_copy", "buffer_overflow", "unsafe_panic",
                     "integer_overflow",
                 )]
    if lint_here:
        for f in lint_here[:5]:
            issues.append(f"LINT [{f.category}]: {f.evidence[0].snippet[:60]}")

    # ── 7. Consistency findings ──
    consistency = [f for f in findings
                   if func in f.title and f.category in (
                       "signature_mismatch", "duplicate_definition",
                   )]
    for f in consistency:
        issues.append(f"CONSISTENCY: {f.title}")

    # ══════════════════════════════════════════════
    # Print report
    print(f"  {'─'*56}")

    if issues:
        print(f"\n  {BRED('❌ ISSUES')} ({len(issues)}):")
        for i in issues:
            print(f"    {RED('•')} {RED(i)}")

    if warnings:
        print(f"\n  {BYELLOW('⚠️  WARNINGS')} ({len(warnings)}):")
        for w in warnings:
            print(f"    {YELLOW('•')} {YELLOW(w)}")

    if good:
        print(f"\n  {BGREEN('✅ HEALTHY')} ({len(good)}):")
        for g in good:
            print(f"    • {g}")

    # ── Callers (brief) ──
    if callers:
        print(f"\n  CALLERS ({len(callers)}):")
        for caller, fp, ln in sorted(callers, key=lambda x: x[0])[:8]:
            ci = func_info.get(caller, {})
            print(f"    ← {caller}()  {fp}:{ln}  {_status_tag(ci)}")
        if len(callers) > 8:
            print(f"    ... +{len(callers) - 8} more")

    # ── Callees (brief) ──
    if callees:
        print(f"\n  CALLS ({len(callees)}):")
        for callee, fp, ln in sorted(callees, key=lambda x: x[0])[:8]:
            ci = func_info.get(callee, {})
            print(f"    → {callee}()  {fp}:{ln}  {_status_tag(ci)}")
        if len(callees) > 8:
            print(f"    ... +{len(callees) - 8} more")

    # ── Verdict ──
    print(f"\n  {'─'*56}")
    if issues:
        print(f"  {BRED('VERDICT: ❌')} {RED(f'{len(issues)} issue(s) found — needs attention')}")
    elif warnings:
        print(f"  {BYELLOW('VERDICT: ⚠️')}  {YELLOW(f'Functional but {len(warnings)} warning(s)')}")
    else:
        print(f"  {BGREEN('VERDICT: ✅ HEALTHY')} — {GREEN('no issues detected')}")
    print()

    # ── Line-by-line source audit ──
    if info and info.get("file"):
        _audit_source_lines(repo_root, func, info, func_info, fwd)

    store.close()


def _diagnose_all(store, repo_root: Path, args):
    """Run line-by-line audit on every function in the repo. Collect all issues."""
    import re as _re
    from collections import defaultdict

    func_info = {}
    for sym in store.find_symbols(kind="function_def", limit=50000):
        func_info[sym.name] = {
            "file": sym.file_path, "line": sym.line_start,
            "body_lines": sym.properties.get("body_lines", 0),
            "body_status": sym.properties.get("body_status", "unknown"),
            "has_todo": sym.properties.get("has_todo", False),
            "signature": sym.properties.get("signature", ""),
        }

    call_edges = store.get_edges(kind="calls", limit=200000)
    fwd = defaultdict(list)
    for edge in call_edges:
        caller = edge.properties.get("caller", "")
        callee = edge.properties.get("callee", "")
        if caller and callee:
            fwd[caller].append((callee, "", 0))

    # Get profile-relevant dirs
    relevant_dirs = set()
    try:
        _, profile = load_config(args)
        for pat in (profile.get_kernel_file_patterns() +
                    profile.get_userspace_file_patterns()):
            prefix = pat.split("*")[0].rstrip("/")
            if prefix:
                relevant_dirs.add(prefix)
    except Exception:
        pass

    # Collect all issues across all functions
    all_issues = []  # [(func, file, line, issue_type, detail)]
    files_audited = set()
    funcs_audited = 0
    funcs_clean = 0

    print(f"Auditing all functions in repo...")
    print()

    for func_name, info in func_info.items():
        fp = info.get("file", "")
        if not fp or not info.get("body_lines"):
            continue
        # Filter to relevant paths if profile provided
        if relevant_dirs and not any(fp.startswith(d) for d in relevant_dirs):
            continue
        if fp.endswith(".h"):
            continue

        file_path = repo_root / fp
        if not file_path.exists():
            continue

        funcs_audited += 1
        func_issues = _audit_function_silent(
            repo_root, func_name, info, func_info, fwd)

        if func_issues:
            all_issues.extend(func_issues)
        else:
            funcs_clean += 1
        files_audited.add(fp)

    # ── Summary ──
    print(f"{'═'*60}")
    print(f"  REPO-WIDE AUDIT")
    print(f"{'═'*60}")
    print(f"  Functions audited: {funcs_audited}")
    print(f"  Files covered:     {len(files_audited)}")
    print(f"  Functions clean:   {funcs_clean}")
    print(f"  Total issues:      {len(all_issues)}")
    print()

    if not all_issues:
        print("  ✅ No issues found across all functions.")
        return

    # Group by issue type
    by_type = defaultdict(list)
    for func_name, fp, line, itype, detail in all_issues:
        by_type[itype].append((func_name, fp, line, detail))

    type_labels = {
        "empty_callee": "Calls to EMPTY/STUB functions",
        "lock_not_released": "Locks not released",
        "alloc_not_checked": "Allocations not NULL-checked",
        "use_after_free": "Use after free",
        "unsafe_api": "Unsafe API usage (sprintf/strcpy/strcat)",
        "unchecked_copy": "Unchecked copy_from_user/copy_to_user",
        "goto_with_lock": "Goto with locks held",
        "todo": "TODO/FIXME markers",
    }

    print(f"  ISSUES BY TYPE:")
    print(f"  {'─'*56}")
    for itype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
        label = type_labels.get(itype, itype)
        print(f"\n  {label} ({len(items)}):")
        for func_name, fp, line, detail in items[:15]:
            print(f"    {fp}:{line}  {func_name}()  {detail}")
        if len(items) > 15:
            print(f"    ... +{len(items) - 15} more")

    print()


def _audit_function_silent(repo_root, func_name, info, func_info, fwd):
    """Audit one function's body silently, return list of issues."""
    import re as _re

    file_path = repo_root / info["file"]
    try:
        with open(file_path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except OSError:
        return []

    start_line = info.get("line", 0)
    body_lines = info.get("body_lines", 0)
    if not start_line or not body_lines:
        return []

    end_line = min(start_line + body_lines + 1, len(all_lines))

    re_call = _re.compile(r'\b([a-zA-Z_]\w{2,})\s*\(')
    re_alloc = _re.compile(r'(\w+)\s*=\s*(k[mz]alloc|kstrdup|kmemdup|alloc_skb)\s*\(')
    re_null_check = _re.compile(r'if\s*\(\s*!?\s*(\w+)\s*\)')
    re_lock = _re.compile(r'(spin_lock|mutex_lock|spin_lock_bh|spin_lock_irq|spin_lock_irqsave)\s*\(')
    re_unlock = _re.compile(r'(spin_unlock|mutex_unlock|spin_unlock_bh|spin_unlock_irq|spin_unlock_irqrestore)\s*\(')
    re_goto = _re.compile(r'\bgoto\s+(\w+)\s*;')
    re_kfree = _re.compile(r'kfree\s*\(\s*(\w+)\s*\)')
    re_deref = _re.compile(r'(\w+)->(\w+)')
    re_copy = _re.compile(r'(copy_from_user|copy_to_user)\s*\(')
    re_sprintf = _re.compile(r'\b(sprintf|strcpy|strcat)\s*\(')
    re_todo = _re.compile(r'(TODO|FIXME|HACK|XXX|STUB)', _re.IGNORECASE)

    skip = frozenset({
        "if", "else", "while", "for", "do", "switch", "case", "return",
        "goto", "sizeof", "typeof", "offsetof", "likely", "unlikely",
        "WARN", "WARN_ON", "BUG_ON", "IS_ERR", "PTR_ERR", "ERR_PTR",
        "container_of", "ARRAY_SIZE", "min", "max", "NULL",
        "pr_err", "pr_info", "pr_warn", "pr_debug", "printk",
        "IS_ENABLED", "WARN_ON_ONCE", "BUG",
    })

    issues = []
    open_locks = []
    alloc_vars = {}
    freed_vars = set()
    fp = info["file"]

    for line_idx in range(start_line - 1, min(end_line, len(all_lines))):
        line_num = line_idx + 1
        stripped = all_lines[line_idx].strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            if re_todo.search(stripped):
                issues.append((func_name, fp, line_num, "todo",
                              stripped[:60]))
            continue

        for m in re_lock.finditer(stripped):
            open_locks.append((m.group(1), line_num))

        for m in re_unlock.finditer(stripped):
            if open_locks:
                open_locks.pop()

        for m in re_alloc.finditer(stripped):
            alloc_vars[m.group(1)] = line_num

        for m in re_null_check.finditer(stripped):
            alloc_vars.pop(m.group(1), None)

        for m in re_kfree.finditer(stripped):
            freed_vars.add(m.group(1))

        for m in re_deref.finditer(stripped):
            if m.group(1) in freed_vars:
                issues.append((func_name, fp, line_num, "use_after_free",
                              f"{m.group(1)} used after kfree"))

        for m in re_sprintf.finditer(stripped):
            issues.append((func_name, fp, line_num, "unsafe_api",
                          m.group(1)))

        for m in re_copy.finditer(stripped):
            if "=" not in stripped.split(m.group(0))[0]:
                issues.append((func_name, fp, line_num, "unchecked_copy",
                              m.group(1)))

        for m in re_goto.finditer(stripped):
            if open_locks:
                issues.append((func_name, fp, line_num, "goto_with_lock",
                              f"goto {m.group(1)} with {len(open_locks)} lock(s)"))

        for m in re_call.finditer(stripped):
            callee = m.group(1)
            if callee in skip:
                continue
            ci = func_info.get(callee, {})
            s = ci.get("body_status", "")
            if s in ("empty", "stub_todo", "stub_return"):
                issues.append((func_name, fp, line_num, "empty_callee",
                              f"calls {callee}() [{s}]"))

    # Post-body checks
    for lock_type, lock_line in open_locks:
        issues.append((func_name, fp, lock_line, "lock_not_released",
                      f"{lock_type} never released"))
    for var, alloc_line in alloc_vars.items():
        issues.append((func_name, fp, alloc_line, "alloc_not_checked",
                      f"{var} not NULL-checked"))

    return issues


def _audit_source_lines(repo_root: Path, func_name: str, info: dict,
                        func_info: dict, fwd: dict):
    """Read the actual source file and annotate every line of the function body."""
    import re as _re

    file_path = repo_root / info["file"]
    if not file_path.exists():
        return

    try:
        with open(file_path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except OSError:
        return

    start_line = info.get("line", 0)
    body_lines = info.get("body_lines", 0)
    if not start_line or not body_lines:
        return

    end_line = start_line + body_lines + 1  # +1 for closing brace
    end_line = min(end_line, len(all_lines))

    print(f"  SOURCE: {info['file']}:{start_line}-{end_line}")
    print(f"  {'─'*56}")

    # Patterns for annotation
    re_call = _re.compile(r'\b([a-zA-Z_]\w{2,})\s*\(')
    re_alloc = _re.compile(r'(\w+)\s*=\s*(k[mz]alloc|kstrdup|kmemdup|alloc_skb|kzalloc_node)\s*\(')
    re_null_check = _re.compile(r'if\s*\(\s*!?\s*(\w+)\s*\)')
    re_lock = _re.compile(r'(spin_lock|mutex_lock|spin_lock_bh|spin_lock_irq|spin_lock_irqsave|read_lock|write_lock|rcu_read_lock)\s*\(')
    re_unlock = _re.compile(r'(spin_unlock|mutex_unlock|spin_unlock_bh|spin_unlock_irq|spin_unlock_irqrestore|read_unlock|write_unlock|rcu_read_unlock)\s*\(')
    re_goto = _re.compile(r'\bgoto\s+(\w+)\s*;')
    re_label = _re.compile(r'^(\w+)\s*:')
    re_kfree = _re.compile(r'kfree\s*\(\s*(\w+)\s*\)')
    re_return = _re.compile(r'\breturn\b\s*(.*?)\s*;')
    re_deref = _re.compile(r'(\w+)->(\w+)')
    re_assign_call = _re.compile(r'(\w+)\s*=\s*(\w{3,})\s*\(')
    re_copy = _re.compile(r'(copy_from_user|copy_to_user)\s*\(')
    re_sprintf = _re.compile(r'\b(sprintf|strcpy|strcat)\s*\(')
    re_todo = _re.compile(r'(TODO|FIXME|HACK|XXX|STUB)', _re.IGNORECASE)

    # C keywords and macros to skip in call detection
    skip_calls = frozenset({
        "if", "else", "while", "for", "do", "switch", "case", "return",
        "goto", "sizeof", "typeof", "offsetof", "likely", "unlikely",
        "WARN", "WARN_ON", "WARN_ON_ONCE", "BUG", "BUG_ON",
        "IS_ERR", "PTR_ERR", "ERR_PTR", "IS_ENABLED",
        "container_of", "ARRAY_SIZE", "min", "max", "min_t", "max_t",
        "LIST_HEAD", "INIT_LIST_HEAD", "NULL",
        "pr_err", "pr_info", "pr_warn", "pr_debug", "printk",
    })

    # Track state across lines
    open_locks = []  # stack of lock names
    alloc_vars = {}  # var → line where allocated (awaiting NULL check)
    freed_vars = set()  # vars that have been kfree'd
    line_annotations = []

    for line_idx in range(start_line - 1, min(end_line, len(all_lines))):
        line_num = line_idx + 1
        raw = all_lines[line_idx].rstrip("\n")
        stripped = raw.strip()
        annotations = []  # list of (color_fn, text)
        has_error = False

        # Skip empty/comment lines
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            if re_todo.search(stripped):
                annotations.append((YELLOW, "📝 TODO"))
            line_annotations.append((line_num, raw, annotations, False))
            continue

        # ── Lock tracking ──
        for m in re_lock.finditer(stripped):
            lock_type = m.group(1)
            open_locks.append((lock_type, line_num))
            annotations.append((CYAN, f"🔒 {lock_type}"))

        for m in re_unlock.finditer(stripped):
            unlock_type = m.group(1)
            if open_locks:
                lock_type, lock_line = open_locks.pop()
                annotations.append((GREEN, f"🔓 {unlock_type} (matches L{lock_line})"))
            else:
                annotations.append((RED, f"⚠️ {unlock_type} — no matching lock!"))
                has_error = True

        # ── Allocation tracking ──
        for m in re_alloc.finditer(stripped):
            var = m.group(1)
            alloc_fn = m.group(2)
            alloc_vars[var] = line_num
            annotations.append((CYAN, f"📦 {alloc_fn} → {var}"))

        # ── NULL check clears allocation warning ──
        for m in re_null_check.finditer(stripped):
            var = m.group(1)
            if var in alloc_vars:
                annotations.append((GREEN, f"✅ NULL check on {var} (alloc L{alloc_vars[var]})"))
                del alloc_vars[var]

        # ── kfree tracking ──
        for m in re_kfree.finditer(stripped):
            var = m.group(1)
            freed_vars.add(var)
            annotations.append((YELLOW, f"🗑️ kfree({var})"))

        # ── Use after free ──
        for m in re_deref.finditer(stripped):
            var = m.group(1)
            if var in freed_vars:
                annotations.append((RED, f"❌ USE AFTER FREE: {var} was freed"))
                has_error = True

        # ── Unsafe functions ──
        for m in re_sprintf.finditer(stripped):
            annotations.append((YELLOW, f"⚠️ {m.group(1)} — no bounds check"))

        for m in re_copy.finditer(stripped):
            if "=" not in stripped.split(m.group(0))[0]:
                annotations.append((RED, f"⚠️ {m.group(1)} return not checked"))
                has_error = True

        # ── goto ──
        for m in re_goto.finditer(stripped):
            label = m.group(1)
            if open_locks:
                annotations.append((RED, f"↪ goto {label} — {len(open_locks)} lock(s) held!"))
                has_error = True
            else:
                annotations.append((DIM, f"↪ goto {label}"))

        # ── Labels ──
        for m in re_label.finditer(stripped):
            if m.group(1) not in ("default", "case"):
                annotations.append((DIM, f"🏷️ label {m.group(1)}"))

        # ── Function calls — look up every callee ──
        for m in re_call.finditer(stripped):
            callee = m.group(1)
            if callee in skip_calls:
                continue
            if callee in func_info:
                ci = func_info[callee]
                status = ci.get("body_status", "unknown")
                lines = ci.get("body_lines", 0)
                loc = ci.get("file", "?")
                if status == "empty":
                    annotations.append((RED, f"❌ {callee}() → EMPTY at {loc}"))
                    has_error = True
                elif status in ("stub_todo", "stub_return"):
                    annotations.append((YELLOW, f"🔨 {callee}() → STUB at {loc}"))
                elif status == "live" and lines > 0:
                    annotations.append((GREEN, f"→ {callee}() [{lines}L] {loc}"))
                elif status == "live_todo":
                    annotations.append((YELLOW, f"⚠️ {callee}() [TODO] {loc}"))

        # ── Return value ──
        for m in re_return.finditer(stripped):
            val = m.group(1)
            if val and val.startswith("-E"):
                annotations.append((CYAN, f"↩ return {val}"))

        # ── TODO in code ──
        if re_todo.search(stripped) and not any("📝" in a[1] for a in annotations):
            annotations.append((YELLOW, "📝 TODO"))

        line_annotations.append((line_num, raw, annotations, has_error))

    # ── Print annotated source ──
    print()
    for line_num, raw, annotations, has_err in line_annotations:
        display = raw[:90]
        line_color = RED if has_err else (lambda x: x)
        num_str = DIM(f"{line_num:>5}")
        if annotations:
            ann_parts = [color_fn(text) for color_fn, text in annotations]
            ann_str = "  ".join(ann_parts)
            print(f"  {num_str} │ {line_color(display)}")
            print(f"  {DIM('     ')} │   {ann_str}")
        else:
            print(f"  {num_str} │ {display}")

    # ── Post-body warnings ──
    print()
    if open_locks:
        for lock_type, lock_line in open_locks:
            print(f"  {BRED('❌ LOCK NOT RELEASED:')} {RED(f'{lock_type} acquired at L{lock_line}')}")
    if alloc_vars:
        for var, alloc_line in alloc_vars.items():
            print(f"  {BYELLOW('⚠️ ALLOC NOT NULL-CHECKED:')} {YELLOW(f'{var} allocated at L{alloc_line}')}")
    if not open_locks and not alloc_vars:
        print(f"  ✅ All locks released, all allocations checked")
    print()


def cmd_dump(args):
    """Dump everything the tool knows — one line per fact, greppable."""
    from collections import defaultdict
    store = load_store(args)

    query = (args.query or "").lower()

    # ── Functions ──
    for sym in store.find_symbols(kind="function_def", limit=50000):
        status = sym.properties.get("body_status", "?")
        lines = sym.properties.get("body_lines", 0)
        sig = sym.properties.get("signature", "")
        tag = status.upper()
        line = (f"FUNC  {sym.name}  {sym.file_path}:{sym.line_start}"
                f"  {tag} {lines}L"
                f"{'  sig=' + sig if sig else ''}")
        if not query or query in line.lower():
            color = GREEN if status == "live" else (
                YELLOW if "stub" in status else (
                RED if status in ("empty", "missing") else lambda x: x))
            print(color(line))

    # ── Function declarations ──
    for sym in store.find_symbols(kind="function_decl", limit=20000):
        sig = sym.properties.get("signature", "")
        line = (f"DECL  {sym.name}  {sym.file_path}:{sym.line_start}"
                f"{'  sig=' + sig if sig else ''}")
        if not query or query in line.lower():
            print(DIM(line))

    # ── Call edges ──
    call_edges = store.get_edges(kind="calls", limit=200000)
    for edge in call_edges:
        caller = edge.properties.get("caller", "")
        callee = edge.properties.get("callee", "")
        ev = edge.evidence[0] if edge.evidence else None
        fp = ev.file_path if ev else "?"
        ln = ev.line_start if ev else 0
        line = f"CALL  {caller} -> {callee}  {fp}:{ln}"
        if not query or query in line.lower():
            print(line)

    # ── Ops table edges ──
    impl_edges = store.get_edges(kind="implements", limit=20000)
    for edge in impl_edges:
        ops = edge.properties.get("ops_table", "")
        field = edge.properties.get("field", "")
        handler = edge.properties.get("handler", "")
        line = f"OPS   {ops}.{field} = {handler}"
        if not query or query in line.lower():
            print(CYAN(line))

    # ── Structs ──
    for sym in store.find_symbols(kind="struct", limit=5000):
        line = f"STRUCT  {sym.name}  {sym.file_path}:{sym.line_start}"
        if not query or query in line.lower():
            print(line)

    # ── Enums ──
    for sym in store.find_symbols(kind="enum", limit=5000):
        line = f"ENUM  {sym.name}  {sym.file_path}:{sym.line_start}"
        if not query or query in line.lower():
            print(line)

    # ── Constants ──
    for sym in store.find_symbols(kind="constant", limit=10000):
        val = sym.properties.get("value", "")
        line = f"CONST  {sym.name} = {val}  {sym.file_path}:{sym.line_start}"
        if not query or query in line.lower():
            print(DIM(line))

    # ── Registrations (init, exit, export, register) ──
    for sym in store.find_symbols(kind="registration", limit=5000):
        itype = sym.properties.get("internal_type", sym.properties.get("type", ""))
        target = sym.properties.get("target", "")
        line = f"REG   {itype}  {target}  {sym.file_path}:{sym.line_start}"
        if not query or query in line.lower():
            print(CYAN(line))

    # ── Surfaces ──
    for surf in store.get_surfaces():
        p = surf.properties
        sub = p.get("substatus", surf.status.value)
        imp = p.get("importance_score", "")
        line = (f"SURFACE  {surf.boundary_type.value}  {surf.name}"
                f"  {sub}  imp={imp}"
                f"  handler={surf.handler or 'NONE'}")
        if not query or query in line.lower():
            print(BLUE(line))

    # ── Findings (HIGH and MEDIUM only unless --all) ──
    show_all_findings = getattr(args, "verbose", False)
    for f in store.get_findings(limit=50000):
        if not show_all_findings and f.severity.value in ("low", "info"):
            continue
        ev = f.evidence[0] if f.evidence else None
        fp = ev.file_path if ev else "?"
        ln = ev.line_start if ev else 0
        line = (f"FINDING  {f.severity.value.upper()}  {f.category}"
                f"  {f.title[:80]}  {fp}:{ln}"
                f"  action={f.recommendation}")
        if not query or query in line.lower():
            color = RED if f.severity.value == "high" else (
                YELLOW if f.severity.value == "medium" else lambda x: x)
            print(color(line))

    store.close()


def cmd_show(args):
    """Show detail for a specific surface."""
    store = load_store(args)
    print(generate_surface_detail(store, args.name))
    store.close()


def cmd_stats(args):
    """Show database statistics."""
    store = load_store(args)
    stats = store.stats()
    for k, v in stats.items():
        print(f"{k:>12}: {v}")
    store.close()


def cmd_profiles(args):
    """List available profiles."""
    print("Builtin profiles:")
    for name, (cls, desc) in BUILTIN_PROFILES.items():
        print(f"  {name:20s} {desc}")
    print()
    print("Custom profiles:")
    print("  Define in .boundary-mapper.json with a 'custom' block.")
    print("  Run 'boundary-mapper init mymod' to scaffold one.")
    print()

    # Check for config in current repo
    repo = Path(args.repo).resolve()
    cfg_path = repo / CONFIG_FILENAME
    if cfg_path.is_file():
        with open(cfg_path) as f:
            data = json.load(f)
        print(f"Active config: {cfg_path}")
        print(f"  profile: {data.get('profile', 'base')}")
        if "custom" in data:
            print(f"  custom name: {data['custom'].get('name', '?')}")


def cmd_languages(args):
    """List available language definitions."""
    # Load custom languages from config if present
    repo = Path(args.repo).resolve()
    cfg_path = repo / CONFIG_FILENAME
    if cfg_path.is_file():
        with open(cfg_path) as f:
            raw = json.load(f)
        _load_custom_languages(raw)

    print("Loaded languages:")
    print()
    print(f"  {'Name':<14} {'Extensions':<24} {'Symbols':<10} {'Boundaries':<12} {'Lint'}")
    print(f"  {'─'*14} {'─'*24} {'─'*10} {'─'*12} {'─'*6}")
    for name, lang in sorted(BUILTIN_LANGUAGES.items()):
        exts = ", ".join(lang.extensions)
        n_sym = len(lang.symbol_patterns)
        n_bnd = len(lang.boundary_patterns)
        n_lint = len(lang.lint_patterns)
        print(f"  {name:<14} {exts:<24} {n_sym:<10} {n_bnd:<12} {n_lint}")
    print()
    print("Add custom languages in .boundary-mapper.json:")
    print('  "languages": [{"name": "zig", "extensions": [".zig"],')
    print('    "symbols": [{"name": "fn", "regex": "^fn (\\\\w+)", "kind": "function_def"}]}]')


def cmd_report(args):
    """Generate reports from existing scan data."""
    store = load_store(args)
    config, profile = load_config(args)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    fmt = args.format
    if fmt in ("md", "all"):
        p = output_dir / "boundary_report.md"
        generate_report(store, p, profile.name)
        print(f"Markdown: {p}")
    if fmt in ("json", "all"):
        p = output_dir / "boundary_report.json"
        generate_json_report(store, p, profile.name)
        print(f"JSON: {p}")
    if fmt in ("dot", "all"):
        p = output_dir / "boundary_graph.dot"
        generate_dot(store, p)
        print(f"DOT: {p}")
    store.close()


# ─── Argument parsing ───

def main():
    parser = argparse.ArgumentParser(
        prog="boundary-mapper",
        description="Kernel↔userspace boundary reachability and wiring verification",
        epilog=(
            "examples:\n"
            "  boundary-mapper init mymod              Scaffold config for 'mymod'\n"
            "  boundary-mapper scan                    Scan repo (auto-detects config)\n"
            "  boundary-mapper scan --fresh            Clean scan from scratch\n"
            "  boundary-mapper surfaces                List all boundary surfaces\n"
            "  boundary-mapper findings --high         Show only HIGH severity\n"
            "  boundary-mapper show MY_OPT_FOO         Detail for one surface\n"
            "  boundary-mapper trace my_func            Who calls this? What does it call?\n"
            "  boundary-mapper trace func_a --to func_b  Path from A to B\n"
            "  boundary-mapper trace func --from-init  Trace from module_init\n"
            "  boundary-mapper profiles                List available profiles\n"
            "  boundary-mapper languages               List language definitions\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show debug output")
    parser.add_argument("--db", default=".boundary_mapper.db",
                        help="SQLite database path (default: .boundary_mapper.db)")
    parser.add_argument("--repo", default=".",
                        help="Repository root path (default: current dir)")
    parser.add_argument("--profile", default="_auto_",
                        help="Profile name (default: auto-detect from config)")

    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser("init",
        help="Create .boundary-mapper.json config",
        description="Scaffold a new config file for your kernel module.")
    p_init.add_argument("module", nargs="?", default=None,
                        help="Module name (e.g., 'mymod')")
    p_init.add_argument("--force", action="store_true",
                        help="Overwrite existing config")
    p_init.add_argument("--skill", action="store_true",
                        help="Also generate a Claude Code skill file")

    # scan
    p_scan = sub.add_parser("scan",
        help="Scan repository and generate report",
        description="Full scan: extract symbols, build graph, run rules, report.")
    p_scan.add_argument("--fresh", action="store_true",
                        help="Clear old data before scanning (alias: --clean)")
    p_scan.add_argument("--clean", dest="fresh", action="store_true",
                        help=argparse.SUPPRESS)  # hidden alias
    p_scan.add_argument("--no-extras", action="store_true",
                        help="Skip JSON and DOT reports (only .md)")

    # surfaces
    p_surf = sub.add_parser("surfaces",
        help="List boundary surfaces",
        description="Show all detected boundary surfaces with status and importance.")
    p_surf.add_argument("type", nargs="?", default=None,
                        help="Filter by type: genetlink, setsockopt, ioctl, sysctl")
    p_surf.add_argument("--type", dest="type_flag",
                        help=argparse.SUPPRESS)  # also accept --type

    # findings
    p_find = sub.add_parser("findings",
        help="List findings",
        description="Show detected issues, sorted by severity.")
    p_find.add_argument("--severity",
                        help="Filter: critical, high, medium, low, info")
    p_find.add_argument("--high", action="store_true",
                        help="Show only HIGH severity")
    p_find.add_argument("--medium", action="store_true",
                        help="Show only MEDIUM severity")
    p_find.add_argument("--low", action="store_true",
                        help="Show only LOW severity")
    p_find.add_argument("--info", action="store_true",
                        help="Show only INFO severity")
    p_find.add_argument("--limit", type=int, default=200,
                        help="Max findings to show (default: 200)")

    # show (renamed from show-surface)
    p_show = sub.add_parser("show",
        help="Show detail for a surface",
        description="Show full detail for a boundary surface (partial name match).")
    p_show.add_argument("name", help="Surface name (partial match)")

    # Also keep show-surface as hidden alias
    p_show2 = sub.add_parser("show-surface", help=argparse.SUPPRESS)
    p_show2.add_argument("name")

    # trace
    p_trace = sub.add_parser("trace",
        help="Trace call paths line by line",
        description=(
            "Trace call paths through the full call graph.\n\n"
            "  boundary-mapper trace FUNC              Show callers + callees\n"
            "  boundary-mapper trace FUNC --to TARGET  Find path between two functions\n"
            "  boundary-mapper trace FUNC --from-init  Trace from module_init to FUNC\n"
            "  boundary-mapper trace FUNC --depth 3    Recursive caller depth\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_trace.add_argument("function",
                         help="Function name (exact or partial match)")
    p_trace.add_argument("--to",
                         help="Target function — find call path from FUNC to this")
    p_trace.add_argument("--from-init", action="store_true",
                         help="Trace path from module_init to this function")
    p_trace.add_argument("--depth", type=int, default=2,
                         help="Depth for recursive caller/callee display (default: 2)")

    # dump
    p_dump = sub.add_parser("dump",
        help="Dump everything — greppable",
        description=(
            "One line per fact. Grep for anything.\n\n"
            "  boundary-mapper dump                     Everything\n"
            "  boundary-mapper dump path_free           Filter to matches\n"
            "  boundary-mapper dump | grep STUB         All stubs\n"
            "  boundary-mapper dump | grep EMPTY        All empty functions\n"
            "  boundary-mapper dump | grep CALL         All call edges\n"
            "  boundary-mapper dump | grep FINDING      All findings\n"
            "  boundary-mapper dump | grep SURFACE      All surfaces\n"
            "  boundary-mapper dump -v                  Include LOW/INFO findings\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_dump.add_argument("query", nargs="?", default=None,
                        help="Filter output (case-insensitive substring match)")

    # diagnose
    p_diag = sub.add_parser("diagnose",
        help="Health check — one function or whole repo",
        description=(
            "Line-by-line audit with lock tracking, alloc checking,\n"
            "callee status, use-after-free detection, and more.\n\n"
            "  boundary-mapper diagnose my_function   Audit one function\n"
            "  boundary-mapper diagnose --all         Audit every function in repo\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_diag.add_argument("function", nargs="?", default=None,
                        help="Function name (exact or partial match)")
    p_diag.add_argument("--all", action="store_true",
                        help="Audit every function in the repo")

    # stats
    sub.add_parser("stats",
        help="Show database statistics",
        description="Show symbol, edge, surface, finding counts.")

    # profiles
    sub.add_parser("profiles",
        help="List available profiles",
        description="Show builtin profiles and active config.")

    # languages
    sub.add_parser("languages",
        help="List loaded language definitions",
        description="Show builtin + custom language definitions and their patterns.")

    # report
    p_report = sub.add_parser("report",
        help="Regenerate reports from existing scan",
        description="Generate reports from already-scanned data.")
    p_report.add_argument("--format", default="all",
                          choices=["md", "json", "dot", "all"])
    p_report.add_argument("--output", default="boundary_reports")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Resolve --type positional vs --type flag for surfaces
    if args.command == "surfaces":
        args.type = args.type or args.type_flag

    handlers = {
        "init": cmd_init,
        "scan": cmd_scan,
        "surfaces": cmd_surfaces,
        "findings": cmd_findings,
        "show": cmd_show,
        "show-surface": cmd_show,
        "trace": cmd_trace,
        "diagnose": cmd_diagnose,
        "dump": cmd_dump,
        "stats": cmd_stats,
        "profiles": cmd_profiles,
        "languages": cmd_languages,
        "report": cmd_report,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
