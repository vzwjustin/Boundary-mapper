"""Configuration and profile loading.

Supports auto-detection of .boundary-mapper.json in the repo root.
Config files store profile selection, paths, and optional inline
custom profile definitions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CONFIG_FILENAME = ".boundary-mapper.json"


@dataclass
class AnalysisConfig:
    """Top-level configuration for a boundary mapper run."""
    repo_root: Path = field(default_factory=lambda: Path("."))
    profile_name: str = "base"
    db_path: Path = field(default_factory=lambda: Path(".boundary_mapper.db"))
    output_dir: Path = field(default_factory=lambda: Path("boundary_reports"))
    verbose: bool = False
    clang_args: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*.mod.c", "*.cmd", ".git/*", "*.o", "*.ko",
    ])
    # Raw custom profile data from config file (if profile == "custom")
    custom_profile_data: Optional[dict] = None

    @classmethod
    def from_file(cls, path: Path) -> "AnalysisConfig":
        with open(path) as f:
            data = json.load(f)
        cfg = cls()
        for k, v in data.items():
            if k in ("repo_root", "db_path", "output_dir"):
                setattr(cfg, k, Path(v))
            elif k == "profile":
                cfg.profile_name = v
            elif k == "custom":
                cfg.custom_profile_data = v
                if cfg.profile_name == "base":
                    cfg.profile_name = "custom"
            elif hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    @classmethod
    def auto_detect(cls, repo_path: Path) -> Optional["AnalysisConfig"]:
        """Look for .boundary-mapper.json in the repo root."""
        cfg_path = repo_path / CONFIG_FILENAME
        if cfg_path.is_file():
            cfg = cls.from_file(cfg_path)
            cfg.repo_root = repo_path
            return cfg
        return None

    def resolve(self):
        """Resolve all paths relative to repo_root."""
        self.repo_root = self.repo_root.resolve()
        if not self.db_path.is_absolute():
            self.db_path = self.repo_root / self.db_path
        if not self.output_dir.is_absolute():
            self.output_dir = self.repo_root / self.output_dir


def generate_config_template(profile_name: str = "custom",
                             module_name: str = "mymod",
                             repo_root: Path = None) -> dict:
    """Generate a .boundary-mapper.json by scanning the repo.

    If repo_root is provided, auto-discovers:
    - Source directories (kernel, userspace, shared, test)
    - #define prefixes (command, option, attribute)
    - Sockopt maps from #define constants
    - Genetlink families from genl_register_family calls
    """
    if repo_root and repo_root.is_dir():
        return _auto_discover(repo_root, module_name, profile_name)
    return _static_template(profile_name, module_name)


def _static_template(profile_name: str, module_name: str) -> dict:
    """Fallback: generate a minimal template when repo isn't available."""
    prefix = module_name.upper()
    return {
        "profile": profile_name,
        "custom": {
            "name": module_name,
            "description": f"{module_name} boundary profile",
            "kernel_paths": [f"**/*.c", f"**/*.h"],
            "userspace_paths": [],
            "shared_paths": [],
            "command_prefixes": [f"{prefix}_CMD_"],
            "option_prefixes": [f"{prefix}_"],
            "attribute_prefixes": [f"{prefix}_ATTR_"],
            "directories": [],
            "sockopt_map": {},
            "genl_families": {},
        },
    }


def _auto_discover(repo_root: Path, module_name: str,
                   profile_name: str) -> dict:
    """Scan the repo and auto-populate the config."""
    import os
    import re
    from collections import Counter

    prefix = module_name.upper()

    # ── Phase 1: Discover directory structure ──
    source_dirs = {"c": [], "h": [], "go": [], "py": [], "rs": [],
                   "ts": [], "java": []}
    ext_map = {".c": "c", ".h": "h", ".go": "go", ".py": "py",
               ".rs": "rs", ".ts": "ts", ".tsx": "ts", ".js": "ts",
               ".java": "java"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "build", "dist", "target", ".boundary_mapper.db"}

    for dirpath, dirnames, filenames in os.walk(str(repo_root)):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        rel_dir = os.path.relpath(dirpath, str(repo_root))
        if rel_dir == ".":
            rel_dir = ""
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            lang = ext_map.get(ext)
            if lang:
                source_dirs[lang].append(rel_dir)

    # Deduplicate and find top-level source directories
    def top_dirs(dirs):
        unique = sorted(set(d for d in dirs if d))
        # Collapse to parent dirs (keep dirs that contain >2 files)
        counts = Counter(dirs)
        tops = []
        for d in unique:
            if counts[d] >= 1:
                # Check if already covered by a parent
                covered = any(d.startswith(t + "/") for t in tops)
                if not covered:
                    tops.append(d)
        return tops[:20]  # cap at 20

    c_dirs = top_dirs(source_dirs["c"] + source_dirs["h"])
    go_dirs = top_dirs(source_dirs["go"])
    py_dirs = top_dirs(source_dirs["py"])
    rs_dirs = top_dirs(source_dirs["rs"])
    ts_dirs = top_dirs(source_dirs["ts"])
    java_dirs = top_dirs(source_dirs["java"])

    # Build path patterns
    kernel_paths = []
    userspace_paths = []
    shared_paths = []
    test_paths = []
    directories = []

    # Classify directories by heuristic
    for d in c_dirs:
        pat = f"{d}/**/*.c" if d else "**/*.c"
        hpat = f"{d}/**/*.h" if d else "**/*.h"
        dl = d.lower()
        if any(k in dl for k in ("test", "selftests", "kunit", "spec")):
            test_paths.extend([pat, hpat])
            directories.append({"path": d + "/", "side": "tooling",
                                "description": "Tests"})
        elif any(k in dl for k in ("uapi", "shared", "public")):
            shared_paths.extend([pat, hpat])
            directories.append({"path": d + "/", "side": "shared",
                                "description": "Shared/UAPI headers"})
        elif any(k in dl for k in ("tools", "cmd", "cli", "userspace",
                                    "daemon", "agent", "client")):
            userspace_paths.extend([pat, hpat])
            directories.append({"path": d + "/", "side": "userspace",
                                "description": "Userspace"})
        else:
            kernel_paths.extend([pat, hpat])
            directories.append({"path": d + "/", "side": "kernel",
                                "description": "Source"})

    for d in go_dirs:
        pat = f"{d}/**/*.go" if d else "**/*.go"
        userspace_paths.append(pat)
        directories.append({"path": d + "/", "side": "userspace",
                            "description": "Go source"})
    for d in py_dirs:
        userspace_paths.append(f"{d}/**/*.py" if d else "**/*.py")
    for d in rs_dirs:
        kernel_paths.append(f"{d}/**/*.rs" if d else "**/*.rs")
    for d in ts_dirs:
        userspace_paths.append(f"{d}/**/*.ts" if d else "**/*.ts")
    for d in java_dirs:
        userspace_paths.append(f"{d}/**/*.java" if d else "**/*.java")

    # ── Phase 2: Scan headers for prefixes and constants ──
    define_re = re.compile(r'^#define\s+(\w+)\s+(\d+)', re.MULTILINE)
    genl_re = re.compile(r'genl_register_family\s*\(\s*&(\w+)\s*\)')
    prefix_counter = Counter()
    sockopt_map = {}
    genl_families = {}

    header_files = []
    for dirpath, _, filenames in os.walk(str(repo_root)):
        rel = os.path.relpath(dirpath, str(repo_root))
        if any(s in rel for s in (".git", "node_modules")):
            continue
        for fname in filenames:
            if fname.endswith(".h"):
                header_files.append(os.path.join(dirpath, fname))

    # Also scan .c files for genl_register_family
    c_files = []
    for dirpath, _, filenames in os.walk(str(repo_root)):
        rel = os.path.relpath(dirpath, str(repo_root))
        if any(s in rel for s in (".git", "node_modules")):
            continue
        for fname in filenames:
            if fname.endswith(".c"):
                c_files.append((os.path.join(dirpath, fname),
                                os.path.relpath(
                                    os.path.join(dirpath, fname),
                                    str(repo_root))))

    for hpath in header_files[:200]:  # cap for speed
        try:
            with open(hpath, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        for m in define_re.finditer(content):
            name = m.group(1)
            val = m.group(2)
            # Count prefix patterns (first 2 underscore-delimited parts)
            parts = name.split("_")
            if len(parts) >= 2:
                pfx = "_".join(parts[:2]) + "_"
                prefix_counter[pfx] += 1
            # Detect sockopt-like constants (prefix matches module, numeric val)
            if name.startswith(prefix) and val.isdigit():
                num = int(val)
                if 0 < num < 1000:
                    sockopt_map[str(num)] = name

    for cpath, crel in c_files[:200]:
        try:
            with open(cpath, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        for m in genl_re.finditer(content):
            fam_var = m.group(1)
            genl_families[fam_var] = {
                "ops_var": "",
                "source_file": crel,
                "commands": {},
            }

    # ── Phase 3: Infer prefixes ──
    # Use the module name as primary prefix, discover CMD_ and ATTR_ variants
    discovered_prefixes = []
    for pfx, count in prefix_counter.most_common(30):
        if count >= 3 and pfx.startswith(prefix):
            discovered_prefixes.append(pfx)

    command_prefixes = [p for p in discovered_prefixes if "_CMD_" in p]
    attribute_prefixes = [p for p in discovered_prefixes if "_ATTR_" in p]
    option_prefixes = [f"{prefix}_"] if any(
        p.startswith(prefix) for p in discovered_prefixes) else []

    # Fallback: if no prefixes found from scanning, use module name
    if not command_prefixes:
        command_prefixes = [f"{prefix}_CMD_"]
    if not option_prefixes:
        option_prefixes = [f"{prefix}_"]
    if not attribute_prefixes:
        attribute_prefixes = [f"{prefix}_ATTR_"]

    # ── Build config ──
    config = {
        "profile": profile_name,
        "custom": {
            "name": module_name,
            "description": f"{module_name} boundary profile (auto-discovered)",
            "kernel_paths": kernel_paths or ["**/*.c", "**/*.h"],
            "userspace_paths": userspace_paths,
            "shared_paths": shared_paths,
            "test_paths": test_paths,
            "command_prefixes": command_prefixes,
            "option_prefixes": option_prefixes,
            "attribute_prefixes": attribute_prefixes,
            "directories": directories,
            "sockopt_map": sockopt_map,
            "genl_families": genl_families,
        },
    }
    return config


def generate_claude_skill(module_name: str = "mymod",
                          tool_path: str = ".") -> str:
    """Generate a Claude Code skill file for this project's boundary mapper."""
    prefix = module_name.upper()
    return f'''---
name: {module_name}-boundary-mapper
description: "Use when: verifying {module_name} code is wired end-to-end, finding dead functions/handlers, tracing call paths, detecting signature mismatches, auditing init chains and ops tables, catching memory safety issues, or answering 'is this code connected?'"
metadata:
  author: boundary-mapper
  version: "1.0.0"
---

# {module_name} Boundary Mapper

Code wiring verification for the {module_name} module. Proves what is connected, what is dead, and what will break.

## Tool Location

```
{tool_path}
```

All commands run from the tool directory with `python3 -m boundary_mapper`.

## Quick Reference

```bash
# Scan the repo
python3 -m boundary_mapper scan --fresh

# List boundary surfaces
python3 -m boundary_mapper surfaces

# Show findings by severity
python3 -m boundary_mapper findings --high
python3 -m boundary_mapper findings --medium

# Trace a function (callers + callees with file:line)
python3 -m boundary_mapper trace some_function

# Trace path between two functions
python3 -m boundary_mapper trace func_a --to func_b

# Trace from module_init
python3 -m boundary_mapper trace some_init --from-init

# Show surface detail
python3 -m boundary_mapper show {prefix}_SOME_OPT

# List languages and lint patterns
python3 -m boundary_mapper languages
```

## What It Finds

### Boundary Wiring
- Dead UAPI surfaces (no kernel handler)
- Missing dispatch cases for socket options
- Orphan handler functions not in ops tables
- Contract drift (UAPI constants unused in kernel)

### Internal Wiring
- Init functions not reachable from module_init (full call graph)
- Ops tables never registered
- Register without matching unregister (resource leaks)
- Dead functions (zero callers in call graph)
- EXPORT_SYMBOL for non-existent functions

### Consistency (build/debug time-savers)
- Signature mismatches across headers (e.g., `foo(void)` vs `foo(struct bar *)`)
- Duplicate function definitions in multiple .c files
- #define constants with different values in different files
- Struct/enum defined in multiple directories (ABI drift)

### Lint (memory safety, security)
- Unchecked kmalloc/kzalloc/alloc_skb (NULL dereference)
- Use-after-free patterns
- Potential deadlocks (double lock acquisition)
- Unchecked copy_from_user / copy_to_user
- sprintf/strcpy/strcat without bounds
- Variable-sized kmalloc from user input
- BUG() instead of WARN_ON
- Deprecated kernel APIs

## Report

After scan, `boundary_reports/boundary_report.md` contains:
1. Executive summary
2. Highest-value gaps
3. Internal wiring audit
4. Consistency problems
5. All surfaces with importance scores
6. Findings by severity
'''
