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
                             module_name: str = "mymod") -> dict:
    """Generate a starter .boundary-mapper.json for a new project."""
    prefix = module_name.upper()
    return {
        "profile": profile_name,
        "db": ".boundary_mapper.db",
        "output_dir": "boundary_reports",
        "custom": {
            "name": module_name,
            "description": f"{module_name} kernel module boundary profile",
            "kernel_paths": [f"net/{module_name}/**/*.c",
                             f"net/{module_name}/**/*.h"],
            "userspace_paths": [f"tools/{module_name}/**/*.go",
                                f"tools/{module_name}/**/*.c"],
            "shared_paths": [f"include/uapi/linux/{module_name}*.h"],
            "test_paths": [f"tools/testing/selftests/net/{module_name}/**/*"],
            "command_prefixes": [f"{prefix}_CMD_"],
            "option_prefixes": [f"{prefix}_"],
            "attribute_prefixes": [f"{prefix}_ATTR_"],
            "directories": [
                {"path": f"net/{module_name}/", "side": "kernel",
                 "description": f"Kernel {module_name} module"},
                {"path": f"include/uapi/linux/{module_name}",
                 "side": "shared", "description": "UAPI headers"},
                {"path": f"tools/{module_name}/", "side": "userspace",
                 "description": "Userspace daemon"},
            ],
            "sockopt_map": {},
            "genl_families": {},
            "ioctl_map": {},
            "future_reserved_sockopts": [],
            "diagnostic_sockopts": [],
            "kernel_only_genl": [],
        },
    }


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
