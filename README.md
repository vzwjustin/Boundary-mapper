# Boundary Mapper

**Know if your code is actually connected.**

Boundary Mapper is a static analysis tool that traces your code line by line to verify it's wired end-to-end. It builds a full call graph, checks every function for live/stub/broken status, detects signature mismatches across files, finds dead code, and catches memory safety issues — across 6 languages.

```
boundary-mapper trace my_init_func --from-init

Call path: module_init(my_module_init) → my_init_func

my_module_init()  src/main.c:45  [✅ LIVE 105L]
  └─ my_subsys_init()  src/subsys.c:12  [✅ LIVE 37L]
     call at src/main.c:52
    └─ my_init_func()  src/handler.c:89  [🔨 STUB TODO 3L]
       call at src/subsys.c:28

  VERDICT: 🔨 NEEDS WORK — 1/3 stubbed, 2/3 live
```

## Install

```bash
git clone https://github.com/vzwjustin/Boundary-mapper.git
cd Boundary-mapper
```

No dependencies. Python 3.8+.

## Quick Start

```bash
# 1. Scaffold a config for your project
python3 -m boundary_mapper init mymod

# 2. Edit .boundary-mapper.json — fill in your paths, prefixes, sockopt maps

# 3. Scan
python3 -m boundary_mapper scan --fresh

# 4. See what's broken
python3 -m boundary_mapper findings --high

# 5. Trace any function
python3 -m boundary_mapper trace some_function
```

## What It Does

### Trace Call Paths — Line by Line

Every hop shows the file, line number, and whether the code is live, stubbed, or broken.

```bash
# Who calls this? What does it call? Is anything stubbed downstream?
boundary-mapper trace my_function

# Find the exact path between two functions
boundary-mapper trace func_a --to func_b

# Is this function reachable from module_init?
boundary-mapper trace my_handler --from-init

# Fuzzy match — partial names work
boundary-mapper trace path_free
```

**Status at every hop:**

| Icon | Status | Meaning |
|------|--------|---------|
| ✅ | LIVE | Real implementation with code |
| ⚠️ | LIVE TODO | Has code but contains TODO/FIXME |
| 🔨 | STUB TODO | Tiny body with TODO marker — needs building |
| 📌 | STUB RETURN | Just `return 0;` — placeholder |
| 💀 | EMPTY | Empty function body `{}` |
| ❌ | MISSING | Referenced but no definition found |

### Boundary Wiring (Kernel ↔ Userspace)

For kernel modules: verifies every UAPI constant has a kernel handler, every socket option has a dispatch case, every genetlink command reaches a handler.

| Check | What it catches |
|-------|----------------|
| Dead surface | UAPI constant with no kernel handler |
| Missing dispatch | Socket option defined but no `case` in switch |
| Orphan handler | Handler function not in any ops table |
| Contract drift | UAPI constants nobody uses |

### Internal Wiring

| Check | What it catches |
|-------|----------------|
| Init chain | `__init` functions unreachable from `module_init` (full call graph BFS) |
| Ops table wiring | Ops tables never registered, slots pointing to missing functions |
| Registration balance | `register_*()` without matching `unregister_*()` |
| Dead functions | Functions with zero callers in the full call graph |
| Export without def | `EXPORT_SYMBOL()` for functions that don't exist |

### Consistency (Things That Waste Hours Debugging)

| Check | What it catches |
|-------|----------------|
| Signature mismatch | `foo(struct bar *)` in one header, `foo(void)` in another |
| Duplicate definition | Same function in multiple `.c` files (linker errors) |
| Constant redefinition | `#define FOO 10` in one file, `#define FOO 20` in another |
| Struct drift | Same struct defined in different directories (ABI mismatch) |

### Lint (65 Patterns Across 6 Languages)

**C (21 patterns):** Unchecked allocs, use-after-free, deadlocks, buffer overflows, unsafe copies, deprecated APIs, incomplete types

**Go (10 patterns):** Unchecked errors, empty error handlers, goroutine leaks, mutex copy, SQL injection, defer-in-loop

**Rust (7 patterns):** unwrap/expect panics, unsafe blocks, transmute, hardcoded secrets

**Python (10 patterns):** Bare except, eval/exec injection, SQL formatting, subprocess shell=True, mutable defaults

**Java (8 patterns):** Empty catch, SQL concatenation, deprecated Thread API, null returns

**TypeScript/JS (11 patterns):** eval, innerHTML XSS, SQL template injection, `any` type, callback nesting

## Commands

```bash
boundary-mapper init mymod              # Scaffold config for your project
boundary-mapper init mymod --skill      # Also generate a Claude Code skill
boundary-mapper scan                    # Scan repo (auto-detects config)
boundary-mapper scan --fresh            # Clean scan from scratch
boundary-mapper surfaces                # List boundary surfaces
boundary-mapper surfaces genetlink      # Filter by type
boundary-mapper findings --high         # Show HIGH severity findings
boundary-mapper findings --medium       # Show MEDIUM severity
boundary-mapper show SOME_OPT          # Detail for one surface
boundary-mapper trace func_name        # Callers + callees with status
boundary-mapper trace a --to b         # Path between two functions
boundary-mapper trace func --from-init # Trace from module_init
boundary-mapper profiles               # List available profiles
boundary-mapper languages              # List language definitions + lint counts
boundary-mapper stats                  # Database statistics
boundary-mapper report                 # Regenerate reports
```

## Configuration

Place `.boundary-mapper.json` in your repo root:

```json
{
  "profile": "custom",
  "custom": {
    "name": "mymod",
    "description": "My kernel module",
    "kernel_paths": ["src/**/*.c", "src/**/*.h"],
    "userspace_paths": ["tools/**/*.go"],
    "shared_paths": ["include/uapi/**/*.h"],
    "command_prefixes": ["MYMOD_CMD_"],
    "option_prefixes": ["MYMOD_"],
    "attribute_prefixes": ["MYMOD_ATTR_"],
    "sockopt_map": {
      "1": "MYMOD_NODELAY",
      "2": "MYMOD_MAXSEG"
    },
    "genl_families": {},
    "directories": [
      {"path": "src/", "side": "kernel"},
      {"path": "include/uapi/", "side": "shared"},
      {"path": "tools/", "side": "userspace"}
    ]
  }
}
```

Then just run `boundary-mapper scan` — no flags needed.

## Custom Languages

Add language definitions in config:

```json
{
  "languages": [{
    "name": "zig",
    "extensions": [".zig"],
    "symbols": [
      {"name": "fn_def", "regex": "^pub fn (\\w+)", "kind": "function_def"}
    ],
    "boundaries": [
      {"name": "switch", "regex": "\\.(\\w+) =>", "type": "dispatch", "groups": {"case": 1}}
    ]
  }]
}
```

## Languages

| Language | Extensions | Symbols | Boundaries | Lint |
|----------|-----------|---------|------------|------|
| C | .c, .h | 7 | 12 | 21 |
| Go | .go | 4 | 0 | 10 |
| Rust | .rs | 6 | 1 | 7 |
| Python | .py | 3 | 1 | 10 |
| Java | .java | 3 | 1 | 8 |
| TypeScript | .ts, .tsx, .js, .jsx | 5 | 1 | 11 |

## Report

After scanning, `boundary_reports/boundary_report.md` contains:

1. **Executive Summary** — surface health, finding severity distribution
2. **Highest-Value Gaps** — top incomplete surfaces by importance
3. **Dead Surface Cleanup** — UAPI constants to remove or gate
4. **Intentional Kernel-Only** — diagnostic surfaces (not urgent)
5. **Action Recommendations** — count by recommended action
6. **Internal Wiring Audit** — init chains, ops tables, dead functions
7. **Consistency Problems** — signature mismatches, duplicate defs
8. **All Surfaces** — full detail with importance scores
9. **Findings by Severity**
10. **Low-Value Items** — separated noise

## How It Works

1. **Scan** — Walk repo, classify files by language and side (kernel/userspace/shared)
2. **Extract** — Regex-based extraction of functions, structs, enums, constants, ops tables, dispatch cases, registrations, call sites, lint patterns
3. **Graph** — Build symbol graph with edges (IMPLEMENTS, CALLS). Resolve call graph: ~6,500 edges from ~23,000 raw refs on a medium kernel module
4. **Rules** — 16 analysis rules check boundary wiring, internal wiring, consistency, and enrichment
5. **Lint** — 65 patterns flag memory safety, security, and code quality issues
6. **Report** — Markdown report with executive summary, top-N priority lists, action recommendations

## Architecture

```
boundary_mapper/
├── cli.py              # Commands: scan, trace, surfaces, findings, show, init
├── config.py           # .boundary-mapper.json auto-detection + skill generation
├── languages.py        # 6 language definitions with symbol + boundary + lint patterns
├── models.py           # SymbolNode, GraphEdge, BoundarySurface, Finding
├── db.py               # SQLite fact store
├── repo_scan.py        # File discovery and classification
├── pattern_extract.py  # Symbol, call graph, signature, body analysis, lint extraction
├── graph_build.py      # Graph assembly, edge resolution, lint storage
├── rules_engine.py     # 16 rules: boundary + internal + consistency + enrichment
├── profiles/
│   ├── base.py         # Generic profile
│   └── custom.py       # JSON-driven profile (no Python needed)
└── reporting/
    ├── report_md.py    # Markdown with executive summary + top-N lists
    ├── report_json.py  # JSON export
    └── report_dot.py   # Graphviz visualization
```

## License

MIT
