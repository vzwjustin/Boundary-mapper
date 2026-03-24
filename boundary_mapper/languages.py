"""Language definitions for boundary mapping.

Each LanguageDef bundles:
  - file extensions it handles
  - regex patterns for extracting symbols (functions, structs, enums, constants)
  - regex patterns for extracting boundary artifacts (dispatch, registration, attrs)
  - an extraction function that uses those patterns

Builtin languages: C/H, Go, Rust, Python, Java, TypeScript.
Users can extend or override via JSON config.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import (
    Confidence, EdgeKind, Evidence, ExtractionMethod, GraphEdge,
    Side, SymbolKind, SymbolNode,
)


# ─── LanguageDef dataclass ───

@dataclass
class SymbolPattern:
    """A named regex that extracts a symbol from source code."""
    name: str                          # e.g., "function_def"
    regex: str                         # raw regex string
    kind: SymbolKind                   # what symbol kind it produces
    group: int = 1                     # which capture group is the name
    confidence: Confidence = Confidence.HIGH
    only_in: str = ""                 # restrict to specific extensions (e.g., "h")


@dataclass
class BoundaryPattern:
    """A named regex for boundary-specific extractions."""
    name: str                          # e.g., "case_dispatch"
    regex: str
    extract_type: str                  # "dispatch", "registration", "attr_read",
                                       # "attr_write", "ops_field"
    groups: dict = field(default_factory=dict)  # named group → field mapping


@dataclass
class LintPattern:
    """A regex pattern that directly flags potential issues in source code."""
    name: str                          # e.g., "unchecked_alloc"
    regex: str                         # pattern to match
    severity: str = "medium"           # finding severity
    category: str = "lint"             # finding category
    message: str = ""                  # human-readable message template
    recommendation: str = ""           # suggested fix
    multiline: bool = False            # whether to use re.DOTALL
    only_in: str = ""                 # restrict to specific extensions


@dataclass
class LanguageDef:
    """Complete language definition for extraction."""
    name: str                          # "c", "go", "rust", etc.
    extensions: list[str]              # [".c", ".h"]
    aliases: list[str] = field(default_factory=list)  # ["c", "h"]
    symbol_patterns: list[SymbolPattern] = field(default_factory=list)
    boundary_patterns: list[BoundaryPattern] = field(default_factory=list)
    lint_patterns: list[LintPattern] = field(default_factory=list)
    # For languages where headers are separate
    header_extensions: list[str] = field(default_factory=list)


# ─── Builtin language definitions ───

LANG_C = LanguageDef(
    name="c",
    extensions=[".c", ".h"],
    aliases=["c", "h"],
    header_extensions=[".h"],
    symbol_patterns=[
        SymbolPattern(
            name="function_def",
            regex=(
                r'^(?:static\s+)?(?:inline\s+)?(?:__init\s+)?'
                r'(?:(?:int|void|bool|ssize_t|unsigned\s+int|long|__be\d+|'
                r'struct\s+\w+\s*\*?|const\s+\w+\s*\*?|u(?:8|16|32|64)|'
                r's(?:8|16|32|64)|size_t|__u\d+|__s\d+|__le\d+|__be\d+|'
                r'enum\s+\w+|char\s*\*?)\s+)'
                r'(\w+)\s*\([^)]*\)\s*\{'
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="init_function",
            regex=(
                r'^(?:static\s+)?(?:int|void)\s+__init\s+'
                r'(\w+)\s*\([^)]*\)\s*\{'
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="exit_function",
            regex=(
                r'^(?:static\s+)?(?:void)\s+__exit\s+'
                r'(\w+)\s*\([^)]*\)\s*\{'
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="function_decl",
            regex=(
                r'^(?:extern\s+)?(?:static\s+inline\s+)?'
                r'(?:(?:int|void|bool|ssize_t|unsigned\s+int|long|__be\d+|'
                r'struct\s+\w+\s*\*?|const\s+\w+\s*\*?|u(?:8|16|32|64)|'
                r'size_t)\s+)'
                r'(\w+)\s*\([^)]*\)\s*;'
            ),
            kind=SymbolKind.FUNCTION_DECL,
            only_in="h",
        ),
        SymbolPattern(
            name="struct_var",
            regex=(
                r'^(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+(\w+)'
                r'(?:\s*__\w+)?\s*=\s*\{'
            ),
            kind=SymbolKind.OPS_TABLE,
            group=2,  # capture variable name, not struct type
        ),
        SymbolPattern(
            name="enum_def",
            regex=r'^(?:enum)\s+(\w+)\s*\{',
            kind=SymbolKind.ENUM,
        ),
        SymbolPattern(
            name="define",
            regex=r'^#define\s+(\w+)\s+(.+?)(?:\s*/\*.*\*/)?$',
            kind=SymbolKind.CONSTANT,
        ),
    ],
    boundary_patterns=[
        BoundaryPattern(
            name="case_dispatch",
            regex=r'^\s*case\s+(\w+)\s*:',
            extract_type="dispatch",
            groups={"case": 1},
        ),
        BoundaryPattern(
            name="ops_field",
            regex=r'^\s*\.(\w+)\s*=\s*(\w+)\s*,',
            extract_type="ops_field",
            groups={"field": 1, "handler": 2},
        ),
        BoundaryPattern(
            name="genl_register",
            regex=r'genl_register_family\s*\(\s*&(\w+)\s*\)',
            extract_type="registration",
            groups={"family": 1},
        ),
        BoundaryPattern(
            name="sysctl_register",
            regex=r'register_net_sysctl\s*\(\s*[^,]+,\s*"([^"]+)"',
            extract_type="registration",
            groups={"path": 1},
        ),
        BoundaryPattern(
            name="nla_get",
            regex=r'nla_get_(\w+)\s*\(\s*\S+\[\s*(\w+)\s*\]',
            extract_type="attr_read",
            groups={"type": 1, "attr": 2},
        ),
        BoundaryPattern(
            name="nla_put",
            regex=r'nla_put_(\w+)\s*\([^,]+,\s*(\w+)\s*,',
            extract_type="attr_write",
            groups={"type": 1, "attr": 2},
        ),
        # ── Internal wiring patterns ──
        BoundaryPattern(
            name="module_init",
            regex=r'module_init\s*\(\s*(\w+)\s*\)',
            extract_type="internal",
            groups={"function": 1, "type": "module_init"},
        ),
        BoundaryPattern(
            name="module_exit",
            regex=r'module_exit\s*\(\s*(\w+)\s*\)',
            extract_type="internal",
            groups={"function": 1, "type": "module_exit"},
        ),
        BoundaryPattern(
            name="export_symbol",
            regex=r'EXPORT_SYMBOL(?:_GPL)?\s*\(\s*(\w+)\s*\)',
            extract_type="internal",
            groups={"function": 1, "type": "export"},
        ),
        BoundaryPattern(
            name="function_call",
            regex=r'\b(\w+)\s*\([^)]*\)\s*;',
            extract_type="internal",
            groups={"function": 1, "type": "call"},
        ),
        BoundaryPattern(
            name="register_call",
            regex=r'\b(\w+_register(?:_\w+)?)\s*\(\s*(?:&\s*)?(\w+)',
            extract_type="internal",
            groups={"register_fn": 1, "target": 2, "type": "register"},
        ),
        BoundaryPattern(
            name="unregister_call",
            regex=r'\b(\w+_unregister(?:_\w+)?)\s*\(\s*(?:&\s*)?(\w+)',
            extract_type="internal",
            groups={"unregister_fn": 1, "target": 2, "type": "unregister"},
        ),
    ],
    lint_patterns=[
        # ── Memory safety ──
        LintPattern(
            name="unchecked_alloc",
            regex=r'(\w+)\s*=\s*k[mz]alloc\s*\([^)]+\)\s*;',
            severity="high",
            category="unchecked_alloc",
            message="Allocation result not checked for NULL on same line",
            recommendation="add_null_check",
            only_in="c",
        ),
        LintPattern(
            name="unchecked_alloc_skb",
            regex=r'(\w+)\s*=\s*(?:alloc_skb|netdev_alloc_skb|__alloc_skb)\s*\(',
            severity="high",
            category="unchecked_alloc",
            message="SKB allocation result may not be NULL-checked",
            recommendation="add_null_check",
            only_in="c",
        ),
        LintPattern(
            name="unchecked_kstrdup",
            regex=r'(\w+)\s*=\s*k(?:str|mem)dup\s*\(',
            severity="medium",
            category="unchecked_alloc",
            message="String/memory dup result may not be NULL-checked",
            recommendation="add_null_check",
            only_in="c",
        ),
        LintPattern(
            name="use_after_free_pattern",
            regex=r'kfree\s*\(\s*(\w+)\s*\)\s*;[^}]*\b\1\b',
            severity="high",
            category="use_after_free",
            message="Variable used after kfree — potential use-after-free",
            recommendation="set_pointer_null_after_free",
            multiline=True,
            only_in="c",
        ),
        # ── Error handling ──
        LintPattern(
            name="bare_bug",
            regex=r'\bBUG\s*\(\s*\)\s*;',
            severity="medium",
            category="unsafe_panic",
            message="BUG() crashes the kernel — use WARN_ON or return error instead",
            recommendation="replace_with_warn_on",
            only_in="c",
        ),
        # ── Lock safety ──
        LintPattern(
            name="double_lock_pattern",
            regex=r'(spin_lock(?:_bh|_irq|_irqsave)?)\s*\([^)]+\).*\1\s*\(',
            severity="high",
            category="deadlock",
            message="Same lock type acquired twice — potential deadlock",
            recommendation="check_lock_ordering",
            multiline=True,
            only_in="c",
        ),
        # ── API misuse ──
        LintPattern(
            name="deprecated_create_proc",
            regex=r'\bcreate_proc_entry\s*\(',
            severity="medium",
            category="deprecated_api",
            message="create_proc_entry is deprecated — use proc_create",
            recommendation="migrate_to_proc_create",
            only_in="c",
        ),
        LintPattern(
            name="deprecated_pci_dma",
            regex=r'\bpci_(?:map|unmap|dma)_',
            severity="low",
            category="deprecated_api",
            message="pci_dma APIs deprecated — use dma_map/unmap_* instead",
            recommendation="migrate_to_dma_api",
            only_in="c",
        ),
        LintPattern(
            name="deprecated_get_ds",
            regex=r'\bget_ds\s*\(\s*\)',
            severity="medium",
            category="deprecated_api",
            message="get_ds() removed in modern kernels",
            recommendation="remove_set_fs_usage",
            only_in="c",
        ),
        LintPattern(
            name="printk_no_level",
            regex=r'\bprintk\s*\(\s*"',
            severity="low",
            category="style",
            message="printk without KERN_ level — use pr_info/pr_err macros",
            recommendation="use_pr_macros",
            only_in="c",
        ),
        # ── Integer safety ──
        LintPattern(
            name="unchecked_copy_from_user",
            regex=r'copy_from_user\s*\([^)]+\)\s*;',
            severity="high",
            category="unsafe_copy",
            message="copy_from_user return value must be checked",
            recommendation="check_copy_return",
            only_in="c",
        ),
        LintPattern(
            name="unchecked_copy_to_user",
            regex=r'copy_to_user\s*\([^)]+\)\s*;',
            severity="high",
            category="unsafe_copy",
            message="copy_to_user return value must be checked",
            recommendation="check_copy_return",
            only_in="c",
        ),
        LintPattern(
            name="user_size_to_kmalloc",
            regex=r'kmalloc\s*\(\s*\w*len\w*\s*[,)]',
            severity="medium",
            category="integer_overflow",
            message="Variable-sized kmalloc — verify size is bounded",
            recommendation="validate_size_bounds",
            only_in="c",
        ),
        # ── Code quality markers ──
        LintPattern(
            name="todo_marker",
            regex=r'(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BROKEN|WORKAROUND)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="hardcoded_ip",
            regex=r'(?:"|\')\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:"|\')',
            severity="medium",
            category="hardcoded_value",
            message="Hardcoded IP address — should be configurable",
            recommendation="make_configurable",
        ),
        LintPattern(
            name="hardcoded_port",
            regex=r'\bport\s*[=!<>]+\s*(?:80|443|8080|8443|3306|5432|6379|27017)\b',
            severity="low",
            category="hardcoded_value",
            message="Hardcoded well-known port — consider making configurable",
            recommendation="make_configurable",
        ),
        # ── Security ──
        LintPattern(
            name="sprintf_usage",
            regex=r'\bsprintf\s*\(',
            severity="medium",
            category="buffer_overflow",
            message="sprintf has no bounds check — use snprintf or scnprintf",
            recommendation="use_snprintf",
            only_in="c",
        ),
        LintPattern(
            name="strcpy_usage",
            regex=r'\bstrcpy\s*\(',
            severity="medium",
            category="buffer_overflow",
            message="strcpy has no bounds check — use strscpy or strlcpy",
            recommendation="use_strscpy",
            only_in="c",
        ),
        LintPattern(
            name="strcat_usage",
            regex=r'\bstrcat\s*\(',
            severity="medium",
            category="buffer_overflow",
            message="strcat has no bounds check — use strlcat",
            recommendation="use_strlcat",
            only_in="c",
        ),
        # ── Forward declaration / incomplete type issues ──
        LintPattern(
            name="opaque_struct_deref",
            regex=r'(?:->|\.)\w+\s*[^;]*\bstruct\s+\w+\s*\*',
            severity="info",
            category="type_usage",
            message="Struct pointer dereference — verify type is fully defined in scope",
            recommendation="check_include_provides_definition",
            only_in="c",
        ),
        LintPattern(
            name="sizeof_incomplete",
            regex=r'sizeof\s*\(\s*(?:struct\s+)?\*?\w+\s*\)',
            severity="info",
            category="type_usage",
            message="sizeof on type — verify not an incomplete/opaque type",
            recommendation="verify_type_complete",
            only_in="c",
        ),
    ],
)

LANG_GO = LanguageDef(
    name="go",
    extensions=[".go"],
    aliases=["go"],
    symbol_patterns=[
        SymbolPattern(
            name="struct_def",
            regex=r'^type\s+(\w+)\s+struct\s*\{',
            kind=SymbolKind.GO_STRUCT,
        ),
        SymbolPattern(
            name="func_def",
            regex=r'^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(',
            kind=SymbolKind.GO_FUNC,
            confidence=Confidence.MEDIUM,
        ),
        SymbolPattern(
            name="interface_def",
            regex=r'^type\s+(\w+)\s+interface\s*\{',
            kind=SymbolKind.GO_STRUCT,  # reuse
        ),
        SymbolPattern(
            name="const_def",
            regex=r'^\s*(\w+)\s*(?:=\s*(?:iota|\d+|"[^"]*"))?\s*$',
            kind=SymbolKind.GO_CONST,
            confidence=Confidence.MEDIUM,
        ),
    ],
    boundary_patterns=[],
    lint_patterns=[
        # ── Error handling ──
        LintPattern(
            name="unchecked_error",
            regex=r'[^_]err\s*:=\s*\w+\([^)]*\)\s*\n\s*(?!if\s+err)',
            severity="high",
            category="unchecked_error",
            message="Error return not checked — if err != nil missing",
            recommendation="add_error_check",
            multiline=True,
        ),
        LintPattern(
            name="bare_panic",
            regex=r'\bpanic\s*\([^)]*\)',
            severity="medium",
            category="unsafe_panic",
            message="panic() in production code — return error instead",
            recommendation="return_error_instead",
        ),
        LintPattern(
            name="empty_error_handler",
            regex=r'if\s+err\s*!=\s*nil\s*\{\s*\}',
            severity="high",
            category="swallowed_error",
            message="Error silently swallowed — empty if err != nil block",
            recommendation="handle_or_propagate_error",
        ),
        # ── Concurrency ──
        LintPattern(
            name="goroutine_leak",
            regex=r'\bgo\s+func\s*\(',
            severity="info",
            category="concurrency",
            message="Anonymous goroutine — verify it terminates and errors are handled",
            recommendation="verify_goroutine_lifecycle",
        ),
        LintPattern(
            name="mutex_copy",
            regex=r'=\s*\*?\w+\.(?:Mutex|RWMutex)',
            severity="high",
            category="concurrency",
            message="Mutex may be copied — mutexes must not be copied after first use",
            recommendation="use_pointer_to_mutex",
        ),
        # ── Security ──
        LintPattern(
            name="sql_concat",
            regex=r'(?:Exec|Query|QueryRow)\s*\(\s*(?:"[^"]*"\s*\+|fmt\.Sprintf)',
            severity="high",
            category="sql_injection",
            message="SQL string concatenation — use parameterized queries",
            recommendation="use_parameterized_query",
        ),
        LintPattern(
            name="hardcoded_secret",
            regex=r'(?:password|secret|token|apikey|api_key)\s*[=:]\s*"[^"]{8,}"',
            severity="high",
            category="hardcoded_secret",
            message="Hardcoded secret/credential — use env vars or config",
            recommendation="use_env_or_config",
        ),
        # ── Code quality ──
        LintPattern(
            name="todo_marker",
            regex=r'//\s*(?:TODO|FIXME|HACK|XXX|BROKEN)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="defer_in_loop",
            regex=r'for\s+.*\{[^}]*defer\b',
            severity="medium",
            category="resource_leak",
            message="defer inside loop — defers don't run until function returns",
            recommendation="move_defer_or_use_closure",
            multiline=True,
        ),
        LintPattern(
            name="fmt_errorf_wrap",
            regex=r'fmt\.Errorf\s*\([^)]*%s',
            severity="low",
            category="style",
            message="Use %w instead of %s to wrap errors (enables errors.Is/As)",
            recommendation="use_percent_w",
        ),
    ],
)

LANG_RUST = LanguageDef(
    name="rust",
    extensions=[".rs"],
    aliases=["rust", "rs"],
    symbol_patterns=[
        SymbolPattern(
            name="fn_def",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'(?:async\s+)?(?:unsafe\s+)?'
                r'(?:extern\s+"C"\s+)?'
                r'fn\s+(\w+)'
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="struct_def",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'struct\s+(\w+)'
            ),
            kind=SymbolKind.STRUCT,
        ),
        SymbolPattern(
            name="enum_def",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'enum\s+(\w+)'
            ),
            kind=SymbolKind.ENUM,
        ),
        SymbolPattern(
            name="trait_def",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'trait\s+(\w+)'
            ),
            kind=SymbolKind.STRUCT,  # reuse for interfaces
        ),
        SymbolPattern(
            name="const_def",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'(?:const|static)\s+(\w+)\s*:'
            ),
            kind=SymbolKind.CONSTANT,
        ),
        SymbolPattern(
            name="type_alias",
            regex=(
                r'^(?:pub(?:\((?:crate|super)\)\s+)?)?'
                r'type\s+(\w+)\s*='
            ),
            kind=SymbolKind.TYPEDEF,
        ),
    ],
    boundary_patterns=[
        BoundaryPattern(
            name="match_arm",
            regex=r'^\s*(\w+(?:::\w+)*)\s*(?:\(.*\))?\s*=>\s*',
            extract_type="dispatch",
            groups={"case": 1},
        ),
    ],
    lint_patterns=[
        LintPattern(
            name="unwrap_usage",
            regex=r'\.unwrap\s*\(\s*\)',
            severity="medium",
            category="unsafe_unwrap",
            message=".unwrap() panics on None/Err — use ? operator or match",
            recommendation="use_question_mark_or_match",
        ),
        LintPattern(
            name="expect_usage",
            regex=r'\.expect\s*\(\s*"',
            severity="low",
            category="unsafe_unwrap",
            message=".expect() panics on None/Err — consider ? or match in libraries",
            recommendation="use_question_mark_in_lib",
        ),
        LintPattern(
            name="unsafe_block",
            regex=r'\bunsafe\s*\{',
            severity="medium",
            category="unsafe_code",
            message="unsafe block — verify memory safety invariants",
            recommendation="document_safety_invariants",
        ),
        LintPattern(
            name="todo_marker",
            regex=r'//\s*(?:TODO|FIXME|HACK|XXX)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="clone_on_ref",
            regex=r'\.clone\s*\(\s*\)',
            severity="info",
            category="performance",
            message=".clone() — verify clone is necessary (may be avoidable with borrows)",
            recommendation="consider_borrowing",
        ),
        LintPattern(
            name="hardcoded_secret",
            regex=r'(?:password|secret|token|api_key)\s*[=:]\s*"[^"]{8,}"',
            severity="high",
            category="hardcoded_secret",
            message="Hardcoded secret — use env vars or config",
            recommendation="use_env_or_config",
        ),
        LintPattern(
            name="transmute_usage",
            regex=r'\btransmute\s*[:<(]',
            severity="high",
            category="unsafe_code",
            message="transmute is extremely unsafe — verify types are compatible",
            recommendation="use_safe_cast_alternative",
        ),
    ],
)

LANG_PYTHON = LanguageDef(
    name="python",
    extensions=[".py"],
    aliases=["py", "python"],
    symbol_patterns=[
        SymbolPattern(
            name="function_def",
            regex=r'^(?:async\s+)?def\s+(\w+)\s*\(',
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="class_def",
            regex=r'^class\s+(\w+)\s*[:\(]',
            kind=SymbolKind.STRUCT,
        ),
        SymbolPattern(
            name="constant",
            regex=r'^([A-Z][A-Z0-9_]{2,})\s*=\s*',
            kind=SymbolKind.CONSTANT,
            confidence=Confidence.MEDIUM,
        ),
    ],
    boundary_patterns=[
        BoundaryPattern(
            name="route_decorator",
            regex=r'@\w+\.(?:route|get|post|put|delete)\s*\(\s*["\']([^"\']+)',
            extract_type="registration",
            groups={"path": 1},
        ),
    ],
    lint_patterns=[
        LintPattern(
            name="bare_except",
            regex=r'\bexcept\s*:',
            severity="medium",
            category="swallowed_error",
            message="Bare except catches everything including KeyboardInterrupt",
            recommendation="catch_specific_exception",
        ),
        LintPattern(
            name="except_pass",
            regex=r'except\s*.*:\s*\n\s+pass\b',
            severity="medium",
            category="swallowed_error",
            message="Exception silently swallowed with pass",
            recommendation="log_or_handle_exception",
            multiline=True,
        ),
        LintPattern(
            name="eval_usage",
            regex=r'\beval\s*\(',
            severity="high",
            category="code_injection",
            message="eval() is a code injection risk — use ast.literal_eval or safer alternative",
            recommendation="use_ast_literal_eval",
        ),
        LintPattern(
            name="exec_usage",
            regex=r'\bexec\s*\(',
            severity="high",
            category="code_injection",
            message="exec() is a code injection risk",
            recommendation="remove_exec",
        ),
        LintPattern(
            name="sql_format",
            regex=r'(?:execute|cursor\.)\w*\(\s*(?:f"|".*"\s*%|".*"\.format)',
            severity="high",
            category="sql_injection",
            message="SQL string formatting — use parameterized queries",
            recommendation="use_parameterized_query",
        ),
        LintPattern(
            name="hardcoded_secret",
            regex=r'(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)\s*=\s*["\'][^"\']{8,}["\']',
            severity="high",
            category="hardcoded_secret",
            message="Hardcoded secret — use env vars or config",
            recommendation="use_env_or_config",
        ),
        LintPattern(
            name="assert_in_production",
            regex=r'^\s*assert\s+',
            severity="low",
            category="style",
            message="assert is stripped with -O flag — use explicit checks for production code",
            recommendation="use_explicit_check",
        ),
        LintPattern(
            name="mutable_default_arg",
            regex=r'def\s+\w+\s*\([^)]*(?:=\s*\[\]|=\s*\{\}|=\s*set\(\))',
            severity="medium",
            category="mutable_default",
            message="Mutable default argument — shared across calls",
            recommendation="use_none_default",
        ),
        LintPattern(
            name="todo_marker",
            regex=r'#\s*(?:TODO|FIXME|HACK|XXX)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="subprocess_shell",
            regex=r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
            severity="high",
            category="command_injection",
            message="subprocess with shell=True — command injection risk",
            recommendation="use_shell_false_with_list",
        ),
    ],
)

LANG_JAVA = LanguageDef(
    name="java",
    extensions=[".java"],
    aliases=["java"],
    symbol_patterns=[
        SymbolPattern(
            name="method_def",
            regex=(
                r'(?:public|private|protected|static|final|abstract|synchronized|native)\s+'
                r'(?:(?:static|final|abstract|synchronized)\s+)*'
                r'(?:\w+(?:<[^>]+>)?)\s+'
                r'(\w+)\s*\('
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="class_def",
            regex=(
                r'(?:public|private|protected)?\s*'
                r'(?:abstract|final|static)?\s*'
                r'(?:class|interface|enum)\s+(\w+)'
            ),
            kind=SymbolKind.STRUCT,
        ),
        SymbolPattern(
            name="constant",
            regex=(
                r'(?:public|private|protected)?\s*'
                r'static\s+final\s+\w+\s+([A-Z][A-Z0-9_]+)\s*='
            ),
            kind=SymbolKind.CONSTANT,
        ),
    ],
    boundary_patterns=[
        BoundaryPattern(
            name="request_mapping",
            regex=r'@(?:Request|Get|Post|Put|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)',
            extract_type="registration",
            groups={"path": 1},
        ),
    ],
    lint_patterns=[
        LintPattern(
            name="empty_catch",
            regex=r'catch\s*\([^)]*\)\s*\{\s*\}',
            severity="medium",
            category="swallowed_error",
            message="Empty catch block — exception silently swallowed",
            recommendation="log_or_rethrow",
        ),
        LintPattern(
            name="sql_concat",
            regex=r'(?:executeQuery|prepareStatement|createQuery)\s*\(\s*(?:"[^"]*"\s*\+|String\.format)',
            severity="high",
            category="sql_injection",
            message="SQL string concatenation — use PreparedStatement",
            recommendation="use_prepared_statement",
        ),
        LintPattern(
            name="hardcoded_secret",
            regex=r'(?:password|secret|token|apiKey)\s*=\s*"[^"]{8,}"',
            severity="high",
            category="hardcoded_secret",
            message="Hardcoded secret — use env vars or config",
            recommendation="use_env_or_config",
        ),
        LintPattern(
            name="system_exit",
            regex=r'System\.exit\s*\(',
            severity="medium",
            category="unsafe_exit",
            message="System.exit() kills the JVM — throw exception instead",
            recommendation="throw_exception",
        ),
        LintPattern(
            name="thread_stop",
            regex=r'\.stop\s*\(\s*\)|\.suspend\s*\(\s*\)|\.resume\s*\(\s*\)',
            severity="high",
            category="deprecated_api",
            message="Thread.stop/suspend/resume are deprecated and unsafe",
            recommendation="use_interrupt_pattern",
        ),
        LintPattern(
            name="raw_type",
            regex=r'\b(?:List|Map|Set|Collection|Iterator)\s+\w+\s*[=;]',
            severity="low",
            category="style",
            message="Raw generic type — use parameterized type (e.g., List<String>)",
            recommendation="add_type_parameter",
        ),
        LintPattern(
            name="todo_marker",
            regex=r'//\s*(?:TODO|FIXME|HACK|XXX)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="null_return",
            regex=r'\breturn\s+null\s*;',
            severity="low",
            category="null_safety",
            message="Returning null — consider Optional or throwing exception",
            recommendation="use_optional_or_throw",
        ),
    ],
)

LANG_TYPESCRIPT = LanguageDef(
    name="typescript",
    extensions=[".ts", ".tsx", ".js", ".jsx"],
    aliases=["ts", "tsx", "js", "jsx", "typescript", "javascript"],
    symbol_patterns=[
        SymbolPattern(
            name="function_def",
            regex=(
                r'^(?:export\s+)?(?:async\s+)?'
                r'function\s+(\w+)\s*[\(<]'
            ),
            kind=SymbolKind.FUNCTION_DEF,
        ),
        SymbolPattern(
            name="arrow_const",
            regex=(
                r'^(?:export\s+)?'
                r'(?:const|let|var)\s+(\w+)\s*=\s*'
                r'(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>'
            ),
            kind=SymbolKind.FUNCTION_DEF,
            confidence=Confidence.MEDIUM,
        ),
        SymbolPattern(
            name="class_def",
            regex=(
                r'^(?:export\s+)?(?:abstract\s+)?'
                r'class\s+(\w+)'
            ),
            kind=SymbolKind.STRUCT,
        ),
        SymbolPattern(
            name="interface_def",
            regex=(
                r'^(?:export\s+)?'
                r'(?:interface|type)\s+(\w+)\s*[=\{<]'
            ),
            kind=SymbolKind.STRUCT,
        ),
        SymbolPattern(
            name="enum_def",
            regex=(
                r'^(?:export\s+)?(?:const\s+)?'
                r'enum\s+(\w+)\s*\{'
            ),
            kind=SymbolKind.ENUM,
        ),
    ],
    boundary_patterns=[
        BoundaryPattern(
            name="express_route",
            regex=r'\.(?:get|post|put|patch|delete|all)\s*\(\s*["\']([^"\']+)',
            extract_type="registration",
            groups={"path": 1},
        ),
    ],
    lint_patterns=[
        LintPattern(
            name="eval_usage",
            regex=r'\beval\s*\(',
            severity="high",
            category="code_injection",
            message="eval() is a code injection risk",
            recommendation="remove_eval",
        ),
        LintPattern(
            name="any_type",
            regex=r':\s*any\b',
            severity="low",
            category="type_safety",
            message="Type 'any' defeats TypeScript's type system",
            recommendation="use_specific_type",
            only_in="ts",
        ),
        LintPattern(
            name="non_null_assertion",
            regex=r'\w+!\.',
            severity="low",
            category="type_safety",
            message="Non-null assertion (!) — may hide null errors at runtime",
            recommendation="use_optional_chaining",
            only_in="ts",
        ),
        LintPattern(
            name="console_log",
            regex=r'\bconsole\.log\s*\(',
            severity="info",
            category="debug_code",
            message="console.log left in code — use proper logging",
            recommendation="use_logger",
        ),
        LintPattern(
            name="hardcoded_secret",
            regex=r'(?:password|secret|token|apiKey|api_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
            severity="high",
            category="hardcoded_secret",
            message="Hardcoded secret — use env vars or config",
            recommendation="use_env_or_config",
        ),
        LintPattern(
            name="sql_template_literal",
            regex=r'(?:query|execute|sql)\s*\(\s*`[^`]*\$\{',
            severity="high",
            category="sql_injection",
            message="SQL template literal with interpolation — use parameterized queries",
            recommendation="use_parameterized_query",
        ),
        LintPattern(
            name="innerhtml_assignment",
            regex=r'\.innerHTML\s*=',
            severity="high",
            category="xss",
            message="innerHTML assignment — XSS risk with untrusted data",
            recommendation="use_textContent_or_sanitize",
        ),
        LintPattern(
            name="document_write",
            regex=r'\bdocument\.write\s*\(',
            severity="medium",
            category="xss",
            message="document.write — XSS risk and bad for performance",
            recommendation="use_dom_api",
        ),
        LintPattern(
            name="todo_marker",
            regex=r'//\s*(?:TODO|FIXME|HACK|XXX)\b[:\s]*(.*)',
            severity="info",
            category="todo",
            message="Developer TODO marker",
            recommendation="resolve_todo",
        ),
        LintPattern(
            name="var_usage",
            regex=r'\bvar\s+\w+',
            severity="low",
            category="style",
            message="var is function-scoped — use const or let instead",
            recommendation="use_const_or_let",
        ),
        LintPattern(
            name="callback_hell",
            regex=r'\)\s*=>\s*\{[^}]*\)\s*=>\s*\{[^}]*\)\s*=>\s*\{',
            severity="medium",
            category="readability",
            message="Deeply nested callbacks — use async/await",
            recommendation="refactor_to_async_await",
            multiline=True,
        ),
    ],
)


# ─── Registry ───

BUILTIN_LANGUAGES: dict[str, LanguageDef] = {
    "c": LANG_C,
    "go": LANG_GO,
    "rust": LANG_RUST,
    "python": LANG_PYTHON,
    "java": LANG_JAVA,
    "typescript": LANG_TYPESCRIPT,
}

# Extension → language name lookup (built from all definitions)
_EXT_MAP: dict[str, str] = {}
for _lang in BUILTIN_LANGUAGES.values():
    for _ext in _lang.extensions:
        _EXT_MAP[_ext] = _lang.name
    for _alias in _lang.aliases:
        _EXT_MAP[_alias] = _lang.name


def get_language(name_or_ext: str) -> Optional[LanguageDef]:
    """Look up a language by name, alias, or extension."""
    # Direct name match
    if name_or_ext in BUILTIN_LANGUAGES:
        return BUILTIN_LANGUAGES[name_or_ext]
    # Extension match
    lang_name = _EXT_MAP.get(name_or_ext)
    if lang_name:
        return BUILTIN_LANGUAGES[lang_name]
    return None


def detect_language(path: str) -> tuple[str, Optional[LanguageDef]]:
    """Detect language from file path.

    Returns (lang_tag, LanguageDef or None).  lang_tag preserves the
    extension-level distinction (e.g., "h" vs "c") for stats counting,
    while both map to the same LANG_C definition for extraction.
    """
    import os
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()

    # Special filenames
    if name in ("makefile", "kbuild", "kconfig"):
        return name, None
    if name in ("dockerfile",):
        return "docker", None
    if name in ("cmakelists.txt",):
        return "cmake", None

    # Use extension-stripped tag for stats (e.g., ".h" → "h", ".c" → "c")
    tag = ext.lstrip(".")

    lang = get_language(ext)
    if lang:
        return tag or lang.name, lang
    return "other", None


def language_from_json(data: dict) -> LanguageDef:
    """Build a LanguageDef from a JSON dict (for user-defined languages).

    Example JSON:
    {
        "name": "zig",
        "extensions": [".zig"],
        "symbols": [
            {"name": "fn_def", "regex": "^pub fn (\\w+)", "kind": "function_def"},
            {"name": "struct_def", "regex": "^const (\\w+) = struct", "kind": "struct"}
        ],
        "boundaries": [
            {"name": "switch_case", "regex": "\\.(\\w+) =>", "type": "dispatch", "groups": {"case": 1}}
        ]
    }
    """
    kind_map = {k.value: k for k in SymbolKind}

    sym_pats = []
    for sp in data.get("symbols", []):
        kind = kind_map.get(sp["kind"], SymbolKind.FUNCTION_DEF)
        sym_pats.append(SymbolPattern(
            name=sp["name"],
            regex=sp["regex"],
            kind=kind,
            group=sp.get("group", 1),
            confidence=Confidence(sp.get("confidence", "high")),
            only_in=sp.get("only_in", ""),
        ))

    bnd_pats = []
    for bp in data.get("boundaries", []):
        bnd_pats.append(BoundaryPattern(
            name=bp["name"],
            regex=bp["regex"],
            extract_type=bp.get("type", "dispatch"),
            groups=bp.get("groups", {}),
        ))

    return LanguageDef(
        name=data["name"],
        extensions=data.get("extensions", []),
        aliases=data.get("aliases", []),
        header_extensions=data.get("header_extensions", []),
        symbol_patterns=sym_pats,
        boundary_patterns=bnd_pats,
    )


def register_language(lang: LanguageDef):
    """Register a language definition at runtime."""
    BUILTIN_LANGUAGES[lang.name] = lang
    for ext in lang.extensions:
        _EXT_MAP[ext] = lang.name
    for alias in lang.aliases:
        _EXT_MAP[alias] = lang.name
