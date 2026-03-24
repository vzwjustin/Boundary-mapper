"""Core data models for boundary mapping.

Every node, edge, and finding carries evidence metadata.
Confidence levels distinguish semantic (AST-backed) from heuristic (pattern-based)
from runtime-observed facts.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Side(enum.Enum):
    KERNEL = "kernel"
    USERSPACE = "userspace"
    SHARED = "shared"
    TOOLING = "tooling"
    UNKNOWN = "unknown"


class WiringStatus(enum.Enum):
    """Classification of how fully a boundary path is connected."""
    DECLARED = "declared"            # symbol exists in source
    DEFINED = "defined"              # has a body / implementation
    REGISTERED = "registered"        # plugged into a dispatch/ops table
    STATICALLY_REACHABLE = "statically_reachable"  # call path from entry
    DISPATCH_LINKED = "dispatch_linked"  # reached via function pointer dispatch
    DATA_LINKED = "data_linked"      # struct/enum shared across boundary
    RUNTIME_OBSERVED = "runtime_observed"  # confirmed via trace/probe
    PARTIALLY_WIRED = "partially_wired"  # some path elements missing
    DEAD = "dead"                    # exists but unreachable
    MISMATCHED = "mismatched"        # exists on both sides but diverges


class ExtractionMethod(enum.Enum):
    """How a fact was extracted."""
    CLANG_AST = "clang_ast"
    PATTERN_MATCH = "pattern_match"
    HEURISTIC = "heuristic"
    BUILD_SYSTEM = "build_system"
    MANUAL_ANNOTATION = "manual_annotation"
    RUNTIME_TRACE = "runtime_trace"


class Confidence(enum.Enum):
    """Confidence in a fact or relationship."""
    HIGH = "high"        # AST-backed or exact match
    MEDIUM = "medium"    # strong pattern match
    LOW = "low"          # heuristic inference
    SPECULATIVE = "speculative"  # educated guess


class SymbolKind(enum.Enum):
    FUNCTION_DECL = "function_decl"
    FUNCTION_DEF = "function_def"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    ENUM_VALUE = "enum_value"
    TYPEDEF = "typedef"
    MACRO = "macro"
    VARIABLE = "variable"
    OPS_TABLE = "ops_table"          # struct of function pointers
    DISPATCH_TABLE = "dispatch_table"  # array of handlers
    REGISTRATION = "registration"    # call to a register function
    FIELD = "field"
    CONSTANT = "constant"
    GO_STRUCT = "go_struct"
    GO_FUNC = "go_func"
    GO_CONST = "go_const"


class EdgeKind(enum.Enum):
    DECLARES = "declares"
    DEFINES = "defines"
    CALLS = "calls"
    REFERENCES = "references"
    SERIALIZES = "serializes"
    DESERIALIZES = "deserializes"
    REGISTERS = "registers"
    DISPATCHES_TO = "dispatches_to"
    READS_FIELD = "reads_field"
    WRITES_FIELD = "writes_field"
    MUTATES_OBJECT = "mutates_object"
    ALLOCATES = "allocates"
    TEARS_DOWN = "tears_down"
    EXPOSES_TO_USERSPACE = "exposes_to_userspace"
    EMITS_EVENT = "emits_event"
    CONSUMES_EVENT = "consumes_event"
    RETURNS_RESPONSE = "returns_response"
    INCLUDES = "includes"
    MEMBER_OF = "member_of"
    IMPLEMENTS = "implements"      # fills ops table slot
    MIRRORS = "mirrors"            # userspace struct mirrors kernel struct
    MAPS_TO_COMMAND = "maps_to_command"
    HANDLES_OPTION = "handles_option"
    NETLINK_ATTR = "netlink_attr"


class BoundaryType(enum.Enum):
    SETSOCKOPT = "setsockopt"
    GETSOCKOPT = "getsockopt"
    SENDMSG = "sendmsg"
    RECVMSG = "recvmsg"
    IOCTL = "ioctl"
    NETLINK = "netlink"
    GENETLINK = "genetlink"
    PROCFS = "procfs"
    SYSFS = "sysfs"
    SYSCTL = "sysctl"
    SOCKET_CREATE = "socket_create"
    PROTOCOL_REGISTER = "protocol_register"
    NETFILTER = "netfilter"
    TRACEPOINT = "tracepoint"
    CUSTOM = "custom"


class FindingSeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """Every fact must carry evidence."""
    file_path: str
    line_start: int
    line_end: int = 0
    symbol: str = ""
    snippet: str = ""
    method: ExtractionMethod = ExtractionMethod.PATTERN_MATCH
    confidence: Confidence = Confidence.MEDIUM
    note: str = ""

    def __post_init__(self):
        if self.line_end == 0:
            self.line_end = self.line_start


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

@dataclass
class SymbolNode:
    """A node in the boundary graph."""
    id: str = ""                  # auto-generated
    name: str = ""
    qualified_name: str = ""      # e.g., struct_name.field_name
    kind: SymbolKind = SymbolKind.FUNCTION_DEF
    side: Side = Side.UNKNOWN
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed edge in the boundary graph."""
    id: str = ""
    source_id: str = ""
    target_id: str = ""
    kind: EdgeKind = EdgeKind.REFERENCES
    evidence: list[Evidence] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    properties: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Boundary surfaces
# ---------------------------------------------------------------------------

@dataclass
class BoundarySurface:
    """A specific crossing point between kernel and userspace."""
    id: str = ""
    boundary_type: BoundaryType = BoundaryType.CUSTOM
    name: str = ""
    description: str = ""
    kernel_entrypoint: str = ""     # function that receives from userspace
    userspace_producer: str = ""    # function that sends to kernel
    shared_contract: str = ""       # struct/enum used by both
    dispatch_key: str = ""          # option number, command ID, etc.
    handler: str = ""               # internal handler after dispatch
    response_path: str = ""         # how results go back
    status: WiringStatus = WiringStatus.DECLARED
    evidence: list[Evidence] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    # Enrichment fields (populated by post-processing rules)
    # properties may contain: substatus, importance_score, family,
    # recommended_action, bucket, object_families


# ---------------------------------------------------------------------------
# Boundary flow (full traced path)
# ---------------------------------------------------------------------------

@dataclass
class BoundaryFlow:
    """A complete traced path from userspace through kernel and back."""
    id: str = ""
    name: str = ""                  # e.g., "create_connection"
    boundary_type: BoundaryType = BoundaryType.CUSTOM
    status: WiringStatus = WiringStatus.DECLARED
    steps: list[FlowStep] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)  # finding IDs
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class FlowStep:
    """One step in a boundary flow."""
    order: int = 0
    description: str = ""
    symbol_id: str = ""
    side: Side = Side.UNKNOWN
    action: str = ""               # e.g., "dispatch", "validate", "mutate"
    evidence: list[Evidence] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A detected issue or observation."""
    id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    category: str = ""             # e.g., "dead_code", "contract_drift"
    status: WiringStatus = WiringStatus.DECLARED
    evidence: list[Evidence] = field(default_factory=list)
    related_symbols: list[str] = field(default_factory=list)
    related_flows: list[str] = field(default_factory=list)
    recommendation: str = ""
