"""Base profile interface.

Profiles encode repo-specific knowledge: naming conventions, boundary idioms,
known object families, dispatch patterns, UAPI locations, etc.

The base profile provides sensible defaults for Linux kernel modules.
Repo-specific profiles override what they need.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..models import BoundaryType, Side


@dataclass
class DirectoryClassification:
    """How a directory maps to kernel/userspace/shared/tooling."""
    path_pattern: str          # glob or regex
    side: Side
    description: str = ""


@dataclass
class BoundaryPattern:
    """A pattern that identifies a boundary surface."""
    boundary_type: BoundaryType
    # Regex patterns to match in source code
    registration_patterns: list[str] = field(default_factory=list)
    handler_patterns: list[str] = field(default_factory=list)
    dispatch_patterns: list[str] = field(default_factory=list)
    userspace_call_patterns: list[str] = field(default_factory=list)
    # For matching struct ops tables
    ops_struct_names: list[str] = field(default_factory=list)
    # For matching option/command IDs
    id_prefix_patterns: list[str] = field(default_factory=list)


@dataclass
class ObjectFamily:
    """A known domain object family (e.g., connection, path, scheduler)."""
    name: str
    struct_names: list[str] = field(default_factory=list)
    create_patterns: list[str] = field(default_factory=list)
    destroy_patterns: list[str] = field(default_factory=list)
    accessor_patterns: list[str] = field(default_factory=list)


class BaseProfile:
    """Base profile for Linux kernel module repos."""

    name: str = "base"
    description: str = "Generic Linux kernel module profile"

    # -- Directory classification --

    def get_directory_classifications(self) -> list[DirectoryClassification]:
        return [
            DirectoryClassification("net/*/", Side.KERNEL, "Kernel networking code"),
            DirectoryClassification("include/uapi/", Side.SHARED, "UAPI headers"),
            DirectoryClassification("include/net/", Side.KERNEL, "Kernel net headers"),
            DirectoryClassification("tools/", Side.TOOLING, "Tooling and userspace"),
            DirectoryClassification("samples/", Side.TOOLING, "Sample code"),
        ]

    def classify_path(self, path: str) -> Side:
        """Classify a file path as kernel/userspace/shared/tooling."""
        for dc in self.get_directory_classifications():
            pat = dc.path_pattern.replace("*", ".*")
            if re.match(pat, path):
                return dc.side
        return Side.UNKNOWN

    # -- Boundary patterns --

    def get_boundary_patterns(self) -> list[BoundaryPattern]:
        return [
            BoundaryPattern(
                boundary_type=BoundaryType.SETSOCKOPT,
                registration_patterns=[r"\.setsockopt\s*="],
                handler_patterns=[r"(int\s+\w+_setsockopt\s*\()"],
                ops_struct_names=["proto_ops"],
                id_prefix_patterns=[r"SOL_\w+", r"\w+_SOCKOPT_\w+"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.GETSOCKOPT,
                registration_patterns=[r"\.getsockopt\s*="],
                handler_patterns=[r"(int\s+\w+_getsockopt\s*\()"],
                ops_struct_names=["proto_ops"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.SENDMSG,
                registration_patterns=[r"\.sendmsg\s*="],
                handler_patterns=[r"(int\s+\w+_sendmsg\s*\()"],
                ops_struct_names=["proto_ops"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.RECVMSG,
                registration_patterns=[r"\.recvmsg\s*="],
                handler_patterns=[r"(int\s+\w+_recvmsg\s*\()"],
                ops_struct_names=["proto_ops"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.NETLINK,
                registration_patterns=[r"genl_register_family", r"rtnl_register"],
                handler_patterns=[r"(int\s+\w+_nl\w*\s*\()"],
                dispatch_patterns=[r"\.cmd\s*=", r"genl_ops"],
                ops_struct_names=["genl_ops", "genl_family"],
                id_prefix_patterns=[r"\w+_CMD_\w+", r"\w+_ATTR_\w+"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.SYSCTL,
                registration_patterns=[r"register_net_sysctl", r"register_sysctl"],
                handler_patterns=[r"proc_do\w+"],
                ops_struct_names=["ctl_table"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.NETFILTER,
                registration_patterns=[r"nf_register_net_hook"],
                handler_patterns=[r"(unsigned\s+int\s+\w+_hook\s*\()"],
                ops_struct_names=["nf_hook_ops"],
            ),
            BoundaryPattern(
                boundary_type=BoundaryType.PROTOCOL_REGISTER,
                registration_patterns=[
                    r"proto_register\s*\(",
                    r"inet_register_protosw",
                    r"sock_register",
                ],
                ops_struct_names=["proto", "inet_protosw", "net_proto_family"],
            ),
        ]

    # -- Object families --

    def get_object_families(self) -> list[ObjectFamily]:
        return []

    # -- Naming conventions --

    def get_kernel_file_patterns(self) -> list[str]:
        return ["net/**/*.c", "net/**/*.h"]

    def get_userspace_file_patterns(self) -> list[str]:
        return ["tools/**/*.c", "tools/**/*.go", "tools/**/*.h"]

    def get_shared_header_patterns(self) -> list[str]:
        return ["include/uapi/**/*.h"]

    def get_test_file_patterns(self) -> list[str]:
        return ["tools/testing/**/*"]

    # -- Known constants/prefixes --

    def get_command_prefixes(self) -> list[str]:
        return []

    def get_option_prefixes(self) -> list[str]:
        return []

    def get_attribute_prefixes(self) -> list[str]:
        return []
