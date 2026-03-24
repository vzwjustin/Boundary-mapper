"""JSON-driven custom profile.

Lets users define a full boundary mapping profile in .boundary-mapper.json
without writing any Python. The JSON "custom" block maps directly to
BaseProfile methods.
"""
from __future__ import annotations

from .base import (
    BaseProfile, BoundaryPattern, DirectoryClassification, ObjectFamily,
)
from ..models import BoundaryType, Side


class CustomProfile(BaseProfile):
    """Profile built from a JSON config dict at runtime."""

    def __init__(self, data: dict):
        self._data = data
        self.name = data.get("name", "custom")
        self.description = data.get("description", "Custom profile from config")

        # Build maps from JSON
        raw_sockopt = data.get("sockopt_map", {})
        self.SOCKOPT_MAP = {int(k): v for k, v in raw_sockopt.items()}

        raw_ioctl = data.get("ioctl_map", {})
        self.IOCTL_MAP = {int(k): v for k, v in raw_ioctl.items()}

        self.GENL_FAMILIES = {}
        for fam_name, fam_data in data.get("genl_families", {}).items():
            cmds = {int(k): v for k, v in fam_data.get("commands", {}).items()}
            self.GENL_FAMILIES[fam_name] = {
                "name_const": fam_data.get("name_const", ""),
                "ops_var": fam_data.get("ops_var", ""),
                "family_var": fam_data.get("family_var", ""),
                "source_file": fam_data.get("source_file", ""),
                "commands": cmds,
            }

        # Classification helpers
        self._command_prefixes = data.get("command_prefixes", [])
        self._option_prefixes = data.get("option_prefixes", [])
        self._attribute_prefixes = data.get("attribute_prefixes", [])

        self._kernel_paths = data.get("kernel_paths", [])
        self._userspace_paths = data.get("userspace_paths", [])
        self._shared_paths = data.get("shared_paths", [])
        self._test_paths = data.get("test_paths", [])

        # Optional enrichment data
        self.SOCKOPT_FAMILIES = data.get("sockopt_families", {})
        self.FUTURE_RESERVED_SOCKOPTS = set(
            data.get("future_reserved_sockopts", []))
        self.DIAGNOSTIC_SOCKOPTS = set(
            data.get("diagnostic_sockopts", []))
        self.KERNEL_ONLY_GENL = set(
            data.get("kernel_only_genl", []))
        self.RESERVED_ATTR_SUFFIXES = set(
            data.get("reserved_attr_suffixes",
                      ["__MAX", "__PAD", "__UNSPEC", "_MAX", "_LAST"]))
        self.FAMILY_IMPORTANCE = data.get("family_importance", {})
        self.SOCKOPT_OBJECT_FAMILIES = data.get("sockopt_object_families", {})

    # ── Directory classification ──

    def get_directory_classifications(self):
        result = []
        side_map = {
            "kernel": Side.KERNEL, "userspace": Side.USERSPACE,
            "shared": Side.SHARED, "tooling": Side.TOOLING,
        }
        for entry in self._data.get("directories", []):
            result.append(DirectoryClassification(
                entry["path"],
                side_map.get(entry.get("side", "kernel"), Side.KERNEL),
                entry.get("description", ""),
            ))
        if not result:
            return super().get_directory_classifications()
        return result

    def classify_path(self, path: str) -> Side:
        for dc in self.get_directory_classifications():
            if path.startswith(dc.path_pattern):
                return dc.side
        if path.startswith("net/"):
            return Side.KERNEL
        if path.startswith("tools/"):
            return Side.USERSPACE
        if path.startswith("include/uapi/"):
            return Side.SHARED
        if path.startswith("include/"):
            return Side.KERNEL
        return Side.UNKNOWN

    # ── File patterns ──

    def get_kernel_file_patterns(self):
        return self._kernel_paths or super().get_kernel_file_patterns()

    def get_userspace_file_patterns(self):
        return self._userspace_paths or super().get_userspace_file_patterns()

    def get_shared_header_patterns(self):
        return self._shared_paths or super().get_shared_header_patterns()

    def get_test_file_patterns(self):
        return self._test_paths or super().get_test_file_patterns()

    # ── Prefixes ──

    def get_command_prefixes(self):
        return self._command_prefixes

    def get_option_prefixes(self):
        return self._option_prefixes

    def get_attribute_prefixes(self):
        return self._attribute_prefixes

    # ── Enrichment helpers ──

    def get_sockopt_family(self, opt_name: str) -> str:
        return self.SOCKOPT_FAMILIES.get(opt_name, "unknown")

    def is_future_reserved(self, opt_name: str) -> bool:
        return opt_name in self.FUTURE_RESERVED_SOCKOPTS

    def is_diagnostic(self, opt_name: str) -> bool:
        return opt_name in self.DIAGNOSTIC_SOCKOPTS

    def is_kernel_only_genl(self, family_name: str) -> bool:
        return family_name in self.KERNEL_ONLY_GENL

    def is_reserved_attr(self, attr_name: str) -> bool:
        for suffix in self.RESERVED_ATTR_SUFFIXES:
            if attr_name.endswith(suffix):
                return True
        return False

    def get_importance_score(self, opt_name: str) -> int:
        family = self.get_sockopt_family(opt_name)
        base = self.FAMILY_IMPORTANCE.get(family, 5)
        obj_fams = self.SOCKOPT_OBJECT_FAMILIES.get(family, [])
        if "connection" in obj_fams or "path" in obj_fams:
            base = min(10, base + 1)
        if self.is_diagnostic(opt_name):
            base = max(1, base - 2)
        if self.is_future_reserved(opt_name):
            base = max(1, base - 3)
        return base

    def get_recommended_action(self, opt_name, has_dispatch, has_userspace):
        if has_dispatch and has_userspace:
            return "none_needed"
        if self.is_future_reserved(opt_name):
            return "keep_as_future_reserved"
        if not has_dispatch:
            if self.is_diagnostic(opt_name):
                return "implement_with_feature"
            return "add_kernel_dispatch"
        if self.is_diagnostic(opt_name):
            return "leave_kernel_only"
        return "implement_userspace_caller"

    def classify_sockopt_bucket(self, opt_name, has_dispatch, has_userspace):
        if has_dispatch and has_userspace:
            return "fully_wired"
        if self.is_future_reserved(opt_name):
            return "likely_future"
        if not has_dispatch:
            if self.is_diagnostic(opt_name):
                return "diagnostic_only"
            return "dead_uapi"
        if self.is_diagnostic(opt_name):
            return "diagnostic_only"
        return "kernel_dispatch_no_userspace"
