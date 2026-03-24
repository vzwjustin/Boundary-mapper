"""Repository scanner — walks the repo and classifies files.

Feeds the profile system with enough info to specialize later phases.
"""
from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import AnalysisConfig
from .languages import detect_language as _lang_detect
from .models import Side

log = logging.getLogger(__name__)


@dataclass
class ScannedFile:
    """A file discovered during repo scan."""
    rel_path: str
    abs_path: str
    side: Side
    language: str          # "c", "h", "go", "py", "makefile", "kbuild", etc.
    size_bytes: int = 0


@dataclass
class RepoLayout:
    """Result of scanning the repo."""
    root: str
    files: list[ScannedFile] = field(default_factory=list)
    kernel_dirs: list[str] = field(default_factory=list)
    userspace_dirs: list[str] = field(default_factory=list)
    shared_dirs: list[str] = field(default_factory=list)
    build_files: list[str] = field(default_factory=list)
    uapi_headers: list[str] = field(default_factory=list)

    # Stats
    total_c_files: int = 0
    total_h_files: int = 0
    total_go_files: int = 0


def _detect_language(path: str) -> str:
    """Detect language using the centralized language registry."""
    lang_name, _ = _lang_detect(path)
    return lang_name


def scan_repo(config: AnalysisConfig, profile) -> RepoLayout:
    """Walk the repo and classify files using the profile."""
    root = str(config.repo_root)
    layout = RepoLayout(root=root)
    seen_dirs = set()

    exclude_set = set(config.exclude_patterns)

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip .git and build artifacts
        dirnames[:] = [d for d in dirnames if d not in (
            ".git", ".svn", "__pycache__", "node_modules",
            ".boundary_mapper.db",
        )]

        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""

        for fname in filenames:
            rel_path = os.path.join(rel_dir, fname) if rel_dir else fname
            abs_path = os.path.join(dirpath, fname)

            # Skip excluded patterns
            skip = False
            for pat in exclude_set:
                if fnmatch.fnmatch(rel_path, pat):
                    skip = True
                    break
            if skip:
                continue

            lang = _detect_language(rel_path)
            if lang == "other":
                continue

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                size = 0

            side = profile.classify_path(rel_path)
            sf = ScannedFile(
                rel_path=rel_path,
                abs_path=abs_path,
                side=side,
                language=lang,
                size_bytes=size,
            )
            layout.files.append(sf)

            # Track directories
            if rel_dir and rel_dir not in seen_dirs:
                seen_dirs.add(rel_dir)
                if side == Side.KERNEL:
                    layout.kernel_dirs.append(rel_dir)
                elif side == Side.USERSPACE:
                    layout.userspace_dirs.append(rel_dir)
                elif side == Side.SHARED:
                    layout.shared_dirs.append(rel_dir)

            # Classify special files
            if lang in ("makefile", "kbuild", "kconfig"):
                layout.build_files.append(rel_path)
            if "uapi" in rel_path.lower():
                layout.uapi_headers.append(rel_path)

            # Stats
            if lang == "c":
                layout.total_c_files += 1
            elif lang == "h":
                layout.total_h_files += 1
            elif lang == "go":
                layout.total_go_files += 1

    log.info(
        "Scanned %d files: %d C, %d H, %d Go | %d kernel dirs, "
        "%d userspace dirs, %d shared dirs",
        len(layout.files), layout.total_c_files, layout.total_h_files,
        layout.total_go_files, len(layout.kernel_dirs),
        len(layout.userspace_dirs), len(layout.shared_dirs),
    )
    return layout
