"""Tests for sockopt map auto-discovery filtering.

Validates that config.py correctly:
- Filters out non-sockopt constants (size/limit/version/block suffixes)
- Validates candidates against actual case dispatch in .c files
- Handles numeric value collisions (prefer dispatched)
- Keeps legitimate sockopt constants

Module-agnostic: uses generic MYMOD prefix.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from boundary_mapper.config import generate_config_template


class _RepoFixture:
    """Creates a temporary repo with headers and C files for testing."""

    def __init__(self, module_name, defines, dispatch_cases):
        self.tmpdir = tempfile.mkdtemp()
        self.module = module_name

        hdir = os.path.join(self.tmpdir, "include")
        os.makedirs(hdir)
        with open(os.path.join(hdir, f"{module_name}.h"), "w") as f:
            for name, val in defines:
                f.write(f"#define {name} {val}\n")

        if dispatch_cases:
            cdir = os.path.join(self.tmpdir, "src")
            os.makedirs(cdir)
            with open(os.path.join(cdir, "sockopt.c"), "w") as f:
                f.write("int handler(int opt) {\n    switch (opt) {\n")
                for case in dispatch_cases:
                    f.write(f"    case {case}:\n        return 0;\n")
                f.write("    }\n    return -1;\n}\n")

    def get_sockopt_map(self):
        cfg = generate_config_template("custom", self.module, Path(self.tmpdir))
        return cfg["custom"]["sockopt_map"]

    def cleanup(self):
        shutil.rmtree(self.tmpdir)


class TestSuffixFiltering(unittest.TestCase):
    """Non-sockopt constants should be filtered by suffix heuristic."""

    def setUp(self):
        self.repo = _RepoFixture("mymod", [
            ("MYMOD_NODELAY", 1),
            ("MYMOD_CC_ALGO", 2),
            ("MYMOD_PAD_BLOCK_128", 128),
            ("MYMOD_MAX_HOSTNAME_LEN", 255),
            ("MYMOD_ACTIVE_CID_LIMIT", 8),
            ("MYMOD_PM_VER", 3),
            ("MYMOD_DEFAULT_TIMEOUT", 30),
            ("MYMOD_BUF_SIZE", 64),
            ("MYMOD_KEEPALIVE", 4),
        ], dispatch_cases=["MYMOD_NODELAY", "MYMOD_CC_ALGO", "MYMOD_KEEPALIVE"])

    def tearDown(self):
        self.repo.cleanup()

    def test_dispatched_included(self):
        sm = self.repo.get_sockopt_map()
        self.assertIn("MYMOD_NODELAY", sm.values())
        self.assertIn("MYMOD_CC_ALGO", sm.values())
        self.assertIn("MYMOD_KEEPALIVE", sm.values())

    def test_block_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_PAD_BLOCK_128", sm.values())

    def test_len_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_MAX_HOSTNAME_LEN", sm.values())

    def test_limit_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_ACTIVE_CID_LIMIT", sm.values())

    def test_ver_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_PM_VER", sm.values())

    def test_default_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_DEFAULT_TIMEOUT", sm.values())

    def test_buf_size_suffix_filtered(self):
        sm = self.repo.get_sockopt_map()
        self.assertNotIn("MYMOD_BUF_SIZE", sm.values())


class TestCollisionResolution(unittest.TestCase):
    """Numeric value collisions should prefer dispatched constants."""

    def test_dispatched_wins(self):
        repo = _RepoFixture("mymod", [
            ("MYMOD_FAST_OPEN", 5),
            ("MYMOD_RETRY_COUNT", 5),
        ], dispatch_cases=["MYMOD_FAST_OPEN"])
        try:
            sm = repo.get_sockopt_map()
            self.assertEqual(sm.get("5"), "MYMOD_FAST_OPEN")
        finally:
            repo.cleanup()

    def test_shorter_name_wins_when_neither_dispatched(self):
        repo = _RepoFixture("mymod", [
            ("MYMOD_A", 7),
            ("MYMOD_SOMETHING_LONG", 7),
        ], dispatch_cases=[])
        try:
            sm = repo.get_sockopt_map()
            if "7" in sm:
                self.assertEqual(sm["7"], "MYMOD_A")
        finally:
            repo.cleanup()


class TestNoDispatchStillIncluded(unittest.TestCase):
    """Constants without bad suffixes should survive even if not dispatched."""

    def test_undispatched_clean_name_kept(self):
        repo = _RepoFixture("mymod", [
            ("MYMOD_STREAMS_AVAIL", 50),
        ], dispatch_cases=[])
        try:
            sm = repo.get_sockopt_map()
            self.assertIn("MYMOD_STREAMS_AVAIL", sm.values())
        finally:
            repo.cleanup()


class TestEmptyRepo(unittest.TestCase):
    """Auto-discovery on an empty or header-less repo shouldn't crash."""

    def test_no_headers(self):
        tmpdir = tempfile.mkdtemp()
        try:
            cfg = generate_config_template("custom", "mymod", Path(tmpdir))
            sm = cfg["custom"]["sockopt_map"]
            self.assertEqual(sm, {})
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
