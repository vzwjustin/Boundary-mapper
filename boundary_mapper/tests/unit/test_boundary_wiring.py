"""Tests for kernel↔userspace boundary wiring detection.

Validates the core purpose of the tool: detecting whether kernel
boundary surfaces (sockopts, genetlink commands, ioctls) are properly
wired to handlers on the kernel side and to callers on the userspace
side.

Covers:
- Sockopt surface building (dispatched vs undeclared)
- Userspace producer detection (Go constant refs, dispatch entries)
- Dead surface detection (no handler, no producer)
- Missing handler rule (userspace sends, no kernel handler)
- Sockopt completeness (defined in UAPI but no case dispatch)
- Surface enrichment (substatus, importance scores)

Module-agnostic: uses generic MYMOD prefix.
"""
import os
import tempfile
import unittest
from pathlib import Path

from boundary_mapper.db import FactStore
from boundary_mapper.graph_build import GraphBuilder
from boundary_mapper.models import (
    BoundaryType, Confidence, Evidence, ExtractionMethod,
    FindingSeverity, Side, SymbolKind, SymbolNode, WiringStatus,
)
from boundary_mapper.pattern_extract import ExtractedFile, PatternExtractor
from boundary_mapper.repo_scan import ScannedFile
from boundary_mapper.rules_engine import (
    AttributeSymmetryRule, ContractDriftRule,
    DeadSurfaceRule, MissingHandlerRule, SockoptCompleteness,
)


class _TestProfile:
    """Generic profile for wiring tests."""

    SOCKOPT_MAP = {
        "1": "MYMOD_NODELAY",
        "2": "MYMOD_CC_ALGO",
        "3": "MYMOD_KEEPALIVE",
        "99": "MYMOD_FUTURE_OPT",  # not dispatched
    }

    GENL_FAMILIES = {}
    IOCTL_MAP = {}

    def get_command_prefixes(self):
        return ["MYMOD_CMD_"]

    def get_option_prefixes(self):
        return ["MYMOD_"]

    def get_attribute_prefixes(self):
        return ["MYMOD_ATTR_"]

    def get_kernel_file_patterns(self):
        return ["src/**/*.c"]

    def get_userspace_file_patterns(self):
        return ["tools/**/*.go"]

    def get_boundary_patterns(self):
        from boundary_mapper.profiles.base import BoundaryPattern
        return [BoundaryPattern(
            boundary_type=BoundaryType.SETSOCKOPT,
            handler_patterns=[r"(int\s+\w+_setsockopt\s*\()"],
        )]

    def is_future_reserved(self, name):
        return name == "MYMOD_FUTURE_OPT"

    def is_diagnostic(self, name):
        return False

    def is_kernel_only_genl(self, name):
        return False

    def classify_sockopt_bucket(self, name, has_dispatch, has_userspace):
        if has_dispatch and has_userspace:
            return "fully_wired"
        if self.is_future_reserved(name):
            return "likely_future"
        if not has_dispatch:
            return "dead_uapi"
        return "kernel_dispatch_no_userspace"

    def get_importance_score(self, name):
        return 5

    def get_recommended_action(self, name, has_dispatch, has_userspace):
        return "investigate"

    def get_sockopt_family(self, name):
        return "mymod"


def _make_store():
    """Create an in-memory fact store."""
    return FactStore(":memory:")


def _add_kernel_dispatch(store, opt_name):
    """Simulate a `case OPT_NAME:` in kernel source."""
    store.upsert_symbol(SymbolNode(
        name=opt_name,
        kind=SymbolKind.ENUM_VALUE,
        side=Side.KERNEL,
        file_path="src/sockopt.c",
        line_start=10,
        properties={"dispatch": True},
        evidence=[Evidence(
            file_path="src/sockopt.c", line_start=10,
            symbol=opt_name, snippet=f"case {opt_name}:",
            method=ExtractionMethod.PATTERN_MATCH,
            confidence=Confidence.HIGH,
        )],
    ))


def _add_userspace_ref(store, const_name, file_path="tools/main.go"):
    """Simulate a userspace Go constant reference."""
    store.upsert_symbol(SymbolNode(
        name=const_name,
        kind=SymbolKind.GO_CONST,
        side=Side.USERSPACE,
        file_path=file_path,
        line_start=5,
        evidence=[Evidence(
            file_path=file_path, line_start=5,
            symbol=const_name,
            method=ExtractionMethod.PATTERN_MATCH,
            confidence=Confidence.MEDIUM,
        )],
    ))


# ── Sockopt surface building ─────────────────────────────────────


class TestSockoptSurfaceBuilding(unittest.TestCase):
    """GraphBuilder._build_sockopt_surfaces should set correct status."""

    def test_dispatched_sockopt_gets_dispatch_linked(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_NODELAY")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        nodelay = [s for s in surfaces if "MYMOD_NODELAY" in s.name]
        self.assertEqual(len(nodelay), 1)
        self.assertEqual(nodelay[0].status, WiringStatus.DISPATCH_LINKED)

    def test_undispatched_sockopt_stays_declared(self):
        store = _make_store()
        profile = _TestProfile()
        # Don't add any dispatch for MYMOD_FUTURE_OPT

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        future = [s for s in surfaces if "MYMOD_FUTURE_OPT" in s.name]
        self.assertEqual(len(future), 1)
        self.assertEqual(future[0].status, WiringStatus.DECLARED)

    def test_dispatched_with_userspace_gets_statically_reachable(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_NODELAY")
        _add_userspace_ref(store, "MYMOD_NODELAY")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        nodelay = [s for s in surfaces if "MYMOD_NODELAY" in s.name]
        self.assertEqual(len(nodelay), 1)
        self.assertEqual(nodelay[0].status, WiringStatus.STATICALLY_REACHABLE)

    def test_userspace_producer_populated(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_CC_ALGO")
        _add_userspace_ref(store, "MYMOD_CC_ALGO", "tools/config.go")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        cc = [s for s in surfaces if "MYMOD_CC_ALGO" in s.name]
        self.assertEqual(len(cc), 1)
        self.assertIn("tools/config.go", cc[0].userspace_producer)

    def test_all_sockopt_map_entries_create_surfaces(self):
        store = _make_store()
        profile = _TestProfile()

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        self.assertEqual(
            len(surfaces), len(profile.SOCKOPT_MAP),
            "Every SOCKOPT_MAP entry should produce a surface"
        )


# ── Dead surface detection ───────────────────────────────────────


class TestDeadSurfaceRule(unittest.TestCase):
    """DeadSurfaceRule should detect surfaces with no handler or producer."""

    def test_future_reserved_suppressed_entirely(self):
        """Future-reserved surfaces should NOT appear in findings at all.

        The old behavior was to downgrade to LOW severity — but that still
        creates noise.  The new behavior is to suppress entirely.
        """
        store = _make_store()
        profile = _TestProfile()

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        future_findings = [
            f for f in findings if "MYMOD_FUTURE_OPT" in f.title
        ]
        self.assertEqual(
            len(future_findings), 0,
            "Future-reserved surface should be suppressed entirely"
        )

    def test_unknown_undispatched_flagged_as_dead(self):
        """Undispatched surface that is NOT future-reserved should be flagged."""
        store = _make_store()
        profile = _TestProfile()

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        # MYMOD_NODELAY, MYMOD_CC_ALGO, MYMOD_KEEPALIVE are not future-reserved
        # and have no dispatch → should be flagged as dead
        dead_names = [f.title for f in findings if "Dead surface" in f.title]
        non_future = [t for t in dead_names if "MYMOD_FUTURE_OPT" not in t]
        self.assertGreater(
            len(non_future), 0,
            "Non-future undispatched sockopt should be flagged as dead"
        )

    def test_dispatched_surface_not_flagged_as_dead(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_NODELAY")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        nodelay_dead = [
            f for f in findings
            if "MYMOD_NODELAY" in f.title and "Dead" in f.title
        ]
        self.assertEqual(
            len(nodelay_dead), 0,
            "Dispatched sockopt should NOT be flagged as dead"
        )

    def test_dispatched_without_userspace_not_dead(self):
        """DISPATCH_LINKED surfaces are not dead — DeadSurfaceRule skips them.

        Missing userspace producer for dispatched surfaces is tracked
        via surface substatus (SurfaceEnrichmentRule), not DeadSurfaceRule.
        """
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_KEEPALIVE")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        keepalive_dead = [
            f for f in findings
            if "MYMOD_KEEPALIVE" in f.title and "Dead" in f.title
        ]
        self.assertEqual(
            len(keepalive_dead), 0,
            "Dispatched sockopt should not be flagged as dead"
        )

        # But the surface should still be DISPATCH_LINKED (not STATICALLY_REACHABLE)
        surfaces = store.get_surfaces(boundary_type="setsockopt")
        keepalive = [s for s in surfaces if "MYMOD_KEEPALIVE" in s.name]
        self.assertEqual(keepalive[0].status, WiringStatus.DISPATCH_LINKED,
                         "Dispatched without userspace = dispatch_linked")

    def test_fully_wired_not_flagged(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_NODELAY")
        _add_userspace_ref(store, "MYMOD_NODELAY")

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        nodelay_findings = [f for f in findings if "MYMOD_NODELAY" in f.title]
        self.assertEqual(
            len(nodelay_findings), 0,
            "Fully wired sockopt should produce no findings"
        )


# ── Sockopt completeness ─────────────────────────────────────────


class TestSockoptCompleteness(unittest.TestCase):
    """SockoptCompleteness should flag sockopts without dispatch cases."""

    def test_missing_dispatch_flagged(self):
        store = _make_store()
        profile = _TestProfile()
        # Only dispatch NODELAY, leave CC_ALGO/KEEPALIVE/FUTURE without

        _add_kernel_dispatch(store, "MYMOD_NODELAY")

        rule = SockoptCompleteness()
        findings = rule.evaluate(store, profile)

        flagged_names = {f.title for f in findings}
        self.assertTrue(
            any("MYMOD_CC_ALGO" in t for t in flagged_names),
            "CC_ALGO without dispatch should be flagged"
        )
        self.assertTrue(
            any("MYMOD_KEEPALIVE" in t for t in flagged_names),
            "KEEPALIVE without dispatch should be flagged"
        )

    def test_dispatched_not_flagged(self):
        store = _make_store()
        profile = _TestProfile()
        _add_kernel_dispatch(store, "MYMOD_NODELAY")

        rule = SockoptCompleteness()
        findings = rule.evaluate(store, profile)

        self.assertFalse(
            any("MYMOD_NODELAY" in f.title for f in findings),
            "Dispatched sockopt should NOT be flagged"
        )

    def test_future_reserved_suppressed_entirely(self):
        """Future-reserved sockopts should NOT appear in completeness findings.

        The old behavior was to emit at LOW severity — but that's still noise.
        """
        store = _make_store()
        profile = _TestProfile()

        rule = SockoptCompleteness()
        findings = rule.evaluate(store, profile)

        future = [f for f in findings if "MYMOD_FUTURE_OPT" in f.title]
        self.assertEqual(
            len(future), 0,
            "Future-reserved sockopt should be suppressed entirely"
        )

    def test_all_dispatched_produces_no_findings(self):
        store = _make_store()
        profile = _TestProfile()
        for opt_name in profile.SOCKOPT_MAP.values():
            _add_kernel_dispatch(store, opt_name)

        rule = SockoptCompleteness()
        findings = rule.evaluate(store, profile)
        self.assertEqual(
            len(findings), 0,
            "All dispatched should produce zero completeness findings"
        )


# ── Missing handler rule ─────────────────────────────────────────


class TestMissingHandlerRule(unittest.TestCase):
    """MissingHandlerRule: userspace sends command, no kernel handler."""

    def test_userspace_cmd_without_kernel_handler_flagged(self):
        store = _make_store()
        profile = _TestProfile()

        # Userspace references MYMOD_CMD_CONNECT but kernel has no
        # function containing "connect"
        _add_userspace_ref(store, "MYMOD_CMD_CONNECT")

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        self.assertGreater(
            len(findings), 0,
            "Userspace command without kernel handler must be flagged"
        )

    def test_userspace_cmd_with_kernel_handler_not_flagged(self):
        store = _make_store()
        profile = _TestProfile()

        _add_userspace_ref(store, "MYMOD_CMD_CONNECT")
        # Add a kernel function whose name contains "connect"
        store.upsert_symbol(SymbolNode(
            name="mymod_nl_cmd_connect",
            kind=SymbolKind.FUNCTION_DEF,
            side=Side.KERNEL,
            file_path="src/netlink.c",
            line_start=100,
        ))

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        cmd_findings = [f for f in findings if "MYMOD_CMD_CONNECT" in f.title]
        self.assertEqual(
            len(cmd_findings), 0,
            "Command with matching kernel handler should NOT be flagged"
        )


# ── End-to-end: extract → build → rules ─────────────────────────


class TestEndToEndWiring(unittest.TestCase):
    """Full pipeline: extract from files, build graph, run rules."""

    def test_c_dispatch_and_go_usage_wire_up(self):
        """Kernel case dispatch + Go constant usage = fully wired."""
        store = _make_store()
        profile = _TestProfile()

        # Simulate kernel extraction: case MYMOD_NODELAY:
        kernel_extracted = ExtractedFile("src/sockopt.c")
        kernel_extracted.dispatch_entries.append({
            "case": "MYMOD_NODELAY",
            "file": "src/sockopt.c",
            "line": 42,
        })

        # Simulate Go extraction: MYMOD_NODELAY constant + dispatch
        go_extracted = ExtractedFile("tools/config.go")
        go_extracted.symbols.append(SymbolNode(
            name="MYMOD_NODELAY",
            kind=SymbolKind.GO_CONST,
            side=Side.USERSPACE,
            file_path="tools/config.go",
            line_start=10,
            evidence=[Evidence(
                file_path="tools/config.go", line_start=10,
                symbol="MYMOD_NODELAY",
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.MEDIUM,
            )],
        ))

        gb = GraphBuilder(store, profile)
        gb.ingest(kernel_extracted)
        gb.ingest(go_extracted)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        nodelay = [s for s in surfaces if "MYMOD_NODELAY" in s.name]
        self.assertEqual(len(nodelay), 1)
        self.assertEqual(
            nodelay[0].status, WiringStatus.STATICALLY_REACHABLE,
            "Kernel dispatch + userspace ref = statically reachable"
        )

    def test_kernel_only_dispatch_is_partial(self):
        """Kernel dispatch without userspace = dispatch_linked only."""
        store = _make_store()
        profile = _TestProfile()

        kernel_extracted = ExtractedFile("src/sockopt.c")
        kernel_extracted.dispatch_entries.append({
            "case": "MYMOD_CC_ALGO",
            "file": "src/sockopt.c",
            "line": 55,
        })

        gb = GraphBuilder(store, profile)
        gb.ingest(kernel_extracted)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        cc = [s for s in surfaces if "MYMOD_CC_ALGO" in s.name]
        self.assertEqual(len(cc), 1)
        self.assertEqual(cc[0].status, WiringStatus.DISPATCH_LINKED)

    def test_no_dispatch_stays_declared(self):
        """No kernel dispatch, no userspace = declared."""
        store = _make_store()
        profile = _TestProfile()

        gb = GraphBuilder(store, profile)
        gb.build_boundary_surfaces(None)

        surfaces = store.get_surfaces(boundary_type="setsockopt")
        future = [s for s in surfaces if "MYMOD_FUTURE_OPT" in s.name]
        self.assertEqual(len(future), 1)
        self.assertEqual(future[0].status, WiringStatus.DECLARED)

    def test_dead_surface_rule_on_pipeline_output(self):
        """Rules correctly identify dead vs wired after full pipeline."""
        store = _make_store()
        profile = _TestProfile()

        # Wire up NODELAY fully, leave FUTURE_OPT dead
        kernel_extracted = ExtractedFile("src/sockopt.c")
        kernel_extracted.dispatch_entries.append({
            "case": "MYMOD_NODELAY",
            "file": "src/sockopt.c",
            "line": 42,
        })
        go_extracted = ExtractedFile("tools/config.go")
        go_extracted.symbols.append(SymbolNode(
            name="MYMOD_NODELAY",
            kind=SymbolKind.GO_CONST,
            side=Side.USERSPACE,
            file_path="tools/config.go",
            line_start=10,
            evidence=[Evidence(
                file_path="tools/config.go", line_start=10,
                symbol="MYMOD_NODELAY",
                method=ExtractionMethod.PATTERN_MATCH,
                confidence=Confidence.MEDIUM,
            )],
        ))

        gb = GraphBuilder(store, profile)
        gb.ingest(kernel_extracted)
        gb.ingest(go_extracted)
        gb.build_boundary_surfaces(None)

        rule = DeadSurfaceRule()
        findings = rule.evaluate(store, profile)

        # NODELAY is fully wired — should NOT be in findings
        nodelay_findings = [f for f in findings if "MYMOD_NODELAY" in f.title]
        self.assertEqual(len(nodelay_findings), 0)

        # FUTURE_OPT is future-reserved — should be SUPPRESSED entirely
        future_findings = [f for f in findings if "MYMOD_FUTURE_OPT" in f.title]
        self.assertEqual(len(future_findings), 0,
                         "Future-reserved surface should be suppressed")

        # But CC_ALGO and KEEPALIVE are NOT future-reserved and have no
        # dispatch → should be flagged as dead
        other_dead = [f for f in findings
                      if "Dead surface" in f.title
                      and "MYMOD_FUTURE_OPT" not in f.title]
        self.assertGreater(len(other_dead), 0,
                           "Non-future undispatched sockopts should be flagged")


# ── Profile without sockopt map ──────────────────────────────────


class TestNoSockoptMap(unittest.TestCase):
    """Tool should not crash when profile has no SOCKOPT_MAP."""

    def test_build_surfaces_no_crash(self):
        store = _make_store()

        class MinimalProfile:
            GENL_FAMILIES = {}
            def get_command_prefixes(self): return []
            def get_option_prefixes(self): return []
            def get_attribute_prefixes(self): return []
            def get_boundary_patterns(self): return []

        gb = GraphBuilder(store, MinimalProfile())
        gb.build_boundary_surfaces(None)  # should not raise

        surfaces = store.get_surfaces()
        self.assertEqual(len(surfaces), 0)

    def test_completeness_rule_no_crash(self):
        store = _make_store()

        class MinimalProfile:
            def get_command_prefixes(self): return []

        rule = SockoptCompleteness()
        findings = rule.evaluate(store, MinimalProfile())
        self.assertEqual(len(findings), 0)


# ── False-positive suppression tests ─────────────────────────────


class TestMissingHandlerFalsePositives(unittest.TestCase):
    """MissingHandlerRule should not match short command stems."""

    def test_short_stem_suppressed(self):
        """MYMOD_CMD_GET has stem 'get' (3 chars) — too short to match."""
        store = _make_store()
        profile = _TestProfile()
        _add_userspace_ref(store, "MYMOD_CMD_GET")

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        get_findings = [f for f in findings if "MYMOD_CMD_GET" in f.title]
        self.assertEqual(
            len(get_findings), 0,
            "Short stems like 'get' should be suppressed"
        )

    def test_long_stem_still_flagged(self):
        """MYMOD_CMD_CONNECT has stem 'connect' (7 chars) — should be flagged."""
        store = _make_store()
        profile = _TestProfile()
        _add_userspace_ref(store, "MYMOD_CMD_CONNECT")

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        connect_findings = [f for f in findings if "MYMOD_CMD_CONNECT" in f.title]
        self.assertGreater(
            len(connect_findings), 0,
            "Long stem without handler should still be flagged"
        )

    def test_dispatched_command_not_flagged(self):
        """Command with kernel dispatch entry should never be flagged."""
        store = _make_store()
        profile = _TestProfile()
        _add_userspace_ref(store, "MYMOD_CMD_CONNECT")
        _add_kernel_dispatch(store, "MYMOD_CMD_CONNECT")

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        connect_findings = [f for f in findings if "MYMOD_CMD_CONNECT" in f.title]
        self.assertEqual(
            len(connect_findings), 0,
            "Dispatched command should not be flagged"
        )

    def test_word_boundary_matching(self):
        """Stem 'connect' should match 'mymod_nl_cmd_connect' but not
        'mymod_reconnect_timer'."""
        store = _make_store()
        profile = _TestProfile()
        _add_userspace_ref(store, "MYMOD_CMD_CONNECT")

        # Add a kernel function that DOES match on word boundary
        store.upsert_symbol(SymbolNode(
            name="mymod_nl_cmd_connect",
            kind=SymbolKind.FUNCTION_DEF,
            side=Side.KERNEL,
            file_path="src/netlink.c",
            line_start=100,
        ))

        rule = MissingHandlerRule()
        findings = rule.evaluate(store, profile)

        connect_findings = [f for f in findings if "MYMOD_CMD_CONNECT" in f.title]
        self.assertEqual(len(connect_findings), 0,
                         "Word-boundary match should suppress finding")


class TestContractDriftSuppression(unittest.TestCase):
    """ContractDriftRule should suppress common sentinel suffixes."""

    def _make_shared_const(self, store, name):
        store.upsert_symbol(SymbolNode(
            name=name,
            kind=SymbolKind.CONSTANT,
            side=Side.SHARED,
            file_path="include/uapi/mymod.h",
            line_start=1,
        ))

    def test_max_suffix_suppressed(self):
        store = _make_store()
        profile = _TestProfile()
        self._make_shared_const(store, "MYMOD_OPT_MAX")

        rule = ContractDriftRule()
        findings = rule.evaluate(store, profile)

        max_findings = [f for f in findings if "MYMOD_OPT_MAX" in f.title]
        self.assertEqual(len(max_findings), 0,
                         "_MAX suffix should be suppressed")

    def test_unspec_suffix_suppressed(self):
        store = _make_store()
        profile = _TestProfile()
        self._make_shared_const(store, "MYMOD_UNSPEC")

        rule = ContractDriftRule()
        findings = rule.evaluate(store, profile)

        unspec_findings = [f for f in findings if "MYMOD_UNSPEC" in f.title]
        self.assertEqual(len(unspec_findings), 0,
                         "_UNSPEC suffix should be suppressed")

    def test_real_unused_still_flagged(self):
        store = _make_store()
        profile = _TestProfile()
        self._make_shared_const(store, "MYMOD_SOME_FEATURE")

        rule = ContractDriftRule()
        findings = rule.evaluate(store, profile)

        feature_findings = [f for f in findings if "MYMOD_SOME_FEATURE" in f.title]
        self.assertGreater(len(feature_findings), 0,
                           "Real unused UAPI constant should still be flagged")


class TestAttributeSymmetrySuppression(unittest.TestCase):
    """AttributeSymmetryRule should suppress sentinel attributes."""

    def test_pad_suppressed(self):
        store = _make_store()
        profile = _TestProfile()
        store.upsert_symbol(SymbolNode(
            name="MYMOD_ATTR_PAD",
            kind=SymbolKind.ENUM_VALUE,
            side=Side.SHARED,
            file_path="include/uapi/mymod.h",
            line_start=1,
        ))

        rule = AttributeSymmetryRule()
        findings = rule.evaluate(store, profile)

        pad_findings = [f for f in findings if "MYMOD_ATTR_PAD" in f.title]
        self.assertEqual(len(pad_findings), 0,
                         "_PAD attribute should be suppressed")


if __name__ == "__main__":
    unittest.main()
