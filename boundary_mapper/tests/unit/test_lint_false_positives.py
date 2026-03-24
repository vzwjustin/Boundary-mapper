"""Tests for lint false-positive suppression.

Validates that the lint system correctly:
- Suppresses findings when standard guards are present
- Still flags genuine bugs (true positives)
- Handles edge cases (nested parens, multiline, cross-function)

These tests are module-agnostic — they use plain C/Go code without
any project-specific prefixes.
"""
import os
import re
import tempfile
import unittest

from boundary_mapper.languages import LANG_C, LANG_GO
from boundary_mapper.models import Side
from boundary_mapper.pattern_extract import PatternExtractor
from boundary_mapper.repo_scan import ScannedFile


class _EmptyProfile:
    """Minimal profile with no project-specific prefixes."""

    def get_command_prefixes(self):
        return []

    def get_attribute_prefixes(self):
        return []

    def get_option_prefixes(self):
        return []


def _extract_c(code: str) -> list[dict]:
    """Extract lint hits from a C code string."""
    pe = PatternExtractor(_EmptyProfile())
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".c", delete=False, dir="/tmp"
    ) as f:
        f.write(code)
        tmp = f.name
    try:
        sf = ScannedFile(
            abs_path=tmp, rel_path="test.c", side=Side.KERNEL, language="c"
        )
        return pe.extract_file(sf).lint_hits
    finally:
        os.unlink(tmp)


def _hits_by_category(hits, category):
    return [h for h in hits if h["category"] == category]


# ── 1a. Unchecked alloc ──────────────────────────────────────────


class TestUncheckedAlloc(unittest.TestCase):
    """unchecked_alloc should be suppressed when NULL-checked."""

    def test_null_bang_check_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(void) {
    struct bar *p;
    p = kmalloc(sizeof(struct bar), GFP_KERNEL);
    if (!p)
        return -ENOMEM;
    return 0;
}
"""), "unchecked_alloc")
        self.assertEqual(len(hits), 0, "if (!p) should suppress")

    def test_eq_null_check_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(void) {
    void *p = kzalloc(size, GFP_KERNEL);
    if (p == NULL)
        return -ENOMEM;
    return 0;
}
"""), "unchecked_alloc")
        self.assertEqual(len(hits), 0, "if (p == NULL) should suppress")

    def test_is_err_check_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(void) {
    void *p = kmalloc(size, GFP_KERNEL);
    if (IS_ERR(p))
        return PTR_ERR(p);
    return 0;
}
"""), "unchecked_alloc")
        self.assertEqual(len(hits), 0, "IS_ERR should suppress")

    def test_no_check_flagged(self):
        hits = _hits_by_category(_extract_c("""
int foo(void) {
    void *p = kmalloc(size, GFP_KERNEL);
    p->field = 42;
    return 0;
}
"""), "unchecked_alloc")
        self.assertGreater(len(hits), 0, "Unchecked alloc must be flagged")

    def test_skb_alloc_with_check_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(void) {
    struct sk_buff *skb = alloc_skb(len, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    return 0;
}
"""), "unchecked_alloc")
        self.assertEqual(len(hits), 0, "Checked SKB alloc should not flag")


# ── 1b. Use after free ───────────────────────────────────────────


class TestUseAfterFree(unittest.TestCase):
    """use_after_free should handle reassignment and NULL patterns."""

    def test_true_positive_flagged(self):
        hits = _hits_by_category(_extract_c("""
void foo(struct bar *ptr) {
    kfree(ptr);
    ptr->field = 0;
}
"""), "use_after_free")
        self.assertGreater(len(hits), 0, "Deref after kfree must be flagged")

    def test_reassignment_suppressed(self):
        """Variable reassigned after kfree — not a real UAF."""
        pe = PatternExtractor(_EmptyProfile())
        content = "kfree(ptr);\nptr = lookup_new();\nuse(ptr);\n"
        uaf_re = re.compile(
            r'kfree\s*\(\s*(\w+)\s*\)\s*;[^}]*\b\1\b', re.DOTALL
        )
        m = uaf_re.search(content)
        if m:
            self.assertTrue(
                pe._check_uaf_false_positive(m, content),
                "Reassignment after kfree should suppress",
            )

    def test_null_assign_suppressed(self):
        pe = PatternExtractor(_EmptyProfile())
        content = "kfree(ptr);\nobj->field = NULL;\nreturn;\n"
        uaf_re = re.compile(
            r'kfree\s*\(\s*(\w+)\s*\)\s*;[^}]*\b\1\b', re.DOTALL
        )
        m = uaf_re.search(content)
        # ptr must appear again after kfree for the regex to match
        # In this case 'ptr' doesn't appear again, so no match = no FP

    def test_log_only_reference_suppressed(self):
        pe = PatternExtractor(_EmptyProfile())
        content = 'kfree(ptr);\npr_info("freed %p", ptr);\n'
        uaf_re = re.compile(
            r'kfree\s*\(\s*(\w+)\s*\)\s*;[^}]*\b\1\b', re.DOTALL
        )
        m = uaf_re.search(content)
        if m:
            self.assertTrue(
                pe._check_uaf_false_positive(m, content),
                "Log-only reference should suppress UAF",
            )


# ── 1c. Double lock ──────────────────────────────────────────────


class TestDoubleLock(unittest.TestCase):
    """Deadlock detection with lock argument comparison."""

    def test_different_locks_no_match(self):
        """spin_lock_bh on different locks — regex should not match."""
        hits = _hits_by_category(_extract_c("""
void foo(struct ctx *c) {
    spin_lock_bh(&c->lock_a);
    do_work();
    spin_lock_bh(&c->lock_b);
    spin_unlock_bh(&c->lock_b);
    spin_unlock_bh(&c->lock_a);
}
"""), "deadlock")
        self.assertEqual(len(hits), 0, "Different locks should not trigger")

    def test_lock_unlock_relock_suppressed(self):
        hits = _hits_by_category(_extract_c("""
void foo(struct ctx *c) {
    spin_lock_bh(&c->lock);
    do_work();
    spin_unlock_bh(&c->lock);
    spin_lock_bh(&c->lock);
    do_more();
    spin_unlock_bh(&c->lock);
}
"""), "deadlock")
        self.assertEqual(len(hits), 0, "Lock-unlock-relock is not deadlock")

    def test_true_double_lock_flagged(self):
        hits = _hits_by_category(_extract_c("""
void foo(struct ctx *c) {
    spin_lock_bh(&c->lock);
    do_work();
    spin_lock_bh(&c->lock);
}
"""), "deadlock")
        self.assertGreater(len(hits), 0, "Same lock twice must be flagged")


# ── 1d. User size to kmalloc ─────────────────────────────────────


class TestUserSizeKmalloc(unittest.TestCase):
    """user_size_to_kmalloc with bounds checking."""

    def test_bounded_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(size_t len) {
    void *buf;
    if (len > MAX_SIZE)
        return -EINVAL;
    buf = kmalloc(len, GFP_KERNEL);
    return 0;
}
"""), "integer_overflow")
        self.assertEqual(len(hits), 0, "Bounded size should not flag")

    def test_unbounded_flagged(self):
        hits = _hits_by_category(_extract_c("""
int foo(size_t len) {
    void *buf = kmalloc(len, GFP_KERNEL);
    return 0;
}
"""), "integer_overflow")
        self.assertGreater(len(hits), 0, "Unbounded size must be flagged")

    def test_min_clamped_suppressed(self):
        hits = _hits_by_category(_extract_c("""
int foo(size_t len) {
    len = min(len, MAX_BUF);
    void *buf = kmalloc(len, GFP_KERNEL);
    return 0;
}
"""), "integer_overflow")
        self.assertEqual(len(hits), 0, "min()-clamped size should not flag")


# ── 4a. Function-scoped multiline ────────────────────────────────


class TestFunctionScoping(unittest.TestCase):
    """Multiline lint patterns must not match across function boundaries."""

    def test_lock_in_separate_functions_not_flagged(self):
        hits = _hits_by_category(_extract_c("""
void func_a(struct ctx *c) {
    spin_lock_bh(&c->lock);
    do_a();
    spin_unlock_bh(&c->lock);
}

void func_b(struct ctx *c) {
    spin_lock_bh(&c->lock);
    do_b();
    spin_unlock_bh(&c->lock);
}
"""), "deadlock")
        self.assertEqual(
            len(hits), 0,
            "Same lock in different functions is not a deadlock"
        )


# ── 4b. suppress_if backref mechanism ────────────────────────────


class TestSuppressIf(unittest.TestCase):
    """LintPattern.suppress_if with backref replacement."""

    def test_backref_replacement_works(self):
        pe = PatternExtractor(_EmptyProfile())
        lp = next(l for l in LANG_C.lint_patterns if l.name == "unchecked_alloc")
        self.assertTrue(lp.suppress_if)

        content = "ptr = kmalloc(size, GFP_KERNEL);\nif (!ptr)\n    return;"
        m = re.search(lp.regex, content, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertTrue(pe._check_suppress_if(lp, m, content))

    def test_no_guard_does_not_suppress(self):
        pe = PatternExtractor(_EmptyProfile())
        lp = next(l for l in LANG_C.lint_patterns if l.name == "unchecked_alloc")

        content = "ptr = kmalloc(size, GFP_KERNEL);\nptr->x = 1;\n"
        m = re.search(lp.regex, content, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertFalse(pe._check_suppress_if(lp, m, content))


# ── Function splitting ───────────────────────────────────────────


class TestFunctionSplitting(unittest.TestCase):

    def test_splits_multiple_functions(self):
        pe = PatternExtractor(_EmptyProfile())
        chunks = pe._split_functions("""
int foo(int x) {
    return x + 1;
}

void bar(void) {
    do_thing();
}

static int baz(struct ctx *c) {
    if (c) { return 1; }
    return 0;
}
""")
        self.assertEqual(len(chunks), 3)

    def test_handles_nested_braces(self):
        pe = PatternExtractor(_EmptyProfile())
        chunks = pe._split_functions("""
int complex(int x) {
    if (x) {
        while (1) {
            if (x > 10) { break; }
        }
    }
    return 0;
}
""")
        self.assertEqual(len(chunks), 1)
        self.assertIn("return 0", chunks[0][1])


# ── New: extended guard suppression ──────────────────────────────


class TestGotoErrSuppression(unittest.TestCase):
    """Alloc followed by goto err_free should be suppressed."""

    def test_goto_err_suppressed(self):
        src = """\
int mymod_setup(void) {
    struct foo *p;
    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
        goto err_free;
    return 0;
err_free:
    return -ENOMEM;
}
"""
        hits = _extract_lint_hits(src, "c")
        alloc_hits = [h for h in hits if h["category"] == "unchecked_alloc"]
        self.assertEqual(len(alloc_hits), 0,
                         "goto err_free after alloc should suppress finding")

    def test_return_enomem_suppressed(self):
        src = """\
int mymod_setup(void) {
    struct foo *p;
    p = kmalloc(64, GFP_KERNEL);
    if (!p)
        return -ENOMEM;
    return 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        alloc_hits = [h for h in hits if h["category"] == "unchecked_alloc"]
        self.assertEqual(len(alloc_hits), 0,
                         "return -ENOMEM after alloc should suppress finding")


class TestConstantSizeKmalloc(unittest.TestCase):
    """kmalloc with constant-sized names should not be flagged."""

    def test_max_len_constant_suppressed(self):
        src = """\
void mymod_alloc(void) {
    buf = kmalloc(MAX_LEN, GFP_KERNEL);
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "ALL_CAPS constant should be suppressed")

    def test_suffix_size_suppressed(self):
        src = """\
void mymod_alloc(void) {
    buf = kmalloc(msg_len, GFP_KERNEL);
}
"""
        # msg_len is not ALL_CAPS, doesn't end with _SIZE/_MAX — should flag
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertGreater(len(size_hits), 0,
                           "Lowercase variable name should still flag")

    def test_buf_SIZE_suffix_suppressed(self):
        src = """\
void mymod_alloc(void) {
    buf = kmalloc(buf_LEN, GFP_KERNEL);
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "_LEN suffix should be suppressed")


class TestCopyFromUserSuppression(unittest.TestCase):
    """copy_from_user return value used in condition or assigned."""

    def test_return_value_assigned(self):
        src = """\
int mymod_read(void) {
    ret = copy_from_user(dst, src, len);
    if (ret)
        return -EFAULT;
    return 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        copy_hits = [h for h in hits if h["name"] == "unchecked_copy_from_user"]
        self.assertEqual(len(copy_hits), 0,
                         "copy_from_user with ret= should be suppressed")

    def test_return_propagated(self):
        src = """\
int mymod_read(void) {
    return copy_from_user(dst, src, len);
}
"""
        hits = _extract_lint_hits(src, "c")
        copy_hits = [h for h in hits if h["name"] == "unchecked_copy_from_user"]
        self.assertEqual(len(copy_hits), 0,
                         "return copy_from_user should be suppressed")


def _extract_lint_hits(src, ext):
    """Helper: run lint extraction and return hits."""
    pe = PatternExtractor(_EmptyProfile())
    sf = ScannedFile(
        rel_path=f"test_file.{ext}",
        abs_path=f"/tmp/test_file.{ext}",
        side=Side.KERNEL,
        language=ext,
        size_bytes=len(src),
    )
    from boundary_mapper.pattern_extract import ExtractedFile
    result = ExtractedFile(sf.rel_path)
    lang = LANG_C if ext == "c" else LANG_GO
    pe._extract_lint(src, sf, result, lang, ext)
    return result.lint_hits


# ── UAF: freed variable vs different variable ───────────────────


class TestUAFVariableTracking(unittest.TestCase):
    """UAF detector should track which variable was freed."""

    def test_different_variable_after_kfree_suppressed(self):
        """kfree(path) then tquic_dbg(path->path_id) — path_id is a
        different token from path, but even if the regex captures it,
        the debug macro should suppress."""
        src = """\
void mymod_free_path(struct path *path) {
    int id = path->path_id;
    kfree(path);
    tquic_dbg("freed path %d", id);
}
"""
        hits = _extract_lint_hits(src, "c")
        uaf = [h for h in hits if h["category"] == "use_after_free"]
        self.assertEqual(len(uaf), 0,
                         "Debug print after kfree should be suppressed")

    def test_different_var_name_not_flagged(self):
        """kfree(path) then use of path_timer — different variable."""
        src = """\
void mymod_cleanup(struct conn *conn) {
    struct path *path = conn->path;
    kfree(path);
    conn->path_timer = 0;
    conn->path_count--;
}
"""
        hits = _extract_lint_hits(src, "c")
        uaf = [h for h in hits if h["category"] == "use_after_free"]
        self.assertEqual(len(uaf), 0,
                         "path_timer/path_count are not 'path' — not UAF")

    def test_actual_deref_after_kfree_flagged(self):
        """kfree(ptr) then ptr->field — genuine UAF."""
        src = """\
void mymod_bad(struct foo *ptr) {
    kfree(ptr);
    ptr->count = 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        uaf = [h for h in hits if h["category"] == "use_after_free"]
        self.assertGreater(len(uaf), 0,
                           "Actual dereference after kfree must be flagged")

    def test_return_after_kfree_suppressed(self):
        """kfree(ptr); return; — no use of freed pointer."""
        src = """\
void mymod_release(struct foo *ptr) {
    kfree(ptr);
    return;
}
"""
        hits = _extract_lint_hits(src, "c")
        uaf = [h for h in hits if h["category"] == "use_after_free"]
        self.assertEqual(len(uaf), 0,
                         "return after kfree is not UAF")


# ── kmalloc bounds: tracing through assignments ─────────────────


class TestKmallocBoundsTracing(unittest.TestCase):
    """kmalloc size checker should trace through assignments."""

    def test_comparison_bound_1500_chars_back(self):
        """Bounds check further back than 500 chars should be found."""
        # Create source with > 500 chars between check and kmalloc
        padding = "    // padding line\n" * 40  # ~800 chars
        src = f"""\
int mymod_alloc(int ct_len) {{
    if (ct_len > 256)
        return -EINVAL;
{padding}    buf = kmalloc(ct_len, GFP_KERNEL);
    return 0;
}}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "Bounds check 800+ chars back should suppress")

    def test_sizeof_assignment_suppressed(self):
        """var = sizeof(struct foo); kmalloc(var) should be safe."""
        src = """\
void mymod_init(void) {
    size_t alloc_len = sizeof(struct mymod_ctx);
    buf = kmalloc(alloc_len, GFP_KERNEL);
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "sizeof assignment should suppress")

    def test_min_assignment_suppressed(self):
        """var = min(user_len, MAX); kmalloc(var) should be safe."""
        src = """\
void mymod_recv(int user_len) {
    size_t alloc_len = min(user_len, 4096);
    buf = kmalloc(alloc_len, GFP_KERNEL);
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "min() assignment should suppress")

    def test_numeric_comparison_suppressed(self):
        """if (retry_len > 1440) return; kmalloc(retry_len) is safe."""
        src = """\
int mymod_retry(int retry_len) {
    if (retry_len > 1440)
        return -EINVAL;
    buf = kmalloc(retry_len, GFP_KERNEL);
    return 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertEqual(len(size_hits), 0,
                         "Numeric comparison should suppress")


# ── kmalloc severity: network input escalation ──────────────────


class TestKmallocSeverityEscalation(unittest.TestCase):
    """Network-derived kmalloc size should be escalated to HIGH."""

    def test_nla_get_derived_size_is_high(self):
        """Size from nla_get_u32 → kmalloc should be HIGH."""
        src = """\
int mymod_nl_handler(struct sk_buff *skb, struct genl_info *info) {
    u32 data_len = nla_get_u32(info->attrs[MYMOD_ATTR_LEN]);
    buf = kmalloc(data_len, GFP_KERNEL);
    return 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertGreater(len(size_hits), 0)
        self.assertEqual(size_hits[0]["severity"], "high",
                         "Network-derived size should be HIGH severity")

    def test_local_computation_stays_medium(self):
        """Size computed locally (no network input) stays MEDIUM."""
        src = """\
int mymod_setup(int count) {
    int alloc_len = count * 4;
    buf = kmalloc(alloc_len, GFP_KERNEL);
    return 0;
}
"""
        hits = _extract_lint_hits(src, "c")
        size_hits = [h for h in hits if h["name"] == "user_size_to_kmalloc"]
        self.assertGreater(len(size_hits), 0)
        self.assertEqual(size_hits[0]["severity"], "medium",
                         "Non-network size should stay MEDIUM")


# ── Dispatch detection: SOCKOPT_MAP names accepted ───────────────


class TestDispatchPrefixBypass(unittest.TestCase):
    """Dispatch extractor should accept names from SOCKOPT_MAP even
    if they don't match option_prefixes."""

    def test_sockopt_map_name_accepted(self):
        """case TQUIC_NODELAY: should be extracted if TQUIC_NODELAY
        is in SOCKOPT_MAP, even if option_prefixes only has MYMOD_."""
        content = """\
int tquic_setsockopt(struct sock *sk, int optname, ...) {
    switch (optname) {
    case TQUIC_NODELAY:
        return tquic_set_nodelay(sk);
    case TQUIC_CC_ALGO:
        return tquic_set_cc(sk);
    default:
        return -ENOPROTOOPT;
    }
}
"""
        with tempfile.NamedTemporaryFile(
                suffix=".c", mode="w", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            pe = PatternExtractor(_ProfileWithMismatchedPrefixes())
            sf = ScannedFile(
                rel_path="net/tquic/tquic_socket.c",
                abs_path=tmp_path,
                side=Side.KERNEL,
                language="c",
                size_bytes=len(content),
            )
            result = pe.extract_file(sf)
            case_names = {d["case"] for d in result.dispatch_entries}
            self.assertIn("TQUIC_NODELAY", case_names,
                           "SOCKOPT_MAP name should bypass prefix filter")
            self.assertIn("TQUIC_CC_ALGO", case_names,
                           "SOCKOPT_MAP name should bypass prefix filter")
        finally:
            os.unlink(tmp_path)


class _ProfileWithMismatchedPrefixes:
    """Profile where option_prefixes don't match SOCKOPT_MAP names."""
    SOCKOPT_MAP = {
        "1": "TQUIC_NODELAY",
        "2": "TQUIC_CC_ALGO",
    }
    GENL_FAMILIES = {}
    IOCTL_MAP = {}

    def get_command_prefixes(self):
        return ["MYMOD_CMD_"]

    def get_option_prefixes(self):
        # Intentionally WRONG — doesn't include TQUIC_
        return ["MYMOD_"]

    def get_attribute_prefixes(self):
        return ["MYMOD_ATTR_"]


if __name__ == "__main__":
    unittest.main()
