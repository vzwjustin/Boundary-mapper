"""Trace templates for runtime verification of boundary surfaces.

These generate bpftrace/ftrace commands that can be used to confirm
that a statically-mapped flow is actually exercised at runtime.

NOT a replacement for static analysis — only marks graph edges
as runtime_observed when trace output is provided.
"""
from __future__ import annotations

from ..models import BoundarySurface, BoundaryType


def generate_bpftrace(surface: BoundarySurface) -> str:
    """Generate a bpftrace one-liner to trace a boundary surface."""
    if surface.boundary_type == BoundaryType.GENETLINK:
        return _genetlink_probe(surface)
    elif surface.boundary_type == BoundaryType.SETSOCKOPT:
        return _sockopt_probe(surface)
    elif surface.boundary_type == BoundaryType.SYSCTL:
        return _sysctl_probe(surface)
    return f"# No trace template for {surface.boundary_type.value}"


def _genetlink_probe(surface: BoundarySurface) -> str:
    handler = surface.handler
    if not handler:
        return f"# No handler for {surface.name}"
    return (
        f"# Trace {surface.name}\n"
        f"bpftrace -e 'kprobe:{handler} {{ "
        f'printf("HIT {handler} pid=%d comm=%s\\n", pid, comm); }}\''
    )


def _sockopt_probe(surface: BoundarySurface) -> str:
    entry = surface.kernel_entrypoint or "unknown_setsockopt"
    key = surface.dispatch_key
    return (
        f"# Trace {surface.name} (opt={key})\n"
        f"bpftrace -e 'kprobe:{entry} / arg2 == {key} / {{ "
        f'printf("HIT {surface.shared_contract} pid=%d\\n", pid); }}\''
    )


def _sysctl_probe(surface: BoundarySurface) -> str:
    return (
        f"# Trace sysctl {surface.name}\n"
        f"bpftrace -e 'kprobe:proc_dointvec {{ "
        f'printf("sysctl write pid=%d\\n", pid); }}\''
    )


def generate_ftrace(surface: BoundarySurface) -> str:
    """Generate ftrace commands for a surface."""
    handler = surface.handler or surface.kernel_entrypoint
    if not handler:
        return f"# No handler for {surface.name}"
    return (
        f"# Trace {surface.name} via ftrace\n"
        f"echo {handler} > /sys/kernel/debug/tracing/set_ftrace_filter\n"
        f"echo function > /sys/kernel/debug/tracing/current_tracer\n"
        f"echo 1 > /sys/kernel/debug/tracing/tracing_on\n"
        f"# ... exercise the path ...\n"
        f"echo 0 > /sys/kernel/debug/tracing/tracing_on\n"
        f"cat /sys/kernel/debug/tracing/trace"
    )
