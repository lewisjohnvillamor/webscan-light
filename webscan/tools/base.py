"""Tool registry and shared options for the scanner suite.

Each tool is a callable that takes a target and ToolOptions and returns a
ToolReport. Tools register metadata so the CLI and web UI can list them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from webscan.core.toolreport import ToolReport

ToolFunc = Callable[[str, "ToolOptions"], ToolReport]


@dataclass
class ToolOptions:
    timeout: float = 10.0
    workers: int = 40
    offline: bool = False
    verify_tls: bool = True
    # tool-specific knobs (only the relevant ones are read by each tool)
    ports: str = ""              # "top100" | "top1000" | "1-1024" | "80,443,..."
    wordlist: str = ""           # path to a custom wordlist
    max_items: int = 0           # cap results (0 = tool default)
    delay: float = 0.0           # min seconds between requests (politeness)
    active: bool = False         # opt-in to active payload testing
    authorized: bool = False     # explicit consent for intrusive tools
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class ToolSpec:
    id: str
    name: str
    category: str                # "Recon" | "Vulnerability" | "Exploit"
    description: str
    func: ToolFunc
    glyph: str = "🛡"
    active: bool = False         # sends payloads / is intrusive
    target_hint: str = "URL or hostname"
    order: int = 100


_REGISTRY: dict[str, ToolSpec] = {}


def tool(**meta) -> Callable[[ToolFunc], ToolFunc]:
    def decorator(func: ToolFunc) -> ToolFunc:
        spec = ToolSpec(func=func, **meta)
        if spec.id in _REGISTRY:
            raise ValueError(f"duplicate tool id: {spec.id}")
        _REGISTRY[spec.id] = spec
        return func

    return decorator


def all_tools() -> list[ToolSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.order, s.name))


def get_tool(tool_id: str) -> ToolSpec | None:
    return _REGISTRY.get(tool_id)


def load_tools() -> None:
    from webscan import tools as _tools  # noqa: F401  (imports every tool module)
