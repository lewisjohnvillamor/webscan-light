"""Check registry.

Every check registers the exact sentence it contributes to the report's
"List of tests performed" section, so the coverage list can never drift out
of sync with the checks that actually ran.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .models import Finding


@dataclass
class CheckSpec:
    test_id: str
    description: str
    func: Callable[..., Iterable[Finding] | None]
    order: int = 100
    requires_crawl: bool = True


_REGISTRY: dict[str, CheckSpec] = {}


def check(test_id: str, description: str, order: int = 100, requires_crawl: bool = True):
    """Register a check function.

    ``description`` is rendered verbatim in the scan coverage list.
    """

    def decorator(func: Callable[..., Iterable[Finding] | None]):
        if test_id in _REGISTRY:
            raise ValueError(f"duplicate check id: {test_id}")
        _REGISTRY[test_id] = CheckSpec(test_id, description, func, order, requires_crawl)
        return func

    return decorator


def all_checks() -> list[CheckSpec]:
    return sorted(_REGISTRY.values(), key=lambda spec: (spec.order, spec.test_id))


def get_check(test_id: str) -> CheckSpec | None:
    return _REGISTRY.get(test_id)


def load_checks() -> None:
    """Import the check modules so their decorators run."""
    from webscan import checks  # noqa: F401  (imports every check module)
