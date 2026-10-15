"""
PURPOSE : Name -> class registries for every extension point, the @register_*
          decorators and plugin auto-discovery.
INPUTS  : decorated classes; the plugins/ directory; built-in package names.
OUTPUTS : REGISTRIES dict, register_* decorators, discover().
HOW TO EXTEND : drop a .py file in plugins/ that uses a decorator, e.g.
          @register_detector("my_detector"). No core change needed; enable it by
          adding it to config/detectors.yaml.
"""
from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from pathlib import Path
from typing import Any, Callable

from core.logging import get_logger

log = get_logger("registry")


class Registry:
    """A simple named registry of classes."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._items: dict[str, type] = {}

    def register(self, name: str) -> Callable[[type], type]:
        def deco(cls: type) -> type:
            cls.name = name  # type: ignore[attr-defined]
            self._items[name] = cls
            return cls
        return deco

    def get(self, name: str) -> type:
        if name not in self._items:
            raise KeyError(f"{self.kind} '{name}' is not registered (known: {sorted(self._items)})")
        return self._items[name]

    def create(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return self.get(name)(*args, **kwargs)

    def names(self) -> list[str]:
        return sorted(self._items)

    def __contains__(self, name: str) -> bool:
        return name in self._items


KINDS = ("detector", "action", "llm", "vector_store", "embedder", "report", "skill", "stage")
REGISTRIES: dict[str, Registry] = {k: Registry(k) for k in KINDS}

register_detector = REGISTRIES["detector"].register
register_action = REGISTRIES["action"].register
register_llm = REGISTRIES["llm"].register
register_vector_store = REGISTRIES["vector_store"].register
register_embedder = REGISTRIES["embedder"].register
register_report = REGISTRIES["report"].register
register_skill = REGISTRIES["skill"].register
register_stage = REGISTRIES["stage"].register

BUILTIN_PACKAGES = (
    "shieldgate.detectors", "shieldgate.detectors.injection", "shieldgate.actions",
    "shieldgate.llm", "shieldgate.llm.skills", "shieldgate.rag.stores",
    "shieldgate.rag.embedders", "shieldgate.reports", "shieldgate.pipeline.stages",
)
_discovered = False


def discover(plugin_dir: str | Path | None = None, force: bool = False) -> list[str]:
    """Import all built-in modules and every .py file in `plugin_dir`.

    Import failures are logged (module name only) and skipped so one broken
    plugin cannot take the gateway down; a missing *required* component is
    still caught later when config references it (fail closed).
    """
    global _discovered
    loaded: list[str] = []
    if _discovered and not force:
        return loaded
    for pkg_name in BUILTIN_PACKAGES:
        try:
            pkg = importlib.import_module(pkg_name)
        except Exception:  # noqa: BLE001
            log.warning("builtin package %s failed to import", pkg_name)
            continue
        for mod in pkgutil.iter_modules(getattr(pkg, "__path__", [])):
            full = f"{pkg_name}.{mod.name}"
            try:
                importlib.import_module(full)
                loaded.append(full)
            except Exception as exc:  # noqa: BLE001
                log.warning("module %s failed to import: %s", full, type(exc).__name__)
    if plugin_dir and Path(plugin_dir).is_dir():
        for path in sorted(Path(plugin_dir).glob("*.py")):
            if path.name.startswith("_"):
                continue
            mod_name = f"shieldgate_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = module
                spec.loader.exec_module(module)
                loaded.append(mod_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("plugin %s failed to load: %s", path.name, type(exc).__name__)
    _discovered = True
    return loaded
