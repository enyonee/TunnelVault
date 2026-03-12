"""Plugin registry - maps tunnel type names to plugin classes."""

from __future__ import annotations

from typing import Type

_registry: dict[str, Type] = {}


def register(type_name: str):
    """Class decorator: register a TunnelPlugin subclass for a tunnel type.

    Usage:
        @register("openvpn")
        class OpenVPNPlugin(TunnelPlugin): ...
    """

    def decorator(cls):
        if type_name in _registry:
            raise ValueError(f"Tunnel type '{type_name}' already registered")
        _registry[type_name] = cls
        return cls

    return decorator


def get_plugin(type_name: str) -> Type:
    """Get plugin class by type name. Raises KeyError if not found."""
    try:
        return _registry[type_name]
    except KeyError:
        available = ", ".join(sorted(_registry)) or "(none)"
        raise KeyError(f"Unknown tunnel type '{type_name}'. Available: {available}")


def available_types() -> list[str]:
    """Return sorted list of registered tunnel type names."""
    return sorted(_registry)


def clear() -> None:
    """Remove all registered plugins. For testing only."""
    _registry.clear()
