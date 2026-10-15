"""Provider implementations. A new source writes fetch() and parse() only."""

from __future__ import annotations

from osint.providers.base import Provider, get_provider, all_providers

__all__ = ["Provider", "get_provider", "all_providers"]
