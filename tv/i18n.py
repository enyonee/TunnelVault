"""Internationalization: locale detection, string translation.

Usage:
    from tv.i18n import t
    print(t("ui.enter"))          # lazy auto-detect on first call
    i18n.init("ru")               # explicit override (e.g. from config)
"""

from __future__ import annotations

import locale
import os
from typing import Optional


_current_lang: Optional[str] = None
_strings: dict[str, str] = {}


def _detect_locale() -> str:
    """Detect language from environment variables, fallback to 'en'."""
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val:
            lang = val.split("_")[0].split(".")[0].lower()
            if lang in ("ru", "en"):
                return lang
            # e.g. "C" or "POSIX" -> English
            if lang in ("c", "posix"):
                return "en"
    # Platform default
    try:
        lang_code = locale.getlocale()[0] or ""
        lang = lang_code.split("_")[0].lower()
        if lang in ("ru", "en"):
            return lang
    except (ValueError, AttributeError):
        pass
    return "en"


def init(lang: str = "") -> None:
    """Initialize or reinitialize with explicit language code.

    Empty string = auto-detect from environment.
    """
    global _current_lang, _strings
    code = lang.strip().lower() if lang else _detect_locale()
    if code == "ru":
        from tv.lang import ru

        _strings = ru.STRINGS
    else:
        from tv.lang import en

        _strings = en.STRINGS
    _current_lang = code


def t(key: str, **kwargs: object) -> str:
    """Translate key. Lazy-init on first call. Fallback = key itself."""
    if _current_lang is None:
        init()
    text = _strings.get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text


def current() -> str:
    """Return current locale code ('en' or 'ru')."""
    if _current_lang is None:
        init()
    return _current_lang  # type: ignore[return-value]


def reset() -> None:
    """Reset to uninitialized state (for tests)."""
    global _current_lang, _strings
    _current_lang = None
    _strings = {}
