"""
Text normalization for detection. Applied as a fallback pass when the raw
text does not match any pattern — raw text is ALWAYS checked first, so
normalization can never introduce false positives on clean input.
"""
import re
import unicodedata

# Confusable homoglyphs (extend as needed; keep the list PUBLIC and small)
CONFUSABLES = {
    "\u027f": "r",   # ɿ -> r
    "\u0269": "l",   # ɩ -> l
    "\u0251": "a",   # ɑ -> a
    "\u025b": "e",   # ɛ -> e
    "\u028c": "a",   # ʌ -> a
    "\u0430": "a",   # cyrillic а -> a
    "\u0435": "e",   # cyrillic е -> e
    "\u043e": "o",   # cyrillic о -> o
    "\u0440": "p",   # cyrillic р -> p
    "\u0441": "c",   # cyrillic с -> c
}

ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")

# \u006e, \x67 literal escape sequences found in agent inputs
UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")

# "i.g.n.o.r.e" -> "ignore" (letter-dot-letter chains)
DOT_SEPARATED = re.compile(r"\b(?:([a-z])\.)+([a-z])\b")


def normalize_for_detection(text: str) -> str:
    """Best-effort de-obfuscation. Cheap, deterministic, no network."""
    s = text

    # 1. Decode literal escape sequences
    s = UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)

    # 2. Unicode normalization (accents, compatibility forms)
    s = unicodedata.normalize("NFKC", s)

    # 3. Map known homoglyphs
    for src, dst in CONFUSABLES.items():
        s = s.replace(src, dst)

    # 4. Strip zero-width characters
    s = ZERO_WIDTH.sub("", s)

    # 5. Collapse "i.g.n.o.r.e" spelled-out words
    s = DOT_SEPARATED.sub(
        lambda m: "".join(c for c in m.group(0) if c != "."), s
    )

    return s


def reversed_words_variant(text: str) -> str:
    """Return the text with each word reversed ('snoitcurtsni' -> 'instructions').
    Only used as a third fallback pass."""
    return " ".join(w[::-1] for w in text.split())
