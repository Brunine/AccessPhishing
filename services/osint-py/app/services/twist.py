"""Native lookalike-domain generation (dnstwist-style algorithms).

No subprocess, no network — pure string permutation of the registrable label.
The leftmost label is fuzzed and the remainder of the domain is kept as the
suffix (except tld-swap, which replaces the suffix). This is a deliberate
simplification over a full public-suffix split; see docs/OSINT.md.

Output order is deterministic: modes in the caller's order, and within each
mode a fixed iteration order, so results are stable for golden tests.
"""

from __future__ import annotations

from typing import Iterable

ASCII_LC = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
VALID_LABEL_CHARS = set(ASCII_LC + DIGITS + "-")

# Common TLDs used by tld-swap (kept small and well-known).
SWAP_TLDS = [
    "com", "net", "org", "info", "biz", "co", "io", "app",
    "online", "site", "xyz", "live", "cloud", "us",
]

# QWERTY adjacency for the replacement fuzzer.
_KEYBOARD = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huiknm", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}


def split_domain(domain: str) -> tuple[str, str]:
    """Return (leftmost label, suffix). 'a.b.c' -> ('a', 'b.c')."""
    domain = domain.strip().lower().rstrip(".")
    label, _, suffix = domain.partition(".")
    return label, suffix


def _valid_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c in VALID_LABEL_CHARS for c in label)


def _addition(label: str) -> Iterable[str]:
    for c in ASCII_LC:
        yield label + c


def _omission(label: str) -> Iterable[str]:
    if len(label) <= 1:
        return
    for i in range(len(label)):
        yield label[:i] + label[i + 1:]


def _repetition(label: str) -> Iterable[str]:
    for i, ch in enumerate(label):
        yield label[:i] + ch + label[i:]


def _hyphenation(label: str) -> Iterable[str]:
    for i in range(1, len(label)):
        yield label[:i] + "-" + label[i:]


def _replacement(label: str) -> Iterable[str]:
    for i, ch in enumerate(label):
        for repl in _KEYBOARD.get(ch, ""):
            yield label[:i] + repl + label[i + 1:]


def _bitsquatting(label: str) -> Iterable[str]:
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped != ch and flipped in VALID_LABEL_CHARS:
                yield label[:i] + flipped + label[i + 1:]


_FUZZERS = {
    "addition": _addition,
    "omission": _omission,
    "repetition": _repetition,
    "hyphenation": _hyphenation,
    "replacement": _replacement,
    "bitsquatting": _bitsquatting,
}


def generate(
    domain: str,
    modes: list[str],
    max_candidates: int,
) -> tuple[list[dict], bool]:
    """Generate lookalike candidates.

    Returns (candidates, truncated) where each candidate is
    {"domain": str, "fuzzer": str}. ``truncated`` is True when the cap was hit
    with more candidates still available.
    """
    label, suffix = split_domain(domain)
    original = f"{label}.{suffix}" if suffix else label

    seen: set[str] = set()
    out: list[dict] = []
    truncated = False

    def emit(new_label: str, new_suffix: str, fuzzer: str) -> bool:
        """Add one candidate. Returns False if the cap is now full."""
        nonlocal truncated
        if not _valid_label(new_label):
            return True
        cand = f"{new_label}.{new_suffix}" if new_suffix else new_label
        if cand == original or cand in seen:
            return True
        if len(out) >= max_candidates:
            truncated = True
            return False
        seen.add(cand)
        out.append({"domain": cand, "fuzzer": fuzzer})
        return True

    for mode in modes:
        if mode == "tld-swap":
            for tld in SWAP_TLDS:
                if tld == suffix:
                    continue
                if not emit(label, tld, "tld-swap"):
                    return out, truncated
            continue
        fuzzer = _FUZZERS.get(mode)
        if fuzzer is None:
            continue  # unknown modes are rejected at the model layer
        for variant in fuzzer(label):
            if not emit(variant, suffix, mode):
                return out, truncated

    return out, truncated
