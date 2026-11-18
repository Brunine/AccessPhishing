"""Deterministic tests for the native lookalike-domain generator."""

from __future__ import annotations

from app.services.twist import SWAP_TLDS, generate


def _domains(candidates):
    return [c["domain"] for c in candidates]


def test_omission_and_hyphenation_order():
    cands, truncated = generate("ab.com", ["omission", "hyphenation"], 500)
    assert truncated is False
    assert cands == [
        {"domain": "b.com", "fuzzer": "omission"},
        {"domain": "a.com", "fuzzer": "omission"},
        {"domain": "a-b.com", "fuzzer": "hyphenation"},
    ]


def test_replacement_keyboard_adjacency():
    cands, _ = generate("ab.com", ["replacement"], 500)
    # 'a' -> q,w,s,z ; 'b' -> v,g,h,n
    assert _domains(cands) == [
        "qb.com", "wb.com", "sb.com", "zb.com",
        "av.com", "ag.com", "ah.com", "an.com",
    ]
    assert all(c["fuzzer"] == "replacement" for c in cands)


def test_tld_swap_excludes_original_tld():
    cands, _ = generate("ab.com", ["tld-swap"], 500)
    doms = _domains(cands)
    assert "ab.com" not in doms
    assert doms[0] == "ab.net"
    assert len(doms) == len([t for t in SWAP_TLDS if t != "com"])
    assert all(c["fuzzer"] == "tld-swap" for c in cands)


def test_addition_count_and_cap():
    full, truncated = generate("ab.com", ["addition"], 500)
    assert truncated is False
    assert len(full) == 26  # one per a-z appended

    capped, truncated = generate("ab.com", ["addition"], 5)
    assert truncated is True
    assert len(capped) == 5
    assert capped[0]["domain"] == "aba.com"


def test_original_excluded_and_deduped():
    # repetition then omission can both yield overlaps; ensure no dupes and no original.
    cands, _ = generate("aa.com", ["repetition", "omission"], 500)
    doms = _domains(cands)
    assert "aa.com" not in doms
    assert len(doms) == len(set(doms))


def test_bitsquatting_valid_labels_only():
    cands, _ = generate("example.com", ["bitsquatting"], 500)
    for c in cands:
        label = c["domain"].split(".")[0]
        assert label and not label.startswith("-") and not label.endswith("-")
        assert all(ch.isalnum() or ch == "-" for ch in label)
        assert c["fuzzer"] == "bitsquatting"


def test_subdomain_label_only_is_fuzzed():
    # multi-label domain: suffix preserved, leftmost label fuzzed.
    cands, _ = generate("mail.corp.example.com", ["omission"], 500)
    assert all(c["domain"].endswith(".corp.example.com") for c in cands)
