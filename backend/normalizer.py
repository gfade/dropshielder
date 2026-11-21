"""Two-pass canonical request normalizer for DropShield.

Explicitly addresses Failure Mode #2 ('Encoding evasion: double-encoding slipped through.
Fix: normalize twice before hashing.') as well as Unicode homoglyphs, SQL inline comment
splitting, and case mixing, while extracting structural evasion telemetry features so
benign free-text searches ('Drop Table Tee', 'O\'Brien') remain distinguishable from attacks.
"""

from __future__ import annotations

import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import List, Set

# Common Cyrillic / Greek / Fullwidth homoglyphs used in WAF evasion
_HOMOGLYPH_MAP = str.maketrans(
    {
        "Ѕ": "S",
        "ѕ": "s",
        "Е": "E",
        "е": "e",
        "А": "A",
        "а": "a",
        "О": "O",
        "о": "o",
        "С": "C",
        "с": "c",
        "Т": "T",
        "т": "t",
        "І": "I",
        "і": "i",
        "Р": "P",
        "р": "p",
        "Х": "X",
        "х": "x",
        "У": "Y",
        "у": "y",
        "＇": "'",
        "＂": '"',
        "／": "/",
        "＼": "\\",
        "．": ".",
        "－": "-",
        "；": ";",
        "（": "(",
        "）": ")",
        "＝": "=",
    }
)

_SQL_INLINE_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_MULTI_SLASH_RE = re.compile(r"/{2,}")
_WHITESPACE_RE = re.compile(r"[\t\r\n\v\f+]+|\s{2,}")

# Structural exploit patterns (distinct from plain English words like "Drop Table Tee" or "O'Brien")
_SQL_STRUCTURAL_RE = re.compile(
    r"(?:"
    r"'\s*(?:or|and)\s+['\d\w]+\s*=|"          # Tautology: ' OR 1=1 / ' OR 'a'='a
    r"\bunion\s+(?:all\s+)?select\b|"          # UNION SELECT
    r";\s*(?:drop|select|insert|update|delete|alter|exec)\b|"  # Stacked query
    r"--\s*$|--\s+[\w']*|"                     # SQL line comment suffix
    r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(|"
    r"\bselect\b.{1,60}\bfrom\b.{1,60}\b(?:where|information_schema|sqlite_master|users|orders)\b|"
    r"\)\s*(?:or|and|union)\s*\("              # Filter parenthesis breakout
    r")",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|win\.ini|\.env\b|%00|\\x00)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class NormalizedRequest:
    raw_text: str
    pass1_text: str
    canonical_text: str
    had_single_encoding: bool
    had_double_encoding: bool
    had_homoglyphs: bool
    had_sql_comment_split: bool
    had_null_byte: bool
    has_sql_structure: bool
    has_traversal_structure: bool
    shannon_entropy: float
    punctuation_ratio: float


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalize_input_twice(raw: str) -> NormalizedRequest:
    """Apply deterministic 2-pass URL decoding, NFKC + homoglyph folding, and comment stripping."""
    if not raw:
        return NormalizedRequest(
            raw_text="",
            pass1_text="",
            canonical_text="",
            had_single_encoding=False,
            had_double_encoding=False,
            had_homoglyphs=False,
            had_sql_comment_split=False,
            had_null_byte=False,
            has_sql_structure=False,
            has_traversal_structure=False,
            shannon_entropy=0.0,
            punctuation_ratio=0.0,
        )

    had_null_byte = "%00" in raw.lower() or "\x00" in raw

    # Pass 1 URL decode
    pass1 = urllib.parse.unquote_plus(raw)
    had_single = pass1 != raw

    # Pass 2 URL decode (catches %2527 -> %27 -> ', %252e%252e%252f -> ../, etc.)
    pass2 = urllib.parse.unquote_plus(pass1)
    had_double = pass2 != pass1

    # Unicode NFKC + explicit homoglyph map
    nfkc = unicodedata.normalize("NFKC", pass2)
    dehomoglyphed = nfkc.translate(_HOMOGLYPH_MAP)
    had_homoglyphs = (dehomoglyphed != pass2) and any(ord(c) > 127 for c in pass2)

    # Strip null bytes & collapse inline SQL comments (e.g., UN/**/ION -> UNION)
    no_nulls = dehomoglyphed.replace("\x00", "")
    had_comment_split = bool(_SQL_INLINE_COMMENT_RE.search(no_nulls))
    uncommented = _SQL_INLINE_COMMENT_RE.sub("", no_nulls)

    # Normalize backslashes in traversal-like segments, collapse multi-slashes and whitespace, lowercase
    slash_norm = uncommented.replace("\\", "/")
    slash_norm = _MULTI_SLASH_RE.sub("/", slash_norm)
    canonical = _WHITESPACE_RE.sub(" ", slash_norm).strip().lower()

    has_sql_struct = bool(_SQL_STRUCTURAL_RE.search(canonical))
    has_trav_struct = bool(_PATH_TRAVERSAL_RE.search(canonical))

    ent = _shannon_entropy(canonical)
    punct_count = sum(1 for c in canonical if not c.isalnum() and not c.isspace())
    punct_ratio = punct_count / max(len(canonical), 1)

    return NormalizedRequest(
        raw_text=raw,
        pass1_text=pass1,
        canonical_text=canonical,
        had_single_encoding=had_single,
        had_double_encoding=had_double,
        had_homoglyphs=had_homoglyphs,
        had_sql_comment_split=had_comment_split,
        had_null_byte=had_null_byte,
        has_sql_structure=has_sql_struct,
        has_traversal_structure=has_trav_struct,
        shannon_entropy=ent,
        punctuation_ratio=punct_ratio,
    )


def hash_char_ngrams(
    text: str,
    num_buckets: int = 1_048_576,  # 2^20 buckets for SparseCore HBM index
    min_n: int = 3,
    max_n: int = 5,
) -> List[int]:
    """Extract character 3..5-grams and hash deterministically with FNV-1a 32-bit into [0, num_buckets)."""
    if not text:
        return []
    padded = f"<{text}>"
    L = len(padded)
    mask = num_buckets - 1
    use_bitmask = (num_buckets & mask) == 0

    seen: Set[int] = set()
    out: List[int] = []
    for n in range(min_n, max_n + 1):
        if L < n:
            continue
        for i in range(L - n + 1):
            gram = padded[i : i + n]
            # Deterministic 32-bit FNV-1a
            h = 2166136261
            for ch in gram:
                h ^= ord(ch)
                h = (h * 16777619) & 0xFFFFFFFF
            bucket = (h & mask) if use_bitmask else (h % num_buckets)
            if bucket not in seen:
                seen.add(bucket)
                out.append(bucket)
    return out
