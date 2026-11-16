"""Ransom-note filename matching."""
from __future__ import annotations

import re
import unicodedata
from typing import Optional

# Patterns are applied to an ASCII-folded, upper-cased basename, so
# "RANÇON.txt" (NFC on Linux, possibly NFD on macOS) becomes "RANCON.TXT".
RANSOM_NOTE_PATTERNS = (
    ("rancon", re.compile(r"RANCON")),                  # ProManager: RANÇON.txt
    ("ransom", re.compile(r"RANSOM")),
    ("decrypt", re.compile(r"DECRYPT")),
    ("recover-files", re.compile(r"(HOW|HELP)[_\-. ]?TO[_\-. ]?(RECOVER|RESTORE|DECRYPT)")),
    ("restore-files", re.compile(r"RESTORE[_\-. ]?(MY[_\-. ]?)?FILES")),
    ("readme-note", re.compile(r"^(!+README!+|_README\.TXT|README[_\-. ]?(NOW|FIRST|FOR[_\-. ]?DECRYPT|TO[_\-. ]?RESTORE))")),
    ("your-files", re.compile(r"YOUR[_\-. ]?FILES[_\-. ]?(ARE[_\-. ]?)?(ENCRYPTED|LOCKED)")),
)


def fold_name(name: str) -> str:
    """Strip accents and upper-case a filename for robust matching."""
    decomposed = unicodedata.normalize("NFKD", name)
    ascii_only = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return ascii_only.upper()


def match_ransom_note(basename: str) -> Optional[str]:
    """Return the id of the first matching pattern, or None."""
    folded = fold_name(basename)
    for pattern_id, regex in RANSOM_NOTE_PATTERNS:
        if regex.search(folded):
            return pattern_id
    return None
