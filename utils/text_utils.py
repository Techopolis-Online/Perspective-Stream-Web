"""
Utility functions for text processing.

Currently includes helpers to sanitize outgoing email content.
"""

import re
from typing import Optional


# Regex pattern that matches most Unicode emoji and related symbols
# Covers: emoticons, transport/map, misc symbols, pictographs, dingbats,
# variation selectors, supplemental symbols, flags, and zero-width joiners
_EMOJI_REGEX = re.compile(
    r"[\U0001F300-\U0001F5FF]"  # Misc Symbols and Pictographs
    r"|[\U0001F600-\U0001F64F]"  # Emoticons
    r"|[\U0001F680-\U0001F6FF]"  # Transport and Map Symbols
    r"|[\U0001F700-\U0001F77F]"  # Alchemical Symbols
    r"|[\U0001F780-\U0001F7FF]"  # Geometric Shapes Extended
    r"|[\U0001F800-\U0001F8FF]"  # Supplemental Arrows-C
    r"|[\U0001F900-\U0001F9FF]"  # Supplemental Symbols and Pictographs
    r"|[\U0001FA00-\U0001FA6F]"  # Chess Symbols, Symbols for Legacy Computing (partial)
    r"|[\U0001FA70-\U0001FAFF]"  # Symbols and Pictographs Extended-A
    r"|[\u2600-\u26FF]"          # Misc symbols
    r"|[\u2700-\u27BF]"          # Dingbats
    r"|[\uFE0F]"                  # Variation Selector-16
    r"|[\u200D]"                  # Zero Width Joiner
    ,
    flags=re.UNICODE,
)


def strip_emojis(text: Optional[str]) -> str:
    """Remove emoji characters from text.

    Args:
        text: Input string that may contain emoji characters.

    Returns:
        The input string with all emoji characters removed. If None is passed,
        returns an empty string.
    """
    if not text:
        return ""
    return _EMOJI_REGEX.sub("", text)


