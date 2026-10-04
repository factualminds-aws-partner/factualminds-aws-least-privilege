from bisect import bisect_right
from functools import lru_cache


@lru_cache(maxsize=4)
def _line_starts(text: str) -> list[int]:
    return [i + 1 for i, char in enumerate(text) if char == "\n"]


def line_at(text: str, offset: int) -> int:
    """1-based line of a character offset. The newline index is built once per text."""
    return bisect_right(_line_starts(text), offset) + 1


def find_line(text: str, needle: str) -> int | None:
    """1-based line of the first occurrence of ``needle``, for source references."""
    index = text.find(needle) if needle else -1
    return None if index < 0 else line_at(text, index)
