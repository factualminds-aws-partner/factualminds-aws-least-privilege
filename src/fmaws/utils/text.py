def find_line(text: str, needle: str) -> int | None:
    """1-based line of the first occurrence of ``needle``, for source references."""
    index = text.find(needle) if needle else -1
    return None if index < 0 else text.count("\n", 0, index) + 1
