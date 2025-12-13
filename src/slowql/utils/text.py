# slowql/src/slowql/utils/text.py
"""Text processing utilities."""
def truncate(text: str, width: int = 50) -> str:
    return text[:width] + "..." if len(text) > width else text