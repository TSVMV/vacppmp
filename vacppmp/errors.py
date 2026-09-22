"""Exception types shared across vacppmp."""

__all__ = ["ParseError", "UsageError", "VacppmpError"]


class VacppmpError(Exception):
    """Base error for all vacppmp failures."""


class ParseError(VacppmpError):
    """A capture file cannot be parsed."""


class UsageError(VacppmpError):
    """The user passed invalid command line input."""
