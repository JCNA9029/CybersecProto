# modules/colors.py — Lightweight colorama wrapper for colored terminal output.
# Soft dependency: gracefully degrades to plain text if colorama is not installed.

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLORAMA = True
except ImportError:
    _COLORAMA = False

    class _Noop:
        """Stub that returns empty string for any attribute access."""
        def __getattr__(self, _):
            return ""

    Fore = _Noop()
    Style = _Noop()


def success(msg: str):
    """Green — clean/safe results, successful operations."""
    print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")


def error(msg: str):
    """Red — errors, failed operations."""
    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


def critical(msg: str):
    """Bright red — MALICIOUS verdicts, containment events."""
    print(f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}")


def warning(msg: str):
    """Yellow — suspicious findings, non-fatal warnings."""
    print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}")


def info(msg: str):
    """Cyan — informational scan progress messages."""
    print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")


def header(msg: str):
    """Bright white — section headers and separators."""
    print(f"{Style.BRIGHT}{msg}{Style.RESET_ALL}")


def verdict_color(verdict: str) -> str:
    """Returns the verdict string wrapped in appropriate ANSI color codes."""
    v = verdict.upper()
    if any(k in v for k in ("MALICIOUS", "CRITICAL")):
        return f"{Fore.RED}{Style.BRIGHT}{verdict}{Style.RESET_ALL}"
    if "SUSPICIOUS" in v:
        return f"{Fore.YELLOW}{verdict}{Style.RESET_ALL}"
    if "SAFE" in v:
        return f"{Fore.GREEN}{verdict}{Style.RESET_ALL}"
    return verdict
