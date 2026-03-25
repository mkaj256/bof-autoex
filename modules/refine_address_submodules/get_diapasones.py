import logging
import subprocess as sp
from typing import List, Tuple


def _filter_lines(data: List[List[str]]) -> List[List[str]]:
    """
    Filter GDB section info lines to keep only executable code sections.

    Keeps lines that:
        - Do not contain "READONLY" (filter out read‑only data sections)
        - Contain "CODE" (ensure it's a code section)
        - Contain "HAS_CONTENTS" (exclude zero‑filled sections like BSS)

    Args:
        data: List of tokenized lines from GDB's `maintenance info sections`.

    Returns:
        Filtered list of lines that correspond to code sections with contents.
    """
    filtered = []
    for line in data:
        if "READONLY" in line or "CODE" not in line:
            continue
        if "HAS_CONTENTS" in line:
            filtered.append(line)
    return filtered


def _extract_diapasones(lines: List[List[str]]) -> List[Tuple[int, int]]:
    """
    Extract address ranges (start, end) from GDB section info lines.

    Each line is expected to contain a string like "0x12340000->0x12341000".
    The function parses the first occurrence of such a pattern and returns
    a list of integer tuples (start, end).

    Args:
        lines: Filtered GDB section info lines (tokenized).

    Returns:
        List of (start_address, end_address) tuples.
    """
    diapasones = []
    for line in lines:
        for elem in line:
            if elem.startswith("0x"):
                parts = elem.split("->")
                if len(parts) == 2:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    diapasones.append((start, end))
                break
    return diapasones


def get_diapasones(corefile: str) -> List[Tuple[int, int]]:
    """
    Search for the NOP sled pattern within a contiguous address range in a core dump.

    The search is performed in chunks of size `STEP` to avoid generating
    extremely large GDB scripts. For each chunk, GDB's `find` command is used
    to locate the 8‑byte NOP pattern. Addresses where the pattern is found are
    collected and returned.

    Args:
        start: Starting address (inclusive) of the range.
        end: Ending address (exclusive) of the range.
        corefile: Path to the core dump file.

    Returns:
        List of addresses (integers) where the NOP pattern was found.
    """
    log = logging.getLogger("bof_exploit")
    cmd = [
        "gdb",
        "-batch",
        "-c", corefile,
        "-ex", "maintenance info sections"
    ]
    try:
        out = sp.check_output(cmd, text=True, stderr=sp.DEVNULL)
    except sp.CalledProcessError as e:
        log.debug(f"GDB failed: {e}")
        return []

    data = []
    for line in out.split("\n"):
        stripped = line.strip()
        if stripped.startswith("["):
            data.append(stripped.split())

    filtered = _filter_lines(data)
    return _extract_diapasones(filtered)
