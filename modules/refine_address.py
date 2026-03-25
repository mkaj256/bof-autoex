import os
import logging
from pathlib import Path

from .refine_address_submodules.get_core_path import get_core_path
from .refine_address_submodules.extract_address_from_core import extract_address_from_core


def refine_address(binary_path: Path, payload_bytes: bytes) -> int | None:
    """
    Attempt to refine the buffer address by analysing the core dump
    generated when the payload is sent to the binary.

    Returns:
        A refined address (int) if successful, otherwise None.
    """
    log = logging.getLogger("bof_exploit")

    core_path = get_core_path(binary_path, payload_bytes)
    if core_path is None:
        log.debug("No core dump obtained; skipping address refinement")
        return None

    try:
        refined_address = extract_address_from_core(core_path)
        if refined_address is None:
            log.debug("Could not extract refined address from core")
            return None

        log.debug(f"Refined buffer address: 0x{refined_address:x}")
    finally:
        # Clean temporary file:
        os.unlink(core_path)

    return refined_address
