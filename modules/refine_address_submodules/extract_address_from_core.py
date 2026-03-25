import logging
from typing import List, Tuple

from .get_diapasones import get_diapasones
from .search_signature import search_signature


def extract_address_from_core(core_path: str) -> int | None:
    """
    Given a core dump, try to locate the NOP sled and return one plausible
    address where it appears. The address is intended to be used as the
    refined return address.
    """
    log = logging.getLogger("bof_exploit")

    diapasones = get_diapasones(core_path)
    if not diapasones:
        log.debug("No code sections found in core dump")
        return None

    matches = search_signature(core_path, diapasones)
    if not matches:
        log.debug("No NOP sled found in core dump")
        return None

    # If multiple matches exist, pick the first one (usually the most plausible)
    chosen = matches[0]
    log.debug(f"Found NOP sled at 0x{chosen:x} (among {len(matches)} matches)")
    return chosen
