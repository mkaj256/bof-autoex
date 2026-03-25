"""Push byte strings onto the stack."""

from ..config import WORD_SIZE, BAD_BYTES
CHUNK_SIZE = WORD_SIZE

from .put_const_to_reg import put_const_to_reg

def reverse_bytes(input_bytes: bytes) -> bytes:
    """
    Reverse the order of bytes for little‑endian stack pushing.

    On x86‑64, the least significant byte of a pushed value occupies the lowest
    stack address. This function prepares a byte string for that order.

    Args:
        input_bytes: Original byte sequence.

    Returns:
        Byte sequence with reversed order.
    """
    bytes_list = list(input_bytes)
    bytes_list.reverse()
    return bytes(bytes_list)

def split_bytes(input_bytes: bytes, chunk_size) -> list:
    """
    Split a byte sequence into chunks suitable for sequential pushes.

    The first chunk may be shorter than chunk_size; the remaining chunks are
    exactly chunk_size bytes. This layout ensures that after pushes the original
    string appears contiguously on the stack.

    Args:
        input_bytes: Little‑endian byte sequence.
        chunk_size: Size of each full chunk (typically WORD_SIZE).

    Returns:
        List of byte chunks (each as bytes).
    """
    if not input_bytes:
        return []

    if len(input_bytes) <= chunk_size:
        return [input_bytes]

    first_chunk_size = len(input_bytes) % chunk_size
    if first_chunk_size == 0:
        first_chunk_size = chunk_size

    chunks = []

    # Add first chunk (may be not full)
    chunks.append(input_bytes[:first_chunk_size])

    # Calculate amount of full chunks excluding the first chunk
    full_chunks_amount = (len(input_bytes) - first_chunk_size) // chunk_size

    # Add other chunks
    for chunk_num in range(full_chunks_amount):
        start = first_chunk_size + chunk_num * chunk_size
        end = start + chunk_size
        chunks.append(input_bytes[start:end])

    return chunks

def push_bytes(input_bytes: bytes) -> list:
    """
    Generate assembly code to push a byte string onto the stack.

    The function reverses the bytes to little‑endian order, splits them into
    chunks, loads each chunk into RAX (avoiding bad bytes), and pushes RAX.

    Args:
        input_bytes: The byte string to be placed on the stack.

    Returns:
        List of assembly instructions.
    """
    asm = []
    # x86_64 uses little-endian: least significant byte goes to lowest stack address
    # (this means data on the stack is stored in reversed order),
    # so we reverse the original bytes.
    little_endian_bytes = reverse_bytes(input_bytes)  # Make bytes little-endian
    chunks = split_bytes(little_endian_bytes, CHUNK_SIZE)
    for chunk in chunks:
        value = int.from_bytes(chunk, byteorder="big")
        asm += put_const_to_reg(value, "rax", BAD_BYTES)
        asm.append("push %rax")
    return asm
