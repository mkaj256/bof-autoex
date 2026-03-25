"""Load constants into registers avoiding bad bytes."""

from ..config import REGISTER_MAP

def contains_bad_bytes(data: bytes, bad_bytes: list) -> bool:
    """
    Check if the given byte sequence contains any bad bytes.

    Args:
        data: Byte sequence to inspect.
        bad_bytes: List of bytes (integers) that are forbidden.

    Returns:
        True if at least one bad byte is found, False otherwise.
    """
    for bad_byte in bad_bytes:
        if bad_byte in data:
            return True
    return False

def get_fix_dict(bad_byte_int: int, bad_bytes: list) -> dict:
    """
    Find a pair (fixed_byte, fix_byte) and an operation (add/sub) that allows
    loading a bad byte into a register without directly using the bad byte.

    The algorithm tries to find a fix_byte such that:
        bad_byte = fixed_byte +/- fix_byte,
    where neither fixed_byte nor fix_byte are in the bad_bytes list.

    Args:
        bad_byte_int: The bad byte value (0–255) to be loaded.
        bad_bytes: List of forbidden byte values.

    Returns:
        A dictionary with keys:
            - fixed_byte: The byte that will be loaded initially.
            - fix_byte: The byte used in the subsequent add/sub operation.
            - fix_op: Either "add" or "sub" to correct the register.
        Returns None if no such pair exists.
    """
    bad_byte = bad_byte_int.to_bytes(1, "big")
    for fix_byte_int in range(1, 256):
        # 1. Try add
        fixed_byte_int = bad_byte_int - fix_byte_int
        if (0 <= fixed_byte_int <= 255
            and fixed_byte_int not in bad_bytes
            and fix_byte_int not in bad_bytes):
            return {
                "fixed_byte": fixed_byte_int,
                "fix_byte": fix_byte_int,
                "fix_op": "add"
            }
        # 2. Try sub
        fixed_byte_int = bad_byte_int + fix_byte_int
        if (0 <= fixed_byte_int <= 255
            and fixed_byte_int not in bad_bytes
            and fix_byte_int not in bad_bytes):
            return {
                "fixed_byte": fixed_byte_int,
                "fix_byte": fix_byte_int,
                "fix_op": "sub"
            }

    return None

def get_bytes_chunks(const: bytes) -> list:
    """
    Split a byte sequence into 1‑ or 2‑byte chunks for loading into a register.

    The function handles odd-length sequences by first isolating the leading
    byte as a separate chunk, then pairing the remaining bytes into 2‑byte chunks.

    Args:
        const: Byte sequence (big‑endian representation of a constant).

    Returns:
        List of byte chunks, each being either 1 or 2 bytes long.
    """
    chunks = []
    if len(const) % 2 == 1:  # If length is odd number (нечётное)
        chunks.append(const[0].to_bytes(1, "big"))  # For consistency
        const = const[1:]
    for i in range(0, len(const), 2):
        if i + 1 < len(const):
            chunks.append(const[i:i + 2])
    return chunks

def load_l_byte(byte: int, reg_map: dict, bad_bytes: list) -> list:
    """
    Generate assembly code to load a single byte into the low byte of a register,
    avoiding any bad bytes.

    If the byte itself is not bad, a simple `mov` is generated. Otherwise,
    it uses the fix_dict approach to load a safe value and then adjust.

    Args:
        byte: The byte value (0–255) to load.
        reg_map: Register map for the target register (from REGISTER_MAP).
        bad_bytes: List of forbidden byte values.

    Returns:
        List of assembly instructions (strings).
    """
    reg_8l = reg_map[8]["low"]
    if byte not in bad_bytes:
        # If byte is good
        return [f"mov $0x{byte:x}, %{reg_8l}"]
    # If byte is bad
    fix_dict = get_fix_dict(byte, bad_bytes)
    if fix_dict is None:
        raise RuntimeError(
            f"Could not load byte 0x{byte:x} into register without introducing bad bytes "
            f"(bad bytes list: {[hex(b) for b in bad_bytes]})."
        )
    fixed_byte = fix_dict["fixed_byte"]
    fix_byte = fix_dict["fix_byte"]
    fix_op = fix_dict["fix_op"]

    return [
        f"mov $0x{fixed_byte:x}, %{reg_8l}",
        f"{fix_op} $0x{fix_byte:x}, %{reg_8l}"
    ]

def load_h_byte(byte: int, reg_map: dict, bad_bytes: list) -> list:
    """
    Generate assembly code to load a single byte into the high byte of a register
    (e.g., AH for RAX), avoiding any bad bytes.

    If the register has no high‑byte counterpart (e.g., RDI), the byte is loaded
    into the low byte and then shifted left by 8 bits.

    Args:
        byte: The byte value (0–255) to load.
        reg_map: Register map for the target register.
        bad_bytes: List of forbidden byte values.

    Returns:
        List of assembly instructions.
    """
    reg_8 = reg_map[8]
    reg_8h = reg_8["high"]
    if reg_8h is None:
        # Just load to low and shift
        # load_l_byte already considering bad bytes fixes
        asm = load_l_byte(byte, reg_map, bad_bytes)
        reg64 = reg_map[64]
        asm.append(f"shl $8, %{reg64}")
        return asm

    if byte not in bad_bytes:
        # If byte is good
        return [f"mov $0x{byte:x}, %{reg_8h}"]

    # Load fixed to high and fix
    fix_dict = get_fix_dict(byte, bad_bytes)
    if fix_dict is None:
        raise RuntimeError(
            f"Could not load byte 0x{byte:x} into register without introducing bad bytes "
            f"(bad bytes list: {[hex(b) for b in bad_bytes]})."
        )
    fixed_byte = fix_dict["fixed_byte"]
    fix_byte = fix_dict["fix_byte"]
    fix_op = fix_dict["fix_op"]
    
    asm = [f"mov $0x{fixed_byte:x}, %{reg_8h}"]
    asm.append(f"{fix_op} $0x{fix_byte:x}, %{reg_8h}")
    return asm

def get_optimize_reg(byte_len: int, reg_map: dict) -> str:
    """
    Return the smallest register name that can hold a constant of given byte length.

    If the constant fits perfectly into a 1‑, 2‑, 4‑, or 8‑byte register, the
    corresponding register name is returned. Otherwise, an empty string is returned.

    Args:
        byte_len: Length of the constant in bytes (1, 2, 4, or 8).
        reg_map: Register map for the destination register.

    Returns:
        Register name (e.g., "al", "ax", "eax", "rax") or empty string.
    """
    if byte_len in (1, 2, 4, 8):
        opt_reg = reg_map[byte_len * 8]  # In bits
        if isinstance(opt_reg, dict):  # Then it's 8-bit
            opt_reg = opt_reg["low"]  # Use low byte
        return opt_reg
    else:
        return ""

def put_const_to_reg(const_int: int, reg: str, bad_bytes: list) -> list:
    """
    Generate assembly instructions to load an integer constant into a 64-bit
    register while avoiding any forbidden bytes in the resulting machine code.

    The function attempts to load the constant in the most efficient way:
    1. If the constant's byte representation contains no bad bytes, it is loaded
       directly into the smallest possible register part (e.g., `mov $0x1234, %ax`).
    2. If bad bytes are present, the constant is split into 1‑ or 2‑byte chunks
       (big‑endian order) and each chunk is loaded sequentially using a
       combination of `mov` and `add`/`sub` instructions to bypass the bad bytes.
       After loading each chunk, the register is shifted left by 16 bits to make
       room for the next chunk.
    3. The algorithm ensures that no byte of the generated machine code equals
       any value in `bad_bytes`.

    The register is first cleared with `xor %reg, %reg`.

    Args:
        const_int: The integer constant to load (must fit into 64 bits).
        reg: Name of the destination register (e.g., "rax", "rdi", "rsi", "rdx").
        bad_bytes: List of forbidden byte values (integers 0–255).

    Returns:
        List of assembly instruction strings that load the constant into the
        register without introducing any bad bytes.

    Raises:
        RuntimeError: If the constant exceeds 64 bits, the register is unknown,
                      or a byte cannot be loaded without using a bad byte.

    Example:
        >>> put_const_to_reg(0x41424344, "rax", [0x00, 0x0a])
        ['xor %rax, %rax',
         'mov $0x41, %ah',
         'mov $0x42, %al',
         'shl $16, %rax',
         'mov $0x43, %ah',
         'mov $0x44, %al']

    Note:
        The generated code uses the low and high 8‑bit parts of the register
        (e.g., `al`/`ah` for `rax`) to load two bytes at a time. If the
        register lacks a high‑byte counterpart (like `rdi`), the high byte is
        loaded into the low part and shifted left by 8 bits.
    """
    bit_len = const_int.bit_length()
    if bit_len > 64:
        raise RuntimeError(
            f"Constant size {bit_len} is greater then 64 bits.\n"
            "This constant can not be writed to 64-bit register."    
        )

    asm = [f"xor %{reg}, %{reg}"]
    
    if const_int == 0:
        return asm  # Already 0

    # Ceil division: (bit_length + 7) // 8 gives the minimal number of bytes
    byte_len = (const_int.bit_length() + 7) // 8
    const = const_int.to_bytes(byte_len, "big")
    try:
        reg_map = REGISTER_MAP[reg]
    except KeyError:
        raise RuntimeError(f"Unknown register: {reg}.\nMaybe it was forgotten to add it to map?")

    # 1. If there are NO bad bytes
    if not contains_bad_bytes(const, bad_bytes):
        # opt_reg = optimization_register
        opt_reg = get_optimize_reg(byte_len, reg_map)
        if opt_reg != "":
            asm.append(f"mov $0x{const_int:x}, %{opt_reg}")
            return asm

    # 2. If there ARE bad bytes
    reg_8h = reg_map[8]["high"]  # May be None
    reg_8l = reg_map[8]["low"]

    chunks = get_bytes_chunks(const)
    for i, chunk in enumerate(chunks):
        if len(chunk) == 1:
            byte = chunk[0]
            asm += load_l_byte(byte, reg_map, bad_bytes)
        else:
            h_byte = chunk[0]
            asm += load_h_byte(h_byte, reg_map, bad_bytes)

            l_byte = chunk[1]
            asm += load_l_byte(l_byte, reg_map, bad_bytes)

        if i != len(chunks) - 1:
            # Free 2 bytes for next chunk (single-element may be only the first)
            asm.append(f"shl $16, %{reg}")

    return asm
