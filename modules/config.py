"""
Configuration constants shared across modules for the BOF exploit generator.
"""

# ============================================================================
# Core dump analysis
# ============================================================================

# Step size (4 KiB) for scanning memory regions in GDB.
STEP = 0x1000

# 8‑byte NOP sled pattern used as a signature during core dump analysis.
NOP_SIGNATURE = 0x9090909090909090


# ============================================================================
# Output and file names
# ============================================================================

# Default directory where generated files are stored.
DEFAULT_OUTPUT_DIR = "output/"

# Name of the raw payload file (contains the exploit bytes).
PAYLOAD_FILE_NAME = "payload.bin"

# Name of the launcher script that runs the vulnerable binary with the payload.
EXPLOIT_FILE_NAME = "exploit.sh"


# ============================================================================
# Architecture-specific constants
# ============================================================================

# Size of a machine word in bytes (for 64-bit systems).
WORD_SIZE = 8


# ============================================================================
# Shellcode generation constraints
# ============================================================================

# Bad bytes that cannot appear in the generated shellcode.
# Common examples: null byte (0x00) terminates strings; newline (0x0a) may
# interfere with input reading.
BAD_BYTES = [0x00, 0x0a]

# Dummy input used during GDB reconnaissance – it should not overflow the buffer.
# This string is fed to the target program while we extract the buffer address
# and RBP.
DUMMY_INPUT = b"A" * 10 + b"\n"


# ============================================================================
# Payload construction
# ============================================================================

# The address obtained via GDB is usually slightly off due to environment
# differences (e.g., stack alignment, ASLR). To reliably land in the NOP sled,
# we add a small empirically determined offset to the buffer address.
# Set this value to a positive integer if the payload consistently misses the
# NOP sled; 0 means no offset.
BUFFER_ADDR_OFFSET = 0


# ============================================================================
# Exploit launcher
# ============================================================================

# Template for the generated exploit script.
# - `setarch -R` disables address space layout randomization (ASLR) for the
#   process. This is necessary for deterministic exploitation.
# - The payload is fed via input redirection.
EXPLOIT_TEMPLATE = "setarch -R {binary_path} < {payload_path}"


# ============================================================================
# External tool dependencies
# ============================================================================

# List of external command-line tools required for the generator to work.
# Each tool must be present in the system's PATH.
REQUIRED_TOOLS = [
    "gdb",       # GNU Debugger – extracts runtime information from the binary
    "as",        # GNU assembler – compiles the generated assembly code
    "objcopy",   # part of binutils – extracts raw machine code from object files
    "setarch"    # used in the exploit script to disable ASLR
]


# ============================================================================
# Register map for x86-64
# ============================================================================

# This map describes the hierarchical naming of sub‑registers for each 64‑bit
# general‑purpose register. It is used by `put_const_to_reg` to load constants
# into the smallest possible register part while avoiding bad bytes.
#
# Structure:
#   "register_name": {
#       64: "full 64-bit name",
#       32: "32-bit name (e.g., eax)",
#       16: "16-bit name (e.g., ax)",
#       8: {
#           "low": "low 8-bit part (e.g., al)",
#           "high": "high 8-bit part (e.g., ah) or None if not available"
#       }
#   }
REGISTER_MAP = {
    "rax": {
        64: "rax",
        32: "eax",
        16: "ax",
        8: {
            "low": "al",
            "high": "ah"
        }
    },
    "rdi": {
        64: "rdi",
        32: "edi",
        16: "di",
        8: {
            "low": "dil",
            "high": None          # RDI has no accessible high 8‑bit part
        }
    },
    "rsi": {
        64: "rsi",
        32: "esi",
        16: "si",
        8: {
            "low": "sil",
            "high": None          # RSI has no accessible high 8‑bit part
        }
    },
    "rdx": {
        64: "rdx",
        32: "edx",
        16: "dx",
        8: {
            "low": "dl",
            "high": "dh"
        }
    }
}
