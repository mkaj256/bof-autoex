"""
Module for extracting runtime information from a vulnerable binary using GDB.
"""

import subprocess
import tempfile
import logging
from pathlib import Path

from .config import WORD_SIZE, DUMMY_INPUT

def _calculate_saved_rip_offset(buffer_addr: int, rbp_value: int) -> int:
    """
    Compute the offset from the start of the buffer to the saved return address.

    On x86_64, after a function prologue, the return address is stored at
    *(rbp + 8). Therefore the offset is (rbp + 8) - buffer_addr.

    Args:
        buffer_addr: Address of the buffer (from RDI after gets).
        rbp_value: Value of RBP after returning from the function that called gets.

    Returns:
        Offset in bytes.
    """
    return (rbp_value + WORD_SIZE) - buffer_addr

def get_data(binary: Path) -> dict:
    """
    Run GDB on the given binary to extract:
        - address of the buffer passed to gets (from $rdi)
        - value of $rbp after returning from the function that called gets

    Returns:
        dict: {'buffer_addr': int, 'rbp': int}

    Raises:
        RuntimeError: if GDB fails or required values cannot be parsed.
    """
    log = logging.getLogger('bof_exploit')
    
    # Create a dummy input file that will not overflow the buffer.
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as input_file:
        input_file.write(DUMMY_INPUT)
        input_path = input_file.name

    try:
        # GDB script as a list of commands
        gdb_commands = f"""
set pagination off
set confirm off
break gets
run < {input_path}
#p/x $rdi
printf "$rdi = 0x%llx\\n", $rdi
finish
#p/x $rbp
printf "$rbp = 0x%llx\\n", $rbp
quit
"""

        # Write commands to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as script_file:
            script_file.write(gdb_commands)
            script_path = script_file.name

        try:
            # Run GDB in batch mode
            result = subprocess.run(
                ['gdb', '-batch', '-x', script_path, str(binary)],
                capture_output=True,
                text=True,
                timeout=30
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("GDB timed out") from e
        finally:
            # Clean up temporary script
            Path(script_path).unlink(missing_ok=True)

        # Check GDB exit code
        if result.returncode != 0:
            log.warning(f"GDB exited with status {result.returncode}. stderr: {result.stderr}")

        output = result.stdout
        lines = output.splitlines()

        buffer_addr = None
        rbp_value = None

        # Manually parse each line for the two patterns
        for line in lines:
            # Look for "$rdi = 0x..." line
            if '$rdi =' in line:
                parts = line.split('=')
                if len(parts) == 2:
                    addr_str = parts[1].strip()
                    try:
                        buffer_addr = int(addr_str, 16)
                    except ValueError:
                        continue
            # Look for "$rbp = 0x..." line
            if '$rbp =' in line:
                parts = line.split('=')
                if len(parts) == 2:
                    addr_str = parts[1].strip()
                    try:
                        rbp_value = int(addr_str, 16)
                    except ValueError:
                        continue

        if buffer_addr is None or rbp_value is None:
            # If parsing failed and GDB had non-zero exit, include stderr
            error_msg = f"Could not extract buffer address or RBP from GDB output.\nGDB stdout:\n{output}"
            if result.stderr:
                error_msg += f"\nGDB stderr:\n{result.stderr}"
            raise RuntimeError(error_msg)

        saved_rip_offset = _calculate_saved_rip_offset(buffer_addr, rbp_value)
        return {'buffer_addr': buffer_addr, 'saved_rip_offset': saved_rip_offset}

    finally:
        # Clean up dummy input file
        Path(input_path).unlink(missing_ok=True)
