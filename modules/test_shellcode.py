#!/usr/bin/env python3
"""Module for building standalone test shellcode executables."""
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .generate_shellcode import generate_shellcode_asm
from .config import WORD_SIZE


def build_test_shellcode(
    shellcode_type: str,
    data: str,
    output_dir: Path,
    verbose: bool = False
) -> Optional[Path]:
    """
    Build a standalone executable that runs the shellcode.
    
    Args:
        shellcode_type: Type of shellcode ("write", "execve", "crash")
        data: Data for shellcode (string to print or command to execute)
        output_dir: Directory to store temporary and final files
        verbose: Enable verbose logging
        
    Returns:
        Path to the created binary, or None if failed
    """
    log = logging.getLogger("bof_exploit")
    log.debug("Building test shellcode executable...")
    
    # Generate assembly
    try:
        asm = generate_shellcode_asm(shellcode_type, data)
    except Exception as e:
        log.error(f"Failed to generate assembly for test shellcode: {e}")
        return None
    
    # Wrap assembly with proper section and entry point
    full_asm = f""".section .text
.global _start
_start:
{asm}
"""
    
    # Create temporary file paths
    asm_path = output_dir / "test_shellcode.s"
    obj_path = output_dir / "test_shellcode.o"
    bin_path = output_dir / "test_shellcode"
    
    # Write assembly file
    try:
        asm_path.write_text(full_asm)
        log.debug(f"Assembly written to {asm_path}")
    except Exception as e:
        log.error(f"Failed to write assembly file: {e}")
        return None
    
    # Assemble and link
    try:
        # Assemble
        result = subprocess.run(
            ['as', '--64', '-o', str(obj_path), str(asm_path)],
            check=True,
            capture_output=True,
            text=True
        )
        log.debug("Assembly successful")
        
        # Link
        result = subprocess.run(
            ['ld', '-o', str(bin_path), str(obj_path)],
            check=True,
            capture_output=True,
            text=True
        )
        log.debug("Linking successful")
        
        # Make executable
        bin_path.chmod(0o755)
        log.debug(f"Made {bin_path} executable")
        
    except subprocess.CalledProcessError as e:
        log.error(f"Build failed:\n{e.stderr}")
        return None
    except Exception as e:
        log.error(f"Unexpected error during build: {e}")
        return None
    finally:
        # Clean up temporary files
        try:
            asm_path.unlink()
            obj_path.unlink()
            log.debug("Cleaned up temporary assembly and object files")
        except OSError as e:
            log.warning(f"Could not clean up temporary files: {e}")
    
    return bin_path
