"""Assembly to machine code conversion using GNU assembler and objcopy."""

import tempfile
import subprocess
import os

def convert_asm_to_machine_code(asm: str) -> bytes:
    """
    Converts assembly code to machine code.
    
    Args:
        asm: String containing assembly code
        
    Returns:
        bytes: Machine code
        
    Raises:
        RuntimeError: On any error during conversion process
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Paths to temporary files
        asm_file = os.path.join(tmpdir, "code.s")
        obj_file = os.path.join(tmpdir, "code.o")
        bin_file = os.path.join(tmpdir, "code.bin")
        
        try:
            # Write assembly code to file
            try:
                with open(asm_file, 'w') as f:
                    f.write(asm)
            except Exception as e:
                raise RuntimeError(f"Failed to write assembly code to temporary file: {e}")
            
            # Assemble to object file using GNU assembler
            try:
                subprocess.run(
                    ['as', '--64', '-o', obj_file, asm_file],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except FileNotFoundError:
                raise RuntimeError("GNU assembler (as) not found. Make sure binutils is installed")
            except subprocess.CalledProcessError as e:
                error_msg = f"Assembly error:\n{e.stderr}"
                raise RuntimeError(error_msg)
            except Exception as e:
                raise RuntimeError(f"Unknown error during assembly: {e}")
            
            # Extract .text section directly from object file to binary file
            try:
                subprocess.run(
                    ['objcopy', '-O', 'binary', '--only-section=.text', obj_file, bin_file],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except FileNotFoundError:
                raise RuntimeError("objcopy not found. Make sure binutils is installed")
            except subprocess.CalledProcessError as e:
                error_msg = f"Error extracting .text section:\n{e.stderr}"
                raise RuntimeError(error_msg)
            except Exception as e:
                raise RuntimeError(f"Unknown error during section extraction: {e}")
            
            # Read the resulting binary file
            try:
                with open(bin_file, 'rb') as f:
                    shellcode = f.read()
                return shellcode
            except Exception as e:
                raise RuntimeError(f"Failed to read binary file: {e}")
                
        except RuntimeError:
            # Re-raise RuntimeError
            raise
        except Exception as e:
            # Any other unexpected error
            raise RuntimeError(f"Unexpected error: {e}")
