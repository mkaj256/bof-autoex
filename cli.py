"""Command line interface for the BOF exploit generator."""

import argparse
from pathlib import Path

from modules.config import DEFAULT_OUTPUT_DIR

# Available shellcode types
SHELLCODE_CHOICES = ["write", "execve", "crash"]
SHELLCODE_HELP = """
Type of shellcode to generate:
  write    - prints a user‑supplied string to stdout.
  execve   - executes a user‑supplied command (via execve or system).
  crash    - makes program crash with segmentation fault
"""

def get_parsed_args() -> dict:
    """
    Parse command line arguments and return them as a dictionary.

    Returns:
        dict: A dictionary with keys:
            - binary (Path): Path to the vulnerable binary.
            - shellcode (str): Type of shellcode to generate.
            - data (str): String to print (for write) or command to execute (for execve).
            - output_dir (Path): Directory where payload and exploit script will be saved.
            - verbose (bool): Enable verbose output (extra info to stderr).
            - test_shellcode (bool): Generate a standalone executable that demonstrates the shellcode.
    """
    parser = argparse.ArgumentParser(
        description="Automatically generate a BOF exploit for a given binary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=SHELLCODE_HELP
    )

    parser.add_argument(
        "binary",
        type=Path,
        help="Path to the vulnerable 64‑bit ELF binary."
    )

    parser.add_argument(
        "-s", "--shellcode",
        choices=SHELLCODE_CHOICES,
        default="execve",
        help="Type of shellcode to use (default: execve)."
    )

    parser.add_argument(
        "-d", "--data",
        help="String to print (for write) or command to execute (for execve)."
    )

    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path(DEFAULT_OUTPUT_DIR),
        help="Directory to store generated files (default: ./output)."
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed progress information to stderr."
    )

    parser.add_argument(
        "--test-shellcode",
        action="store_true",
        help="Instead of generating an exploit, create a standalone executable that runs the shellcode."
    )

    args = parser.parse_args()
    if args.shellcode != "crash" and not args.data:
        parser.error("--data is required for shellcode types 'write' and 'execve'")

    return {
        "binary": args.binary,
        "shellcode": args.shellcode,
        "data": args.data,
        "output_dir": args.output_dir,
        "verbose": args.verbose,
        "test_shellcode": args.test_shellcode,
    }
