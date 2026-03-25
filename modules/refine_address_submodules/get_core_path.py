import logging
import subprocess as sp
import tempfile as tf
from pathlib import Path


def _save_last_core() -> str | None:
    """
    Obtain the path to the most recent core dump.

    If the kernel core pattern is set to `"core"`, returns `"core"` (assuming
    the file exists in the current working directory). Otherwise, attempts to
    dump the latest core using `coredumpctl` and returns the path to a temporary
    file containing the core dump. Returns `None` if no core dump can be obtained.

    Returns:
        Path to the core dump file, or `None` if retrieval fails.
    """
    log = logging.getLogger("bof_exploit")

    # Check current core pattern
    try:
        with open("/proc/sys/kernel/core_pattern", "r") as f:
            pattern = f.read().strip()
    except Exception as e:
        log.debug(f"Could not read core_pattern: {e}")
        pattern = None

    # If pattern is exactly "core", we can rely on a file named "core" in cwd
    if pattern == "core":
        return "core"

    # Otherwise, try to use coredumpctl
    core_path = None
    try:
        with tf.NamedTemporaryFile(mode="wb", delete=False) as core_file:
            core_path = core_file.name
        cmd = ["coredumpctl", "dump", "-o", core_path]
        sp.run(cmd, check=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        return core_path
    except (sp.CalledProcessError, FileNotFoundError) as e:
        log.debug(f"coredumpctl failed: {e}")
        if core_path is not None:
            try:
                Path(core_path).unlink()
            except OSError:
                pass
        return None


def get_core_path(binary_path: Path, payload_bytes: bytes) -> str | None:
    """
    Run the binary with the given payload, let it crash, and return the
    path to the generated core dump.
    """
    log = logging.getLogger("bof_exploit")
    proc = sp.Popen(
        ["setarch", "-R", str(binary_path)],
        stdin=sp.PIPE,
        stdout=sp.DEVNULL,
        stderr=sp.DEVNULL,
    )

    try:
        proc.communicate(input=payload_bytes, timeout=5)
    except sp.TimeoutExpired:
        proc.kill()
        proc.wait()
        log.debug("Process timed out")
        return None

    # Process must have crashed (negative return code)
    if proc.returncode >= 0:
        log.debug(f"Process exited with code {proc.returncode}, not a crash")
        return None

    core_path = _save_last_core()
    if core_path is None:
        log.debug("No core dump found")
        return None

    log.debug(f"Core dump saved to {core_path}")
    return core_path
