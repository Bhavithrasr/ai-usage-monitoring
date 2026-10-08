"""
Windows-safe launcher for the LiteLLM proxy.

Why this exists
---------------
LiteLLM watches its Prisma query-engine subprocess by calling os.kill(pid, 0)
once a second -- the POSIX idiom for "is this process alive?". On Windows,
signal 0 is CTRL_C_EVENT, so Python calls GenerateConsoleCtrlEvent() and sends
a real Ctrl+C to every process attached to the console: the query engine dies,
uvicorn shuts down, and the proxy exits right after "Uvicorn running on ...".

This wrapper replaces os.kill(pid, 0) on Windows with a genuine liveness check
(OpenProcess + GetExitCodeProcess) and then hands off to LiteLLM's normal CLI,
so every litellm argument works unchanged:

    python scripts/run_litellm.py --config config/litellm_config.yaml --port 4000
"""
import os
import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _STILL_ACTIVE = 259
    _ERROR_INVALID_PARAMETER = 87  # OpenProcess on a PID that no longer exists

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _original_kill = os.kill

    def _check_process_alive(pid: int) -> None:
        """POSIX kill(pid, 0) semantics: return if alive, raise if not."""
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == _ERROR_INVALID_PARAMETER:
                raise ProcessLookupError(f"No such process: {pid}")
            raise PermissionError(f"Cannot open process {pid} (winerror {err})")
        try:
            code = wintypes.DWORD()
            if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                raise PermissionError(f"Cannot query process {pid}")
            if code.value != _STILL_ACTIVE:
                raise ProcessLookupError(f"Process {pid} has exited")
        finally:
            _kernel32.CloseHandle(handle)

    def _safe_kill(pid: int, sig: int) -> None:
        if sig == 0:
            _check_process_alive(pid)
            return
        _original_kill(pid, sig)

    os.kill = _safe_kill


if __name__ == "__main__":
    from litellm.proxy.proxy_cli import run_server

    sys.argv[0] = "litellm"
    run_server()
